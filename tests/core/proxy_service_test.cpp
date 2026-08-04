// ProxyService unit tests: one audit append per controlled request, the
// audit-failure release rule, and the outcome mapping. No database, no
// sockets — the parser, executor and audit repository are all fakes.

#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "core/proxy_service.h"
#include "core/service_result.h"
#include "fake_audit_repository.h"
#include "fake_query_executor.h"
#include "fake_sql_parser.h"

namespace {

using Cell = std::optional<std::string>;

ports::ParseResult parsed_select(std::vector<std::string> projection,
                                 bool wildcard = false) {
    ports::ParseResult parse;
    parse.success = true;
    parse.statements.resize(1);
    parse.statements[0].type = core::StatementType::Select;
    parse.statements[0].tables = {{"", "customers"}};
    parse.statements[0].projection_columns = std::move(projection);
    parse.statements[0].has_wildcard_projection = wildcard;
    return parse;
}

ports::ExecutionResult ok_result(std::vector<std::string> column_names,
                                 std::vector<std::vector<Cell>> rows) {
    ports::ExecutionResult result;
    result.status = ports::ExecutionStatus::Ok;
    for (std::string& name : column_names) {
        ports::ColumnInfo column;
        column.name = std::move(name);
        result.columns.push_back(std::move(column));
    }
    result.rows = std::move(rows);
    result.row_count = static_cast<long long>(result.rows.size());
    result.has_result_set = !result.columns.empty();
    return result;
}

// A parser that violates the ISqlParser no-escape contract, to prove the
// orchestrator still produces exactly one controlled outcome.
class ThrowingParser : public ports::ISqlParser {
public:
    ports::ParseResult parse(const std::string&) override {
        throw std::runtime_error("simulated parser failure");
    }
};

// Owns the fakes and the service under test, keeping the fake parser
// reachable for per-test setup. Self-contained: no shared state.
struct FakeParserHarness {
    FakeParserHarness() {
        auto owned = std::make_unique<fakes::FakeSqlParser>();
        parser = owned.get();
        analyzer = std::make_unique<core::SqlAnalyzer>(std::move(owned));
        service = std::make_unique<core::ProxyService>(*analyzer, executor, audit);
    }

    fakes::FakeSqlParser* parser = nullptr;
    std::unique_ptr<core::SqlAnalyzer> analyzer;
    fakes::FakeQueryExecutor executor;
    fakes::FakeAuditRepository audit;
    std::unique_ptr<core::ProxyService> service;
};

const core::AuditRecord& only_record(const fakes::FakeAuditRepository& audit) {
    EXPECT_EQ(audit.appended.size(), 1u);  // exactly one append per request
    return audit.appended.front();
}

// --- Result type contract -----------------------------------------------------

TEST(ServiceResultTest, IsNotDefaultConstructible) {
    static_assert(!std::is_default_constructible_v<core::ServiceResult>,
                  "ServiceResult must be factory-only");
}

TEST(ServiceResultTest, FailureExposesNoResult) {
    const auto failed = core::ServiceResult::failure(core::ServiceFailure::InternalError);
    EXPECT_FALSE(failed.succeeded());
    EXPECT_THROW(failed.result(), std::bad_variant_access);
}

// --- Rejection paths ----------------------------------------------------------

TEST(ProxyServiceTest, ParseFailureIsAuditedAsParsingFailure) {
    FakeParserHarness h;
    h.parser->result_to_return.success = false;
    h.parser->result_to_return.error = "syntax error at line 1, column 7";

    const core::ServiceResult result = h.service->handle("SELEC * FRM customers");

    EXPECT_FALSE(result.succeeded());
    EXPECT_EQ(result.failure_reason(), core::ServiceFailure::UnparseableSql);
    EXPECT_EQ(only_record(h.audit).outcome(), core::AuditOutcome::ParsingFailure);
    EXPECT_EQ(h.executor.call_count(), 0u);  // never executed
}

TEST(ProxyServiceTest, EmptyInputIsRejectedAndAuditedAsPolicyRejection) {
    FakeParserHarness h;  // the parser is never invoked for empty input

    const core::ServiceResult result = h.service->handle("");

    EXPECT_FALSE(result.succeeded());
    EXPECT_EQ(result.failure_reason(), core::ServiceFailure::EmptyInput);
    const core::AuditRecord& record = only_record(h.audit);
    EXPECT_EQ(record.outcome(), core::AuditOutcome::PolicyRejected);
    EXPECT_EQ(record.policy_rejected_details().reason, core::RejectReason::EmptyInput);
    EXPECT_EQ(h.executor.call_count(), 0u);
}

TEST(ProxyServiceTest, PolicyRejectionIsGenericToClientButTypedInAudit) {
    FakeParserHarness h;
    ports::ParseResult parse;
    parse.success = true;
    parse.statements.resize(1);
    parse.statements[0].type = core::StatementType::Drop;
    parse.statements[0].tables = {{"", "customers"}};
    h.parser->result_to_return = parse;

    const core::ServiceResult result = h.service->handle("DROP TABLE customers");

    // Client sees only the generic category...
    EXPECT_EQ(result.failure_reason(), core::ServiceFailure::PolicyRejected);
    // ...while the audit trail keeps the precise reason.
    const core::AuditRecord& record = only_record(h.audit);
    EXPECT_EQ(record.outcome(), core::AuditOutcome::PolicyRejected);
    EXPECT_EQ(record.policy_rejected_details().reason, core::RejectReason::DdlNotAllowed);
    EXPECT_EQ(h.executor.call_count(), 0u);
}

// --- Database failures --------------------------------------------------------

TEST(ProxyServiceTest, DatabaseFailuresMapToTypedCategories) {
    struct Case {
        ports::ExecutionStatus status;
        core::ServiceFailure expected_failure;
        core::DbFailureCategory expected_category;
    };
    const Case cases[] = {
        {ports::ExecutionStatus::ConnectionFailure,
         core::ServiceFailure::DatabaseUnavailable,
         core::DbFailureCategory::ConnectionFailure},
        {ports::ExecutionStatus::ExecutionFailure, core::ServiceFailure::QueryFailed,
         core::DbFailureCategory::ExecutionFailure},
    };
    for (const Case& c : cases) {
        FakeParserHarness h;
        h.parser->result_to_return = parsed_select({"id"});
        h.executor.result_to_return.status = c.status;
        h.executor.result_to_return.error = "statement failed (SQLSTATE 42P01)";

        const core::ServiceResult result = h.service->handle("SELECT id FROM customers");

        EXPECT_EQ(result.failure_reason(), c.expected_failure);
        const core::AuditRecord& record = only_record(h.audit);
        EXPECT_EQ(record.outcome(), core::AuditOutcome::DatabaseFailure);
        EXPECT_EQ(record.database_failure_details().category, c.expected_category);
    }
}

// --- Success path -------------------------------------------------------------

TEST(ProxyServiceTest, SuccessfulQueryReturnsMaskedValuesAndAudits) {
    FakeParserHarness h;
    h.parser->result_to_return = parsed_select({"id", "email", "phone"});
    h.executor.result_to_return =
        ok_result({"id", "email", "phone"},
                  {{Cell{"1"}, Cell{"lihi.roas@example.com"}, Cell{"0501230101"}},
                   {Cell{"2"}, Cell{"kim.perez@example.org"}, Cell{std::nullopt}}});

    const core::ServiceResult result =
        h.service->handle("SELECT id, email, phone FROM customers");

    ASSERT_TRUE(result.succeeded());
    const core::MaskedQueryResult& masked = result.result();
    EXPECT_EQ(masked.column_names, (std::vector<std::string>{"id", "email", "phone"}));
    EXPECT_EQ(masked.rows[0][1], Cell{"l***@example.com"});
    EXPECT_EQ(masked.rows[0][2], Cell{"***0101"});
    EXPECT_EQ(masked.rows[1][2], Cell{std::nullopt});  // NULL preserved
    EXPECT_EQ(masked.rows[0][0], Cell{"1"});           // non-PII untouched

    const core::AuditRecord& record = only_record(h.audit);
    ASSERT_EQ(record.outcome(), core::AuditOutcome::Success);
    EXPECT_EQ(record.success_details().row_count, 2u);
    EXPECT_EQ(record.success_details().column_count, 3u);
    EXPECT_EQ(record.success_details().pii.email_columns, 1u);
    EXPECT_EQ(record.success_details().pii.phone_columns, 1u);
    EXPECT_EQ(record.success_details().pii.credit_card_columns, 0u);
}

TEST(ProxyServiceTest, ZeroRowsPreservesColumnMetadataAndEmptyStringStaysEmpty) {
    FakeParserHarness h;
    h.parser->result_to_return = parsed_select({"id", "email"});
    h.executor.result_to_return = ok_result({"id", "email"}, {});

    const core::ServiceResult empty = h.service->handle("SELECT id, email FROM customers");
    ASSERT_TRUE(empty.succeeded());
    EXPECT_EQ(empty.result().column_names.size(), 2u);
    EXPECT_TRUE(empty.result().rows.empty());
    EXPECT_EQ(only_record(h.audit).success_details().row_count, 0u);

    // Empty string is a value, not NULL, and survives masking.
    FakeParserHarness h2;
    h2.parser->result_to_return = parsed_select({"phone"});
    h2.executor.result_to_return = ok_result({"phone"}, {{Cell{""}}});
    const core::ServiceResult with_empty = h2.service->handle("SELECT phone FROM customers");
    ASSERT_TRUE(with_empty.succeeded());
    EXPECT_EQ(with_empty.result().rows[0][0], Cell{""});
}

TEST(ProxyServiceTest, DuplicateColumnNamesArePreservedPositionally) {
    FakeParserHarness h;
    h.parser->result_to_return = parsed_select({}, /*wildcard=*/true);
    h.executor.result_to_return =
        ok_result({"email", "email"},
                  {{Cell{"lihi.roas@example.com"}, Cell{"kim.perez@example.org"}}});

    const core::ServiceResult result = h.service->handle("SELECT * FROM customers");

    ASSERT_TRUE(result.succeeded());
    EXPECT_EQ(result.result().column_names,
              (std::vector<std::string>{"email", "email"}));
    EXPECT_EQ(result.result().rows[0][0], Cell{"l***@example.com"});
    EXPECT_EQ(result.result().rows[0][1], Cell{"k***@example.org"});
    EXPECT_EQ(only_record(h.audit).success_details().pii.email_columns, 2u);
}

TEST(ProxyServiceTest, ComputedProjectionIsRefusedByMaskingAndAudited) {
    FakeParserHarness h;
    ports::ParseResult parse = parsed_select({});
    parse.statements[0].has_computed_projection = true;  // e.g. UPPER(email)
    h.parser->result_to_return = parse;
    h.executor.result_to_return = ok_result({"upper"}, {{Cell{"LIHI.ROAS@EXAMPLE.COM"}}});

    const core::ServiceResult result = h.service->handle("SELECT UPPER(email) FROM customers");

    EXPECT_FALSE(result.succeeded());
    EXPECT_EQ(result.failure_reason(), core::ServiceFailure::MaskingRefused);
    EXPECT_THROW(result.result(), std::bad_variant_access);  // no data released
    const core::AuditRecord& record = only_record(h.audit);
    EXPECT_EQ(record.outcome(), core::AuditOutcome::MaskingRefused);
    EXPECT_EQ(record.masking_refused_details().column_count, 1u);
}

// --- Unexpected failures ------------------------------------------------------

TEST(ProxyServiceTest, UnexpectedParserExceptionBecomesInternalFailure) {
    fakes::FakeQueryExecutor executor;
    fakes::FakeAuditRepository audit;
    core::SqlAnalyzer analyzer(std::make_unique<ThrowingParser>());
    core::ProxyService service(analyzer, executor, audit);

    const core::ServiceResult result = service.handle("SELECT id FROM customers");

    EXPECT_EQ(result.failure_reason(), core::ServiceFailure::InternalError);
    EXPECT_EQ(only_record(audit).outcome(), core::AuditOutcome::InternalFailure);
}

TEST(ProxyServiceTest, UnexpectedExecutorExceptionBecomesInternalFailure) {
    FakeParserHarness h;
    h.parser->result_to_return = parsed_select({"id"});
    h.executor.throw_on_execute = true;

    const core::ServiceResult result = h.service->handle("SELECT id FROM customers");

    EXPECT_EQ(result.failure_reason(), core::ServiceFailure::InternalError);
    EXPECT_EQ(only_record(h.audit).outcome(), core::AuditOutcome::InternalFailure);
}

TEST(ProxyServiceTest, NegativeSignedCountIsRejectedBeforeConversion) {
    FakeParserHarness h;
    h.parser->result_to_return = parsed_select({"id"});
    h.executor.result_to_return = ok_result({"id"}, {{Cell{"1"}}});
    h.executor.result_to_return.row_count = -1;  // broken upstream contract

    const core::ServiceResult result = h.service->handle("SELECT id FROM customers");

    EXPECT_EQ(result.failure_reason(), core::ServiceFailure::InternalError);
    EXPECT_EQ(only_record(h.audit).outcome(), core::AuditOutcome::InternalFailure);
}

// --- Audit-failure policy -----------------------------------------------------

TEST(ProxyServiceTest, AuditFailureOnSuccessWithholdsAllData) {
    FakeParserHarness h;
    h.parser->result_to_return = parsed_select({"email"});
    h.executor.result_to_return = ok_result({"email"}, {{Cell{"lihi.roas@example.com"}}});
    h.audit.result_to_return = ports::AuditAppendResult::WriteFailure;

    const core::ServiceResult result = h.service->handle("SELECT email FROM customers");

    EXPECT_FALSE(result.succeeded());
    EXPECT_EQ(result.failure_reason(), core::ServiceFailure::InternalError);
    // No columns and no rows are reachable through a failure outcome.
    EXPECT_THROW(result.result(), std::bad_variant_access);
    // The append was still attempted exactly once, for the real outcome.
    EXPECT_EQ(only_record(h.audit).outcome(), core::AuditOutcome::Success);
}

TEST(ProxyServiceTest, AuditFailureOnFailedRequestPreservesOriginalFailure) {
    FakeParserHarness h;
    ports::ParseResult parse;
    parse.success = true;
    parse.statements.resize(1);
    parse.statements[0].type = core::StatementType::Insert;
    parse.statements[0].tables = {{"", "customers"}};
    h.parser->result_to_return = parse;
    h.audit.result_to_return = ports::AuditAppendResult::OpenFailure;

    const core::ServiceResult result = h.service->handle("INSERT INTO customers ...");

    // Not replaced by InternalError: no data was leaving anyway.
    EXPECT_EQ(result.failure_reason(), core::ServiceFailure::PolicyRejected);
    EXPECT_EQ(h.audit.appended.size(), 1u);  // no recursive second attempt
}

TEST(ProxyServiceTest, ThrowingAuditRepositoryIsHandledLikeAFailure) {
    class ThrowingAudit : public ports::IAuditRepository {
    public:
        int calls = 0;
        ports::AuditAppendResult append(const core::AuditRecord&) override {
            ++calls;
            throw std::runtime_error("simulated audit failure");
        }
    };

    ThrowingAudit audit;
    fakes::FakeQueryExecutor executor;
    auto parser = std::make_unique<fakes::FakeSqlParser>();
    parser->result_to_return = parsed_select({"email"});
    core::SqlAnalyzer analyzer(std::move(parser));
    executor.result_to_return = ok_result({"email"}, {{Cell{"lihi.roas@example.com"}}});
    core::ProxyService service(analyzer, executor, audit);

    const core::ServiceResult result = service.handle("SELECT email FROM customers");

    EXPECT_EQ(result.failure_reason(), core::ServiceFailure::InternalError);
    EXPECT_EQ(audit.calls, 1);  // exactly one attempt, never audited recursively
}

// --- Envelope and concurrency -------------------------------------------------

TEST(ProxyServiceTest, EveryRequestProducesExactlyOneRecordWithAMonotonicId) {
    FakeParserHarness h;
    h.parser->result_to_return = parsed_select({"id"});
    h.executor.result_to_return = ok_result({"id"}, {{Cell{"1"}}});

    h.service->handle("SELECT id FROM customers");
    h.parser->result_to_return.success = false;  // second request fails to parse
    h.service->handle("SELEC id FROM customers");
    h.service->handle("");

    ASSERT_EQ(h.audit.appended.size(), 3u);
    EXPECT_EQ(h.audit.appended[0].outcome(), core::AuditOutcome::Success);
    EXPECT_EQ(h.audit.appended[1].outcome(), core::AuditOutcome::ParsingFailure);
    EXPECT_EQ(h.audit.appended[2].outcome(), core::AuditOutcome::PolicyRejected);
    for (std::size_t i = 1; i < h.audit.appended.size(); ++i) {
        EXPECT_GT(h.audit.appended[i].request_id(), h.audit.appended[i - 1].request_id());
        EXPECT_GE(h.audit.appended[i].timestamp_ms(), h.audit.appended[i - 1].timestamp_ms());
    }
    EXPECT_GT(h.audit.appended[0].timestamp_ms(), 0);
}

TEST(ProxyServiceTest, ConcurrentRequestsAreSerializedAndEachIsAuditedOnce) {
    FakeParserHarness h;
    h.parser->result_to_return = parsed_select({"id"});
    h.executor.result_to_return = ok_result({"id"}, {{Cell{"1"}}});
    h.executor.delay_ms = 5;  // widen any overlap window

    constexpr int kThreads = 8;
    std::vector<std::thread> threads;
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&h] { h.service->handle("SELECT id FROM customers"); });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }

    // The service processes one request at a time: the executor is never
    // re-entered.
    EXPECT_EQ(h.executor.max_in_flight(), 1);
    EXPECT_EQ(h.executor.call_count(), static_cast<std::size_t>(kThreads));
    ASSERT_EQ(h.audit.appended.size(), static_cast<std::size_t>(kThreads));

    std::set<std::uint64_t> ids;
    for (const core::AuditRecord& record : h.audit.appended) {
        ids.insert(record.request_id());
    }
    EXPECT_EQ(ids.size(), static_cast<std::size_t>(kThreads));  // no duplicates
}

}  // namespace
