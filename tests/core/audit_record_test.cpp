// AuditRecord unit tests: closed enum vocabulary, factory-only
// construction, derived outcome, and the factory contracts that keep a
// record from misrepresenting the pipeline event it audits.

#include <stdexcept>
#include <string>
#include <type_traits>
#include <variant>

#include <gtest/gtest.h>

#include "core/audit_record.h"
#include "ports/audit_repository.h"

namespace {

core::SuccessDetails valid_success() {
    core::SuccessDetails d{core::StatementType::Select, 4, 5, {1, 1, 1}};
    return d;
}

// --- Closed vocabularies ------------------------------------------------------

TEST(AuditRecordTest, AuditOutcomeToStringValues) {
    EXPECT_STREQ(core::to_string(core::AuditOutcome::Success), "SUCCESS");
    EXPECT_STREQ(core::to_string(core::AuditOutcome::ParsingFailure),
                 "PARSING_FAILURE");
    EXPECT_STREQ(core::to_string(core::AuditOutcome::PolicyRejected),
                 "POLICY_REJECTED");
    EXPECT_STREQ(core::to_string(core::AuditOutcome::DatabaseFailure),
                 "DATABASE_FAILURE");
    EXPECT_STREQ(core::to_string(core::AuditOutcome::MaskingRefused),
                 "MASKING_REFUSED");
    EXPECT_STREQ(core::to_string(core::AuditOutcome::InternalFailure),
                 "INTERNAL_FAILURE");
}

TEST(AuditRecordTest, AuxiliaryEnumToStringValues) {
    EXPECT_STREQ(core::to_string(core::DbFailureCategory::ConnectionFailure),
                 "CONNECTION_FAILURE");
    EXPECT_STREQ(core::to_string(core::DbFailureCategory::ExecutionFailure),
                 "EXECUTION_FAILURE");
    EXPECT_STREQ(ports::to_string(ports::AuditAppendResult::Ok), "OK");
    EXPECT_STREQ(ports::to_string(ports::AuditAppendResult::OpenFailure),
                 "OPEN_FAILURE");
    EXPECT_STREQ(ports::to_string(ports::AuditAppendResult::WriteFailure),
                 "WRITE_FAILURE");
}

// --- Construction contract -----------------------------------------------------

TEST(AuditRecordTest, NotDefaultConstructibleAndWrongStateAccessThrows) {
    static_assert(!std::is_default_constructible_v<core::AuditRecord>,
                  "AuditRecord must be factory-only");

    const auto record = core::AuditRecord::policy_rejected(
        1000, 7,
        {core::RejectReason::DmlNotAllowed, core::StatementType::Delete, 1});
    EXPECT_NO_THROW(record.policy_rejected_details());
    EXPECT_THROW(record.success_details(), std::bad_variant_access);
    EXPECT_THROW(record.database_failure_details(), std::bad_variant_access);
}

TEST(AuditRecordTest, FactoriesDeriveCorrectOutcomeAndEnvelope) {
    const auto success = core::AuditRecord::success(1234, 1, valid_success());
    EXPECT_EQ(success.outcome(), core::AuditOutcome::Success);
    EXPECT_EQ(success.timestamp_ms(), 1234);
    EXPECT_EQ(success.request_id(), 1u);

    EXPECT_EQ(core::AuditRecord::parsing_failure(1, 2).outcome(),
              core::AuditOutcome::ParsingFailure);
    EXPECT_EQ(core::AuditRecord::policy_rejected(
                  1, 3,
                  {core::RejectReason::EmptyInput, core::StatementType::Unknown,
                   0})
                  .outcome(),
              core::AuditOutcome::PolicyRejected);
    EXPECT_EQ(core::AuditRecord::database_failure(
                  1, 4,
                  {core::DbFailureCategory::ConnectionFailure,
                   core::StatementType::Select})
                  .outcome(),
              core::AuditOutcome::DatabaseFailure);
    EXPECT_EQ(core::AuditRecord::masking_refused(
                  1, 5, {core::StatementType::Select, 2})
                  .outcome(),
              core::AuditOutcome::MaskingRefused);
    EXPECT_EQ(core::AuditRecord::internal_failure(1, 6).outcome(),
              core::AuditOutcome::InternalFailure);
}

// --- Factory validation ---------------------------------------------------------

TEST(AuditRecordTest, PolicyRejectedFactoryRejectsInvalidReasons) {
    // No real rejection reason.
    EXPECT_THROW(core::AuditRecord::policy_rejected(
                     1, 1,
                     {core::RejectReason::None, core::StatementType::Select, 1}),
                 std::invalid_argument);
    EXPECT_THROW(
        core::AuditRecord::policy_rejected(
            1, 1,
            {core::RejectReason::NotEvaluated, core::StatementType::Select, 1}),
        std::invalid_argument);
    // Parser failures are audited ONLY as ParsingFailure — never as
    // PolicyRejected + UNPARSEABLE_SQL (no duplicate representation).
    EXPECT_THROW(core::AuditRecord::policy_rejected(
                     1, 1,
                     {core::RejectReason::UnparseableSql,
                      core::StatementType::Unknown, 1}),
                 std::invalid_argument);
}

TEST(AuditRecordTest, SelectOnlyFactoriesRejectNonSelect) {
    // Success, DatabaseFailure, and MaskingRefused are reachable only for
    // SELECT under the read-only policy.
    core::SuccessDetails bad_success = valid_success();
    bad_success.statement_type = core::StatementType::Insert;
    EXPECT_THROW(core::AuditRecord::success(1, 1, bad_success),
                 std::invalid_argument);

    EXPECT_THROW(core::AuditRecord::database_failure(
                     1, 1,
                     {core::DbFailureCategory::ExecutionFailure,
                      core::StatementType::Drop}),
                 std::invalid_argument);

    EXPECT_THROW(core::AuditRecord::masking_refused(
                     1, 1, {core::StatementType::Update, 3}),
                 std::invalid_argument);
}

// === Referenced-table metadata =============================================
//
// The full validation matrix lives here. Other layers only check that the
// metadata reaches a record; they do not repeat these cases.

namespace {

// Builds a record through a real factory so validation cannot be bypassed.
core::AuditTableMetadata metadata_for(std::vector<std::string> names) {
    return core::AuditRecord::success(1, 1, valid_success(), std::move(names))
        .referenced_tables();
}

}  // namespace

TEST(AuditTableMetadataTest, ValidNamesArePresentAndPreserveOrder) {
    const core::AuditTableMetadata m = metadata_for({"customers", "orders"});
    EXPECT_EQ(m.state, core::AuditTableState::Present);
    EXPECT_EQ(m.tables, std::vector<std::string>({"customers", "orders"}));

    // Underscores, digits, dollar signs and a leading underscore are legal.
    EXPECT_EQ(metadata_for({"_tmp$1", "Orders2"}).state,
              core::AuditTableState::Present);

    // Exactly at the limits.
    EXPECT_EQ(metadata_for({std::string(63, 'a')}).state,
              core::AuditTableState::Present);
    EXPECT_EQ(metadata_for({"t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8"}).state,
              core::AuditTableState::Present);
}

TEST(AuditTableMetadataTest, EmptyListIsAbsent) {
    const core::AuditTableMetadata m = metadata_for({});
    EXPECT_EQ(m.state, core::AuditTableState::Absent);
    EXPECT_TRUE(m.tables.empty());
}

TEST(AuditTableMetadataTest, AnyUnsafeOrAmbiguousNameOmitsTheWholeList) {
    const std::vector<std::vector<std::string>> rejected = {
        {"public.customers"},              // qualified: ambiguous
        {"customers", "public.orders"},    // one bad name poisons the list
        {"a b"},                           // space
        {std::string("a\tb")},             // control character
        {std::string("a\xFF\xEB")},        // invalid UTF-8, would break dump()
        {"1customers"},                    // leading digit
        {"$customers"},                    // leading dollar
        {""},                              // empty
        {std::string(64, 'a')},            // one byte over the length limit
        {"cust-omers"},                    // hyphen
        {"\"orders\""},                    // embedded quotes
    };
    for (const std::vector<std::string>& names : rejected) {
        SCOPED_TRACE(names.empty() ? "(empty)" : names.front());
        const core::AuditTableMetadata m = metadata_for(names);
        EXPECT_EQ(m.state, core::AuditTableState::Omitted);
        EXPECT_TRUE(m.tables.empty()) << "nothing may be retained on omission";
    }
}

TEST(AuditTableMetadataTest, MoreThanEightNamesIsOmitted) {
    const core::AuditTableMetadata m =
        metadata_for({"t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9"});
    EXPECT_EQ(m.state, core::AuditTableState::Omitted);
    EXPECT_TRUE(m.tables.empty());
}

TEST(AuditTableMetadataTest, StateDependsOnlyOnTheNameList) {
    // A rejected DDL statement still reports Present when its table list is
    // safe: the state is not derived from the outcome or the reason.
    const core::AuditRecord rejected = core::AuditRecord::policy_rejected(
        1, 1, {core::RejectReason::DdlNotAllowed, core::StatementType::Drop, 1},
        {"customers"});
    EXPECT_EQ(rejected.referenced_tables().state, core::AuditTableState::Present);
    EXPECT_EQ(rejected.referenced_tables().tables,
              std::vector<std::string>({"customers"}));

    // And an ordinary success reports Omitted when its list is unsafe.
    EXPECT_EQ(metadata_for({"public.customers"}).state,
              core::AuditTableState::Omitted);
}

TEST(AuditTableMetadataTest, IneligibleOutcomesAreAlwaysAbsent) {
    // These factories take no table parameter at all, so the metadata cannot
    // be supplied even by mistake.
    EXPECT_EQ(core::AuditRecord::parsing_failure(1, 1).referenced_tables().state,
              core::AuditTableState::Absent);
    EXPECT_EQ(core::AuditRecord::internal_failure(1, 2).referenced_tables().state,
              core::AuditTableState::Absent);
}

TEST(AuditTableMetadataTest, EveryEligibleFactoryAcceptsMetadata) {
    const std::vector<std::string> names{"orders"};
    EXPECT_EQ(core::AuditRecord::success(1, 1, valid_success(), names)
                  .referenced_tables().state,
              core::AuditTableState::Present);
    EXPECT_EQ(core::AuditRecord::write_success(
                  1, 2, {core::StatementType::Insert, 1}, names)
                  .referenced_tables().state,
              core::AuditTableState::Present);
    EXPECT_EQ(core::AuditRecord::policy_rejected(
                  1, 3,
                  {core::RejectReason::DmlNotAllowed, core::StatementType::Update, 1},
                  names)
                  .referenced_tables().state,
              core::AuditTableState::Present);
    EXPECT_EQ(core::AuditRecord::database_failure(
                  1, 4,
                  {core::DbFailureCategory::ExecutionFailure, core::StatementType::Select},
                  names)
                  .referenced_tables().state,
              core::AuditTableState::Present);
    EXPECT_EQ(core::AuditRecord::masking_refused(
                  1, 5, {core::StatementType::Select, 1}, names)
                  .referenced_tables().state,
              core::AuditTableState::Present);
}

TEST(AuditRecordTest, WriteSuccessCarriesAffectedRowsAndReportsSuccess) {
    const core::AuditRecord record =
        core::AuditRecord::write_success(1700000000000, 7,
                                         {core::StatementType::Insert, 1});

    EXPECT_EQ(record.outcome(), core::AuditOutcome::Success);
    EXPECT_TRUE(record.is_write_success());
    EXPECT_EQ(record.write_success_details().affected_rows, 1u);
    EXPECT_EQ(record.write_success_details().statement_type,
              core::StatementType::Insert);
    // The two success shapes are not interchangeable.
    EXPECT_THROW(record.success_details(), std::bad_variant_access);
}

TEST(AuditRecordTest, WriteSuccessRequiresInsertAndReadSuccessStaysSelectOnly) {
    for (core::StatementType type :
         {core::StatementType::Select, core::StatementType::Update,
          core::StatementType::Delete, core::StatementType::Drop}) {
        EXPECT_THROW(core::AuditRecord::write_success(1, 1, {type, 1}),
                     std::invalid_argument);
    }

    // A masked-result success is still SELECT-only.
    core::SuccessDetails read = valid_success();
    read.statement_type = core::StatementType::Insert;
    EXPECT_THROW(core::AuditRecord::success(1, 1, read), std::invalid_argument);

    // A read success is not a write success.
    const core::AuditRecord select_record = core::AuditRecord::success(1, 1, valid_success());
    EXPECT_FALSE(select_record.is_write_success());
    EXPECT_THROW(select_record.write_success_details(), std::bad_variant_access);
}

TEST(AuditRecordTest, DatabaseFailureAcceptsBothAuthorizedStatementTypes) {
    EXPECT_NO_THROW(core::AuditRecord::database_failure(
        1, 1, {core::DbFailureCategory::ExecutionFailure, core::StatementType::Insert}));
    EXPECT_NO_THROW(core::AuditRecord::database_failure(
        1, 1, {core::DbFailureCategory::ConnectionFailure, core::StatementType::Select}));
    EXPECT_THROW(core::AuditRecord::database_failure(
                     1, 1,
                     {core::DbFailureCategory::ExecutionFailure, core::StatementType::Update}),
                 std::invalid_argument);
}

}  // namespace
