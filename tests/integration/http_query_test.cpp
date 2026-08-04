// HTTP contract tests for POST /query.
//
// Almost every test invokes the handler directly with an httplib::Request and
// an httplib::Response — no socket, no server thread, fully deterministic.
// One socket-level smoke test verifies that the routes are actually
// registered on a live server.
//
// No database is required: the parser, executor and audit repository are
// fakes, so this target never skips.

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "adapters/http/http_server.h"
#include "adapters/http/query_routes.h"
#include "core/proxy_service.h"
#include "logging/system_log.h"
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

class HttpQueryTest : public ::testing::Test {
protected:
    void SetUp() override {
        // HttpServer::run() logs on startup, and system_log requires init()
        // before logger() is used (the same contract main.cpp honors).
        // Idempotent, so calling it per test is safe.
        system_log::init();

        auto owned = std::make_unique<fakes::FakeSqlParser>();
        parser = owned.get();
        analyzer = std::make_unique<core::SqlAnalyzer>(std::move(owned));
        service = std::make_unique<core::ProxyService>(*analyzer, executor, audit);
    }

    // Invokes the real handler without any socket.
    httplib::Response post(const std::string& body,
                           const std::string& content_type = "application/json") {
        httplib::Request request;
        request.method = "POST";
        request.path = "/query";
        request.body = body;
        if (!content_type.empty()) {
            request.set_header("Content-Type", content_type);
        }
        httplib::Response response;
        http_adapter::handle_query_request(*service, request, response);
        return response;
    }

    nlohmann::json body_of(const httplib::Response& response) {
        return nlohmann::json::parse(response.body, nullptr, false);
    }

    fakes::FakeSqlParser* parser = nullptr;
    std::unique_ptr<core::SqlAnalyzer> analyzer;
    fakes::FakeQueryExecutor executor;
    fakes::FakeAuditRepository audit;
    std::unique_ptr<core::ProxyService> service;
};

// --- Write response shape -----------------------------------------------------

TEST_F(HttpQueryTest, AuthorizedInsertReturnsAffectedRowsWithoutAResultSet) {
    ports::ParseResult parse;
    parse.success = true;
    parse.statements.resize(1);
    parse.statements[0].type = core::StatementType::Insert;
    parse.statements[0].tables = {{"", "orders"}};
    parse.statements[0].affected_columns = {"customer_id", "amount"};
    parse.statements[0].insert_source = core::InsertSource::Values;
    parse.statements[0].insert_value_kinds = {
        core::InsertValueKind::PositiveIntegerLiteral,
        core::InsertValueKind::PositiveDecimalLiteral};
    parser->result_to_return = parse;

    ports::ExecutionResult executed;
    executed.status = ports::ExecutionStatus::Ok;
    executed.affected_rows = 1;
    executor.result_to_return = executed;

    const httplib::Response response = post(
        R"json({"sql":"INSERT INTO orders (customer_id, amount) VALUES (1, 199.90)"})json");

    EXPECT_EQ(response.status, 200);
    const nlohmann::json body = body_of(response);
    EXPECT_EQ(body["affected_rows"], 1);
    // A write response carries no result-set fields at all.
    EXPECT_FALSE(body.contains("rows"));
    EXPECT_FALSE(body.contains("columns"));
    EXPECT_FALSE(body.contains("row_count"));
}

// --- Success shape ------------------------------------------------------------

TEST_F(HttpQueryTest, SuccessfulQueryReturnsPositionalRowsWithMaskedValues) {
    parser->result_to_return = parsed_select({"id", "email", "phone"});
    executor.result_to_return =
        ok_result({"id", "email", "phone"},
                  {{Cell{"1"}, Cell{"lihi.roas@example.com"}, Cell{std::nullopt}},
                   {Cell{"2"}, Cell{"kim.perez@example.org"}, Cell{""}}});

    const httplib::Response response =
        post(R"({"sql":"SELECT id, email, phone FROM customers"})");

    EXPECT_EQ(response.status, 200);
    const nlohmann::json body = body_of(response);
    EXPECT_EQ(body["columns"], nlohmann::json::array({"id", "email", "phone"}));
    EXPECT_EQ(body["row_count"], 2);
    // Rows are arrays, not objects: order is preserved.
    ASSERT_TRUE(body["rows"].is_array());
    EXPECT_EQ(body["rows"][0][1], "l***@example.com");
    EXPECT_TRUE(body["rows"][0][2].is_null());   // SQL NULL -> JSON null
    EXPECT_EQ(body["rows"][1][2], "");           // empty string preserved
    EXPECT_EQ(audit.appended.size(), 1u);
}

TEST_F(HttpQueryTest, ZeroRowsStillReturnsColumnMetadata) {
    parser->result_to_return = parsed_select({"id", "email"});
    executor.result_to_return = ok_result({"id", "email"}, {});

    const httplib::Response response = post(R"({"sql":"SELECT id, email FROM customers"})");

    EXPECT_EQ(response.status, 200);
    const nlohmann::json body = body_of(response);
    EXPECT_EQ(body["columns"], nlohmann::json::array({"id", "email"}));
    EXPECT_EQ(body["rows"], nlohmann::json::array());
    EXPECT_EQ(body["row_count"], 0);
}

TEST_F(HttpQueryTest, DuplicateColumnNamesSurviveInPositionalRows) {
    parser->result_to_return = parsed_select({}, /*wildcard=*/true);
    executor.result_to_return =
        ok_result({"email", "email"},
                  {{Cell{"lihi.roas@example.com"}, Cell{"kim.perez@example.org"}}});

    const nlohmann::json body = body_of(post(R"({"sql":"SELECT * FROM customers"})"));

    EXPECT_EQ(body["columns"], nlohmann::json::array({"email", "email"}));
    EXPECT_EQ(body["rows"][0][0], "l***@example.com");
    EXPECT_EQ(body["rows"][0][1], "k***@example.org");
}

// --- Transport-level rejections (never audited) -------------------------------

TEST_F(HttpQueryTest, MalformedRequestsAreRejectedWithoutEnteringThePipeline) {
    struct Case {
        const char* body;
        const char* content_type;
        const char* expected_code;
    };
    const Case cases[] = {
        {R"({"sql":"SELECT 1"})", "text/plain", "invalid_content_type"},
        {"{not json", "application/json", "invalid_json"},
        {R"(["SELECT 1"])", "application/json", "invalid_json"},
        {R"({"query":"SELECT 1"})", "application/json", "invalid_request"},
        {R"({"sql":42})", "application/json", "invalid_request"},
        {R"({"sql":null})", "application/json", "invalid_request"},
    };
    for (const Case& c : cases) {
        SCOPED_TRACE(c.expected_code);
        const httplib::Response response = post(c.body, c.content_type);
        EXPECT_EQ(response.status, 400);
        EXPECT_EQ(body_of(response)["error"], c.expected_code);
    }
    // A malformed request is not a controlled SQL request: nothing audited.
    EXPECT_TRUE(audit.appended.empty());
    EXPECT_EQ(executor.call_count(), 0u);
}

TEST_F(HttpQueryTest, OversizedSqlIsRejectedWithoutEnteringThePipeline) {
    const std::string huge(65 * 1024, 'x');
    const httplib::Response response =
        post(nlohmann::json{{"sql", huge}}.dump());

    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(body_of(response)["error"], "sql_too_large");
    EXPECT_TRUE(audit.appended.empty());
}

// --- Controlled SQL rejections (audited) --------------------------------------

TEST_F(HttpQueryTest, EmptySqlIsBadRequestButStillAudited) {
    const httplib::Response response = post(R"({"sql":""})");

    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(body_of(response)["error"], "empty_sql");
    // Empty input IS a controlled SQL request: it is audited as a policy
    // rejection carrying the typed reason.
    ASSERT_EQ(audit.appended.size(), 1u);
    EXPECT_EQ(audit.appended[0].outcome(), core::AuditOutcome::PolicyRejected);
    EXPECT_EQ(audit.appended[0].policy_rejected_details().reason,
              core::RejectReason::EmptyInput);
}

TEST_F(HttpQueryTest, PolicyRejectionIsGenericAndRevealsNoReason) {
    ports::ParseResult parse;
    parse.success = true;
    parse.statements.resize(1);
    parse.statements[0].type = core::StatementType::Drop;
    parse.statements[0].tables = {{"", "customers"}};
    parser->result_to_return = parse;

    const httplib::Response response = post(R"({"sql":"DROP TABLE customers"})");

    EXPECT_EQ(response.status, 403);
    const std::string body = response.body;
    EXPECT_EQ(body_of(response)["error"], "policy_rejected");
    // The typed reason stays in the audit trail only.
    EXPECT_EQ(body.find("DDL_NOT_ALLOWED"), std::string::npos);
    EXPECT_EQ(body.find("DdlNotAllowed"), std::string::npos);
    EXPECT_EQ(audit.appended[0].policy_rejected_details().reason,
              core::RejectReason::DdlNotAllowed);
}

TEST_F(HttpQueryTest, MaskingRefusalReturns422WithoutRows) {
    ports::ParseResult parse = parsed_select({});
    parse.statements[0].has_computed_projection = true;
    parser->result_to_return = parse;
    executor.result_to_return = ok_result({"upper"}, {{Cell{"LIHI.ROAS@EXAMPLE.COM"}}});

    const httplib::Response response =
        post(R"({"sql":"SELECT UPPER(email) FROM customers"})");

    EXPECT_EQ(response.status, 422);
    const nlohmann::json body = body_of(response);
    EXPECT_EQ(body["error"], "masking_refused");
    EXPECT_FALSE(body.contains("rows"));
    EXPECT_FALSE(body.contains("columns"));
    EXPECT_EQ(response.body.find("LIHI.ROAS@EXAMPLE.COM"), std::string::npos);
    EXPECT_EQ(audit.appended[0].outcome(), core::AuditOutcome::MaskingRefused);
}

TEST_F(HttpQueryTest, AuditFailureOnSuccessReturnsNoColumnsOrRows) {
    parser->result_to_return = parsed_select({"email"});
    executor.result_to_return = ok_result({"email"}, {{Cell{"lihi.roas@example.com"}}});
    audit.result_to_return = ports::AuditAppendResult::WriteFailure;

    const httplib::Response response = post(R"({"sql":"SELECT email FROM customers"})");

    EXPECT_EQ(response.status, 500);
    const nlohmann::json body = body_of(response);
    EXPECT_EQ(body["error"], "internal_error");
    EXPECT_FALSE(body.contains("columns"));
    EXPECT_FALSE(body.contains("rows"));
    EXPECT_EQ(response.body.find("l***@example.com"), std::string::npos);
}

// --- Leak assertions -----------------------------------------------------------

TEST_F(HttpQueryTest, ErrorBodiesNeverEchoSubmittedSqlOrInternalErrorText) {
    const std::string sql = "SELECT secret_column FROM secret_table";
    parser->result_to_return = parsed_select({"id"});
    executor.result_to_return.status = ports::ExecutionStatus::ExecutionFailure;
    executor.result_to_return.error =
        "statement failed (SQLSTATE 42P01) INTERNAL_MARKER_TEXT";

    const httplib::Response response = post(nlohmann::json{{"sql", sql}}.dump());

    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(body_of(response)["error"], "query_failed");
    EXPECT_EQ(response.body.find("secret_column"), std::string::npos);
    EXPECT_EQ(response.body.find("secret_table"), std::string::npos);
    EXPECT_EQ(response.body.find("INTERNAL_MARKER_TEXT"), std::string::npos);
    EXPECT_EQ(response.body.find("SQLSTATE"), std::string::npos);
    EXPECT_EQ(response.body.find("42P01"), std::string::npos);
}

TEST_F(HttpQueryTest, ParseFailureBodyRevealsNothingAboutTheStatement) {
    parser->result_to_return.success = false;
    parser->result_to_return.error = "syntax error at line 1, column 7";

    const httplib::Response response = post(R"({"sql":"SELEC * FRM customers"})");

    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(body_of(response)["error"], "invalid_sql");
    EXPECT_EQ(response.body.find("customers"), std::string::npos);
    EXPECT_EQ(response.body.find("line 1"), std::string::npos);
    EXPECT_EQ(audit.appended[0].outcome(), core::AuditOutcome::ParsingFailure);
}

// --- Socket-level smoke test ---------------------------------------------------

TEST_F(HttpQueryTest, RoutesAreRegisteredOnALiveServer) {
    parser->result_to_return = parsed_select({"email"});
    executor.result_to_return = ok_result({"email"}, {{Cell{"lihi.roas@example.com"}}});

    const int port = 18080 + static_cast<int>(::getpid() % 1500);
    http_adapter::HttpServer server(*service);
    std::thread server_thread([&server, port] {
        server.run(static_cast<uint16_t>(port));
    });

    httplib::Client client("127.0.0.1", port);
    client.set_connection_timeout(1, 0);
    httplib::Result health;
    for (int attempt = 0; attempt < 100; ++attempt) {
        health = client.Get("/health");
        if (health) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    ASSERT_TRUE(health) << "server did not become ready";
    EXPECT_EQ(health->status, 200);

    const httplib::Result query = client.Post(
        "/query", R"({"sql":"SELECT email FROM customers"})", "application/json");
    ASSERT_TRUE(query);
    EXPECT_EQ(query->status, 200);
    EXPECT_EQ(nlohmann::json::parse(query->body)["rows"][0][0], "l***@example.com");

    server.stop();
    server_thread.join();
}

}  // namespace
