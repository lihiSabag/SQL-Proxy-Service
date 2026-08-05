// End-to-end tests: the REAL pipeline against a REAL PostgreSQL.
//
// Every component here is production code — HyriseSqlParser, SqlAnalyzer,
// PolicyEngine, PostgresQueryExecutor, DataClassifier, PiiMasker,
// JsonlAuditRepository, ProxyService — driven through the real HTTP handler
// (handle_query_request) with an httplib::Request/Response pair. No fakes.
//
// These tests verify the PIPELINE. They do NOT verify main.cpp's process
// wiring (config resolution, component construction, signal handling); that
// is exercised by running the built binary directly.
//
// Fail-closed safety guards (both must pass before ANY SQL is executed):
//   1. TEST_DATABASE_URL must name the dedicated database "sql_proxy_test";
//      anything else is a hard failure with zero SQL executed.
//   2. SQL_PROXY_TEST_DB_RESET=1 must be set before schema.sql/seed.sql are
//      applied. If TEST_DATABASE_URL is unset, the whole suite SKIPs.
// No message here ever prints the URL or anything derived from it.
//
// Isolation: each test gets its own temporary directory and its own audit
// file, and issues exactly one request unless it is explicitly a multi-request
// corpus test.

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>
#include <unistd.h>

#include "audit/jsonl_audit_repository.h"
#include "http/query_routes.h"
#include "parser/hyrise_sql_parser.h"
#include "postgres/postgres_query_executor.h"
#include "config/database_config.h"
#include "core/proxy_service.h"
#include "core/sql_analyzer.h"
#include "logging/system_log.h"

namespace {

using Json = nlohmann::json;

constexpr const char* kRequiredDbName = "sql_proxy_test";

std::string database_name_of(const std::string& url) {
    auto slash = url.find_last_of('/');
    if (slash == std::string::npos || slash + 1 >= url.size()) {
        return "";
    }
    std::string name = url.substr(slash + 1);
    auto query = name.find('?');
    if (query != std::string::npos) {
        name = name.substr(0, query);
    }
    return name;
}

std::string read_file(const std::string& path) {
    std::ifstream in(path);
    EXPECT_TRUE(in.good()) << "cannot read " << path;
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

struct TestEnvironment {
    bool url_set = false;
    bool reset_opt_in = false;
    bool db_name_ok = false;
    std::string url;  // never printed
};

const TestEnvironment& test_environment() {
    static const TestEnvironment env = [] {
        TestEnvironment e;
        const char* url = std::getenv("TEST_DATABASE_URL");
        if (url != nullptr && *url != '\0') {
            e.url_set = true;
            e.url = url;
            e.db_name_ok = database_name_of(e.url) == kRequiredDbName;
        }
        const char* reset = std::getenv("SQL_PROXY_TEST_DB_RESET");
        e.reset_opt_in = reset != nullptr && std::string(reset) == "1";
        return e;
    }();
    return env;
}

// ---------------------------------------------------------------------------
// Audit-line validation.
//
// Deliberately NOT a raw substring sweep of the serialized line: legitimate
// audit content includes the strings "SELECT" and "pii_email_columns", so a
// naive sweep would either false-positive or be watered down to uselessness.
// Instead each line is parsed and validated structurally:
//   - its key set must match EXACTLY the closed schema for its outcome;
//   - a list of forbidden keys must never appear;
//   - every string value must be either the timestamp (shape-checked) or a
//     closed-vocabulary enum value from the allowed set for that field.
// Because the schema has no free-form string field at all, any leak of SQL,
// values, names, paths, or driver text would necessarily show up as an
// unexpected key or a string value outside the closed vocabulary.
// ---------------------------------------------------------------------------

const std::set<std::string>& forbidden_keys() {
    static const std::set<std::string> keys{
        "sql",     "query",         "raw_sql",   "values",      "rows",
        "columns", "column_names",  "aliases",   "error_message", "exception",
        "path",    "user_id",       "database_url", "stack_trace", "sqlstate",
        "message", "error",         "table",     "tables",      "schema"};
    return keys;
}

// SUCCESS covers two shapes: a masked result set and a completed write. The
// statement type tells them apart, and neither may carry the other's fields.
std::set<std::string> expected_keys_for(const std::string& outcome,
                                        const std::string& statement_type) {
    const std::set<std::string> envelope{"timestamp", "request_id", "outcome"};
    std::set<std::string> keys = envelope;
    if (outcome == "SUCCESS" && statement_type == "INSERT") {
        keys.insert({"statement_type", "affected_rows"});
    } else if (outcome == "SUCCESS") {
        keys.insert({"statement_type", "row_count", "column_count",
                     "pii_email_columns", "pii_phone_columns",
                     "pii_credit_card_columns"});
    } else if (outcome == "POLICY_REJECTED") {
        keys.insert({"reason", "statement_type", "statement_count"});
    } else if (outcome == "DATABASE_FAILURE") {
        keys.insert({"category", "statement_type"});
    } else if (outcome == "MASKING_REFUSED") {
        keys.insert({"statement_type", "column_count"});
    }
    // PARSING_FAILURE and INTERNAL_FAILURE carry the envelope only.
    return keys;
}

const std::map<std::string, std::set<std::string>>& closed_vocabulary() {
    static const std::map<std::string, std::set<std::string>> vocabulary{
        {"outcome",
         {"SUCCESS", "PARSING_FAILURE", "POLICY_REJECTED", "DATABASE_FAILURE",
          "MASKING_REFUSED", "INTERNAL_FAILURE"}},
        {"statement_type",
         {"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP",
          "UNKNOWN"}},
        {"reason",
         {"EMPTY_INPUT", "MULTIPLE_STATEMENTS", "UNSUPPORTED_STATEMENT_TYPE",
          "UNSUPPORTED_SQL_FEATURE", "DDL_NOT_ALLOWED", "DML_NOT_ALLOWED",
          "SYSTEM_TABLE_ACCESS", "UNATTRIBUTABLE_PROJECTION"}},
        {"category", {"CONNECTION_FAILURE", "EXECUTION_FAILURE"}}};
    return vocabulary;
}

// YYYY-MM-DDTHH:MM:SS.mmmZ
bool looks_like_utc_timestamp(const std::string& value) {
    if (value.size() != 24) {
        return false;
    }
    for (std::size_t i = 0; i < value.size(); ++i) {
        const char c = value[i];
        if (i == 4 || i == 7) {
            if (c != '-') return false;
        } else if (i == 10) {
            if (c != 'T') return false;
        } else if (i == 13 || i == 16) {
            if (c != ':') return false;
        } else if (i == 19) {
            if (c != '.') return false;
        } else if (i == 23) {
            if (c != 'Z') return false;
        } else if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

void validate_audit_line(const Json& line) {
    ASSERT_TRUE(line.is_object());
    ASSERT_TRUE(line.contains("outcome"));
    const std::string outcome = line["outcome"].get<std::string>();

    std::set<std::string> actual_keys;
    for (auto it = line.begin(); it != line.end(); ++it) {
        actual_keys.insert(it.key());
    }

    // Referenced-table metadata is optional on every outcome that can carry
    // it, so it is checked separately and removed before the closed-schema
    // comparison. The two keys are mutually exclusive by contract.
    const bool has_tables = actual_keys.erase("referenced_tables") == 1;
    const bool has_omitted = actual_keys.erase("referenced_tables_omitted") == 1;
    EXPECT_FALSE(has_tables && has_omitted)
        << "referenced_tables and referenced_tables_omitted must not co-occur";
    if (has_omitted) {
        EXPECT_TRUE(line["referenced_tables_omitted"].is_boolean());
        EXPECT_TRUE(line["referenced_tables_omitted"].get<bool>());
    }
    if (has_tables) {
        ASSERT_TRUE(line["referenced_tables"].is_array());
        const auto& names = line["referenced_tables"];
        EXPECT_LE(names.size(), 8u);
        for (const Json& entry : names) {
            ASSERT_TRUE(entry.is_string());
            const std::string name = entry.get<std::string>();
            EXPECT_FALSE(name.empty());
            EXPECT_LE(name.size(), 63u);
            // Plain unqualified ASCII identifier: no dots, no whitespace, no
            // control characters, no byte outside the whitelist.
            const unsigned char first = static_cast<unsigned char>(name.front());
            EXPECT_TRUE((first >= 'A' && first <= 'Z') ||
                        (first >= 'a' && first <= 'z') || first == '_')
                << "bad first byte in referenced table: " << name;
            for (char raw : name) {
                const unsigned char c = static_cast<unsigned char>(raw);
                EXPECT_TRUE((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') || c == '_' || c == '$')
                    << "bad byte in referenced table: " << name;
            }
        }
    }

    const std::string statement_type =
        line.contains("statement_type") ? line["statement_type"].get<std::string>() : "";
    EXPECT_EQ(actual_keys, expected_keys_for(outcome, statement_type))
        << "audit schema drift for outcome " << outcome;

    for (const std::string& key : actual_keys) {
        EXPECT_EQ(forbidden_keys().count(key), 0u) << "forbidden audit key: " << key;
    }

    for (auto it = line.begin(); it != line.end(); ++it) {
        if (!it.value().is_string()) {
            continue;  // counts and ids are numbers; nothing to leak
        }
        const std::string key = it.key();
        const std::string value = it.value().get<std::string>();
        if (key == "timestamp") {
            EXPECT_TRUE(looks_like_utc_timestamp(value)) << value;
            continue;
        }
        const auto vocabulary = closed_vocabulary().find(key);
        ASSERT_NE(vocabulary, closed_vocabulary().end())
            << "unexpected free-form string field '" << key << "' in audit output";
        EXPECT_EQ(vocabulary->second.count(value), 1u)
            << "value outside the closed vocabulary for '" << key << "': " << value;
    }
}

// ---------------------------------------------------------------------------
// Real pipeline assembly.
// ---------------------------------------------------------------------------

struct Pipeline {
    std::unique_ptr<core::SqlAnalyzer> analyzer;
    std::unique_ptr<postgres_adapter::PostgresQueryExecutor> executor;
    std::unique_ptr<audit_adapter::JsonlAuditRepository> audit;
    std::unique_ptr<core::ProxyService> service;
};

Pipeline make_pipeline(const config::DatabaseConfig& database,
                       const std::string& audit_path) {
    Pipeline pipeline;
    pipeline.analyzer = std::make_unique<core::SqlAnalyzer>(
        std::make_unique<parser_adapter::HyriseSqlParser>());
    pipeline.executor =
        std::make_unique<postgres_adapter::PostgresQueryExecutor>(database);
    pipeline.audit = std::make_unique<audit_adapter::JsonlAuditRepository>(audit_path);
    pipeline.service = std::make_unique<core::ProxyService>(
        *pipeline.analyzer, *pipeline.executor, *pipeline.audit);
    return pipeline;
}

class EndToEndTest : public ::testing::Test {
protected:
    void SetUp() override {
        const TestEnvironment& env = test_environment();
        if (!env.url_set) {
            GTEST_SKIP() << "TEST_DATABASE_URL is not set — end-to-end tests "
                            "skipped. This does NOT count as verification.";
        }
        ASSERT_TRUE(env.db_name_ok)
            << "TEST_DATABASE_URL must name the dedicated database '"
            << kRequiredDbName << "'. Refusing to run. No SQL was executed.";
        if (!env.reset_opt_in) {
            GTEST_SKIP() << "SQL_PROXY_TEST_DB_RESET=1 is required before the "
                            "test schema is applied.";
        }
        system_log::init();  // real logging path, as in production
        apply_schema_once();

        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        directory_ = std::filesystem::temp_directory_path() /
                     ("sql_proxy_e2e_" + std::string(info->name()) + "_" +
                      std::to_string(static_cast<long>(::getpid())));
        std::filesystem::create_directories(directory_);
        audit_path_ = (directory_ / "audit.jsonl").string();

        pipeline_ = make_pipeline(database_config(), audit_path_);
    }

    void TearDown() override {
        pipeline_ = Pipeline{};
        if (!directory_.empty()) {
            std::filesystem::remove_all(directory_);
        }
    }

    static config::DatabaseConfig database_config() {
        return config::DatabaseConfig{test_environment().url, 5000};
    }

    static void apply_schema_once() {
        static const bool applied = [] {
            pqxx::connection connection(test_environment().url);
            pqxx::work transaction(connection);
            transaction.exec(read_file(std::string(SQL_PROXY_SQL_DIR) + "/schema.sql"));
            transaction.exec(read_file(std::string(SQL_PROXY_SQL_DIR) + "/seed.sql"));
            transaction.commit();
            return true;
        }();
        ASSERT_TRUE(applied);
    }

    // Drives the REAL HTTP handler; no socket needed.
    httplib::Response post(const std::string& sql, core::ProxyService* service = nullptr) {
        httplib::Request request;
        request.method = "POST";
        request.path = "/query";
        request.set_header("Content-Type", "application/json");
        request.body = Json{{"sql", sql}}.dump();
        httplib::Response response;
        http_adapter::handle_query_request(service != nullptr ? *service
                                                              : *pipeline_.service,
                                           request, response);
        return response;
    }

    Json body_of(const httplib::Response& response) {
        return Json::parse(response.body, nullptr, false);
    }

    std::vector<Json> audit_lines(const std::string& path = "") {
        std::vector<Json> lines;
        std::ifstream in(path.empty() ? audit_path_ : path);
        std::string raw;
        while (std::getline(in, raw)) {
            lines.push_back(Json::parse(raw, nullptr, false));
        }
        return lines;
    }

    // Asserts the single audited outcome of a one-request test.
    Json only_audit_line() {
        const std::vector<Json> lines = audit_lines();
        EXPECT_EQ(lines.size(), 1u) << "expected exactly one audit line";
        if (lines.empty()) {
            return Json::object();
        }
        validate_audit_line(lines.front());
        return lines.front();
    }

    // Direct database state check (bypasses the pipeline on purpose, so
    // verification queries never add audit lines).
    static long long scalar(const std::string& sql) {
        pqxx::connection connection(test_environment().url);
        pqxx::work transaction(connection);
        const long long value = transaction.query_value<long long>(sql);
        transaction.commit();
        return value;
    }

    // Direct statement execution, used only to undo rows an insert test
    // created so later tests still see the seeded data unchanged.
    static void execute_directly(const std::string& sql) {
        pqxx::connection connection(test_environment().url);
        pqxx::work transaction(connection);
        transaction.exec(sql);
        transaction.commit();
    }

    // Removes anything an insert test added, restoring the seeded row set.
    static void delete_orders_above(long long highest_seeded_id) {
        execute_directly("DELETE FROM orders WHERE id > " +
                         std::to_string(highest_seeded_id));
    }

    std::filesystem::path directory_;
    std::string audit_path_;
    Pipeline pipeline_;
};

// Expected masked values from sql/seed.sql, in id order.
const std::vector<std::string> kMaskedEmails{"l***@example.com", "k***@example.org",
                                             "d***@example.net", "y***@example.com"};
const std::vector<std::string> kNames{"Lihi Roas", "Kim Perez", "Daniel Mizrahi",
                                      "Yael Azulay"};

// === Successful queries =====================================================

TEST_F(EndToEndTest, NonPiiSelectReturnsUnmaskedValues) {
    const httplib::Response response = post("SELECT id, amount FROM orders ORDER BY id");

    ASSERT_EQ(response.status, 200);
    const Json body = body_of(response);
    EXPECT_EQ(body["columns"], Json::array({"id", "amount"}));
    EXPECT_EQ(body["row_count"], 4);
    EXPECT_EQ(body["rows"], Json::array({{"1", "19.99"},
                                         {"2", "250.00"},
                                         {"3", "5.49"},
                                         {"4", "999.90"}}));

    const Json audit = only_audit_line();
    EXPECT_EQ(audit["outcome"], "SUCCESS");
    EXPECT_EQ(audit["statement_type"], "SELECT");
    EXPECT_EQ(audit["row_count"], 4);
    EXPECT_EQ(audit["column_count"], 2);
    EXPECT_EQ(audit["pii_email_columns"], 0);
    EXPECT_EQ(audit["pii_phone_columns"], 0);
    EXPECT_EQ(audit["pii_credit_card_columns"], 0);
}

TEST_F(EndToEndTest, EmailColumnIsMaskedForEverySeededRow) {
    const httplib::Response response = post("SELECT email FROM customers ORDER BY id");

    ASSERT_EQ(response.status, 200);
    const Json body = body_of(response);
    EXPECT_EQ(body["columns"], Json::array({"email"}));
    ASSERT_EQ(body["rows"].size(), 4u);
    for (std::size_t i = 0; i < kMaskedEmails.size(); ++i) {
        EXPECT_EQ(body["rows"][i][0], kMaskedEmails[i]);
    }
    EXPECT_EQ(only_audit_line()["pii_email_columns"], 1);
}

TEST_F(EndToEndTest, PhoneColumnMasksValuesAndPreservesNullVersusEmptyString) {
    const httplib::Response response = post("SELECT phone FROM customers ORDER BY id");

    ASSERT_EQ(response.status, 200);
    const Json body = body_of(response);
    ASSERT_EQ(body["rows"].size(), 4u);
    EXPECT_EQ(body["rows"][0][0], "***0101");   // 0501230101
    EXPECT_EQ(body["rows"][1][0], "***0102");   // 0524560102
    EXPECT_TRUE(body["rows"][2][0].is_null());  // SQL NULL stays null
    EXPECT_EQ(body["rows"][3][0], "");          // empty string stays empty
    EXPECT_EQ(only_audit_line()["pii_phone_columns"], 1);
}

TEST_F(EndToEndTest, CreditCardColumnIsMaskedIncludingFifteenDigitAndNull) {
    const httplib::Response response =
        post("SELECT credit_card FROM customers ORDER BY id");

    ASSERT_EQ(response.status, 200);
    const Json body = body_of(response);
    ASSERT_EQ(body["rows"].size(), 4u);
    EXPECT_EQ(body["rows"][0][0], "****1111");  // 16-digit
    EXPECT_EQ(body["rows"][1][0], "****4444");  // 16-digit
    EXPECT_EQ(body["rows"][2][0], "****0009");  // 15-digit, same masked shape
    EXPECT_TRUE(body["rows"][3][0].is_null());  // NULL card
    EXPECT_EQ(only_audit_line()["pii_credit_card_columns"], 1);
}

TEST_F(EndToEndTest, AliasedColumnIsStillMaskedBySourceColumn) {
    const httplib::Response response =
        post("SELECT email AS contact FROM customers ORDER BY id");

    ASSERT_EQ(response.status, 200);
    const Json body = body_of(response);
    EXPECT_EQ(body["columns"], Json::array({"contact"}));  // alias is preserved
    for (std::size_t i = 0; i < kMaskedEmails.size(); ++i) {
        EXPECT_EQ(body["rows"][i][0], kMaskedEmails[i]);  // but masking still applies
    }
    EXPECT_EQ(only_audit_line()["pii_email_columns"], 1);
}

TEST_F(EndToEndTest, WildcardSelectMasksAllThreePiiColumns) {
    const httplib::Response response = post("SELECT * FROM customers ORDER BY id");

    ASSERT_EQ(response.status, 200);
    const Json body = body_of(response);
    EXPECT_EQ(body["columns"],
              Json::array({"id", "name", "email", "phone", "credit_card"}));
    EXPECT_EQ(body["row_count"], 4);
    ASSERT_EQ(body["rows"].size(), 4u);
    for (std::size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(body["rows"][i][0], std::to_string(i + 1));  // id, not PII
        EXPECT_EQ(body["rows"][i][1], kNames[i]);              // name, not PII
        EXPECT_EQ(body["rows"][i][2], kMaskedEmails[i]);
    }
    EXPECT_EQ(body["rows"][0][3], "***0101");
    EXPECT_TRUE(body["rows"][2][3].is_null());
    EXPECT_EQ(body["rows"][3][3], "");
    EXPECT_EQ(body["rows"][0][4], "****1111");
    EXPECT_TRUE(body["rows"][3][4].is_null());

    const Json audit = only_audit_line();
    EXPECT_EQ(audit["column_count"], 5);
    EXPECT_EQ(audit["pii_email_columns"], 1);
    EXPECT_EQ(audit["pii_phone_columns"], 1);
    EXPECT_EQ(audit["pii_credit_card_columns"], 1);
}

TEST_F(EndToEndTest, JoinAcrossTablesMasksTheJoinedPiiColumn) {
    const httplib::Response response = post(
        "SELECT c.email, o.amount FROM customers c JOIN orders o "
        "ON o.customer_id = c.id ORDER BY o.id");

    ASSERT_EQ(response.status, 200);
    const Json body = body_of(response);
    EXPECT_EQ(body["columns"], Json::array({"email", "amount"}));
    EXPECT_EQ(body["rows"], Json::array({{"l***@example.com", "19.99"},
                                         {"l***@example.com", "250.00"},
                                         {"k***@example.org", "5.49"},
                                         {"d***@example.net", "999.90"}}));
    EXPECT_EQ(only_audit_line()["pii_email_columns"], 1);
}

TEST_F(EndToEndTest, DuplicateResultColumnNamesAreBothPreservedAndBothMasked) {
    const httplib::Response response =
        post("SELECT email, email FROM customers ORDER BY id");

    ASSERT_EQ(response.status, 200);
    const Json body = body_of(response);
    // Both names preserved (positional arrays, not an object that would
    // collapse the duplicate key)...
    EXPECT_EQ(body["columns"], Json::array({"email", "email"}));
    ASSERT_EQ(body["rows"].size(), 4u);
    for (std::size_t i = 0; i < 4; ++i) {
        // ...both positional values preserved, and both masked by index.
        ASSERT_EQ(body["rows"][i].size(), 2u);
        EXPECT_EQ(body["rows"][i][0], kMaskedEmails[i]);
        EXPECT_EQ(body["rows"][i][1], kMaskedEmails[i]);
    }
    const Json audit = only_audit_line();
    EXPECT_EQ(audit["column_count"], 2);
    EXPECT_EQ(audit["pii_email_columns"], 2);  // classified by index, not name
}

TEST_F(EndToEndTest, ZeroRowResultPreservesColumnMetadata) {
    const httplib::Response response = post("SELECT id FROM customers WHERE id = 999");

    ASSERT_EQ(response.status, 200);
    const Json body = body_of(response);
    EXPECT_EQ(body["columns"], Json::array({"id"}));  // metadata survives
    EXPECT_EQ(body["rows"], Json::array());
    EXPECT_EQ(body["row_count"], 0);

    const Json audit = only_audit_line();
    EXPECT_EQ(audit["row_count"], 0);
    EXPECT_EQ(audit["column_count"], 1);
}

// === Rejections =============================================================

TEST_F(EndToEndTest, EmptySqlIsBadRequestAndAuditedAsPolicyRejection) {
    const httplib::Response response = post("");

    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(body_of(response)["error"], "empty_sql");

    const Json audit = only_audit_line();
    EXPECT_EQ(audit["outcome"], "POLICY_REJECTED");
    EXPECT_EQ(audit["reason"], "EMPTY_INPUT");
    EXPECT_EQ(audit["statement_type"], "UNKNOWN");
    EXPECT_EQ(audit["statement_count"], 0);
}

TEST_F(EndToEndTest, UnparsableSqlIsAuditedAsParsingFailure) {
    const httplib::Response response = post("SELEC * FRM customers");

    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(body_of(response)["error"], "invalid_sql");
    // No statement details are invented for a statement that never parsed.
    const Json audit = only_audit_line();
    EXPECT_EQ(audit["outcome"], "PARSING_FAILURE");
    EXPECT_FALSE(audit.contains("statement_type"));
}

TEST_F(EndToEndTest, MultipleStatementsAreRejectedAndNothingIsExecuted) {
    const long long before = scalar("SELECT count(*) FROM customers");

    const httplib::Response response =
        post("SELECT id FROM customers; SELECT id FROM orders");

    EXPECT_EQ(response.status, 403);
    EXPECT_EQ(body_of(response)["error"], "policy_rejected");
    const Json audit = only_audit_line();
    EXPECT_EQ(audit["outcome"], "POLICY_REJECTED");
    EXPECT_EQ(audit["reason"], "MULTIPLE_STATEMENTS");
    EXPECT_EQ(audit["statement_count"], 2);
    EXPECT_EQ(scalar("SELECT count(*) FROM customers"), before);
}

TEST_F(EndToEndTest, DmlIsRejectedAndTheDataIsUnchanged) {
    const long long before = scalar("SELECT count(*) FROM customers");

    const httplib::Response response = post("DELETE FROM customers");

    EXPECT_EQ(response.status, 403);
    EXPECT_EQ(body_of(response)["error"], "policy_rejected");
    const Json audit = only_audit_line();
    EXPECT_EQ(audit["reason"], "DML_NOT_ALLOWED");
    EXPECT_EQ(audit["statement_type"], "DELETE");
    EXPECT_EQ(scalar("SELECT count(*) FROM customers"), before);  // nothing deleted
}

TEST_F(EndToEndTest, DdlIsRejectedAndTheTableStillExists) {
    const httplib::Response response = post("DROP TABLE orders");

    EXPECT_EQ(response.status, 403);
    const Json audit = only_audit_line();
    EXPECT_EQ(audit["reason"], "DDL_NOT_ALLOWED");
    EXPECT_EQ(audit["statement_type"], "DROP");
    EXPECT_EQ(scalar("SELECT count(*) FROM pg_tables WHERE tablename = 'orders'"), 1);
}

TEST_F(EndToEndTest, UnsupportedSqlFeatureIsRejected) {
    const httplib::Response response =
        post("SELECT id FROM customers UNION SELECT id FROM orders");

    EXPECT_EQ(response.status, 403);
    EXPECT_EQ(only_audit_line()["reason"], "UNSUPPORTED_SQL_FEATURE");
}

TEST_F(EndToEndTest, SystemCatalogAccessIsRejectedBeforeExecution) {
    const httplib::Response response = post("SELECT * FROM pg_catalog.pg_authid");

    EXPECT_EQ(response.status, 403);
    // Generic body: it must not confirm that the catalog rule exists.
    EXPECT_EQ(body_of(response)["error"], "policy_rejected");
    EXPECT_EQ(only_audit_line()["reason"], "SYSTEM_TABLE_ACCESS");
}

TEST_F(EndToEndTest, MixedWildcardProjectionIsRejected) {
    const httplib::Response response = post("SELECT *, credit_card AS x FROM customers");

    EXPECT_EQ(response.status, 403);
    EXPECT_EQ(only_audit_line()["reason"], "UNATTRIBUTABLE_PROJECTION");
}

// === Masking refusal (current computed-projection behavior) ==================

TEST_F(EndToEndTest, ComputedProjectionIsRefusedAndLeaksNoValues) {
    const httplib::Response response = post("SELECT UPPER(email) FROM customers");

    EXPECT_EQ(response.status, 422);
    const Json body = body_of(response);
    EXPECT_EQ(body["error"], "masking_refused");
    EXPECT_FALSE(body.contains("rows"));
    EXPECT_FALSE(body.contains("columns"));
    EXPECT_EQ(response.body.find("LIHI.ROAS@EXAMPLE.COM"), std::string::npos);
    EXPECT_EQ(response.body.find("lihi.roas"), std::string::npos);

    const Json audit = only_audit_line();
    EXPECT_EQ(audit["outcome"], "MASKING_REFUSED");
    EXPECT_EQ(audit["column_count"], 1);
    EXPECT_FALSE(audit.contains("pii_email_columns"));  // counts would mislead here
}

// Documented current limitation, not a defect: a table-less computed
// projection is policy-allowed but cannot be attributed to a source column,
// so masking refuses rather than returning an unclassified value.
TEST_F(EndToEndTest, SelectLiteralIsCurrentlyRefused_DocumentedLimitation) {
    const httplib::Response response = post("SELECT 1");

    EXPECT_EQ(response.status, 422);
    EXPECT_EQ(body_of(response)["error"], "masking_refused");
    EXPECT_EQ(only_audit_line()["outcome"], "MASKING_REFUSED");
}

// === Canonical COUNT(*) =====================================================
//
// The one computed shape that is executed and returned. Everything else in
// the COUNT family, and every mixed projection containing one, stays refused.

TEST_F(EndToEndTest, CountStarSucceedsAndIsAudited) {
    const httplib::Response response = post("SELECT COUNT(*) FROM customers");

    ASSERT_EQ(response.status, 200);
    const Json body = body_of(response);
    EXPECT_EQ(body["columns"], Json::array({"count"}));
    EXPECT_EQ(body["row_count"], 1);
    EXPECT_EQ(body["rows"], Json::array({Json::array({"4"})}));  // 4 seeded rows

    const Json audit = only_audit_line();
    EXPECT_EQ(audit["outcome"], "SUCCESS");
    EXPECT_EQ(audit["statement_type"], "SELECT");
    EXPECT_EQ(audit["column_count"], 1);
    EXPECT_EQ(audit["pii_email_columns"], 0);
    EXPECT_EQ(audit["pii_phone_columns"], 0);
    EXPECT_EQ(audit["pii_credit_card_columns"], 0);
}

TEST_F(EndToEndTest, CountStarWithAliasSucceedsAndIsNotMasked) {
    // The alias is deliberately a mapped PII name. Attribution is by shape,
    // so the count is returned intact rather than masked to "***".
    const httplib::Response response = post("SELECT COUNT(*) AS email FROM customers");

    ASSERT_EQ(response.status, 200);
    const Json body = body_of(response);
    EXPECT_EQ(body["columns"], Json::array({"email"}));
    EXPECT_EQ(body["rows"], Json::array({Json::array({"4"})}));
    EXPECT_EQ(only_audit_line()["pii_email_columns"], 0);
}

TEST_F(EndToEndTest, CountStarIsCaseInsensitiveEndToEnd) {
    const httplib::Response response = post("select count(*) from customers");

    ASSERT_EQ(response.status, 200);
    EXPECT_EQ(body_of(response)["rows"], Json::array({Json::array({"4"})}));
}

TEST_F(EndToEndTest, CountStarOverAJoinSucceeds) {
    const httplib::Response response =
        post("SELECT COUNT(*) FROM customers c JOIN orders o ON c.id = o.customer_id");

    ASSERT_EQ(response.status, 200);
    EXPECT_EQ(body_of(response)["rows"], Json::array({Json::array({"4"})}));
}

TEST_F(EndToEndTest, CountVariantsRemainRefusedByClassification) {
    // Each of these was refused before COUNT(*) was supported and must stay
    // refused after it. COUNT(1) is included deliberately: it is equivalent
    // in SQL, but only the canonical form is recognized. All are valid SQL,
    // so they execute and are then refused because no column can be
    // attributed.
    for (const char* sql : {"SELECT COUNT(1) FROM customers",
                            "SELECT COUNT(NULL) FROM customers",
                            "SELECT COUNT(email) FROM customers",
                            "SELECT COUNT(DISTINCT email) FROM customers",
                            "SELECT COUNT(*) OVER () FROM customers",
                            "SELECT COUNT(*) + 1 FROM customers",
                            "SELECT COUNT(*) FROM customers GROUP BY email",
                            "SELECT COUNT(*), COUNT(email) FROM customers"}) {
        SCOPED_TRACE(sql);
        Pipeline pipeline = make_pipeline(database_config(), audit_path_);
        const httplib::Response response = post(sql, pipeline.service.get());
        EXPECT_EQ(response.status, 422);
        EXPECT_EQ(body_of(response)["error"], "masking_refused");
        EXPECT_FALSE(body_of(response).contains("rows"));
    }
}

TEST_F(EndToEndTest, MixedCountAndColumnIsRefusedByTheDatabase) {
    // Mixing a bare column with an aggregate is invalid SQL in PostgreSQL
    // ("must appear in the GROUP BY clause"), so these are rejected at
    // execution and never reach classification. The classifier-level guard
    // for the same shape is covered by
    // DataClassifierTest.CountStarShapesThatMustStayUnattributed.
    for (const char* sql : {"SELECT COUNT(*), email FROM customers",
                            "SELECT COUNT(*), * FROM customers"}) {
        SCOPED_TRACE(sql);
        Pipeline pipeline = make_pipeline(database_config(), audit_path_);
        const httplib::Response response = post(sql, pipeline.service.get());
        EXPECT_EQ(response.status, 400);
        EXPECT_EQ(body_of(response)["error"], "query_failed");
        EXPECT_FALSE(body_of(response).contains("rows"));
        EXPECT_EQ(response.body.find("@example."), std::string::npos);
    }
}

TEST_F(EndToEndTest, ValueReturningAggregatesRemainRefusedAndLeakNothing) {
    // MIN/MAX over a PII column return an actual value, so a regression here
    // would be a direct disclosure rather than a shape error.
    for (const char* sql : {"SELECT MIN(email) FROM customers",
                            "SELECT MAX(email) FROM customers",
                            "SELECT MAX(credit_card) FROM customers"}) {
        SCOPED_TRACE(sql);
        Pipeline pipeline = make_pipeline(database_config(), audit_path_);
        const httplib::Response response = post(sql, pipeline.service.get());
        EXPECT_EQ(response.status, 422);
        EXPECT_EQ(response.body.find("@example."), std::string::npos);
        EXPECT_EQ(response.body.find("4111"), std::string::npos);
        EXPECT_EQ(response.body.find("5555"), std::string::npos);
    }
}

// === The single authorized write ============================================
//
// Each test that inserts restores the seeded row set afterwards, so the rest
// of the suite still sees exactly four orders.

TEST_F(EndToEndTest, AuthorizedOrderInsertWritesOneRowAndIsAudited) {
    const long long before = scalar("SELECT COUNT(*) FROM orders");
    const long long highest = scalar("SELECT COALESCE(MAX(id), 0) FROM orders");

    const httplib::Response response =
        post("INSERT INTO orders (customer_id, amount) VALUES (1, 199.90)");

    ASSERT_EQ(response.status, 200);
    const Json body = body_of(response);
    EXPECT_EQ(body["affected_rows"], 1);
    EXPECT_FALSE(body.contains("rows"));
    EXPECT_FALSE(body.contains("columns"));

    EXPECT_EQ(scalar("SELECT COUNT(*) FROM orders"), before + 1);
    EXPECT_EQ(scalar("SELECT COUNT(*) FROM orders WHERE customer_id = 1 "
                     "AND amount = 199.90 AND id > " + std::to_string(highest)),
              1);

    const Json audit = only_audit_line();
    EXPECT_EQ(audit["outcome"], "SUCCESS");
    EXPECT_EQ(audit["statement_type"], "INSERT");
    EXPECT_EQ(audit["affected_rows"], 1);
    // No values, no table name, and none of the read-only counts.
    for (const char* absent : {"row_count", "column_count", "pii_email_columns",
                               "target_table", "reason"}) {
        EXPECT_FALSE(audit.contains(absent)) << absent;
    }

    delete_orders_above(highest);
}

TEST_F(EndToEndTest, InsertedOrderIsReadableThroughTheProxy) {
    const long long highest = scalar("SELECT COALESCE(MAX(id), 0) FROM orders");
    ASSERT_EQ(post("INSERT INTO orders (customer_id, amount) VALUES (2, 12.34)").status, 200);

    Pipeline reader = make_pipeline(database_config(), audit_path_);
    const httplib::Response read =
        post("SELECT amount FROM orders WHERE id > " + std::to_string(highest),
             reader.service.get());

    ASSERT_EQ(read.status, 200);
    EXPECT_EQ(body_of(read)["rows"], Json::array({Json::array({"12.34"})}));

    delete_orders_above(highest);
}

TEST_F(EndToEndTest, InsertWithUnknownCustomerFailsCleanlyAndWritesNothing) {
    const long long before = scalar("SELECT COUNT(*) FROM orders");

    // 999999 violates the foreign key on orders.customer_id.
    const httplib::Response response =
        post("INSERT INTO orders (customer_id, amount) VALUES (999999, 10.00)");

    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(body_of(response)["error"], "query_failed");
    // No constraint name, SQLSTATE, or value reaches the caller.
    EXPECT_EQ(response.body.find("SQLSTATE"), std::string::npos);
    EXPECT_EQ(response.body.find("999999"), std::string::npos);
    EXPECT_EQ(response.body.find("customer_id"), std::string::npos);

    EXPECT_EQ(scalar("SELECT COUNT(*) FROM orders"), before);  // rolled back

    const Json audit = only_audit_line();
    EXPECT_EQ(audit["outcome"], "DATABASE_FAILURE");
    EXPECT_EQ(audit["statement_type"], "INSERT");
    EXPECT_EQ(audit["category"], "EXECUTION_FAILURE");
    EXPECT_FALSE(audit.contains("affected_rows"));
}

TEST_F(EndToEndTest, RejectedInsertShapesWriteNothingAndLeakNothing) {
    const long long before_orders = scalar("SELECT COUNT(*) FROM orders");
    const long long before_customers = scalar("SELECT COUNT(*) FROM customers");

    for (const char* sql : {
             // wrong target
             "INSERT INTO customers (name, email) VALUES ('Noa', 'noa@example.com')",
             // copying insert: same table list as the permitted shape
             "INSERT INTO orders (customer_id, amount) SELECT id, 100 FROM customers",
             // column-list variations
             "INSERT INTO orders (amount, customer_id) VALUES (100, 1)",
             "INSERT INTO orders (customer_id) VALUES (1)",
             "INSERT INTO orders (customer_id, amount, id) VALUES (1, 100, 5)",
             // omitted column list, reported as an unsupported feature
             "INSERT INTO orders VALUES (99, 1, 100)",
             // value variations
             "INSERT INTO orders (customer_id, amount) VALUES (1, -10)",
             "INSERT INTO orders (customer_id, amount) VALUES (0, 100)",
             "INSERT INTO orders (customer_id, amount) VALUES (1, 0)",
             "INSERT INTO orders (customer_id, amount) VALUES (1, NULL)",
             "INSERT INTO orders (customer_id, amount) VALUES (1, '100')",
             // identifier variations
             "INSERT INTO public.orders (customer_id, amount) VALUES (1, 100)",
             "INSERT INTO ORDERS (customer_id, amount) VALUES (1, 100)",
             "INSERT INTO orders (CUSTOMER_ID, AMOUNT) VALUES (1, 100)",
             // other writes
             "UPDATE orders SET amount = 1 WHERE id = 1",
             "DELETE FROM orders WHERE id = 1",
             "TRUNCATE orders",
             "DROP TABLE orders",
         }) {
        SCOPED_TRACE(sql);
        Pipeline pipeline = make_pipeline(database_config(), audit_path_);
        const httplib::Response response = post(sql, pipeline.service.get());

        EXPECT_EQ(response.status, 403);
        EXPECT_EQ(body_of(response)["error"], "policy_rejected");
        // Every denial looks identical from outside, so the rule set cannot
        // be mapped by probing.
        EXPECT_EQ(response.body.find("orders"), std::string::npos);
        EXPECT_EQ(response.body.find("noa@example.com"), std::string::npos);
    }

    EXPECT_EQ(scalar("SELECT COUNT(*) FROM orders"), before_orders);
    EXPECT_EQ(scalar("SELECT COUNT(*) FROM customers"), before_customers);
}

TEST_F(EndToEndTest, InsertShapesTheParserRefusesAreBadRequests) {
    const long long before = scalar("SELECT COUNT(*) FROM orders");

    for (const char* sql : {
             "INSERT INTO orders (customer_id, amount) VALUES (1, 100), (2, 200)",
             "INSERT INTO orders (customer_id, amount) VALUES (1, 100) RETURNING *",
             "INSERT INTO orders (customer_id, amount) VALUES (1, DEFAULT)",
             "INSERT INTO orders (customer_id, amount) VALUES (1, random() * 100)",
             "INSERT INTO orders (customer_id, amount) VALUES ((SELECT id FROM customers), 1)",
         }) {
        SCOPED_TRACE(sql);
        Pipeline pipeline = make_pipeline(database_config(), audit_path_);
        const httplib::Response response = post(sql, pipeline.service.get());
        EXPECT_EQ(response.status, 400);
        EXPECT_EQ(body_of(response)["error"], "invalid_sql");
    }

    EXPECT_EQ(scalar("SELECT COUNT(*) FROM orders"), before);
}

// === Referenced-table metadata ==============================================

TEST_F(EndToEndTest, SelectRecordsItsReferencedTables) {
    const httplib::Response response =
        post("SELECT c.id, o.amount FROM customers c JOIN orders o "
             "ON c.id = o.customer_id ORDER BY o.id");

    ASSERT_EQ(response.status, 200);
    const Json audit = only_audit_line();
    EXPECT_EQ(audit["outcome"], "SUCCESS");
    EXPECT_EQ(audit["referenced_tables"], Json::array({"customers", "orders"}));
    EXPECT_FALSE(audit.contains("referenced_tables_omitted"));
}

TEST_F(EndToEndTest, SystemCatalogRejectionRecordsTheProbedTable) {
    // The forensic payoff: the trail now shows which catalog was probed.
    const httplib::Response response = post("SELECT * FROM pg_authid");

    EXPECT_EQ(response.status, 403);
    const Json audit = only_audit_line();
    EXPECT_EQ(audit["outcome"], "POLICY_REJECTED");
    EXPECT_EQ(audit["reason"], "SYSTEM_TABLE_ACCESS");
    EXPECT_EQ(audit["referenced_tables"], Json::array({"pg_authid"}));
}

TEST_F(EndToEndTest, QualifiedTableNameIsOmittedButTheQueryStillSucceeds) {
    // A schema-qualified reference is ambiguous, so the metadata is dropped.
    // The client result is unaffected.
    const httplib::Response response =
        post("SELECT id FROM public.customers ORDER BY id LIMIT 1");

    ASSERT_EQ(response.status, 200);
    EXPECT_EQ(body_of(response)["rows"], Json::array({Json::array({"1"})}));

    const Json audit = only_audit_line();
    EXPECT_EQ(audit["outcome"], "SUCCESS");
    EXPECT_EQ(audit["referenced_tables_omitted"], true);
    EXPECT_FALSE(audit.contains("referenced_tables"));
}

TEST_F(EndToEndTest, NonAsciiIdentifierIsOmittedAndTheRecordSurvives) {
    // A quoted identifier can legally carry non-ASCII bytes. They are valid
    // UTF-8, so they survive JSON parsing and reach the analyzer, but they
    // are outside the audit whitelist, so the metadata is dropped rather
    // than written. The audit line itself is still produced.
    const httplib::Response response = post("SELECT * FROM \"caf\xC3\xA9\"");

    EXPECT_NE(response.status, 200);  // no such relation

    const Json audit = only_audit_line();
    EXPECT_TRUE(audit.contains("outcome"));
    EXPECT_EQ(audit["referenced_tables_omitted"], true);
    EXPECT_FALSE(audit.contains("referenced_tables"));
    // No byte of the identifier reaches the trail.
    EXPECT_EQ(audit.dump().find("caf"), std::string::npos);
}

TEST_F(EndToEndTest, ReferencedTablesCarryNoSqlOrLiterals) {
    const httplib::Response response =
        post("SELECT id FROM customers WHERE email = 'zzq-canary-9137@example.com'");

    ASSERT_EQ(response.status, 200);
    const Json audit = only_audit_line();
    EXPECT_EQ(audit["referenced_tables"], Json::array({"customers"}));

    // Only the table name is recorded: no literal, no predicate, no column.
    const std::string raw = audit.dump();
    for (const char* forbidden : {"zzq-canary-9137", "@example.com", "WHERE",
                                  "SELECT id", "'"}) {
        EXPECT_EQ(raw.find(forbidden), std::string::npos) << forbidden;
    }
}

// === Database failures ======================================================

TEST_F(EndToEndTest, DatabaseExecutionFailureIsGenericAndLeaksNothing) {
    const httplib::Response response = post("SELECT * FROM no_such_table");

    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(body_of(response)["error"], "query_failed");
    // No driver text, SQLSTATE, or object name reaches the client.
    EXPECT_EQ(response.body.find("no_such_table"), std::string::npos);
    EXPECT_EQ(response.body.find("SQLSTATE"), std::string::npos);
    EXPECT_EQ(response.body.find("42P01"), std::string::npos);
    EXPECT_EQ(response.body.find("relation"), std::string::npos);

    const Json audit = only_audit_line();
    EXPECT_EQ(audit["outcome"], "DATABASE_FAILURE");
    EXPECT_EQ(audit["category"], "EXECUTION_FAILURE");
    EXPECT_EQ(audit["statement_type"], "SELECT");
}

TEST_F(EndToEndTest, DatabaseConnectionFailureIsReportedAsUnavailable) {
    // Unreachable local endpoint: connection is refused immediately on
    // loopback, and connect_timeout bounds the worst case. No new executor
    // contract is introduced for this.
    const config::DatabaseConfig unreachable{
        "postgresql://localhost:1/sql_proxy_test?connect_timeout=1", 1000};
    Pipeline offline = make_pipeline(unreachable, audit_path_);

    const httplib::Response response =
        post("SELECT id FROM customers", offline.service.get());

    EXPECT_EQ(response.status, 503);
    EXPECT_EQ(body_of(response)["error"], "database_unavailable");
    EXPECT_EQ(response.body.find("localhost"), std::string::npos);
    EXPECT_EQ(response.body.find("5432"), std::string::npos);

    const Json audit = only_audit_line();
    EXPECT_EQ(audit["outcome"], "DATABASE_FAILURE");
    EXPECT_EQ(audit["category"], "CONNECTION_FAILURE");
}

// === Audit persistence failure ==============================================

TEST_F(EndToEndTest, AuditPersistenceFailureWithholdsSuccessfulData) {
    // Deterministic, privilege-independent failure: a regular file sits where
    // the parent directory would have to be, so opening the audit file fails
    // with ENOTDIR for any user, including root.
    const std::filesystem::path blocker = directory_ / "blocker";
    { std::ofstream out(blocker.string()); out << "not a directory\n"; }
    const std::string unusable = (blocker / "audit.jsonl").string();
    Pipeline broken = make_pipeline(database_config(), unusable);

    const httplib::Response response =
        post("SELECT email FROM customers ORDER BY id", broken.service.get());

    EXPECT_EQ(response.status, 500);
    const Json body = body_of(response);
    EXPECT_EQ(body["error"], "internal_error");
    // No data escapes when its audit record could not be persisted.
    EXPECT_FALSE(body.contains("rows"));
    EXPECT_FALSE(body.contains("columns"));
    EXPECT_EQ(response.body.find("l***@example.com"), std::string::npos);
    EXPECT_EQ(response.body.find("lihi.roas@example.com"), std::string::npos);

    // A failed append writes no line — the invariant is one append ATTEMPT per
    // request (proven with the fake repository), not one line in every case.
    EXPECT_FALSE(std::filesystem::exists(unusable));
    EXPECT_TRUE(audit_lines().empty());
}

// === Multi-request corpus ===================================================

TEST_F(EndToEndTest, AuditCorpusAppendsOneLinePerSuccessfulAppendAndStaysClean) {
    const std::vector<std::string> requests{
        "SELECT * FROM customers ORDER BY id",              // SUCCESS
        "SELECT email AS contact FROM customers",           // SUCCESS
        "",                                                 // POLICY_REJECTED
        "SELEC * FRM customers",                            // PARSING_FAILURE
        "DROP TABLE orders",                                // POLICY_REJECTED
        "SELECT * FROM no_such_table",                      // DATABASE_FAILURE
        "SELECT UPPER(email) FROM customers",               // MASKING_REFUSED
    };
    for (const std::string& sql : requests) {
        post(sql);
    }

    const std::vector<Json> lines = audit_lines();
    ASSERT_EQ(lines.size(), requests.size());  // appends all succeeded here

    std::map<std::string, int> outcomes;
    std::uint64_t previous_id = 0;
    for (const Json& line : lines) {
        validate_audit_line(line);  // structural + closed-vocabulary check
        outcomes[line["outcome"].get<std::string>()] += 1;
        const std::uint64_t id = line["request_id"].get<std::uint64_t>();
        EXPECT_GT(id, previous_id) << "request ids must be monotonic";
        previous_id = id;
    }
    EXPECT_EQ(outcomes["SUCCESS"], 2);
    EXPECT_EQ(outcomes["POLICY_REJECTED"], 2);
    EXPECT_EQ(outcomes["PARSING_FAILURE"], 1);
    EXPECT_EQ(outcomes["DATABASE_FAILURE"], 1);
    EXPECT_EQ(outcomes["MASKING_REFUSED"], 1);
}

}  // namespace
