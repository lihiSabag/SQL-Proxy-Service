// Integration tests for PostgresQueryExecutor. Require a real PostgreSQL.
//
// Fail-closed safety guards (both must pass before ANY SQL is executed):
//   1. TEST_DATABASE_URL must name the dedicated database "sql_proxy_test" —
//      anything else is a hard failure with zero SQL executed. Merely setting
//      the variable to a real database can never cause writes.
//   2. SQL_PROXY_TEST_DB_RESET=1 must be set before schema.sql/seed.sql (which
//      drop and recreate the two demo tables) are applied; otherwise SKIP.
// If TEST_DATABASE_URL is unset entirely, the whole suite SKIPs so unit-level
// runs stay self-contained.
//
// Credential rule: no message below ever prints the URL or anything derived
// from it — variable names only.
//
// pqxx is used here directly ONLY to apply the setup scripts (multi-statement
// files, which the executor's single-statement precondition forbids). All
// assertions go through the IQueryExecutor port. Production code keeps pqxx
// confined to the adapter.

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

#include <pqxx/pqxx>

#include "postgres/postgres_query_executor.h"
#include "config/config.h"
#include "ports/query_executor.h"

namespace {

constexpr const char* kRequiredDbName = "sql_proxy_test";

// Extracts the database name from a libpq URI: the path segment after the
// last '/', with any '?query' stripped. Parsing only — executes nothing.
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

class PostgresExecutorTest : public ::testing::Test {
protected:
    void SetUp() override {
        const TestEnvironment& env = test_environment();
        if (!env.url_set) {
            GTEST_SKIP() << "TEST_DATABASE_URL is not set — integration tests skipped. "
                            "This does NOT count as database verification.";
        }
        // Guard 1: dedicated database name, or hard failure with zero SQL run.
        ASSERT_TRUE(env.db_name_ok)
            << "TEST_DATABASE_URL must name the dedicated database '" << kRequiredDbName
            << "'. Refusing to run against anything else. No SQL was executed.";
        // Guard 2: destructive reset needs explicit opt-in.
        if (!env.reset_opt_in) {
            GTEST_SKIP() << "SQL_PROXY_TEST_DB_RESET=1 is required before the test schema "
                            "is applied (schema.sql drops and recreates the demo tables).";
        }
        apply_schema_once();
        executor_ = std::make_unique<postgres_adapter::PostgresQueryExecutor>(
            config::DatabaseConfig{env.url, 5000});
    }

    static void apply_schema_once() {
        static const bool applied = [] {
            // Setup only: scripts are multi-statement files, outside the
            // executor's single-statement precondition.
            pqxx::connection connection(test_environment().url);
            pqxx::work transaction(connection);
            transaction.exec(read_file(std::string(SQL_PROXY_SQL_DIR) + "/schema.sql"));
            transaction.exec(read_file(std::string(SQL_PROXY_SQL_DIR) + "/seed.sql"));
            transaction.commit();
            return true;
        }();
        ASSERT_TRUE(applied);
    }

    ports::ExecutionResult execute(const std::string& sql) { return executor_->execute(sql); }

    std::unique_ptr<postgres_adapter::PostgresQueryExecutor> executor_;
};

}  // namespace

TEST_F(PostgresExecutorTest, SelectSeededCustomers) {
    auto result = execute("SELECT name, email FROM customers ORDER BY id");
    ASSERT_EQ(result.status, ports::ExecutionStatus::Ok) << result.error;
    EXPECT_TRUE(result.has_result_set);
    ASSERT_EQ(result.columns.size(), 2u);
    EXPECT_EQ(result.columns[0].name, "name");
    EXPECT_EQ(result.columns[1].name, "email");
    EXPECT_GE(result.row_count, 4);
    ASSERT_FALSE(result.rows.empty());
    ASSERT_TRUE(result.rows[0][1].has_value());
    EXPECT_EQ(*result.rows[0][1], "lihi.roas@example.com");
}

TEST_F(PostgresExecutorTest, ColumnTypesTranslatedToNeutralEnum) {
    auto result = execute(
        "SELECT customers.id, customers.email, orders.amount, orders.created_at FROM orders "
        "JOIN customers ON customers.id = orders.customer_id LIMIT 1");
    ASSERT_EQ(result.status, ports::ExecutionStatus::Ok) << result.error;
    ASSERT_EQ(result.columns.size(), 4u);
    EXPECT_EQ(result.columns[0].type, ports::ColumnType::Integer);   // id
    EXPECT_EQ(result.columns[1].type, ports::ColumnType::Text);      // email
    EXPECT_EQ(result.columns[2].type, ports::ColumnType::Numeric);   // amount
    EXPECT_EQ(result.columns[3].type, ports::ColumnType::Timestamp); // created_at
}

TEST_F(PostgresExecutorTest, NullAndEmptyStringStayDistinct) {
    auto result = execute(
        "SELECT phone FROM customers WHERE email IN "
        "('daniel.mizrahi@example.net', 'yael.azulay@example.com') ORDER BY email");
    ASSERT_EQ(result.status, ports::ExecutionStatus::Ok) << result.error;
    ASSERT_EQ(result.rows.size(), 2u);
    // daniel: NULL phone; yael: empty-string phone.
    EXPECT_FALSE(result.rows[0][0].has_value());
    ASSERT_TRUE(result.rows[1][0].has_value());
    EXPECT_EQ(*result.rows[1][0], "");
}

TEST_F(PostgresExecutorTest, InsertReportsAffectedRowsWithoutResultSet) {
    auto result = execute(
        "INSERT INTO customers (name, email) VALUES ('Temp Insert', 'temp-insert@test.local')");
    ASSERT_EQ(result.status, ports::ExecutionStatus::Ok) << result.error;
    EXPECT_FALSE(result.has_result_set);
    EXPECT_EQ(result.affected_rows, 1);
    EXPECT_EQ(result.row_count, 0);
}

TEST_F(PostgresExecutorTest, InsertReturningHasResultSetAndAffectedRows) {
    auto result = execute(
        "INSERT INTO customers (name, email) VALUES ('Temp Returning', "
        "'temp-returning@test.local') RETURNING id");
    ASSERT_EQ(result.status, ports::ExecutionStatus::Ok) << result.error;
    EXPECT_TRUE(result.has_result_set);
    ASSERT_EQ(result.columns.size(), 1u);
    EXPECT_EQ(result.columns[0].name, "id");
    EXPECT_EQ(result.row_count, 1);
    EXPECT_EQ(result.affected_rows, 1);
}

TEST_F(PostgresExecutorTest, UpdateAndDeleteReportAffectedRows) {
    auto insert = execute(
        "INSERT INTO customers (name, email) VALUES ('Temp Mutate', 'temp-mutate@test.local')");
    ASSERT_EQ(insert.status, ports::ExecutionStatus::Ok) << insert.error;

    auto update = execute(
        "UPDATE customers SET phone = '+1-555-9999' WHERE email = 'temp-mutate@test.local'");
    ASSERT_EQ(update.status, ports::ExecutionStatus::Ok) << update.error;
    EXPECT_EQ(update.affected_rows, 1);

    auto del = execute("DELETE FROM customers WHERE email = 'temp-mutate@test.local'");
    ASSERT_EQ(del.status, ports::ExecutionStatus::Ok) << del.error;
    EXPECT_EQ(del.affected_rows, 1);
}

TEST_F(PostgresExecutorTest, SyntaxErrorIsSanitizedExecutionFailure) {
    auto result = execute("SELEC nonsense FROM nowhere");
    EXPECT_EQ(result.status, ports::ExecutionStatus::ExecutionFailure);
    EXPECT_NE(result.error.find("SQLSTATE"), std::string::npos);
    // No fragment of the statement may leak into the error.
    EXPECT_EQ(result.error.find("SELEC"), std::string::npos);
    EXPECT_EQ(result.error.find("nonsense"), std::string::npos);
    EXPECT_EQ(result.error.find("nowhere"), std::string::npos);
}

TEST_F(PostgresExecutorTest, ConstraintViolationDoesNotLeakValues) {
    // Duplicate of a seeded unique email, with a distinctive literal along
    // for the ride. PostgreSQL's own message would echo the value; ours must not.
    auto result = execute(
        "INSERT INTO customers (name, email, credit_card) "
        "VALUES ('XYZZY Leaky', 'lihi.roas@example.com', 'XYZZY-4111-1111')");
    EXPECT_EQ(result.status, ports::ExecutionStatus::ExecutionFailure);
    EXPECT_NE(result.error.find("SQLSTATE"), std::string::npos);
    EXPECT_EQ(result.error.find("XYZZY"), std::string::npos);
    EXPECT_EQ(result.error.find("lihi.roas"), std::string::npos);
    EXPECT_EQ(result.error.find("4111"), std::string::npos);
}

TEST_F(PostgresExecutorTest, FailedStatementIsNotCommitted) {
    auto before = execute("SELECT count(*) FROM orders");
    ASSERT_EQ(before.status, ports::ExecutionStatus::Ok) << before.error;
    ASSERT_TRUE(before.rows[0][0].has_value());
    const std::string count_before = *before.rows[0][0];

    // Foreign-key violation: customer 999999 does not exist.
    auto failing = execute("INSERT INTO orders (customer_id, amount) VALUES (999999, 1.00)");
    EXPECT_EQ(failing.status, ports::ExecutionStatus::ExecutionFailure);

    auto after = execute("SELECT count(*) FROM orders");
    ASSERT_EQ(after.status, ports::ExecutionStatus::Ok) << after.error;
    ASSERT_TRUE(after.rows[0][0].has_value());
    EXPECT_EQ(*after.rows[0][0], count_before);
}

TEST_F(PostgresExecutorTest, StatementTimeoutSurfacesAsSanitizedFailure) {
    postgres_adapter::PostgresQueryExecutor slow_executor(
        config::DatabaseConfig{test_environment().url, 100});  // 100 ms

    auto result = slow_executor.execute("SELECT pg_sleep(2)");

    EXPECT_EQ(result.status, ports::ExecutionStatus::ExecutionFailure);
    EXPECT_NE(result.error.find("57014"), std::string::npos);  // query_canceled
}

TEST_F(PostgresExecutorTest, UnreachableServerIsConnectionFailure) {
    // Guard-consistent dbname; port 1 is never PostgreSQL. Independent of
    // TEST_DATABASE_URL — no credentials involved, nothing printed.
    postgres_adapter::PostgresQueryExecutor unreachable(
        config::DatabaseConfig{"postgresql://localhost:1/sql_proxy_test", 1000});

    auto result = unreachable.execute("SELECT 1");

    EXPECT_EQ(result.status, ports::ExecutionStatus::ConnectionFailure);
    EXPECT_EQ(result.error, "connection failed");
}
