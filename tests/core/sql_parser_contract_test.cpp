// Contract tests for the production ISqlParser implementation.
//
// These run real SQL through the port interface and assert on ParseResult
// alone — they document exactly what the shipped parser guarantees, and they
// enforce contracts that were previously comment-only (sanitized errors,
// spelling preservation, projection classification).

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "adapters/parser/hyrise_sql_parser.h"
#include "core/sql_analyzer.h"
#include "ports/sql_parser.h"

namespace {

ports::ParseResult parse(const std::string& sql) {
    parser_adapter::HyriseSqlParser parser;
    return parser.parse(sql);
}

const ports::ParsedStatement& only_statement(const ports::ParseResult& result) {
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.statements.size(), 1u);
    return result.statements.front();
}

bool contains_note(const ports::ParsedStatement& stmt, const std::string& note) {
    for (const std::string& feature : stmt.unsupported_features) {
        if (feature == note) {
            return true;
        }
    }
    return false;
}

}  // namespace

TEST(SqlParserContract, SelectPlainColumns) {
    auto result = parse("SELECT id, email FROM customers");
    const auto& stmt = only_statement(result);
    EXPECT_EQ(stmt.type, core::StatementType::Select);
    ASSERT_EQ(stmt.tables.size(), 1u);
    EXPECT_EQ(stmt.tables[0].schema, "");
    EXPECT_EQ(stmt.tables[0].name, "customers");
    EXPECT_EQ(stmt.projection_columns, std::vector<std::string>({"id", "email"}));
    EXPECT_FALSE(stmt.has_wildcard_projection);
    EXPECT_FALSE(stmt.has_computed_projection);
}

TEST(SqlParserContract, SelectWildcard) {
    auto result = parse("SELECT * FROM customers");
    const auto& stmt = only_statement(result);
    EXPECT_TRUE(stmt.has_wildcard_projection);
    EXPECT_TRUE(stmt.projection_columns.empty());
    EXPECT_FALSE(stmt.has_computed_projection);
}

TEST(SqlParserContract, SelectQualifiedWildcard) {
    auto result = parse("SELECT c.* FROM customers c");
    const auto& stmt = only_statement(result);
    EXPECT_TRUE(stmt.has_wildcard_projection);
}

TEST(SqlParserContract, SelectMixedPlainAndComputed) {
    auto result = parse("SELECT id, UPPER(email) FROM customers");
    const auto& stmt = only_statement(result);
    EXPECT_EQ(stmt.projection_columns, std::vector<std::string>({"id"}));
    EXPECT_TRUE(stmt.has_computed_projection);
    EXPECT_FALSE(stmt.has_wildcard_projection);
}

TEST(SqlParserContract, SelectJoinExposesBothTables) {
    auto result =
        parse("SELECT c.id FROM customers c JOIN orders o ON c.id = o.customer_id");
    const auto& stmt = only_statement(result);
    ASSERT_EQ(stmt.tables.size(), 2u);
    EXPECT_EQ(stmt.tables[0].name, "customers");
    EXPECT_EQ(stmt.tables[1].name, "orders");
    // Qualified projection columns keep their spelling as written (alias kept).
    EXPECT_EQ(stmt.projection_columns, std::vector<std::string>({"c.id"}));
}

TEST(SqlParserContract, SelectSchemaQualified) {
    auto result = parse("SELECT id FROM public.customers");
    const auto& stmt = only_statement(result);
    ASSERT_EQ(stmt.tables.size(), 1u);
    EXPECT_EQ(stmt.tables[0].schema, "public");
    EXPECT_EQ(stmt.tables[0].name, "customers");
}

TEST(SqlParserContract, QuotedIdentifierSpellingPreserved) {
    auto result = parse("SELECT \"Id\" FROM \"Customers\"");
    const auto& stmt = only_statement(result);
    ASSERT_EQ(stmt.tables.size(), 1u);
    EXPECT_EQ(stmt.tables[0].name, "Customers");
    EXPECT_EQ(stmt.projection_columns, std::vector<std::string>({"Id"}));
}

TEST(SqlParserContract, UnquotedIdentifierSpellingAlsoPreserved) {
    // Documented parser limitation: no case folding, no quoting flag —
    // unquoted mixed case comes back exactly as written, same as quoted.
    auto result = parse("SELECT Id FROM Customers");
    const auto& stmt = only_statement(result);
    ASSERT_EQ(stmt.tables.size(), 1u);
    EXPECT_EQ(stmt.tables[0].name, "Customers");
    EXPECT_EQ(stmt.projection_columns, std::vector<std::string>({"Id"}));
}

TEST(SqlParserContract, InsertWithColumnList) {
    auto result = parse("INSERT INTO customers (name, email) VALUES ('a', 'b')");
    const auto& stmt = only_statement(result);
    EXPECT_EQ(stmt.type, core::StatementType::Insert);
    ASSERT_EQ(stmt.tables.size(), 1u);
    EXPECT_EQ(stmt.tables[0].name, "customers");
    EXPECT_EQ(stmt.affected_columns, std::vector<std::string>({"name", "email"}));
}

TEST(SqlParserContract, InsertWithoutColumnListDegradesGracefully) {
    auto result = parse("INSERT INTO customers VALUES (1, 'a', 'b', 'c')");
    const auto& stmt = only_statement(result);
    EXPECT_EQ(stmt.type, core::StatementType::Insert);
    EXPECT_TRUE(stmt.affected_columns.empty());
    EXPECT_TRUE(contains_note(stmt, "INSERT without column list"));
}

TEST(SqlParserContract, UpdateSetTargets) {
    auto result = parse("UPDATE customers SET phone = 'x' WHERE id = 1");
    const auto& stmt = only_statement(result);
    EXPECT_EQ(stmt.type, core::StatementType::Update);
    ASSERT_EQ(stmt.tables.size(), 1u);
    EXPECT_EQ(stmt.tables[0].name, "customers");
    EXPECT_EQ(stmt.affected_columns, std::vector<std::string>({"phone"}));
}

TEST(SqlParserContract, DeleteTableOnly) {
    auto result = parse("DELETE FROM orders WHERE id = 1");
    const auto& stmt = only_statement(result);
    EXPECT_EQ(stmt.type, core::StatementType::Delete);
    ASSERT_EQ(stmt.tables.size(), 1u);
    EXPECT_EQ(stmt.tables[0].name, "orders");
    EXPECT_TRUE(stmt.affected_columns.empty());
}

TEST(SqlParserContract, CreateTable) {
    auto result = parse("CREATE TABLE t (id INT)");
    const auto& stmt = only_statement(result);
    EXPECT_EQ(stmt.type, core::StatementType::Create);
    ASSERT_EQ(stmt.tables.size(), 1u);
    EXPECT_EQ(stmt.tables[0].name, "t");
}

TEST(SqlParserContract, DropTable) {
    auto result = parse("DROP TABLE t");
    const auto& stmt = only_statement(result);
    EXPECT_EQ(stmt.type, core::StatementType::Drop);
    ASSERT_EQ(stmt.tables.size(), 1u);
    EXPECT_EQ(stmt.tables[0].name, "t");
}

TEST(SqlParserContract, AlterDropColumn) {
    auto result = parse("ALTER TABLE t DROP COLUMN c");
    const auto& stmt = only_statement(result);
    EXPECT_EQ(stmt.type, core::StatementType::Alter);
    ASSERT_EQ(stmt.tables.size(), 1u);
    EXPECT_EQ(stmt.tables[0].name, "t");
}

TEST(SqlParserContract, AlterAddColumnIsSanitizedParseFailure) {
    // Documented parser limitation: only ALTER ... DROP COLUMN is supported.
    auto result = parse("ALTER TABLE t ADD COLUMN c INT");
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error.empty());
    // The error must not echo any fragment of the input.
    EXPECT_EQ(result.error.find("ADD"), std::string::npos);
    EXPECT_EQ(result.error.find("INT"), std::string::npos);
}

TEST(SqlParserContract, MultiStatementDetected) {
    auto result = parse("SELECT 1; DELETE FROM orders");
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.statements.size(), 2u);
    EXPECT_EQ(result.statements[0].type, core::StatementType::Select);
    EXPECT_EQ(result.statements[1].type, core::StatementType::Delete);
}

TEST(SqlParserContract, InjectionShapedMultiStatementDetected) {
    auto result = parse("INSERT INTO customers (name) VALUES ('a'); DROP TABLE customers");
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.statements.size(), 2u);
    EXPECT_EQ(result.statements[0].type, core::StatementType::Insert);
    EXPECT_EQ(result.statements[1].type, core::StatementType::Drop);
}

TEST(SqlParserContract, SyntaxErrorReportedCleanly) {
    auto result = parse("SELEC id FROM t");
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error.empty());
    EXPECT_TRUE(result.statements.empty());
}

TEST(SqlParserContract, ErrorNeverEchoesInputLiterals) {
    // Force a syntax error on input containing a distinctive literal and
    // assert the literal does not leak into the returned error.
    auto result = parse("SELECT * FROM t WHERE card = 'XYZZY-4111-1111' AND");
    ASSERT_FALSE(result.success);
    EXPECT_EQ(result.error.find("XYZZY"), std::string::npos);
    EXPECT_EQ(result.error.find("4111"), std::string::npos);
}

TEST(SqlParserContract, EmptyInputFailsWithoutCrashing) {
    auto result = parse("");
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error.empty());
}

TEST(SqlParserContract, OutOfScopeStatementMapsToUnknown) {
    auto result = parse("SHOW TABLES");
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.statements.size(), 1u);
    EXPECT_EQ(result.statements[0].type, core::StatementType::Unknown);
}

TEST(SqlParserContract, AnalyzerComposesWithRealParser) {
    // End-to-end through the analyzer, unchanged, over the real adapter.
    core::SqlAnalyzer analyzer(std::make_unique<parser_adapter::HyriseSqlParser>());

    auto analysis = analyzer.analyze("SELECT id, email FROM public.customers");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::Ok);
    EXPECT_EQ(analysis.statement_type, core::StatementType::Select);
    EXPECT_EQ(analysis.statement_class, core::StatementClass::Select);
    EXPECT_EQ(analysis.statement_count, 1);
    EXPECT_EQ(analysis.tables, std::vector<std::string>({"public.customers"}));
    EXPECT_EQ(analysis.projection_columns, std::vector<std::string>({"id", "email"}));
}

TEST(SqlParserContract, AnalyzerRejectsMultiStatementFromRealParser) {
    core::SqlAnalyzer analyzer(std::make_unique<parser_adapter::HyriseSqlParser>());

    auto analysis = analyzer.analyze("SELECT 1; DROP TABLE customers");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::MultipleStatements);
    EXPECT_EQ(analysis.statement_count, 2);
}
