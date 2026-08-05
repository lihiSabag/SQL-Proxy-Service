// Contract tests for the production ISqlParser implementation.
//
// These run real SQL through the port interface and assert on ParseResult
// alone — they document exactly what the shipped parser guarantees, and they
// enforce contracts that were previously comment-only (sanitized errors,
// spelling preservation, projection classification).

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "parser/hyrise_sql_parser.h"
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

// === Canonical COUNT(*) recognition ========================================
//
// The single computed shape reported as safe. Each negative case asserts
// that a near-miss stays a generic computed projection, which is what keeps
// it refused downstream.

TEST(SqlParserContract, CountStarIsSafeCountStar) {
    auto result = parse("SELECT COUNT(*) FROM customers");
    const auto& stmt = only_statement(result);
    EXPECT_TRUE(stmt.has_safe_count_star_projection);
    EXPECT_FALSE(stmt.has_computed_projection);
    EXPECT_FALSE(stmt.has_wildcard_projection);
    EXPECT_TRUE(stmt.projection_columns.empty());
    EXPECT_FALSE(stmt.has_group_by);
}

TEST(SqlParserContract, CountStarIsCaseInsensitive) {
    // The parser preserves function-name spelling verbatim, so recognition
    // has to fold case itself.
    for (const char* sql : {"SELECT count(*) FROM customers",
                            "SELECT CoUnT(*) FROM customers",
                            "SELECT COUNT(*) FROM customers"}) {
        SCOPED_TRACE(sql);
        auto result = parse(sql);
        const auto& stmt = only_statement(result);
        EXPECT_TRUE(stmt.has_safe_count_star_projection);
        EXPECT_FALSE(stmt.has_computed_projection);
    }
}

TEST(SqlParserContract, CountStarWithAliasIsStillSafeCountStar) {
    // An alias lives on the same node and changes neither its type nor the
    // function name, so it cannot affect recognition.
    auto result = parse("SELECT COUNT(*) AS total FROM customers");
    const auto& stmt = only_statement(result);
    EXPECT_TRUE(stmt.has_safe_count_star_projection);
    EXPECT_FALSE(stmt.has_computed_projection);
}

TEST(SqlParserContract, CountVariantsAreNotSafeCountStar) {
    // Only the canonical form is recognized. COUNT(1) is equivalent in SQL
    // and is still refused: this feature accepts one shape, not a family.
    for (const char* sql : {"SELECT COUNT(1) FROM customers",
                            "SELECT COUNT(0) FROM customers",
                            "SELECT COUNT(1.0) FROM customers",
                            "SELECT COUNT(NULL) FROM customers",
                            "SELECT COUNT(email) FROM customers",
                            "SELECT COUNT(DISTINCT email) FROM customers",
                            "SELECT COUNT(DISTINCT 1) FROM customers"}) {
        SCOPED_TRACE(sql);
        auto result = parse(sql);
        const auto& stmt = only_statement(result);
        EXPECT_FALSE(stmt.has_safe_count_star_projection);
        EXPECT_TRUE(stmt.has_computed_projection);
    }
}

TEST(SqlParserContract, CountStarOverWindowIsNotSafeCountStar) {
    // Byte-identical to a plain COUNT(*) except for the window description;
    // missing this check would silently admit window functions.
    auto result = parse("SELECT COUNT(*) OVER () FROM customers");
    const auto& stmt = only_statement(result);
    EXPECT_FALSE(stmt.has_safe_count_star_projection);
    EXPECT_TRUE(stmt.has_computed_projection);
}

TEST(SqlParserContract, CountStarInsideArithmeticIsNotSafeCountStar) {
    // The top-level node is an operator; the call is nested inside it.
    auto result = parse("SELECT COUNT(*) + 1 FROM customers");
    const auto& stmt = only_statement(result);
    EXPECT_FALSE(stmt.has_safe_count_star_projection);
    EXPECT_TRUE(stmt.has_computed_projection);
}

TEST(SqlParserContract, OtherAggregatesAndFunctionsAreNotSafeCountStar) {
    // MIN/MAX return actual column values; SUM/AVG derive from them;
    // UPPER/LOWER/CONCAT transform them.
    for (const char* sql : {"SELECT MIN(email) FROM customers",
                            "SELECT MAX(email) FROM customers",
                            "SELECT MAX(credit_card) FROM customers",
                            "SELECT SUM(amount) FROM orders",
                            "SELECT AVG(amount) FROM orders",
                            "SELECT UPPER(email) FROM customers",
                            "SELECT LOWER(email) FROM customers",
                            "SELECT CONCAT(name, email) FROM customers"}) {
        SCOPED_TRACE(sql);
        auto result = parse(sql);
        const auto& stmt = only_statement(result);
        EXPECT_FALSE(stmt.has_safe_count_star_projection);
        EXPECT_TRUE(stmt.has_computed_projection);
    }
}

TEST(SqlParserContract, GroupByIsReportedAsSyntaxFact) {
    auto grouped = parse("SELECT COUNT(*) FROM customers GROUP BY email");
    const auto& grouped_stmt = only_statement(grouped);
    EXPECT_TRUE(grouped_stmt.has_safe_count_star_projection);
    EXPECT_TRUE(grouped_stmt.has_group_by);  // the core decides what it means

    auto having = parse("SELECT COUNT(*) FROM customers GROUP BY id HAVING COUNT(*) > 1");
    EXPECT_TRUE(only_statement(having).has_group_by);

    auto ungrouped = parse("SELECT COUNT(*) FROM customers");
    EXPECT_FALSE(only_statement(ungrouped).has_group_by);
}

TEST(SqlParserContract, MixedProjectionsReportEveryShapeTheyContain) {
    // Exactly one arm fires per entry, so the core sees the full picture and
    // can refuse the combination.
    auto with_column = parse("SELECT COUNT(*), email FROM customers");
    const auto& a = only_statement(with_column);
    EXPECT_TRUE(a.has_safe_count_star_projection);
    EXPECT_EQ(a.projection_columns, std::vector<std::string>({"email"}));

    auto with_wildcard = parse("SELECT COUNT(*), * FROM customers");
    const auto& b = only_statement(with_wildcard);
    EXPECT_TRUE(b.has_safe_count_star_projection);
    EXPECT_TRUE(b.has_wildcard_projection);

    auto with_literal = parse("SELECT COUNT(*), 1 FROM customers");
    const auto& c = only_statement(with_literal);
    EXPECT_TRUE(c.has_safe_count_star_projection);
    EXPECT_TRUE(c.has_computed_projection);  // a bare literal is not safe here

    auto with_unsafe_count = parse("SELECT COUNT(*), COUNT(email) FROM customers");
    const auto& d = only_statement(with_unsafe_count);
    EXPECT_TRUE(d.has_safe_count_star_projection);
    EXPECT_TRUE(d.has_computed_projection);

    auto two_counts = parse("SELECT COUNT(*), COUNT(*) FROM customers");
    const auto& e = only_statement(two_counts);
    EXPECT_TRUE(e.has_safe_count_star_projection);
    EXPECT_FALSE(e.has_computed_projection);
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

// === INSERT source form and VALUES literal kinds ===========================
//
// The facts the write policy is built on. The negative cases matter most:
// each asserts that a near-miss is reported as something the policy cannot
// authorize. Several shapes never reach the adapter at all because the
// grammar refuses them, and those are pinned separately below so a parser
// upgrade cannot quietly start accepting them.

using Kind = core::InsertValueKind;
using Kinds = std::vector<core::InsertValueKind>;

TEST(SqlParserContract, InsertValuesReportsSourceAndLiteralKinds) {
    auto result = parse("INSERT INTO orders (customer_id, amount) VALUES (1, 199.90)");
    const auto& stmt = only_statement(result);
    EXPECT_EQ(stmt.type, core::StatementType::Insert);
    EXPECT_EQ(stmt.insert_source, core::InsertSource::Values);
    ASSERT_EQ(stmt.tables.size(), 1u);
    EXPECT_EQ(stmt.tables[0].schema, "");
    EXPECT_EQ(stmt.tables[0].name, "orders");
    EXPECT_EQ(stmt.affected_columns, std::vector<std::string>({"customer_id", "amount"}));
    EXPECT_EQ(stmt.insert_value_kinds,
              Kinds({Kind::PositiveIntegerLiteral, Kind::PositiveDecimalLiteral}));
}

TEST(SqlParserContract, InsertIntegerAmountIsAPositiveIntegerLiteral) {
    auto result = parse("INSERT INTO orders (customer_id, amount) VALUES (1, 100)");
    EXPECT_EQ(only_statement(result).insert_value_kinds,
              Kinds({Kind::PositiveIntegerLiteral, Kind::PositiveIntegerLiteral}));
}

TEST(SqlParserContract, InsertSelectIsReportedAsASelectSource) {
    // The table list of a copying insert is identical to a permitted one, so
    // the source form is the only fact that separates them.
    auto result = parse("INSERT INTO orders (customer_id, amount) "
                        "SELECT id, 100 FROM customers");
    const auto& stmt = only_statement(result);
    EXPECT_EQ(stmt.insert_source, core::InsertSource::Select);
    EXPECT_TRUE(stmt.insert_value_kinds.empty());
    ASSERT_EQ(stmt.tables.size(), 1u);
    EXPECT_EQ(stmt.tables[0].name, "orders");  // source table is NOT recorded
}

TEST(SqlParserContract, InsertZeroLiteralsAreNonPositive) {
    EXPECT_EQ(only_statement(parse(
                  "INSERT INTO orders (customer_id, amount) VALUES (0, 100)"))
                  .insert_value_kinds[0],
              Kind::NonPositiveNumericLiteral);
    EXPECT_EQ(only_statement(parse(
                  "INSERT INTO orders (customer_id, amount) VALUES (1, 0.0)"))
                  .insert_value_kinds[1],
              Kind::NonPositiveNumericLiteral);
}

TEST(SqlParserContract, InsertNegativeValuesAreNotLiteralsAtAll) {
    // A negative number parses as a negation operator wrapping a literal, so
    // it is Unsupported rather than NonPositiveNumericLiteral.
    for (const char* sql : {"INSERT INTO orders (customer_id, amount) VALUES (1, -10)",
                            "INSERT INTO orders (customer_id, amount) VALUES (1, -1.5)",
                            "INSERT INTO orders (customer_id, amount) VALUES (-1, 100)"}) {
        SCOPED_TRACE(sql);
        auto result = parse(sql);
        const auto& kinds = only_statement(result).insert_value_kinds;
        ASSERT_EQ(kinds.size(), 2u);
        EXPECT_TRUE(kinds[0] == Kind::Unsupported || kinds[1] == Kind::Unsupported);
    }
}

TEST(SqlParserContract, InsertNonNumericValuesAreUnsupported) {
    EXPECT_EQ(only_statement(parse(
                  "INSERT INTO orders (customer_id, amount) VALUES (1, NULL)"))
                  .insert_value_kinds[1],
              Kind::Unsupported);
    EXPECT_EQ(only_statement(parse(
                  "INSERT INTO orders (customer_id, amount) VALUES (1, '100')"))
                  .insert_value_kinds[1],
              Kind::Unsupported);
}

TEST(SqlParserContract, InsertStringLiteralTextNeverLeavesTheAdapter) {
    // The literal's text lives in the AST node, and nothing copies it out.
    const std::string secret = "zzq-canary-9137@example.com";
    auto result = parse("INSERT INTO customers (name, email) VALUES ('Noa', '" +
                        secret + "')");
    const auto& stmt = only_statement(result);
    EXPECT_EQ(stmt.insert_value_kinds, Kinds({Kind::Unsupported, Kind::Unsupported}));
    for (const std::string& table : {stmt.tables[0].schema, stmt.tables[0].name}) {
        EXPECT_EQ(table.find(secret), std::string::npos);
    }
    for (const std::string& column : stmt.affected_columns) {
        EXPECT_EQ(column.find(secret), std::string::npos);
    }
    for (const std::string& feature : stmt.unsupported_features) {
        EXPECT_EQ(feature.find(secret), std::string::npos);
    }
}

TEST(SqlParserContract, InsertIdentifierSpellingIsPreservedVerbatim) {
    // Case is not folded, and a schema qualifier is kept, so the policy can
    // compare exactly and refuse anything that is not the canonical name.
    auto upper = parse("INSERT INTO ORDERS (CUSTOMER_ID, AMOUNT) VALUES (1, 100)");
    EXPECT_EQ(only_statement(upper).tables[0].name, "ORDERS");
    EXPECT_EQ(only_statement(upper).affected_columns,
              std::vector<std::string>({"CUSTOMER_ID", "AMOUNT"}));

    auto qualified = parse("INSERT INTO public.orders (customer_id, amount) VALUES (1, 100)");
    EXPECT_EQ(only_statement(qualified).tables[0].schema, "public");

    auto mixed = parse("INSERT INTO \"Orders\" (customer_id, amount) VALUES (1, 100)");
    EXPECT_EQ(only_statement(mixed).tables[0].name, "Orders");
}

TEST(SqlParserContract, InsertShapesTheGrammarRefusesOutright) {
    // Pins parser-version assumptions: each of these is a parse error today,
    // and the write policy relies on never seeing them. If a parser upgrade
    // starts accepting one, this fails instead of silently widening the
    // authorized surface.
    for (const char* sql : {
             "INSERT INTO orders (customer_id, amount) VALUES (1, 100), (2, 200)",
             "INSERT INTO orders (customer_id, amount) VALUES (1, 100) RETURNING *",
             "INSERT INTO orders (customer_id, amount) VALUES (1, DEFAULT)",
             "INSERT INTO orders (customer_id, amount) VALUES (1, random() * 100)",
             "INSERT INTO orders (customer_id, amount) VALUES (1, 100 + 1)",
             "INSERT INTO orders (customer_id, amount) VALUES ((SELECT id FROM customers), 1)",
             "INSERT INTO orders (customer_id, amount) VALUES (1, CAST(100 AS NUMERIC))",
             "INSERT INTO orders (customer_id, amount) VALUES (1, 100) ON CONFLICT DO NOTHING",
         }) {
        SCOPED_TRACE(sql);
        EXPECT_FALSE(parse(sql).success);
    }
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
