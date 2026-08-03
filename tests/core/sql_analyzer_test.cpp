#include <gtest/gtest.h>

#include <memory>
#include <stdexcept>
#include <utility>

#include "core/sql_analyzer.h"
#include "fake_sql_parser.h"

namespace {

ports::ParseResult single_statement(ports::ParsedStatement statement) {
    ports::ParseResult result;
    result.success = true;
    result.statements.push_back(std::move(statement));
    return result;
}

// Owns nothing: the analyzer owns the fake; the raw pointer lets tests
// reconfigure and inspect it between analyze() calls.
struct AnalyzerFixture {
    fakes::FakeSqlParser* fake;
    core::SqlAnalyzer analyzer;

    AnalyzerFixture()
        : fake(nullptr),
          analyzer([this] {
              auto parser = std::make_unique<fakes::FakeSqlParser>();
              fake = parser.get();
              return parser;
          }()) {}
};

}  // namespace

TEST(SqlAnalyzer, NullParserRejected) {
    EXPECT_THROW(core::SqlAnalyzer(nullptr), std::invalid_argument);
}

TEST(SqlAnalyzer, SimpleSelectAnalyzedOk) {
    AnalyzerFixture f;
    ports::ParsedStatement stmt;
    stmt.type = core::StatementType::Select;
    stmt.tables = {{"", "customers"}};
    stmt.projection_columns = {"id", "email"};
    f.fake->result_to_return = single_statement(std::move(stmt));

    auto analysis = f.analyzer.analyze("SELECT id, email FROM customers");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::Ok);
    EXPECT_EQ(analysis.statement_type, core::StatementType::Select);
    EXPECT_EQ(analysis.statement_class, core::StatementClass::Select);
    EXPECT_EQ(analysis.statement_count, 1);
    EXPECT_EQ(analysis.tables, std::vector<std::string>({"customers"}));
    EXPECT_EQ(analysis.projection_columns, std::vector<std::string>({"id", "email"}));
    EXPECT_FALSE(analysis.has_wildcard_projection);
    EXPECT_FALSE(analysis.has_computed_projection);
}

TEST(SqlAnalyzer, WildcardFlagPropagated) {
    AnalyzerFixture f;
    ports::ParsedStatement stmt;
    stmt.type = core::StatementType::Select;
    stmt.has_wildcard_projection = true;
    f.fake->result_to_return = single_statement(std::move(stmt));

    auto analysis = f.analyzer.analyze("SELECT * FROM customers");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::Ok);
    EXPECT_TRUE(analysis.has_wildcard_projection);
}

TEST(SqlAnalyzer, ComputedFlagPropagated) {
    AnalyzerFixture f;
    ports::ParsedStatement stmt;
    stmt.type = core::StatementType::Select;
    stmt.has_computed_projection = true;
    f.fake->result_to_return = single_statement(std::move(stmt));

    auto analysis = f.analyzer.analyze("SELECT UPPER(email) FROM customers");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::Ok);
    EXPECT_TRUE(analysis.has_computed_projection);
    EXPECT_TRUE(analysis.projection_columns.empty());
}

TEST(SqlAnalyzer, MixedPlainAndComputedProjection) {
    AnalyzerFixture f;
    ports::ParsedStatement stmt;
    stmt.type = core::StatementType::Select;
    stmt.projection_columns = {"id"};  // UPPER(email) is absent by contract
    stmt.has_computed_projection = true;
    f.fake->result_to_return = single_statement(std::move(stmt));

    auto analysis = f.analyzer.analyze("SELECT id, UPPER(email) FROM customers");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::Ok);
    EXPECT_EQ(analysis.projection_columns, std::vector<std::string>({"id"}));
    EXPECT_TRUE(analysis.has_computed_projection);
}

TEST(SqlAnalyzer, WildcardPlusExplicitColumns) {
    AnalyzerFixture f;
    ports::ParsedStatement stmt;
    stmt.type = core::StatementType::Select;
    stmt.projection_columns = {"id"};
    stmt.has_wildcard_projection = true;
    f.fake->result_to_return = single_statement(std::move(stmt));

    auto analysis = f.analyzer.analyze("SELECT *, id FROM customers");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::Ok);
    EXPECT_EQ(analysis.projection_columns, std::vector<std::string>({"id"}));
    EXPECT_TRUE(analysis.has_wildcard_projection);
}

TEST(SqlAnalyzer, InsertWithColumnListIsDml) {
    AnalyzerFixture f;
    ports::ParsedStatement stmt;
    stmt.type = core::StatementType::Insert;
    stmt.tables = {{"", "customers"}};
    stmt.affected_columns = {"name", "email"};
    f.fake->result_to_return = single_statement(std::move(stmt));

    auto analysis = f.analyzer.analyze("INSERT INTO customers (name, email) VALUES (...)");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::Ok);
    EXPECT_EQ(analysis.statement_class, core::StatementClass::Dml);
    EXPECT_EQ(analysis.affected_columns, std::vector<std::string>({"name", "email"}));
}

TEST(SqlAnalyzer, UpdateIsDml) {
    AnalyzerFixture f;
    ports::ParsedStatement stmt;
    stmt.type = core::StatementType::Update;
    stmt.tables = {{"", "customers"}};
    stmt.affected_columns = {"phone"};
    f.fake->result_to_return = single_statement(std::move(stmt));

    auto analysis = f.analyzer.analyze("UPDATE customers SET phone = ...");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::Ok);
    EXPECT_EQ(analysis.statement_class, core::StatementClass::Dml);
    EXPECT_EQ(analysis.affected_columns, std::vector<std::string>({"phone"}));
}

TEST(SqlAnalyzer, DeleteWithoutColumnsIsDml) {
    AnalyzerFixture f;
    ports::ParsedStatement stmt;
    stmt.type = core::StatementType::Delete;
    stmt.tables = {{"", "orders"}};
    f.fake->result_to_return = single_statement(std::move(stmt));

    auto analysis = f.analyzer.analyze("DELETE FROM orders");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::Ok);
    EXPECT_EQ(analysis.statement_class, core::StatementClass::Dml);
    EXPECT_TRUE(analysis.affected_columns.empty());
}

TEST(SqlAnalyzer, CreateAlterDropAreDdl) {
    AnalyzerFixture f;
    const core::StatementType ddl_types[] = {
        core::StatementType::Create,
        core::StatementType::Alter,
        core::StatementType::Drop,
    };
    for (core::StatementType type : ddl_types) {
        ports::ParsedStatement stmt;
        stmt.type = type;
        stmt.tables = {{"", "customers"}};
        f.fake->result_to_return = single_statement(std::move(stmt));

        auto analysis = f.analyzer.analyze("DDL statement");

        EXPECT_EQ(analysis.status, core::AnalysisStatus::Ok) << to_string(type);
        EXPECT_EQ(analysis.statement_class, core::StatementClass::Ddl) << to_string(type);
    }
}

TEST(SqlAnalyzer, ParseFailurePropagatesSanitizedReason) {
    AnalyzerFixture f;
    f.fake->result_to_return.success = false;
    f.fake->result_to_return.error = "syntax error at position 12";

    auto analysis = f.analyzer.analyze("SELEC id FROM customers");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::ParseError);
    EXPECT_EQ(analysis.error_reason, "syntax error at position 12");
    EXPECT_EQ(analysis.statement_type, core::StatementType::Unknown);
    EXPECT_EQ(analysis.statement_class, core::StatementClass::Unknown);
    EXPECT_EQ(analysis.statement_count, 0);
}

TEST(SqlAnalyzer, ParseFailureWithEmptyErrorGetsGenericReason) {
    AnalyzerFixture f;
    f.fake->result_to_return.success = false;
    f.fake->result_to_return.error = "";

    auto analysis = f.analyzer.analyze("SELEC id FROM customers");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::ParseError);
    EXPECT_EQ(analysis.error_reason, "parser reported failure");
}

TEST(SqlAnalyzer, SuccessWithNoStatementsIsParseError) {
    AnalyzerFixture f;
    f.fake->result_to_return.success = true;  // contract violation by the parser

    auto analysis = f.analyzer.analyze(";");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::ParseError);
    EXPECT_FALSE(analysis.error_reason.empty());
}

TEST(SqlAnalyzer, MultiStatementDetected) {
    AnalyzerFixture f;
    ports::ParsedStatement first;
    first.type = core::StatementType::Select;
    ports::ParsedStatement second;
    second.type = core::StatementType::Delete;
    f.fake->result_to_return.success = true;
    f.fake->result_to_return.statements = {first, second};

    auto analysis = f.analyzer.analyze("SELECT 1; DELETE FROM orders");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::MultipleStatements);
    EXPECT_EQ(analysis.statement_count, 2);
}

TEST(SqlAnalyzer, EmptyAndWhitespaceInputSkipParser) {
    AnalyzerFixture f;

    auto empty = f.analyzer.analyze("");
    auto blank = f.analyzer.analyze("  \t\n ");

    EXPECT_EQ(empty.status, core::AnalysisStatus::EmptyInput);
    EXPECT_EQ(blank.status, core::AnalysisStatus::EmptyInput);
    EXPECT_EQ(empty.statement_count, 0);
    EXPECT_EQ(blank.statement_count, 0);
    EXPECT_EQ(f.fake->parse_call_count, 0);
}

TEST(SqlAnalyzer, TableSpellingPreservedAndSchemaQualified) {
    AnalyzerFixture f;
    ports::ParsedStatement stmt;
    stmt.type = core::StatementType::Select;
    stmt.tables = {{"Public", "Customers"}, {"", "orders"}};
    f.fake->result_to_return = single_statement(std::move(stmt));

    auto analysis = f.analyzer.analyze("SELECT ...");

    EXPECT_EQ(analysis.tables,
              std::vector<std::string>({"Public.Customers", "orders"}));
}

TEST(SqlAnalyzer, DuplicateTablesDedupedFirstSeenOrder) {
    AnalyzerFixture f;
    ports::ParsedStatement stmt;
    stmt.type = core::StatementType::Select;
    stmt.tables = {{"", "orders"}, {"", "customers"}, {"", "orders"}};
    f.fake->result_to_return = single_statement(std::move(stmt));

    auto analysis = f.analyzer.analyze("SELECT ...");

    EXPECT_EQ(analysis.tables, std::vector<std::string>({"orders", "customers"}));
}

TEST(SqlAnalyzer, UnknownTypeAnalyzedOkWithUnknownClass) {
    AnalyzerFixture f;
    ports::ParsedStatement stmt;
    stmt.type = core::StatementType::Unknown;
    f.fake->result_to_return = single_statement(std::move(stmt));

    auto analysis = f.analyzer.analyze("EXPLAIN SELECT 1");

    EXPECT_EQ(analysis.status, core::AnalysisStatus::Ok);
    EXPECT_EQ(analysis.statement_class, core::StatementClass::Unknown);
}

TEST(SqlAnalyzer, UnsupportedFeaturesPropagated) {
    AnalyzerFixture f;
    ports::ParsedStatement stmt;
    stmt.type = core::StatementType::Select;
    stmt.unsupported_features = {"JOIN", "subquery"};
    f.fake->result_to_return = single_statement(std::move(stmt));

    auto analysis = f.analyzer.analyze("SELECT ...");

    EXPECT_EQ(analysis.unsupported_features,
              std::vector<std::string>({"JOIN", "subquery"}));
}

TEST(SqlAnalysisHelpers, StatementClassOfCoversAllTypes) {
    using core::StatementClass;
    using core::StatementType;
    using core::statement_class_of;

    EXPECT_EQ(statement_class_of(StatementType::Select), StatementClass::Select);
    EXPECT_EQ(statement_class_of(StatementType::Insert), StatementClass::Dml);
    EXPECT_EQ(statement_class_of(StatementType::Update), StatementClass::Dml);
    EXPECT_EQ(statement_class_of(StatementType::Delete), StatementClass::Dml);
    EXPECT_EQ(statement_class_of(StatementType::Create), StatementClass::Ddl);
    EXPECT_EQ(statement_class_of(StatementType::Alter), StatementClass::Ddl);
    EXPECT_EQ(statement_class_of(StatementType::Drop), StatementClass::Ddl);
    EXPECT_EQ(statement_class_of(StatementType::Unknown), StatementClass::Unknown);
}

TEST(SqlAnalysisHelpers, StatementTypeToStringCoversAllValues) {
    using core::StatementType;
    using core::to_string;

    EXPECT_STREQ(to_string(StatementType::Select), "SELECT");
    EXPECT_STREQ(to_string(StatementType::Insert), "INSERT");
    EXPECT_STREQ(to_string(StatementType::Update), "UPDATE");
    EXPECT_STREQ(to_string(StatementType::Delete), "DELETE");
    EXPECT_STREQ(to_string(StatementType::Create), "CREATE");
    EXPECT_STREQ(to_string(StatementType::Alter), "ALTER");
    EXPECT_STREQ(to_string(StatementType::Drop), "DROP");
    EXPECT_STREQ(to_string(StatementType::Unknown), "UNKNOWN");
}

TEST(SqlAnalysisHelpers, StatementClassToStringCoversAllValues) {
    using core::StatementClass;
    using core::to_string;

    EXPECT_STREQ(to_string(StatementClass::Select), "SELECT");
    EXPECT_STREQ(to_string(StatementClass::Dml), "DML");
    EXPECT_STREQ(to_string(StatementClass::Ddl), "DDL");
    EXPECT_STREQ(to_string(StatementClass::Unknown), "UNKNOWN");
}
