// PolicyEngine unit tests. Analyses are constructed directly as structs —
// no parser, no database. RN comments reference the rule order
// (R1–R11, first match wins).

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "core/policy_decision.h"
#include "core/policy_engine.h"
#include "core/sql_analysis.h"
#include "core/sql_analyzer.h"
#include "fake_sql_parser.h"

namespace {

const core::PolicyEngine engine;

core::SqlAnalysis ok_statement(core::StatementType type) {
    core::SqlAnalysis a;
    a.status = core::AnalysisStatus::Ok;
    a.statement_type = type;
    a.statement_class = core::statement_class_of(type);
    a.statement_count = 1;
    return a;
}

core::SqlAnalysis select_on(std::vector<std::string> tables) {
    core::SqlAnalysis a = ok_statement(core::StatementType::Select);
    a.tables = std::move(tables);
    return a;
}

void expect_rejected(const core::SqlAnalysis& a, core::RejectReason expected) {
    const core::PolicyDecision d = engine.evaluate(a);
    EXPECT_FALSE(d.allowed);
    EXPECT_EQ(d.reason, expected);
}

// Also asserts the invariant: allowed implies reason None.
void expect_allowed(const core::SqlAnalysis& a) {
    const core::PolicyDecision d = engine.evaluate(a);
    EXPECT_TRUE(d.allowed);
    EXPECT_EQ(d.reason, core::RejectReason::None);
}

// --- Fail-closed invariants -------------------------------------------------

TEST(PolicyDecisionTest, DefaultConstructedIsFailClosed) {
    const core::PolicyDecision d;
    EXPECT_FALSE(d.allowed);
    EXPECT_EQ(d.reason, core::RejectReason::NotEvaluated);
}

TEST(PolicyEngineTest, DefaultConstructedAnalysisIsRejected) {
    // A default SqlAnalysis reads as ParseError (fail-closed defaults).
    expect_rejected(core::SqlAnalysis{}, core::RejectReason::UnparseableSql);
}

// --- One rule, one externally observable rejection --------------------------

TEST(PolicyEngineTest, EmptyInputIsRejected) {  // R1
    core::SqlAnalysis a;
    a.status = core::AnalysisStatus::EmptyInput;
    expect_rejected(a, core::RejectReason::EmptyInput);
}

TEST(PolicyEngineTest, MultipleStatementsAreRejected) {  // R3 + defensive R4
    core::SqlAnalysis reported;  // analyzer-reported multi-statement input
    reported.status = core::AnalysisStatus::MultipleStatements;
    reported.statement_count = 2;
    expect_rejected(reported, core::RejectReason::MultipleStatements);

    // Defensive: Ok must mean exactly one statement (executor precondition).
    for (int count : {0, 2}) {
        SCOPED_TRACE(count);
        core::SqlAnalysis a = ok_statement(core::StatementType::Select);
        a.statement_count = count;
        expect_rejected(a, core::RejectReason::MultipleStatements);
    }
}

TEST(PolicyEngineTest, UnknownStatementTypeIsRejected) {  // R5
    // COPY / SHOW / BEGIN / PREPARE all arrive as Unknown from the parser.
    expect_rejected(ok_statement(core::StatementType::Unknown),
                    core::RejectReason::UnsupportedStatementType);
}

TEST(PolicyEngineTest, DdlIsRejected) {  // R6 — includes the CTAS shape
    for (core::StatementType type :
         {core::StatementType::Create, core::StatementType::Alter,
          core::StatementType::Drop}) {
        SCOPED_TRACE(core::to_string(type));
        core::SqlAnalysis a = ok_statement(type);
        a.tables = {"customers"};
        expect_rejected(a, core::RejectReason::DdlNotAllowed);
    }
}

TEST(PolicyEngineTest, DmlIsRejected) {  // R7
    // Delete also covers the TRUNCATE shape: TRUNCATE parses as a plain
    // Delete — the read-only gate is what keeps it out.
    for (core::StatementType type :
         {core::StatementType::Insert, core::StatementType::Update,
          core::StatementType::Delete}) {
        SCOPED_TRACE(core::to_string(type));
        core::SqlAnalysis a = ok_statement(type);
        a.tables = {"customers"};
        expect_rejected(a, core::RejectReason::DmlNotAllowed);
    }
}

TEST(PolicyEngineTest, UnsupportedFeaturesAreRejected) {  // R8
    for (const char* feature :
         {"WITH/CTE", "set operation", "subquery in FROM"}) {
        SCOPED_TRACE(feature);
        core::SqlAnalysis a = select_on({"customers"});
        a.unsupported_features = {feature};
        expect_rejected(a, core::RejectReason::UnsupportedSqlFeature);
    }
}

// --- System-catalog rule (R9) ------------------------------------------------

TEST(PolicyEngineTest, SystemCatalogTablesAreRejected) {
    // Case-insensitive: Postgres folds unquoted identifiers down, the parser
    // preserves spelling, so PG_AUTHID must match. Includes a mixed join.
    for (const char* table :
         {"pg_catalog.pg_authid", "pg_authid", "PG_AUTHID", "Pg_Authid",
          "pg_stat_activity", "information_schema.tables",
          "INFORMATION_SCHEMA.TABLES"}) {
        SCOPED_TRACE(table);
        expect_rejected(select_on({table}),
                        core::RejectReason::SystemTableAccess);
    }
    expect_rejected(select_on({"customers", "pg_stat_activity"}),
                    core::RejectReason::SystemTableAccess);
}

TEST(PolicyEngineTest, NearMissTableNamesStayAllowed) {
    for (const char* table :
         {"pgcustomers", "mypg_table", "public.customers"}) {
        SCOPED_TRACE(table);
        expect_allowed(select_on({table}));
    }
}

// --- Allow path --------------------------------------------------------------

TEST(PolicyEngineTest, AllowedSelectShapes) {  // R11
    core::SqlAnalysis plain = select_on({"customers"});
    plain.projection_columns = {"id", "email"};
    expect_allowed(plain);

    core::SqlAnalysis wildcard = select_on({"customers"});
    wildcard.has_wildcard_projection = true;
    expect_allowed(wildcard);

    core::SqlAnalysis tableless = select_on({});  // SELECT 1
    tableless.has_computed_projection = true;
    expect_allowed(tableless);
}

TEST(PolicyEngineTest, MixedWildcardProjectionIsRejected) {  // R10
    // SELECT *, credit_card AS x FROM customers — defeats both classification
    // attribution modes (star breaks positions, alias breaks names), so the
    // aliased column would reach the caller unclassified.
    core::SqlAnalysis a = select_on({"customers"});
    a.has_wildcard_projection = true;
    a.projection_columns = {"credit_card"};
    expect_rejected(a, core::RejectReason::UnattributableProjection);
}

// Pins CURRENT behavior: general computed projections over tables
// (UPPER(email), CONCAT(name, email), COUNT(*)) remain ALLOWED by policy.
// The classifier marks them Unattributed rather than guessing a source
// column. Whether policy should reject them outright is an open question; if
// that rejection is adopted later, this test must change with it.
TEST(PolicyEngineTest, ComputedProjectionIsCurrentlyAllowed) {
    core::SqlAnalysis computed = select_on({"customers"});
    computed.has_computed_projection = true;
    expect_allowed(computed);

    core::SqlAnalysis mixed = select_on({"customers"});
    mixed.projection_columns = {"id"};
    mixed.has_computed_projection = true;
    expect_allowed(mixed);
}

// --- Precedence (two meaningful pairs) ---------------------------------------

TEST(PolicyEngineTest, DdlBeatsUnsupportedFeature) {  // R6 > R8
    // The coarser posture reason is the stabler audit signal.
    core::SqlAnalysis a = ok_statement(core::StatementType::Create);
    a.unsupported_features = {"non-table CREATE"};
    expect_rejected(a, core::RejectReason::DdlNotAllowed);
}

TEST(PolicyEngineTest, UnsupportedFeatureBeatsSystemTable) {  // R8 > R9
    // An incomplete table list must never reach the catalog scan.
    core::SqlAnalysis a = select_on({"pg_catalog.pg_authid"});
    a.unsupported_features = {"WITH/CTE"};
    expect_rejected(a, core::RejectReason::UnsupportedSqlFeature);
}

// --- Composition: analyzer + engine uphold the executor precondition ---------

TEST(PolicyEngineTest, AnalyzerAndEngineUpholdSingleStatementPrecondition) {
    auto parser = std::make_unique<fakes::FakeSqlParser>();
    fakes::FakeSqlParser* fake = parser.get();
    const core::SqlAnalyzer analyzer(std::move(parser));

    // Two parsed statements -> analyzer reports MultipleStatements ->
    // policy rejects: nothing multi-statement can reach IQueryExecutor.
    ports::ParseResult multi;
    multi.success = true;
    multi.statements.resize(2);
    multi.statements[0].type = core::StatementType::Select;
    multi.statements[1].type = core::StatementType::Drop;
    fake->result_to_return = multi;
    expect_rejected(analyzer.analyze("SELECT 1; DROP TABLE customers"),
                    core::RejectReason::MultipleStatements);

    // Exactly one supported SELECT -> allowed.
    ports::ParseResult single;
    single.success = true;
    single.statements.resize(1);
    single.statements[0].type = core::StatementType::Select;
    single.statements[0].tables = {{"", "customers"}};
    fake->result_to_return = single;
    expect_allowed(analyzer.analyze("SELECT id FROM customers"));
}

}  // namespace
