// DataClassifier unit tests. Classification is metadata- and mapping-based:
// the classifier never sees result rows or cell values, so every test here
// constructs only an analysis and a column list.

#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "core/data_classification.h"
#include "core/data_classifier.h"
#include "core/sql_analysis.h"
#include "ports/query_executor.h"

namespace {

core::SqlAnalysis select_with_projection(std::vector<std::string> projection) {
    core::SqlAnalysis a;
    a.status = core::AnalysisStatus::Ok;
    a.statement_type = core::StatementType::Select;
    a.statement_class = core::StatementClass::Select;
    a.statement_count = 1;
    a.tables = {"customers"};
    a.projection_columns = std::move(projection);
    return a;
}

core::SqlAnalysis wildcard_select() {
    core::SqlAnalysis a = select_with_projection({});
    a.has_wildcard_projection = true;
    return a;
}

std::vector<ports::ColumnInfo> columns(std::vector<std::string> names) {
    std::vector<ports::ColumnInfo> out;
    for (std::string& name : names) {
        ports::ColumnInfo c;
        c.name = std::move(name);
        out.push_back(std::move(c));
    }
    return out;
}

// Central invariant checks, applied to every result in this file:
//   - data_class == Pii  <=>  pii_category.has_value()
//   - fully_attributed   <=>  no column is Unattributed
void expect_invariants(const core::ClassificationResult& r) {
    bool any_unattributed = false;
    for (const core::ColumnClassification& c : r.columns) {
        EXPECT_EQ(c.data_class == core::ColumnDataClass::Pii,
                  c.pii_category.has_value());
        any_unattributed |= c.data_class == core::ColumnDataClass::Unattributed;
    }
    EXPECT_EQ(r.fully_attributed, !any_unattributed);
}

void expect_pii(const core::ClassificationResult& r, std::size_t i,
                core::PiiCategory category) {
    ASSERT_LT(i, r.columns.size());
    EXPECT_EQ(r.columns[i].data_class, core::ColumnDataClass::Pii);
    ASSERT_TRUE(r.columns[i].pii_category.has_value());
    EXPECT_EQ(*r.columns[i].pii_category, category);
}

void expect_not_pii(const core::ClassificationResult& r, std::size_t i) {
    ASSERT_LT(i, r.columns.size());
    EXPECT_EQ(r.columns[i].data_class,
              core::ColumnDataClass::NotClassifiedAsPii);
}

const core::DataClassifier classifier;  // default mappings

// --- Positional attribution --------------------------------------------------

TEST(DataClassifierTest, DefaultMappingsClassifyRequiredCategories) {
    const auto r = classifier.classify(
        select_with_projection({"id", "name", "email", "phone", "credit_card"}),
        columns({"id", "name", "email", "phone", "credit_card"}));
    ASSERT_EQ(r.columns.size(), 5u);
    expect_not_pii(r, 0);
    expect_not_pii(r, 1);
    expect_pii(r, 2, core::PiiCategory::Email);
    expect_pii(r, 3, core::PiiCategory::Phone);
    expect_pii(r, 4, core::PiiCategory::CreditCard);
    EXPECT_TRUE(r.fully_attributed);
    expect_invariants(r);

    // The canonical category tags (the closed classification vocabulary).
    EXPECT_STREQ(core::to_string(core::PiiCategory::Email), "PII.Email");
    EXPECT_STREQ(core::to_string(core::PiiCategory::Phone), "PII.Phone");
    EXPECT_STREQ(core::to_string(core::PiiCategory::CreditCard),
                 "PII.CreditCard");
}

TEST(DataClassifierTest, AliasedProjectionAttributesBySourceColumn) {
    // SELECT email AS contact — the result column is named "contact", but the
    // analysis kept the true source "email"; the alias cannot evade the tag.
    const auto r = classifier.classify(select_with_projection({"email"}),
                                       columns({"contact"}));
    ASSERT_EQ(r.columns.size(), 1u);
    expect_pii(r, 0, core::PiiCategory::Email);
    expect_invariants(r);
}

TEST(DataClassifierTest, QualifiedProjectionEntriesAreStripped) {
    // SELECT customers.email, c.phone ... — qualifier (real name or alias)
    // is stripped before the mapping lookup.
    const auto r =
        classifier.classify(select_with_projection({"customers.email", "c.phone"}),
                            columns({"email", "phone"}));
    ASSERT_EQ(r.columns.size(), 2u);
    expect_pii(r, 0, core::PiiCategory::Email);
    expect_pii(r, 1, core::PiiCategory::Phone);
    expect_invariants(r);
}

TEST(DataClassifierTest, MappingLookupIsCaseInsensitive) {
    // SELECT EMAIL ... — parser preserves spelling; Postgres folds it; the
    // mapping must match anyway.
    const auto r = classifier.classify(select_with_projection({"EMAIL"}),
                                       columns({"email"}));
    expect_pii(r, 0, core::PiiCategory::Email);
    expect_invariants(r);
}

// --- Pure wildcard attribution ----------------------------------------------

TEST(DataClassifierTest, PureWildcardClassifiesByResultColumnNames) {
    // SELECT * — the database returns true source column names.
    const auto r = classifier.classify(
        wildcard_select(),
        columns({"id", "name", "email", "phone", "credit_card"}));
    ASSERT_EQ(r.columns.size(), 5u);
    expect_not_pii(r, 0);
    expect_not_pii(r, 1);
    expect_pii(r, 2, core::PiiCategory::Email);
    expect_pii(r, 3, core::PiiCategory::Phone);
    expect_pii(r, 4, core::PiiCategory::CreditCard);
    expect_invariants(r);
}

TEST(DataClassifierTest, DuplicateResultColumnNamesStayIndexSafe) {
    // SELECT * over a join where both sides expose "email": classifications
    // are stored by index, so every occurrence is tagged — no name-keyed map
    // that could collapse duplicates.
    const auto r = classifier.classify(wildcard_select(),
                                       columns({"email", "email", "id"}));
    ASSERT_EQ(r.columns.size(), 3u);
    expect_pii(r, 0, core::PiiCategory::Email);
    expect_pii(r, 1, core::PiiCategory::Email);
    expect_not_pii(r, 2);
    expect_invariants(r);
}

// --- Configuration -----------------------------------------------------------

TEST(DataClassifierTest, CustomMappingClassifiesDifferentlyNamedColumn) {
    // Extensibility demo: a differently named column classified through a
    // custom config, which also exercises case-insensitive normalization.
    core::ClassificationConfig config;
    config.column_mappings = {{"Customer_Mail", core::PiiCategory::Email}};
    const core::DataClassifier custom(config);

    const auto r = custom.classify(select_with_projection({"customer_mail"}),
                                   columns({"customer_mail"}));
    expect_pii(r, 0, core::PiiCategory::Email);

    // And the default mappings are absent in a custom config.
    const auto r2 =
        custom.classify(select_with_projection({"email"}), columns({"email"}));
    expect_not_pii(r2, 0);
    expect_invariants(r);
    expect_invariants(r2);
}

TEST(DataClassifierTest, DuplicateNormalizedMappingIsRejectedAtConstruction) {
    // "email" and "EMAIL" collide after normalization; the config is refused
    // outright — never resolved silently in favor of either entry.
    core::ClassificationConfig config;
    config.column_mappings = {{"email", core::PiiCategory::Email},
                              {"EMAIL", core::PiiCategory::Phone}};
    EXPECT_THROW(core::DataClassifier{config}, std::invalid_argument);
}

// --- Fail-closed shapes ------------------------------------------------------

TEST(DataClassifierTest, ProjectionResultCountMismatchIsAllUnattributed) {
    // One projection entry, two result columns: no prefix classification, no
    // index shifting or guessing — everything Unattributed.
    const auto r = classifier.classify(select_with_projection({"email"}),
                                       columns({"email", "phone"}));
    ASSERT_EQ(r.columns.size(), 2u);
    EXPECT_EQ(r.columns[0].data_class, core::ColumnDataClass::Unattributed);
    EXPECT_EQ(r.columns[1].data_class, core::ColumnDataClass::Unattributed);
    EXPECT_FALSE(r.fully_attributed);
    expect_invariants(r);
}

TEST(DataClassifierTest, UnsupportedShapesAreUnattributed) {
    // Computed projection over a table (source column lost at parse time).
    core::SqlAnalysis computed = select_with_projection({});
    computed.has_computed_projection = true;

    // Mixed star+explicit (policy rejects it upstream; this is defensive).
    core::SqlAnalysis mixed = select_with_projection({"credit_card"});
    mixed.has_wildcard_projection = true;

    // Not an analyzable SELECT at all.
    core::SqlAnalysis not_ok;  // defaults: ParseError / Unknown

    for (const core::SqlAnalysis* a : {&computed, &mixed, &not_ok}) {
        const auto r = classifier.classify(*a, columns({"a", "email"}));
        ASSERT_EQ(r.columns.size(), 2u);
        EXPECT_EQ(r.columns[0].data_class, core::ColumnDataClass::Unattributed);
        EXPECT_EQ(r.columns[1].data_class, core::ColumnDataClass::Unattributed);
        EXPECT_FALSE(r.fully_attributed);
        expect_invariants(r);
    }
}

TEST(DataClassifierTest, EmptyResultColumnListIsEmptyAndFullyAttributed) {
    // No columns -> nothing to attribute -> vacuously fully attributed.
    const auto r = classifier.classify(select_with_projection({"email"}),
                                       columns({}));
    EXPECT_TRUE(r.columns.empty());
    EXPECT_TRUE(r.fully_attributed);
    expect_invariants(r);
}

}  // namespace
