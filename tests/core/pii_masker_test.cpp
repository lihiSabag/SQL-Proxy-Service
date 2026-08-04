// PiiMasker unit tests. The masker never re-classifies: every test hands
// it an explicit ClassificationResult and checks the transformed (or refused)
// outcome. A failure outcome cannot carry a result BY TYPE (MaskingOutcome
// wrapper), so "no partial output after failure" is a structural property —
// asserted here via masked() and the throwing wrong-state accessors.

#include <optional>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "core/data_classification.h"
#include "core/pii_masker.h"
#include "ports/query_executor.h"

namespace {

const core::PiiMasker masker;

using Cell = std::optional<std::string>;
using Row = std::vector<Cell>;

ports::ExecutionResult make_result(std::vector<std::string> column_names,
                                   std::vector<Row> rows) {
    ports::ExecutionResult r;
    r.status = ports::ExecutionStatus::Ok;
    for (std::string& name : column_names) {
        ports::ColumnInfo c;
        c.name = std::move(name);
        r.columns.push_back(std::move(c));
    }
    r.rows = std::move(rows);
    r.row_count = static_cast<long long>(r.rows.size());
    r.has_result_set = !r.columns.empty();
    return r;
}

core::ColumnClassification pii(core::PiiCategory category) {
    core::ColumnClassification c;
    c.data_class = core::ColumnDataClass::Pii;
    c.pii_category = category;
    return c;
}

core::ColumnClassification not_pii() {
    core::ColumnClassification c;
    c.data_class = core::ColumnDataClass::NotClassifiedAsPii;
    return c;
}

core::ColumnClassification unattributed() {
    return core::ColumnClassification{};  // fail-closed default
}

core::ClassificationResult classification(
    std::vector<core::ColumnClassification> columns) {
    core::ClassificationResult r;
    r.fully_attributed = true;
    for (const auto& c : columns) {
        if (c.data_class == core::ColumnDataClass::Unattributed) {
            r.fully_attributed = false;
        }
    }
    r.columns = std::move(columns);
    return r;
}

// Masks a single cell through the full component (1 column, 1 row).
Cell mask_single(core::PiiCategory category, Cell value) {
    const auto outcome = masker.mask(make_result({"col"}, {{std::move(value)}}),
                                     classification({pii(category)}));
    EXPECT_TRUE(outcome.masked());
    return outcome.result().rows[0][0];
}

core::MaskingFailureReason expect_failure(ports::ExecutionResult result,
                                          core::ClassificationResult c) {
    const auto outcome = masker.mask(std::move(result), std::move(c));
    // A failure outcome cannot carry an ExecutionResult — no raw or
    // partially masked data is reachable from it; result() cannot silently
    // succeed.
    EXPECT_FALSE(outcome.masked());
    EXPECT_THROW(outcome.result(), std::bad_variant_access);
    return outcome.failure_reason();
}

// --- Category rules ----------------------------------------------------------

TEST(PiiMaskerTest, EmailMaskingShapes) {
    const std::pair<const char*, const char*> cases[] = {
        {"lihi.roas@example.com", "l***@example.com"},
        {"a@example.com", "a***@example.com"},        // one-char local part
        {"KIM.PEREZ@EXAMPLE.ORG", "K***@EXAMPLE.ORG"},  // case preserved
        {"lihi.roas@@example.com", "***"},            // multiple '@'
        {"not-an-email", "***"},                      // no '@'
        {"@example.com", "***"},                      // empty local part
        {"lihi.roas@", "***"},                        // empty domain
        {"\xC3\xB1ice@example.com", "***@example.com"},  // non-ASCII first
    };
    for (const auto& [input, expected] : cases) {
        SCOPED_TRACE(input);
        EXPECT_EQ(mask_single(core::PiiCategory::Email, input), Cell{expected});
    }
}

TEST(PiiMaskerTest, PhoneMaskingShapes) {
    const std::pair<const char*, const char*> cases[] = {
        {"+972501234567", "***4567"},
        {"050-123-4567", "***4567"},
        {"(050) 123 4567", "***4567"},
        {"12345", "***"},      // short: below 7 digits
        {"no-digits", "***"},  // malformed
    };
    for (const auto& [input, expected] : cases) {
        SCOPED_TRACE(input);
        EXPECT_EQ(mask_single(core::PiiCategory::Phone, input), Cell{expected});
    }
}

TEST(PiiMaskerTest, CreditCardMaskingShapes) {
    const std::pair<const char*, const char*> cases[] = {
        {"4111111111111111", "****1111"},
        {"378282246310009", "****0009"},  // 15-digit: uniform masked shape
        {"4111 1111 1111 1111", "****1111"},
        {"4111-1111-1111-1111", "****1111"},
        {"1234", "***"},              // short
        {"41x1111111111111", "***"},  // non-digit character
    };
    for (const auto& [input, expected] : cases) {
        SCOPED_TRACE(input);
        EXPECT_EQ(mask_single(core::PiiCategory::CreditCard, input),
                  Cell{expected});
    }
}

// --- NULL / empty / never-unchanged ------------------------------------------

TEST(PiiMaskerTest, NullStaysNullAcrossAllCategories) {
    for (core::PiiCategory category :
         {core::PiiCategory::Email, core::PiiCategory::Phone,
          core::PiiCategory::CreditCard}) {
        EXPECT_EQ(mask_single(category, std::nullopt), Cell{std::nullopt});
    }
}

TEST(PiiMaskerTest, EmptyStringStaysEmptyAcrossAllCategories) {
    for (core::PiiCategory category :
         {core::PiiCategory::Email, core::PiiCategory::Phone,
          core::PiiCategory::CreditCard}) {
        EXPECT_EQ(mask_single(category, Cell{""}), Cell{""});
    }
}

TEST(PiiMaskerTest, NonEmptyClassifiedValuesAreNeverReturnedUnchanged) {
    // Malformed shapes across all categories: output must always differ.
    const std::pair<core::PiiCategory, const char*> cases[] = {
        {core::PiiCategory::Email, "x"},
        {core::PiiCategory::Email, "@"},
        {core::PiiCategory::Phone, "1"},
        {core::PiiCategory::Phone, "call me"},
        {core::PiiCategory::CreditCard, "0"},
        {core::PiiCategory::CreditCard, "gift-card"},
    };
    for (const auto& [category, input] : cases) {
        SCOPED_TRACE(input);
        const Cell out = mask_single(category, input);
        ASSERT_TRUE(out.has_value());
        EXPECT_NE(*out, input);
    }
}

// --- Shape handling ----------------------------------------------------------

TEST(PiiMaskerTest, MultipleRowsAndPiiColumnsAllMasked) {
    auto outcome = masker.mask(
        make_result({"id", "email", "phone", "credit_card"},
                    {{Cell{"1"}, Cell{"lihi.roas@example.com"},
                      Cell{"0501230101"}, Cell{"4111111111111111"}},
                     {Cell{"2"}, Cell{"kim.perez@example.org"}, Cell{std::nullopt},
                      Cell{"378282246310009"}}}),
        classification({not_pii(), pii(core::PiiCategory::Email),
                        pii(core::PiiCategory::Phone),
                        pii(core::PiiCategory::CreditCard)}));
    ASSERT_TRUE(outcome.masked());
    const auto& r = outcome.result();
    EXPECT_EQ(r.rows[0][0], Cell{"1"});  // NotClassifiedAsPii preserved
    EXPECT_EQ(r.rows[0][1], Cell{"l***@example.com"});
    EXPECT_EQ(r.rows[0][2], Cell{"***0101"});
    EXPECT_EQ(r.rows[0][3], Cell{"****1111"});
    EXPECT_EQ(r.rows[1][1], Cell{"k***@example.org"});
    EXPECT_EQ(r.rows[1][2], Cell{std::nullopt});  // NULL survives masking
    EXPECT_EQ(r.rows[1][3], Cell{"****0009"});
    // Column metadata untouched.
    ASSERT_EQ(r.columns.size(), 4u);
    EXPECT_EQ(r.columns[1].name, "email");
}

TEST(PiiMaskerTest, NotClassifiedColumnsPreservedExactly) {
    // Including a value that LOOKS like PII: classification already decided,
    // and the masker must not second-guess it from the value.
    auto outcome = masker.mask(
        make_result({"note"}, {{Cell{"reach me at lihi.roas@example.com"}}}),
        classification({not_pii()}));
    ASSERT_TRUE(outcome.masked());
    EXPECT_EQ(outcome.result().rows[0][0],
              Cell{"reach me at lihi.roas@example.com"});
}

TEST(PiiMaskerTest, DuplicateColumnNamesStayIndexSafe) {
    // Two columns both named "email", DIFFERENTLY classified: index-based
    // processing masks exactly the classified one.
    auto outcome = masker.mask(
        make_result({"email", "email"},
                    {{Cell{"lihi.roas@example.com"}, Cell{"kim.perez@example.org"}}}),
        classification({pii(core::PiiCategory::Email), not_pii()}));
    ASSERT_TRUE(outcome.masked());
    const auto& r = outcome.result();
    EXPECT_EQ(r.rows[0][0], Cell{"l***@example.com"});
    EXPECT_EQ(r.rows[0][1], Cell{"kim.perez@example.org"});
}

TEST(PiiMaskerTest, EmptyShapesSucceed) {
    // No columns, no classifications, no rows.
    auto empty = masker.mask(make_result({}, {}), classification({}));
    ASSERT_TRUE(empty.masked());
    EXPECT_TRUE(empty.result().rows.empty());

    // Columns with zero rows: metadata preserved.
    auto no_rows = masker.mask(make_result({"email"}, {}),
                               classification({pii(core::PiiCategory::Email)}));
    ASSERT_TRUE(no_rows.masked());
    const auto& r = no_rows.result();
    ASSERT_EQ(r.columns.size(), 1u);
    EXPECT_EQ(r.columns[0].name, "email");
    EXPECT_TRUE(r.rows.empty());
}

// --- Fail-closed outcomes ----------------------------------------------------

TEST(PiiMaskerTest, ClassificationColumnCountMismatchFails) {
    EXPECT_EQ(expect_failure(
                  make_result({"a", "b"}, {{Cell{"1"}, Cell{"2"}}}),
                  classification({not_pii()})),
              core::MaskingFailureReason::StructuralMismatch);
}

TEST(PiiMaskerTest, RowWidthMismatchFails) {
    // The bad row is the SECOND one — validation must cover all rows before
    // any transformation touches the first.
    auto result = make_result({"email"}, {{Cell{"lihi.roas@example.com"}}});
    result.rows.push_back({Cell{"x"}, Cell{"y"}});  // width 2 != 1
    EXPECT_EQ(expect_failure(std::move(result),
                             classification({pii(core::PiiCategory::Email)})),
              core::MaskingFailureReason::StructuralMismatch);
}

TEST(PiiMaskerTest, InvalidClassificationInvariantFailsBothDirections) {
    // Pii without a category.
    core::ColumnClassification pii_no_category;
    pii_no_category.data_class = core::ColumnDataClass::Pii;
    EXPECT_EQ(expect_failure(make_result({"a"}, {{Cell{"v"}}}),
                             classification({pii_no_category})),
              core::MaskingFailureReason::InvalidClassification);

    // Non-Pii with a category.
    core::ColumnClassification not_pii_with_category = not_pii();
    not_pii_with_category.pii_category = core::PiiCategory::Email;
    EXPECT_EQ(expect_failure(make_result({"a"}, {{Cell{"v"}}}),
                             classification({not_pii_with_category})),
              core::MaskingFailureReason::InvalidClassification);
}

TEST(PiiMaskerTest, FullyAttributedInconsistencyFailsBothDirections) {
    // Claims fully attributed while a column is Unattributed.
    core::ClassificationResult lying_true;
    lying_true.columns = {unattributed()};
    lying_true.fully_attributed = true;
    EXPECT_EQ(expect_failure(make_result({"a"}, {{Cell{"v"}}}),
                             std::move(lying_true)),
              core::MaskingFailureReason::InvalidClassification);

    // Claims NOT fully attributed while every column is accounted for.
    core::ClassificationResult lying_false;
    lying_false.columns = {not_pii()};
    lying_false.fully_attributed = false;
    EXPECT_EQ(expect_failure(make_result({"a"}, {{Cell{"v"}}}),
                             std::move(lying_false)),
              core::MaskingFailureReason::InvalidClassification);
}

TEST(PiiMaskerTest, UnattributedColumnFailsClosedWithoutResult) {
    // A consistent classification containing an Unattributed column (the
    // computed-projection shapes): refused outright — not passed
    // through, not generically redacted, never inspected for a category.
    EXPECT_EQ(expect_failure(
                  make_result({"upper", "email"},
                              {{Cell{"LIHI.ROAS@EXAMPLE.COM"},
                                Cell{"lihi.roas@example.com"}}}),
                  classification({unattributed(),
                                  pii(core::PiiCategory::Email)})),
              core::MaskingFailureReason::UnattributedColumn);
}

// --- MaskingOutcome contract --------------------------------------------------

TEST(MaskingOutcomeTest, IsNotDefaultConstructible) {
    // A bare std::variant alias would default-construct to a default
    // ExecutionResult and masquerade as a success PiiMasker never produced.
    static_assert(!std::is_default_constructible_v<core::MaskingOutcome>,
                  "MaskingOutcome must not be default-constructible");
}

TEST(MaskingOutcomeTest, ExplicitSuccessContainsResult) {
    const auto outcome =
        core::MaskingOutcome::success(make_result({"col"}, {{Cell{"v"}}}));
    ASSERT_TRUE(outcome.masked());
    ASSERT_EQ(outcome.result().columns.size(), 1u);
    EXPECT_EQ(outcome.result().rows[0][0], Cell{"v"});
    // A success has no failure reason to give.
    EXPECT_THROW(outcome.failure_reason(), std::bad_variant_access);
}

TEST(MaskingOutcomeTest, ExplicitFailureContainsOnlyReason) {
    const auto outcome = core::MaskingOutcome::failure(
        core::MaskingFailureReason::StructuralMismatch);
    EXPECT_FALSE(outcome.masked());
    EXPECT_EQ(outcome.failure_reason(),
              core::MaskingFailureReason::StructuralMismatch);
}

TEST(MaskingOutcomeTest, ResultAccessCannotSilentlySucceedForFailure) {
    const auto outcome = core::MaskingOutcome::failure(
        core::MaskingFailureReason::UnattributedColumn);
    EXPECT_THROW(outcome.result(), std::bad_variant_access);
}

}  // namespace
