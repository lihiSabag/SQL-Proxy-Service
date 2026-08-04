#pragma once

#include <optional>
#include <vector>

namespace core {

// The supported classification categories. to_string returns the canonical
// tags ("PII.Email", ...) — a closed vocabulary, so a classification can
// never echo data or identifiers.
enum class PiiCategory {
    Email,
    Phone,
    CreditCard,
};

const char* to_string(PiiCategory category);

// Three states, deliberately not two: NotClassifiedAsPii means "examined and
// not sensitive"; Unattributed means "could not determine what this column
// carries". Collapsing them is exactly the bug that would let unattributable
// data flow downstream unmasked.
enum class ColumnDataClass {
    NotClassifiedAsPii,
    Pii,
    Unattributed,
};

// Invariant (enforced by DataClassifier, asserted by tests):
//   data_class == ColumnDataClass::Pii  <=>  pii_category.has_value()
struct ColumnClassification {
    ColumnDataClass data_class = ColumnDataClass::Unattributed;  // fail-closed
    std::optional<PiiCategory> pii_category;
};

// Exactly one entry per result column, in exact result-column order.
// fully_attributed is false iff any column is Unattributed.
struct ClassificationResult {
    std::vector<ColumnClassification> columns;
    bool fully_attributed = false;  // fail-closed default
};

}  // namespace core
