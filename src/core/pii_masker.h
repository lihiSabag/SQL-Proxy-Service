#pragma once

#include <variant>

#include "core/data_classification.h"
#include "ports/query_executor.h"

namespace core {

enum class MaskingFailureReason {
    UnattributedColumn,     // expected fail-closed outcome: the classification
                            // could not account for every column
    StructuralMismatch,     // upstream contract violation: shapes don't line up
    InvalidClassification,  // upstream contract violation: classification
                            // invariants broken
};

// Closed vocabulary: never contains SQL, names, or values.
const char* to_string(MaskingFailureReason reason);

// Success-or-failure by type: a failure cannot carry an ExecutionResult, so
// no caller can reach unmasked or partially masked data through a failure.
// Not default-constructible, since a default would masquerade as a success
// the masker never produced.
class MaskingOutcome {
public:
    MaskingOutcome() = delete;

    static MaskingOutcome success(ports::ExecutionResult result) {
        return MaskingOutcome(Value(std::move(result)));
    }
    static MaskingOutcome failure(MaskingFailureReason reason) {
        return MaskingOutcome(Value(reason));
    }

    bool masked() const {
        return std::holds_alternative<ports::ExecutionResult>(value_);
    }

    // Valid only when masked(); wrong-state access throws
    // std::bad_variant_access, it can never silently yield a result for a
    // failure (or a reason for a success).
    const ports::ExecutionResult& result() const {
        return std::get<ports::ExecutionResult>(value_);
    }
    MaskingFailureReason failure_reason() const {
        return std::get<MaskingFailureReason>(value_);
    }

private:
    using Value = std::variant<ports::ExecutionResult, MaskingFailureReason>;
    explicit MaskingOutcome(Value value) : value_(std::move(value)) {}
    Value value_;
};

// Concrete class: transforms result values according to the classifications
// produced by DataClassifier. It never re-classifies:
// a cell value is inspected only to apply the already-selected
// transformation, never to decide whether a column is PII. It contains no
// logging (it is the one component guaranteed to hold raw PII).
//
// Ownership: the result is passed by value, so the caller must not touch it
// after the call. No secure memory wiping is provided or claimed.
//
// Atomicity: phase 1 validates the whole result and classification before
// any cell is touched, so a partially masked result is unrepresentable.
//
// Per column, by index (never by name, duplicate names stay safe):
//   Pii                -> fixed transformation selected by pii_category
//   NotClassifiedAsPii -> cell preserved exactly
//   Unattributed       -> MaskingFailureReason::UnattributedColumn, no result
//
// NULL (nullopt) stays NULL and "" stays "" in every category; every OTHER
// value in a Pii column changes, malformed values fall back to "***" and
// are never returned unchanged.
//
// Not idempotent: the pipeline masks exactly once, and already-masked
// values are not detected.
class PiiMasker {
public:
    MaskingOutcome mask(ports::ExecutionResult result,
                        const ClassificationResult& classification) const;
};

}  // namespace core
