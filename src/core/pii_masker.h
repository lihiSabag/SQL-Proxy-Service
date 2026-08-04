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

// Closed vocabulary for later audit integration. Never contains SQL, column
// names, row values, or cell values — the enum is the entire message.
const char* to_string(MaskingFailureReason reason);

// Success-or-failure by TYPE: a failure cannot carry an ExecutionResult, so
// no caller can reach unmasked or partially masked data through a failure
// outcome. The only result eligible to leave this component is the fully
// masked success value.
//
// Deliberately NOT a bare std::variant alias: a
// default-constructed variant would hold a default ExecutionResult and
// masquerade as a successful masking outcome that PiiMasker never produced.
// This wrapper cannot be default-constructed — an outcome exists only via
// the explicit success()/failure() factories.
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
    // std::bad_variant_access — it can never silently yield a result for a
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
// produced by DataClassifier. It never re-classifies —
// a cell value is inspected only to apply the already-selected
// transformation, never to decide whether a column is PII. It contains no
// logging (it is the one component guaranteed to hold raw PII).
//
// Ownership: the caller passes the raw ExecutionResult by value (std::move),
// which transfers logical ownership, reduces accidental reuse, and avoids an
// intentional full copy. C++ does not guarantee secure memory erasure, and
// the moved-from caller object remains in a valid-but-unspecified state —
// the orchestrator must not access it after the call. No secure wiping is
// provided or claimed.
//
// Atomicity: phase 1 validates the entire result + classification before
// any cell is touched; phase 2 (transformation) is total for validated
// input. A partially masked result is unrepresentable.
//
// Per column, by index (never by name — duplicate names stay safe):
//   Pii                -> fixed transformation selected by pii_category
//   NotClassifiedAsPii -> cell preserved exactly
//   Unattributed       -> MaskingFailureReason::UnattributedColumn, no result
//
// NULL (nullopt) stays NULL and "" stays "" in every category; every OTHER
// value in a Pii column changes — malformed values fall back to "***" and
// are never returned unchanged.
//
// Idempotence is explicitly NOT a guarantee: the pipeline invariant is that
// the orchestrator masks exactly once. There is no detection of
// already-masked values.
class PiiMasker {
public:
    MaskingOutcome mask(ports::ExecutionResult result,
                        const ClassificationResult& classification) const;
};

}  // namespace core
