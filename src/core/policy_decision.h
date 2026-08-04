#pragma once

namespace core {

// Machine-readable policy rejection codes. Audit-ready by construction: an
// enum cannot echo SQL text, identifiers, or data values (the same
// "sanitization by type system" rule as the executor's SQLSTATE-only errors).
//
// Presentation constraint: when an HTTP adapter later maps reasons to
// responses, SystemTableAccess must map to the same generic rejection
// presentation as any other policy rejection — the precise reason is for
// internal records only, never for probing from outside.
enum class RejectReason {
    NotEvaluated,  // default sentinel — a finished decision never carries it
    None,          // the only value legal alongside allowed == true
    EmptyInput,
    UnparseableSql,
    MultipleStatements,
    UnsupportedStatementType,
    UnsupportedSqlFeature,
    DdlNotAllowed,
    DmlNotAllowed,
    SystemTableAccess,
    // Projection shapes that defeat both classification attribution modes.
    // Produced ONLY for mixed wildcard+explicit projections
    // (SELECT *, col ...); see the note on rule R10.
    UnattributableProjection,
    // INSERT into anything other than the single permitted target table.
    InsertTargetNotAllowed,
    // An INSERT into the permitted target whose shape or values are outside
    // the one authorized form. One reason and not several: every denial is
    // externally indistinguishable anyway, so a finer split would only
    // record which check failed.
    UnsupportedInsertShape,
};

const char* to_string(RejectReason reason);

// Defaults are fail-closed, as elsewhere: a default-constructed decision
// reads as "rejected, never evaluated" — and NotEvaluated surfacing anywhere
// downstream is a self-diagnosing orchestrator bug, distinct from every real
// rejection.
struct PolicyDecision {
    bool allowed = false;
    RejectReason reason = RejectReason::NotEvaluated;
};

}  // namespace core
