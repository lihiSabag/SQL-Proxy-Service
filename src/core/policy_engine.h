#pragma once

#include "core/sql_analysis.h"

namespace core {

// Machine-readable rejection codes. An enum cannot echo SQL text,
// identifiers, or data values, so a decision is safe to audit as-is.
// Every reason maps to the same generic HTTP rejection: the precise reason
// is for the audit trail, never for probing from outside.
enum class RejectReason {
    NotEvaluated,  // default sentinel, a finished decision never carries it
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
// reads as "rejected, never evaluated", and NotEvaluated surfacing anywhere
// downstream is a self-diagnosing orchestrator bug, distinct from every real
// rejection.
struct PolicyDecision {
    bool allowed = false;
    RejectReason reason = RejectReason::NotEvaluated;
};

// The single authorization point of the pipeline: converts the facts in a
// SqlAnalysis into an allow/reject decision. Concrete, stateless,
// deterministic. Consumes only SqlAnalysis; returns only PolicyDecision.
// Never sees raw SQL text, execution results, or identity.
//
// Rule order is fixed, first match wins (R1 to R11 in policy_engine.cpp).
// R3 and R4 uphold the IQueryExecutor single-statement precondition: the
// executor never counts statements itself.
class PolicyEngine {
public:
    PolicyDecision evaluate(const SqlAnalysis& analysis) const;
};

}  // namespace core
