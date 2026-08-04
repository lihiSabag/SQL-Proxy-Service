#pragma once

#include "core/policy_decision.h"
#include "core/sql_analysis.h"

namespace core {

// The single authorization point of the pipeline: converts the facts in a
// SqlAnalysis into an allow/reject decision. Concrete, stateless,
// deterministic. Consumes only SqlAnalysis; returns only PolicyDecision.
// Never sees raw SQL text, execution results, or identity.
//
// Rule order is fixed, first match wins (R1–R11 in policy_engine.cpp).
// Rules R3/R4 are what uphold the IQueryExecutor single-statement
// precondition — the executor deliberately refuses to count statements.
class PolicyEngine {
public:
    PolicyDecision evaluate(const SqlAnalysis& analysis) const;
};

}  // namespace core
