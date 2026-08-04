#include "core/policy_engine.h"

#include <string>

namespace core {

namespace {

// ASCII-only lowering, deliberately not std::tolower (locale-dependent, UB on
// negative char). Approximates PostgreSQL's own unquoted-identifier folding,
// which is the point: the parser preserves spelling,
// but Postgres folds unquoted names down, so "PG_AUTHID" reaches the server
// as pg_authid. Case-INSENSITIVE deny matching errs toward over-blocking,
// which is the safe direction for a deny rule.
std::string ascii_lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return s;
}

// R9 deny set. Entries arrive as "schema.table" or "table" (SqlAnalysis
// contract). Best-effort by design — WHERE-clause subqueries are invisible to
// the analyzer's table list; the real boundary is the database role's
// privileges (documented in the README).
bool is_system_table(const std::string& table_entry) {
    const std::string lowered = ascii_lower(table_entry);
    const auto dot = lowered.find('.');
    const std::string schema =
        dot == std::string::npos ? std::string() : lowered.substr(0, dot);
    const std::string table =
        dot == std::string::npos ? lowered : lowered.substr(dot + 1);
    if (schema == "pg_catalog" || schema == "information_schema") {
        return true;
    }
    return table.rfind("pg_", 0) == 0;  // pg_authid, pg_stat_activity, ...
}

// The single table this proxy may write to.
constexpr const char* kInsertTargetTable = "orders";

// THE COMPLETE AUTHORIZATION RULE FOR THE ONE PERMITTED WRITE:
//
//     INSERT INTO orders (customer_id, amount) VALUES (<+int>, <+number>)
//
// Every condition must hold; anything else is rejected. Identifier
// comparisons are exact and case-sensitive, which is stricter than the
// read path on purpose: for a write, over-rejecting is the safe direction.
// A qualified name ("public.orders") does not compare equal and is refused.
//
// insert_source is mandatory and cannot be replaced by a table check:
// INSERT ... SELECT records only its target, so its table list is identical
// to a permitted insert's and the source form is the only thing separating
// them.
bool is_allowed_order_insert(const SqlAnalysis& analysis) {
    return analysis.unsupported_features.empty()  // e.g. omitted column list
        && analysis.insert_source == InsertSource::Values
        && analysis.affected_columns.size() == 2
        && analysis.affected_columns[0] == "customer_id"  // fixed order
        && analysis.affected_columns[1] == "amount"
        && analysis.insert_value_kinds.size() == 2
        && analysis.insert_value_kinds[0] == InsertValueKind::PositiveIntegerLiteral
        && (analysis.insert_value_kinds[1] == InsertValueKind::PositiveIntegerLiteral ||
            analysis.insert_value_kinds[1] == InsertValueKind::PositiveDecimalLiteral);
}

bool targets_insert_table(const SqlAnalysis& analysis) {
    return analysis.tables.size() == 1 && analysis.tables[0] == kInsertTargetTable;
}

PolicyDecision reject(RejectReason reason) {
    PolicyDecision d;
    d.allowed = false;
    d.reason = reason;
    return d;
}

PolicyDecision allow() {
    PolicyDecision d;
    d.allowed = true;
    d.reason = RejectReason::None;
    return d;
}

}  // namespace

PolicyDecision PolicyEngine::evaluate(const SqlAnalysis& analysis) const {
    // R1–R3 — analysis outcomes. Non-Ok analyses have undefined downstream
    // fields, so they must resolve before anything else is inspected.
    switch (analysis.status) {
        case AnalysisStatus::EmptyInput:
            return reject(RejectReason::EmptyInput);
        case AnalysisStatus::ParseError:
            return reject(RejectReason::UnparseableSql);
        case AnalysisStatus::MultipleStatements:
            return reject(RejectReason::MultipleStatements);
        case AnalysisStatus::Ok:
            break;
    }

    // R4 — defensive: Ok must mean exactly one statement. Upholds the
    // executor precondition even against a hypothetical upstream bug.
    if (analysis.statement_count != 1) {
        return reject(RejectReason::MultipleStatements);
    }

    // R5–R7 — the statement-class gate (read-only posture; the reasoning is
    // in the README).
    switch (analysis.statement_class) {
        case StatementClass::Unknown:
            return reject(RejectReason::UnsupportedStatementType);
        case StatementClass::Ddl:
            return reject(RejectReason::DdlNotAllowed);
        case StatementClass::Dml:
            // UPDATE, DELETE and TRUNCATE (which parses as DELETE) keep the
            // blanket DML rejection. INSERT is the sole exception, and only
            // in the one authorized shape.
            if (analysis.statement_type != StatementType::Insert) {
                return reject(RejectReason::DmlNotAllowed);
            }
            if (!targets_insert_table(analysis)) {
                return reject(RejectReason::InsertTargetNotAllowed);
            }
            if (!is_allowed_order_insert(analysis)) {
                return reject(RejectReason::UnsupportedInsertShape);
            }
            return allow();
        case StatementClass::Select:
            break;
    }

    // R8 — the analyzer's own signal that its picture is incomplete (CTE,
    // set operation, FROM-subquery, ...). Ordered before R9 so the catalog
    // scan below only ever runs against a table list the analyzer vouches
    // for.
    if (!analysis.unsupported_features.empty()) {
        return reject(RejectReason::UnsupportedSqlFeature);
    }

    // R9 — system-catalog denial (defense in depth).
    for (const std::string& table : analysis.tables) {
        if (is_system_table(table)) {
            return reject(RejectReason::SystemTableAccess);
        }
    }

    // R10 — mixed wildcard + explicit projection, e.g.
    // SELECT *, credit_card AS x FROM customers. Such a shape defeats BOTH
    // classification attribution modes: the star breaks positional alignment
    // and the alias breaks result-name lookup, so the explicit columns could
    // reach the caller unclassified. Rejected before execution.
    //
    // Deliberately NOT extended to general computed projections
    // (has_computed_projection && !tables.empty()); those remain allowed and
    // are handled by the classifier, which marks them Unattributed.
    if (analysis.has_wildcard_projection &&
        !analysis.projection_columns.empty()) {
        return reject(RejectReason::UnattributableProjection);
    }

    // R11 — exactly one fully analyzed SELECT. Wildcards, aliases, computed
    // projections and table-less selects are allowed.
    return allow();
}

}  // namespace core
