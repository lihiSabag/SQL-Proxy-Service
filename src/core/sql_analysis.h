#pragma once

#include <string>
#include <vector>

namespace core {

enum class StatementType {
    Select,
    Insert,
    Update,
    Delete,
    Create,
    Alter,
    Drop,
    Unknown,  // parsed, but not one of the 7 supported types
};

enum class StatementClass { Select, Dml, Ddl, Unknown };

// Derived from StatementType, never stored independently, so it cannot drift.
StatementClass statement_class_of(StatementType type);

const char* to_string(StatementType type);
const char* to_string(StatementClass cls);

// Where an INSERT takes its rows from. None for every non-INSERT statement.
// Mandatory in the insert policy predicate: INSERT ... SELECT names only its
// target table, so the table list of a copying insert is indistinguishable
// from a permitted one and cannot be used to reject it.
enum class InsertSource { None, Values, Select };

// What one INSERT VALUES entry IS, as a syntactic fact about the parsed node.
// This vocabulary describes the token; it never states whether the statement
// is acceptable, which is PolicyEngine's decision alone.
//
// No magnitude and no text is carried: a value is knowable by kind only and
// is not reproducible from the analysis model. A negative number is not a
// literal in this grammar (it parses as a negation operator), so it lands in
// Unsupported rather than NonPositiveNumericLiteral.
enum class InsertValueKind {
    Unsupported,                // not a plain numeric literal (fail-closed)
    PositiveIntegerLiteral,     // integer literal, value > 0
    PositiveDecimalLiteral,     // decimal literal, value > 0
    NonPositiveNumericLiteral,  // numeric literal, value <= 0
};

enum class AnalysisStatus {
    Ok,                  // exactly one supported statement, analyzed
    EmptyInput,          // empty/whitespace-only SQL; the parser is never invoked
    ParseError,          // parser could not parse the input
    MultipleStatements,  // more than one statement; policy rejects downstream
};

// Defaults are deliberately fail-closed: a default-constructed SqlAnalysis
// reads as an unanalyzed, unclassifiable statement.
struct SqlAnalysis {
    AnalysisStatus status = AnalysisStatus::ParseError;
    StatementType statement_type = StatementType::Unknown;
    StatementClass statement_class = StatementClass::Unknown;
    int statement_count = 0;  // parsed statement count; >1 with MultipleStatements

    // "schema.table" or "table", deduplicated, first-seen order preserved.
    // Spelling is preserved exactly as the parser resolved it: it never
    // case-folds and does not report whether an identifier was quoted, so
    // PostgreSQL-accurate case normalization is not possible here.
    std::vector<std::string> tables;

    // SELECT only. Plain column identifiers only: computed expressions set
    // has_computed_projection instead. A mixed projection sets both.
    std::vector<std::string> projection_columns;
    bool has_wildcard_projection = false;  // SELECT * (or t.*)
    bool has_computed_projection = false;

    // The canonical COUNT(*) appeared in the projection. It counts rows, not
    // column contents, so it is the one computed shape with no lineage to a
    // source value. It is reported separately from a generic computed
    // projection so the classifier can attribute it. Narrow by design:
    // COUNT(1), COUNT(NULL), COUNT(col), COUNT(DISTINCT ...) and
    // COUNT(*) OVER (...) all remain has_computed_projection.
    bool has_safe_count_star_projection = false;

    // Syntax fact only. A grouped result is one row per group rather than one
    // row for the whole input, which is why a grouped COUNT(*) is not
    // attributable. That rule lives in DataClassifier, not in the parser.
    bool has_group_by = false;

    std::vector<std::string> affected_columns;  // INSERT column list / UPDATE SET targets

    // INSERT only. insert_value_kinds is populated for a VALUES source and is
    // positional: entry i describes the i-th value, aligned with
    // affected_columns. Empty for every other source and statement type.
    InsertSource insert_source = InsertSource::None;
    std::vector<InsertValueKind> insert_value_kinds;

    std::vector<std::string> unsupported_features;

    // ParseError only. Carries the sanitized reason from ParseResult::error,
    // never raw SQL or literal values.
    std::string error_reason;
};

}  // namespace core
