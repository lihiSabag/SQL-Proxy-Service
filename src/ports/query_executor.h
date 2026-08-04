#pragma once

#include <optional>
#include <string>
#include <vector>

namespace ports {

// Database-neutral column type. The adapter translates driver-specific type
// information (PostgreSQL OIDs) into this privately; nothing outside the
// adapter ever sees an OID.
enum class ColumnType {
    Text,
    Integer,
    Float,
    Numeric,
    Boolean,
    Timestamp,
    Date,
    Other,  // anything unmapped — fail-closed, never a guess
};

struct ColumnInfo {
    std::string name;
    ColumnType type = ColumnType::Other;
};

enum class ExecutionStatus {
    Ok,
    ConnectionFailure,  // could not reach/authenticate to the database
    ExecutionFailure,   // statement failed (syntax, constraint, timeout, ...)
};

// Result semantics:
// - has_result_set: the database returned at least one column. True for
//   SELECT and for DML with RETURNING — it makes no claim about statement type.
// - row_count: rows RETURNED in the result set (0 when there is none).
// - affected_rows: rows AFFECTED as reported by the database where it reports
//   them (DML, including RETURNING forms); 0 where nothing is reported
//   (plain SELECT, DDL).
// - Cells: std::nullopt is SQL NULL; "" is an empty string. Never conflated.
// - error: sanitized — fixed text plus at most a 5-char SQLSTATE code. Never
//   driver message text, SQL fragments, data values, or connection details.
struct ExecutionResult {
    ExecutionStatus status = ExecutionStatus::ExecutionFailure;  // fail-closed
    std::string error;
    bool has_result_set = false;
    std::vector<ColumnInfo> columns;
    std::vector<std::vector<std::optional<std::string>>> rows;
    long long row_count = 0;
    long long affected_rows = 0;
};

// PRECONDITION: execute() must be called with exactly ONE already-analyzed,
// already-approved statement (the orchestrator invokes it only after
// SqlAnalyzer and PolicyEngine confirm this). Passing multiple statements
// violates the precondition; behavior in that case is unsupported and must
// not be relied upon. The executor never parses, splits, counts, or polices
// SQL — that responsibility lives upstream, and no promise is made about
// what a precondition-violating call produces.
//
// Implementations must not let driver exceptions escape execute(); every
// failure is reported through ExecutionResult, mirroring the ISqlParser rule.
class IQueryExecutor {
public:
    virtual ~IQueryExecutor() = default;
    // Executes the exact analyzed SQL text — never a reconstructed query.
    virtual ExecutionResult execute(const std::string& sql) = 0;
};

}  // namespace ports
