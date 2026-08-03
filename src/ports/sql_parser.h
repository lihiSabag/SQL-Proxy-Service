#pragma once

#include <string>
#include <vector>

#include "core/sql_analysis.h"

namespace ports {

// Identifiers are returned in their parser-resolved form and passed through
// unchanged by SqlAnalyzer. Spelling is preserved permanently: the accepted
// parser does not report whether an identifier was quoted and never
// case-folds, so PostgreSQL-accurate quoted-versus-unquoted normalization is
// not possible with it — a documented limitation, not deferred work.
struct TableRef {
    std::string schema;  // empty when the reference is unqualified
    std::string name;
};

// Raw syntax facts for ONE statement. No normalization, no policy meaning.
//
// Projection contract: projection_columns contains plain column identifiers
// only. Computed expressions (function calls, arithmetic, CASE, ...) must not
// appear in it — they set has_computed_projection. A mixed projection
// (e.g. SELECT id, UPPER(email)) yields both list entries and the flag.
struct ParsedStatement {
    core::StatementType type = core::StatementType::Unknown;
    std::vector<TableRef> tables;
    std::vector<std::string> projection_columns;  // SELECT only
    bool has_wildcard_projection = false;
    bool has_computed_projection = false;
    std::vector<std::string> affected_columns;  // INSERT/UPDATE only
    std::vector<std::string> unsupported_features;
};

// Error contract: `error` must be a generic, bounded description (optionally
// with a position). It must never contain raw SQL text, token text, literal
// values, or anything derived from user input.
struct ParseResult {
    bool success = false;
    std::vector<ParsedStatement> statements;  // size() > 1 == multi-statement input
    std::string error;
};

// Implementations must not let exceptions escape parse(): any internal or
// third-party failure is reported as ParseResult{success = false} with a
// sanitized error, mirroring the project rule that library exceptions never
// cross an adapter boundary.
class ISqlParser {
public:
    virtual ~ISqlParser() = default;
    virtual ParseResult parse(const std::string& sql) = 0;
};

}  // namespace ports
