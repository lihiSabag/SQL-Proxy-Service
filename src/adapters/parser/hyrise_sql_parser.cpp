#include "adapters/parser/hyrise_sql_parser.h"

#include <string>
#include <vector>

#include "SQLParser.h"
#include "SQLParserResult.h"
#include "sql/statements.h"

// Translation notes:
// - The SQLParserResult is a stack local: it owns every AST node and char*.
//   Everything is deep-copied into std::string during the walk, so nothing
//   parser-owned can outlive parse().
// - errorMsg() is discarded entirely; the error string is built only from
//   fixed text plus numeric position, never from input-derived content.
// - Identifier spelling is preserved exactly as the parser resolved it.

namespace parser_adapter {

namespace {

std::string copy_or_empty(const char* s) {
    return s == nullptr ? std::string() : std::string(s);
}

// Fixed note strings only — never derived from user input.
constexpr const char* kNoteInsertWithoutColumns = "INSERT without column list";
constexpr const char* kNoteFromSubquery = "subquery in FROM";
constexpr const char* kNoteWithCte = "WITH/CTE";
constexpr const char* kNoteSetOperation = "set operation (UNION/INTERSECT/EXCEPT)";
constexpr const char* kNoteNonTableCreate = "non-table CREATE";
constexpr const char* kNoteNonTableDrop = "non-table DROP";

// Joins and cross products nest child TableRefs; a FROM subquery is reported
// as an unsupported feature rather than a fake table name.
void collect_tables(const hsql::TableRef* ref, ports::ParsedStatement& out) {
    if (ref == nullptr) {
        return;
    }
    switch (ref->type) {
        case hsql::kTableName:
            out.tables.push_back({copy_or_empty(ref->schema), copy_or_empty(ref->name)});
            break;
        case hsql::kTableJoin:
            if (ref->join != nullptr) {
                collect_tables(ref->join->left, out);
                collect_tables(ref->join->right, out);
            }
            break;
        case hsql::kTableCrossProduct:
            if (ref->list != nullptr) {
                for (const hsql::TableRef* child : *ref->list) {
                    collect_tables(child, out);
                }
            }
            break;
        case hsql::kTableSelect:
            out.unsupported_features.push_back(kNoteFromSubquery);
            break;
    }
}

// Projection contract (ports::ParsedStatement): plain column identifiers only,
// spelled as written (qualifier kept, e.g. "c.id"); a star sets the wildcard
// flag; anything else sets the computed flag.
void classify_projection(const std::vector<hsql::Expr*>* select_list,
                         ports::ParsedStatement& out) {
    if (select_list == nullptr) {
        return;
    }
    for (const hsql::Expr* e : *select_list) {
        if (e == nullptr) {
            continue;
        }
        if (e->type == hsql::kExprStar) {
            out.has_wildcard_projection = true;
        } else if (e->type == hsql::kExprColumnRef) {
            std::string column;
            if (e->table != nullptr) {
                column = std::string(e->table) + ".";
            }
            column += copy_or_empty(e->name);
            out.projection_columns.push_back(std::move(column));
        } else {
            out.has_computed_projection = true;
        }
    }
}

void translate_select(const hsql::SelectStatement& stmt, ports::ParsedStatement& out) {
    out.type = core::StatementType::Select;
    collect_tables(stmt.fromTable, out);
    classify_projection(stmt.selectList, out);
    if (stmt.withDescriptions != nullptr && !stmt.withDescriptions->empty()) {
        out.unsupported_features.push_back(kNoteWithCte);
    }
    if (stmt.setOperations != nullptr && !stmt.setOperations->empty()) {
        out.unsupported_features.push_back(kNoteSetOperation);
    }
}

void translate_insert(const hsql::InsertStatement& stmt, ports::ParsedStatement& out) {
    out.type = core::StatementType::Insert;
    out.tables.push_back({copy_or_empty(stmt.schema), copy_or_empty(stmt.tableName)});
    if (stmt.columns != nullptr) {
        for (const char* column : *stmt.columns) {
            out.affected_columns.push_back(copy_or_empty(column));
        }
    } else {
        out.unsupported_features.push_back(kNoteInsertWithoutColumns);
    }
}

void translate_update(const hsql::UpdateStatement& stmt, ports::ParsedStatement& out) {
    out.type = core::StatementType::Update;
    collect_tables(stmt.table, out);
    if (stmt.updates != nullptr) {
        for (const hsql::UpdateClause* clause : *stmt.updates) {
            if (clause != nullptr) {
                out.affected_columns.push_back(copy_or_empty(clause->column));
            }
        }
    }
}

void translate_delete(const hsql::DeleteStatement& stmt, ports::ParsedStatement& out) {
    out.type = core::StatementType::Delete;
    out.tables.push_back({copy_or_empty(stmt.schema), copy_or_empty(stmt.tableName)});
}

void translate_create(const hsql::CreateStatement& stmt, ports::ParsedStatement& out) {
    out.type = core::StatementType::Create;
    if (stmt.tableName != nullptr) {
        out.tables.push_back({copy_or_empty(stmt.schema), copy_or_empty(stmt.tableName)});
    }
    if (stmt.type != hsql::kCreateTable) {
        out.unsupported_features.push_back(kNoteNonTableCreate);
    }
}

void translate_drop(const hsql::DropStatement& stmt, ports::ParsedStatement& out) {
    out.type = core::StatementType::Drop;
    if (stmt.name != nullptr) {
        out.tables.push_back({copy_or_empty(stmt.schema), copy_or_empty(stmt.name)});
    }
    if (stmt.type != hsql::kDropTable) {
        out.unsupported_features.push_back(kNoteNonTableDrop);
    }
}

void translate_alter(const hsql::AlterStatement& stmt, ports::ParsedStatement& out) {
    out.type = core::StatementType::Alter;
    if (stmt.name != nullptr) {
        out.tables.push_back({copy_or_empty(stmt.schema), copy_or_empty(stmt.name)});
    }
}

ports::ParsedStatement translate_statement(const hsql::SQLStatement& stmt) {
    ports::ParsedStatement out;  // defaults: type Unknown
    switch (stmt.type()) {
        case hsql::kStmtSelect:
            translate_select(static_cast<const hsql::SelectStatement&>(stmt), out);
            break;
        case hsql::kStmtInsert:
            translate_insert(static_cast<const hsql::InsertStatement&>(stmt), out);
            break;
        case hsql::kStmtUpdate:
            translate_update(static_cast<const hsql::UpdateStatement&>(stmt), out);
            break;
        case hsql::kStmtDelete:
            translate_delete(static_cast<const hsql::DeleteStatement&>(stmt), out);
            break;
        case hsql::kStmtCreate:
            translate_create(static_cast<const hsql::CreateStatement&>(stmt), out);
            break;
        case hsql::kStmtDrop:
            translate_drop(static_cast<const hsql::DropStatement&>(stmt), out);
            break;
        case hsql::kStmtAlter:
            translate_alter(static_cast<const hsql::AlterStatement&>(stmt), out);
            break;
        default:
            // SHOW, transactions, prepare/execute, import/export, ... —
            // parseable but out of scope; policy rejects Unknown downstream.
            out.type = core::StatementType::Unknown;
            break;
    }
    return out;
}

std::string sanitized_error(const hsql::SQLParserResult& result) {
    std::string error = "syntax error";
    if (result.errorLine() >= 0) {
        error += " at line " + std::to_string(result.errorLine() + 1) +
                 ", column " + std::to_string(result.errorColumn() + 1);
    }
    return error;
}

}  // namespace

ports::ParseResult HyriseSqlParser::parse(const std::string& sql) {
    ports::ParseResult out;
    try {
        hsql::SQLParserResult result;  // owns the whole AST; freed on return
        hsql::SQLParser::parse(sql, &result);

        if (!result.isValid()) {
            out.success = false;
            out.error = sanitized_error(result);
            return out;
        }

        out.success = true;
        out.statements.reserve(result.size());
        for (const hsql::SQLStatement* stmt : result.getStatements()) {
            if (stmt != nullptr) {
                out.statements.push_back(translate_statement(*stmt));
            }
        }
        return out;
    } catch (...) {
        // Port contract: no exception escapes the adapter.
        return ports::ParseResult{false, {}, "parser failure"};
    }
}

}  // namespace parser_adapter
