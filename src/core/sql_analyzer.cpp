#include "core/sql_analyzer.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace core {

using std::string;
using std::vector;

namespace {

bool is_blank(const string& sql) {
    return sql.find_first_not_of(" \t\n\r\f\v") == string::npos;
}

// "schema.table" when qualified, "table" otherwise; spelling preserved
// exactly as the parser resolved it (see the TableRef contract).
string qualified_name(const ports::TableRef& table) {
    if (table.schema.empty()) {
        return table.name;
    }
    return table.schema + "." + table.name;
}

vector<string> normalized_tables(const vector<ports::TableRef>& tables) {
    vector<string> result;
    for (const ports::TableRef& table : tables) {
        string name = qualified_name(table);
        if (std::find(result.begin(), result.end(), name) == result.end()) {
            result.push_back(std::move(name));
        }
    }
    return result;
}

}  // namespace

SqlAnalyzer::SqlAnalyzer(std::unique_ptr<ports::ISqlParser> parser)
    : parser_(std::move(parser)) {
    if (!parser_) {
        throw std::invalid_argument("SqlAnalyzer requires a non-null ISqlParser");
    }
}

SqlAnalysis SqlAnalyzer::analyze(const string& sql) const {
    SqlAnalysis analysis;  // fail-closed defaults

    if (is_blank(sql)) {
        analysis.status = AnalysisStatus::EmptyInput;
        return analysis;
    }

    ports::ParseResult parsed = parser_->parse(sql);
    analysis.statement_count = static_cast<int>(parsed.statements.size());

    if (!parsed.success) {
        analysis.status = AnalysisStatus::ParseError;
        analysis.error_reason = parsed.error.empty() ? "parser reported failure" : parsed.error;
        return analysis;
    }

    if (parsed.statements.empty()) {
        analysis.status = AnalysisStatus::ParseError;
        analysis.error_reason = "parser returned success with no statements";
        return analysis;
    }

    if (parsed.statements.size() > 1) {
        analysis.status = AnalysisStatus::MultipleStatements;
        return analysis;
    }

    const ports::ParsedStatement& statement = parsed.statements.front();
    analysis.status = AnalysisStatus::Ok;
    analysis.statement_type = statement.type;
    analysis.statement_class = statement_class_of(statement.type);
    analysis.tables = normalized_tables(statement.tables);
    analysis.projection_columns = statement.projection_columns;
    analysis.has_wildcard_projection = statement.has_wildcard_projection;
    analysis.has_computed_projection = statement.has_computed_projection;
    analysis.has_safe_count_star_projection = statement.has_safe_count_star_projection;
    analysis.has_group_by = statement.has_group_by;
    analysis.affected_columns = statement.affected_columns;
    analysis.insert_source = statement.insert_source;
    analysis.insert_value_kinds = statement.insert_value_kinds;
    analysis.unsupported_features = statement.unsupported_features;
    return analysis;
}

}  // namespace core
