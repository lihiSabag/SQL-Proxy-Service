#pragma once

#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "core/data_classification.h"
#include "core/sql_analysis.h"
#include "ports/query_executor.h"

namespace core {

// Source-column-name -> category mappings. Names are matched
// case-insensitively (ASCII). Table-qualified keys are not supported —
// qualifiers on projection entries are stripped before lookup, because in a
// join the qualifier is a table *alias* the analyzer cannot resolve back to
// a real table (a documented analysis limitation). Column-name-only mappings
// over-classify at worst, which is the fail-safe direction.
struct ClassificationConfig {
    std::vector<std::pair<std::string, PiiCategory>> column_mappings;
};

// The default mappings:
//   email -> PII.Email, phone -> PII.Phone, credit_card -> PII.CreditCard
ClassificationConfig default_classification_config();

// Concrete class: metadata- and mapping-based PII classification.
// Consumes ONLY the SQL analysis and result-set column
// metadata — never result rows or cell values, so no PII can enter (or leak
// from) this class.
//
// Two attribution modes:
//   1. Positional — plain/aliased explicit projections: result column i
//      attributes to projection_columns[i] (qualifier stripped).
//   2. Pure wildcard — SELECT * only: result-column names ARE the true
//      source names as returned by the database.
// Every other shape (computed projections, mixed star+explicit, count
// mismatches, non-SELECT analyses) yields Unattributed columns with
// fully_attributed == false — never a silent NotClassifiedAsPii.
class DataClassifier {
public:
    DataClassifier();  // uses default_classification_config()

    // Throws std::invalid_argument if two mappings collide after
    // case-insensitive normalization: a colliding config is a programming
    // error, refused at construction (SqlAnalyzer precedent) — never
    // resolved silently in favor of either entry.
    explicit DataClassifier(const ClassificationConfig& config);

    ClassificationResult classify(
        const SqlAnalysis& analysis,
        const std::vector<ports::ColumnInfo>& result_columns) const;

private:
    std::unordered_map<std::string, PiiCategory> normalized_mappings_;
};

}  // namespace core
