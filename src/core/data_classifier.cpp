#include "core/data_classifier.h"

#include <cstddef>
#include <stdexcept>

namespace core {

namespace {

// ASCII-only lowering, as in the policy engine: locale-independent, and
// approximates PostgreSQL's unquoted-identifier folding, which is the
// semantics that matter here.
std::string ascii_lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return s;
}

// "customers.email" / "c.email" -> "email"
std::string strip_qualifier(const std::string& name) {
    const auto dot = name.rfind('.');
    return dot == std::string::npos ? name : name.substr(dot + 1);
}

ColumnClassification pii(PiiCategory category) {
    ColumnClassification c;
    c.data_class = ColumnDataClass::Pii;
    c.pii_category = category;
    return c;
}

ColumnClassification not_pii() {
    ColumnClassification c;
    c.data_class = ColumnDataClass::NotClassifiedAsPii;
    c.pii_category.reset();
    return c;
}

}  // namespace

ClassificationConfig default_classification_config() {
    return ClassificationConfig{{
        {"email", PiiCategory::Email},
        {"phone", PiiCategory::Phone},
        {"credit_card", PiiCategory::CreditCard},
    }};
}

DataClassifier::DataClassifier()
    : DataClassifier(default_classification_config()) {}

DataClassifier::DataClassifier(const ClassificationConfig& config) {
    for (const auto& mapping : config.column_mappings) {
        const std::string key = ascii_lower(mapping.first);
        const bool inserted =
            normalized_mappings_.emplace(key, mapping.second).second;
        if (!inserted) {
            // Mapping keys are developer-authored config, not user input or
            // secrets, so naming the colliding key is safe and useful.
            throw std::invalid_argument(
                "duplicate classification mapping after case-insensitive "
                "normalization: '" + key + "'");
        }
    }
}

ClassificationResult DataClassifier::classify(
    const SqlAnalysis& analysis,
    const std::vector<ports::ColumnInfo>& result_columns) const {
    ClassificationResult result;
    // Default-constructed entries are Unattributed — the fail-closed floor.
    result.columns.assign(result_columns.size(), ColumnClassification{});
    result.fully_attributed = false;

    if (result_columns.empty()) {
        result.fully_attributed = true;  // vacuous: no column is Unattributed
        return result;
    }

    // Defensive: only a fully analyzed single SELECT is classifiable at all.
    // Policy guarantees this upstream; the classifier does not rely on it.
    const bool analyzable =
        analysis.status == AnalysisStatus::Ok &&
        analysis.statement_class == StatementClass::Select;

    const bool positional_shape =
        analyzable && !analysis.has_wildcard_projection &&
        !analysis.has_computed_projection &&
        !analysis.projection_columns.empty() &&
        analysis.projection_columns.size() == result_columns.size();

    const bool wildcard_shape =
        analyzable && analysis.has_wildcard_projection &&
        analysis.projection_columns.empty() &&
        !analysis.has_computed_projection;

    if (!positional_shape && !wildcard_shape) {
        // Computed projections, mixed star+explicit shapes, and
        // projection/result count mismatches all land here: never guess a
        // source column, never shift indices, never classify a partial
        // prefix, never silently claim NotClassifiedAsPii.
        return result;
    }

    for (std::size_t i = 0; i < result_columns.size(); ++i) {
        const std::string source =
            positional_shape ? strip_qualifier(analysis.projection_columns[i])
                             : result_columns[i].name;
        const auto it = normalized_mappings_.find(ascii_lower(source));
        result.columns[i] =
            it == normalized_mappings_.end() ? not_pii() : pii(it->second);
    }
    result.fully_attributed = true;
    return result;
}

}  // namespace core
