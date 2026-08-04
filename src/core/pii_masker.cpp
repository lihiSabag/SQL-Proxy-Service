#include "core/pii_masker.h"

#include <cstddef>
#include <optional>
#include <string>
#include <utility>

namespace core {

namespace {

constexpr const char* kFullRedaction = "***";

// Deliberately small deterministic rule, not a validator: exactly one '@',
// non-empty local part, non-empty domain — anything else is fully redacted.
// Quoted local-part syntax (which can legally contain '@') is deliberately
// unsupported; such values redact fully, which is the safe direction.
std::string mask_email(const std::string& value) {
    std::size_t at_count = 0;
    std::size_t at_pos = 0;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '@') {
            ++at_count;
            at_pos = i;
        }
    }
    if (at_count != 1 || at_pos == 0 || at_pos == value.size() - 1) {
        return kFullRedaction;
    }
    const std::string domain = value.substr(at_pos + 1);
    // Never emit a partial multibyte character: if the first local-part byte
    // is non-ASCII, drop the "keep first character" nicety entirely.
    if (static_cast<unsigned char>(value[0]) >= 0x80) {
        return "***@" + domain;
    }
    return std::string(1, value[0]) + "***@" + domain;
}

// Collect digits only; >= 7 digits (shortest realistic subscriber number)
// keeps the last four, otherwise the value is too short for "partial" to be
// meaningfully partial and it redacts fully. Original formatting is
// discarded. Not a telephone-number parser.
std::string mask_phone(const std::string& value) {
    std::string digits;
    for (char c : value) {
        if (c >= '0' && c <= '9') {
            digits.push_back(c);
        }
    }
    if (digits.size() < 7) {
        return kFullRedaction;
    }
    return "***" + digits.substr(digits.size() - 4);
}

// Strip spaces and hyphens; require all-digits and >= 12 digits (minimum
// real PAN length), keep the last four with a uniform prefix — the original
// length is NOT preserved, so a 15-digit Amex is indistinguishable from a
// 16-digit Visa in masked output. No Luhn: classification is settled
// metadata, and a checksum here would be value-based re-classification.
std::string mask_credit_card(const std::string& value) {
    std::string digits;
    for (char c : value) {
        if (c == ' ' || c == '-') {
            continue;
        }
        if (c < '0' || c > '9') {
            return kFullRedaction;
        }
        digits.push_back(c);
    }
    if (digits.size() < 12) {
        return kFullRedaction;
    }
    return "****" + digits.substr(digits.size() - 4);
}

std::string mask_value(PiiCategory category, const std::string& value) {
    switch (category) {
        case PiiCategory::Email:
            return mask_email(value);
        case PiiCategory::Phone:
            return mask_phone(value);
        case PiiCategory::CreditCard:
            return mask_credit_card(value);
    }
    // Unreachable with a valid enum; fail closed — never the original value.
    return kFullRedaction;
}

}  // namespace

const char* to_string(MaskingFailureReason reason) {
    switch (reason) {
        case MaskingFailureReason::UnattributedColumn:
            return "UNATTRIBUTED_COLUMN";
        case MaskingFailureReason::StructuralMismatch:
            return "STRUCTURAL_MISMATCH";
        case MaskingFailureReason::InvalidClassification:
            return "INVALID_CLASSIFICATION";
    }
    return "INVALID_CLASSIFICATION";
}

MaskingOutcome PiiMasker::mask(ports::ExecutionResult result,
                               const ClassificationResult& classification) const {
    // ---- Phase 1: preflight validation. No cell is touched until the whole
    // input is proven well-formed, so failure can never expose partially
    // masked output — and a failure outcome cannot carry a result at all,
    // by type.
    const std::size_t column_count = result.columns.size();

    if (classification.columns.size() != column_count) {
        return MaskingOutcome::failure(MaskingFailureReason::StructuralMismatch);
    }
    for (const auto& row : result.rows) {
        if (row.size() != column_count) {
            return MaskingOutcome::failure(MaskingFailureReason::StructuralMismatch);
        }
    }

    bool any_unattributed = false;
    for (const ColumnClassification& c : classification.columns) {
        const bool is_pii = c.data_class == ColumnDataClass::Pii;
        if (is_pii != c.pii_category.has_value()) {
            return MaskingOutcome::failure(MaskingFailureReason::InvalidClassification);
        }
        any_unattributed |= c.data_class == ColumnDataClass::Unattributed;
    }
    // fully_attributed == true  <=>  no column is Unattributed.
    if (classification.fully_attributed != !any_unattributed) {
        return MaskingOutcome::failure(MaskingFailureReason::InvalidClassification);
    }
    if (any_unattributed) {
        // Expected fail-closed outcome: this component does not emit data it
        // cannot account for. Which shapes reach it at all is decided
        // upstream by policy and classification, not here.
        return MaskingOutcome::failure(MaskingFailureReason::UnattributedColumn);
    }

    // ---- Phase 2: transformation. Total for validated input: iterates by
    // index only (duplicate column names are irrelevant), preserves column
    // order, row order, shape, and ColumnInfo metadata. NULL stays NULL and
    // "" stays "" — masking transforms values, it does not fabricate them.
    for (std::size_t col = 0; col < column_count; ++col) {
        const ColumnClassification& c = classification.columns[col];
        if (c.data_class != ColumnDataClass::Pii) {
            continue;  // NotClassifiedAsPii: preserved exactly
        }
        const PiiCategory category = *c.pii_category;
        for (auto& row : result.rows) {
            std::optional<std::string>& cell = row[col];
            if (!cell.has_value() || cell->empty()) {
                continue;
            }
            cell = mask_value(category, *cell);
        }
    }
    return MaskingOutcome::success(std::move(result));
}

}  // namespace core
