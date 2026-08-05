#include "audit/jsonl_audit_repository.h"

#include <cstdio>
#include <ctime>

namespace audit_adapter {

std::string format_utc_timestamp(std::int64_t epoch_ms) {
    const std::time_t seconds = static_cast<std::time_t>(epoch_ms / 1000);
    const int millis = static_cast<int>(epoch_ms % 1000);
    std::tm utc{};
    gmtime_r(&seconds, &utc);
    char buffer[64];  // comfortably beyond the 24-char fixed format
    std::snprintf(buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                  utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday, utc.tm_hour,
                  utc.tm_min, utc.tm_sec, millis);
    return buffer;
}

nlohmann::json serialize(const core::AuditRecord& record) {
    nlohmann::json j;
    j["timestamp"] = format_utc_timestamp(record.timestamp_ms());
    j["request_id"] = record.request_id();
    j["outcome"] = core::to_string(record.outcome());

    // Present and Omitted are mutually exclusive, and Absent writes neither
    // key, so a record never claims "no tables" when the truth is "not known".
    switch (record.referenced_tables().state) {
        case core::AuditTableState::Present:
            j["referenced_tables"] = record.referenced_tables().tables;
            break;
        case core::AuditTableState::Omitted:
            j["referenced_tables_omitted"] = true;
            break;
        case core::AuditTableState::Absent:
            break;
    }

    switch (record.outcome()) {
        case core::AuditOutcome::Success: {
            // Two shapes share this outcome. A write has no result set, so it
            // records affected_rows and omits the read-only counts entirely
            // rather than writing zeros that would read as a real measurement.
            if (record.is_write_success()) {
                const core::WriteSuccessDetails& w = record.write_success_details();
                j["statement_type"] = core::to_string(w.statement_type);
                j["affected_rows"] = w.affected_rows;
                break;
            }
            const core::SuccessDetails& d = record.success_details();
            j["statement_type"] = core::to_string(d.statement_type);
            j["row_count"] = d.row_count;
            j["column_count"] = d.column_count;
            j["pii_email_columns"] = d.pii.email_columns;
            j["pii_phone_columns"] = d.pii.phone_columns;
            j["pii_credit_card_columns"] = d.pii.credit_card_columns;
            break;
        }
        case core::AuditOutcome::PolicyRejected: {
            const core::PolicyRejectedDetails& d =
                record.policy_rejected_details();
            j["reason"] = core::to_string(d.reason);
            j["statement_type"] = core::to_string(d.statement_type);
            j["statement_count"] = d.statement_count;
            break;
        }
        case core::AuditOutcome::DatabaseFailure: {
            const core::DatabaseFailureDetails& d =
                record.database_failure_details();
            j["category"] = core::to_string(d.category);
            j["statement_type"] = core::to_string(d.statement_type);
            break;
        }
        case core::AuditOutcome::MaskingRefused: {
            const core::MaskingRefusedDetails& d =
                record.masking_refused_details();
            j["statement_type"] = core::to_string(d.statement_type);
            j["column_count"] = d.column_count;
            // Deliberately NO pii_* fields: classification is incomplete in
            // this outcome and category counts could mislead.
            break;
        }
        case core::AuditOutcome::ParsingFailure:
        case core::AuditOutcome::InternalFailure:
            break;  // envelope only
    }
    return j;
}

JsonlAuditRepository::JsonlAuditRepository(const std::string& file_path) {
    // Append mode creates the file if missing and preserves existing
    // contents. A failed open is reported per append() call, as a bare enum.
    stream_.open(file_path, std::ios::out | std::ios::app);
}

ports::AuditAppendResult JsonlAuditRepository::append(
    const core::AuditRecord& record) {
    try {
        // Serialization is a pure function of the record — done outside the
        // lock so the critical section is exactly: write + flush + check.
        const std::string line = serialize(record).dump();

        std::lock_guard<std::mutex> lock(mutex_);
        if (!stream_.is_open()) {
            return ports::AuditAppendResult::OpenFailure;
        }
        stream_ << line << '\n';
        stream_.flush();
        if (!stream_) {
            return ports::AuditAppendResult::WriteFailure;
        }
        return ports::AuditAppendResult::Ok;
    } catch (...) {
        // Port contract: no exception escapes; no message text survives.
        return ports::AuditAppendResult::WriteFailure;
    }
}

}  // namespace audit_adapter
