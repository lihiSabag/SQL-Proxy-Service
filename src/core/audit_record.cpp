#include "core/audit_record.h"

#include <stdexcept>
#include <utility>

namespace core {

const char* to_string(AuditOutcome outcome) {
    switch (outcome) {
        case AuditOutcome::Success:
            return "SUCCESS";
        case AuditOutcome::ParsingFailure:
            return "PARSING_FAILURE";
        case AuditOutcome::PolicyRejected:
            return "POLICY_REJECTED";
        case AuditOutcome::DatabaseFailure:
            return "DATABASE_FAILURE";
        case AuditOutcome::MaskingRefused:
            return "MASKING_REFUSED";
        case AuditOutcome::InternalFailure:
            return "INTERNAL_FAILURE";
    }
    return "INTERNAL_FAILURE";
}

const char* to_string(DbFailureCategory category) {
    switch (category) {
        case DbFailureCategory::ConnectionFailure:
            return "CONNECTION_FAILURE";
        case DbFailureCategory::ExecutionFailure:
            return "EXECUTION_FAILURE";
    }
    return "EXECUTION_FAILURE";
}

namespace {

// Success (with a result set) and MaskingRefused are reachable only for
// SELECT: both describe a classified, masked result, which a write never
// produces. Enforced here as a factory contract.
void require_select(StatementType type, const char* factory) {
    if (type != StatementType::Select) {
        throw std::invalid_argument(
            std::string(factory) +
            " audit records require StatementType::Select: they describe a "
            "masked result set");
    }
}

// A write outcome is reachable only for INSERT, the single statement type
// the policy may authorize as a write.
void require_insert(StatementType type, const char* factory) {
    if (type != StatementType::Insert) {
        throw std::invalid_argument(
            std::string(factory) +
            " audit records require StatementType::Insert: it is the only "
            "authorized write");
    }
}

// Execution can fail on either path, so the failure record accepts both.
void require_select_or_insert(StatementType type, const char* factory) {
    if (type != StatementType::Select && type != StatementType::Insert) {
        throw std::invalid_argument(
            std::string(factory) +
            " audit records require StatementType::Select or "
            "StatementType::Insert");
    }
}

}  // namespace

AuditRecord::AuditRecord(std::int64_t timestamp_ms, std::uint64_t request_id,
                         Details details)
    : timestamp_ms_(timestamp_ms),
      request_id_(request_id),
      details_(std::move(details)) {}

AuditRecord AuditRecord::success(std::int64_t timestamp_ms,
                                 std::uint64_t request_id,
                                 SuccessDetails details) {
    require_select(details.statement_type, "success");
    return AuditRecord(timestamp_ms, request_id, Details(std::move(details)));
}

AuditRecord AuditRecord::write_success(std::int64_t timestamp_ms,
                                       std::uint64_t request_id,
                                       WriteSuccessDetails details) {
    require_insert(details.statement_type, "write_success");
    return AuditRecord(timestamp_ms, request_id, Details(details));
}

AuditRecord AuditRecord::parsing_failure(std::int64_t timestamp_ms,
                                         std::uint64_t request_id,
                                         ParsingFailureDetails details) {
    return AuditRecord(timestamp_ms, request_id, Details(details));
}

AuditRecord AuditRecord::policy_rejected(std::int64_t timestamp_ms,
                                         std::uint64_t request_id,
                                         PolicyRejectedDetails details) {
    if (details.reason == RejectReason::None ||
        details.reason == RejectReason::NotEvaluated) {
        throw std::invalid_argument(
            "policy_rejected audit records require a real rejection reason");
    }
    // A parser failure is represented ONLY as AuditOutcome::ParsingFailure;
    // permitting PolicyRejected + UNPARSEABLE_SQL would create a second
    // audit representation of the same event.
    if (details.reason == RejectReason::UnparseableSql) {
        throw std::invalid_argument(
            "parser failures are audited as ParsingFailure, not as "
            "PolicyRejected");
    }
    return AuditRecord(timestamp_ms, request_id, Details(std::move(details)));
}

AuditRecord AuditRecord::database_failure(std::int64_t timestamp_ms,
                                          std::uint64_t request_id,
                                          DatabaseFailureDetails details) {
    require_select_or_insert(details.statement_type, "database_failure");
    return AuditRecord(timestamp_ms, request_id, Details(details));
}

AuditRecord AuditRecord::masking_refused(std::int64_t timestamp_ms,
                                         std::uint64_t request_id,
                                         MaskingRefusedDetails details) {
    require_select(details.statement_type, "masking_refused");
    return AuditRecord(timestamp_ms, request_id, Details(details));
}

AuditRecord AuditRecord::internal_failure(std::int64_t timestamp_ms,
                                          std::uint64_t request_id,
                                          InternalFailureDetails details) {
    return AuditRecord(timestamp_ms, request_id, Details(details));
}

AuditOutcome AuditRecord::outcome() const {
    // Derived from the active alternative — never stored, so it can never
    // contradict the details.
    // Both success alternatives report the same outcome: the request was
    // authorized and completed. Which one is active decides the fields.
    if (std::holds_alternative<SuccessDetails>(details_) ||
        std::holds_alternative<WriteSuccessDetails>(details_)) {
        return AuditOutcome::Success;
    }
    if (std::holds_alternative<ParsingFailureDetails>(details_)) {
        return AuditOutcome::ParsingFailure;
    }
    if (std::holds_alternative<PolicyRejectedDetails>(details_)) {
        return AuditOutcome::PolicyRejected;
    }
    if (std::holds_alternative<DatabaseFailureDetails>(details_)) {
        return AuditOutcome::DatabaseFailure;
    }
    if (std::holds_alternative<MaskingRefusedDetails>(details_)) {
        return AuditOutcome::MaskingRefused;
    }
    return AuditOutcome::InternalFailure;
}

bool AuditRecord::is_write_success() const {
    return std::holds_alternative<WriteSuccessDetails>(details_);
}

const SuccessDetails& AuditRecord::success_details() const {
    return std::get<SuccessDetails>(details_);
}

const WriteSuccessDetails& AuditRecord::write_success_details() const {
    return std::get<WriteSuccessDetails>(details_);
}

const PolicyRejectedDetails& AuditRecord::policy_rejected_details() const {
    return std::get<PolicyRejectedDetails>(details_);
}

const DatabaseFailureDetails& AuditRecord::database_failure_details() const {
    return std::get<DatabaseFailureDetails>(details_);
}

const MaskingRefusedDetails& AuditRecord::masking_refused_details() const {
    return std::get<MaskingRefusedDetails>(details_);
}

}  // namespace core
