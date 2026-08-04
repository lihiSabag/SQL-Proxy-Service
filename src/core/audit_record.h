#pragma once

#include <cstddef>
#include <cstdint>
#include <variant>

#include "core/policy_decision.h"
#include "core/sql_analysis.h"

namespace core {

// Final audit outcome vocabulary. Closed by construction:
// no AuditRecord type contains any open string field, so SQL, values,
// names, identities, messages, and paths are structurally unrepresentable.
enum class AuditOutcome {
    Success,
    ParsingFailure,
    PolicyRejected,
    DatabaseFailure,
    MaskingRefused,
    InternalFailure,
};

const char* to_string(AuditOutcome outcome);

// Typed translation of ports::ExecutionStatus failure states.
enum class DbFailureCategory {
    ConnectionFailure,
    ExecutionFailure,
};

const char* to_string(DbFailureCategory category);

// Column counts, not cell counts (a 1000-row result with one email column
// audits as email_columns = 1). Appears ONLY in SuccessDetails: after a
// masking refusal the classification is incomplete by definition, and
// category counts could mislead (SELECT CONCAT(name, email) would audit
// as pii_email_columns = 0 while email data sits inside the unattributed
// expression).
struct PiiSummary {
    std::size_t email_columns = 0;
    std::size_t phone_columns = 0;
    std::size_t credit_card_columns = 0;
};
// Total PII columns is derived (the sum); it is never stored.

struct SuccessDetails {
    StatementType statement_type;  // must be Select under the read-only policy
    std::size_t row_count = 0;
    std::size_t column_count = 0;
    PiiSummary pii;
};

// A completed write. Carries no result-set counts (there is none) and no
// PII counts (nothing was classified or masked). affected_rows is the one
// fact worth recording: it says how much changed. No table name is stored:
// under the current policy an allowed write is always the one permitted
// target, so the name adds nothing, and on any other path it would be
// caller-controlled text.
struct WriteSuccessDetails {
    StatementType statement_type;  // must be Insert under the current policy
    std::size_t affected_rows = 0;
};

// Deliberately empty: a parse failure produced no reliable analysis, and
// the record must not invent certainty the analyzer never had.
struct ParsingFailureDetails {};

struct PolicyRejectedDetails {
    RejectReason reason;           // never None; never UnparseableSql (that
                                   // event is AuditOutcome::ParsingFailure)
    StatementType statement_type;  // may legitimately be Unknown
    std::size_t statement_count = 0;
};

struct DatabaseFailureDetails {
    DbFailureCategory category;
    StatementType statement_type;  // must be Select under the read-only policy
};

struct MaskingRefusedDetails {     // NO PiiSummary — see PiiSummary comment
    StatementType statement_type;  // must be Select under the read-only policy
    std::size_t column_count = 0;
};

// No open text, ever — an internal failure audits as the fact alone.
struct InternalFailureDetails {};

// One audit record per controlled request outcome. Envelope + one
// outcome-specific details alternative; the outcome is DERIVED from the
// active alternative and never stored separately, so record and outcome
// cannot contradict each other.
//
// Not default-constructible (MaskingOutcome lesson); created only through
// the per-outcome factories below. Factories reject semantically invalid
// values inside an outcome with std::invalid_argument (programmer-contract
// misuse):
//   - policy_rejected(): reason must not be None or UnparseableSql;
//   - success()/database_failure()/masking_refused(): statement_type must
//     be Select — these outcomes are reachable only for SELECT under the
//     read-only policy (revisit explicitly if that policy is ever
//     relaxed).
//
// timestamp_ms is UTC epoch milliseconds, supplied by the caller — there is
// no clock port, and the repository never decides event time. request_id is
// a process-local caller-supplied identifier; it may repeat across process
// restarts and carries no uniqueness or identity claim.
class AuditRecord {
public:
    AuditRecord() = delete;

    static AuditRecord success(std::int64_t timestamp_ms,
                               std::uint64_t request_id, SuccessDetails details);
    static AuditRecord write_success(std::int64_t timestamp_ms,
                                     std::uint64_t request_id,
                                     WriteSuccessDetails details);
    static AuditRecord parsing_failure(std::int64_t timestamp_ms,
                                       std::uint64_t request_id,
                                       ParsingFailureDetails details = {});
    static AuditRecord policy_rejected(std::int64_t timestamp_ms,
                                       std::uint64_t request_id,
                                       PolicyRejectedDetails details);
    static AuditRecord database_failure(std::int64_t timestamp_ms,
                                        std::uint64_t request_id,
                                        DatabaseFailureDetails details);
    static AuditRecord masking_refused(std::int64_t timestamp_ms,
                                       std::uint64_t request_id,
                                       MaskingRefusedDetails details);
    static AuditRecord internal_failure(std::int64_t timestamp_ms,
                                        std::uint64_t request_id,
                                        InternalFailureDetails details = {});

    AuditOutcome outcome() const;

    // Distinguishes the two alternatives that share AuditOutcome::Success:
    // a masked result set versus a completed write.
    bool is_write_success() const;
    std::int64_t timestamp_ms() const { return timestamp_ms_; }
    std::uint64_t request_id() const { return request_id_; }

    // Wrong-state access throws std::bad_variant_access — a detail can
    // never be silently read from a record of a different outcome.
    const SuccessDetails& success_details() const;
    const WriteSuccessDetails& write_success_details() const;
    const PolicyRejectedDetails& policy_rejected_details() const;
    const DatabaseFailureDetails& database_failure_details() const;
    const MaskingRefusedDetails& masking_refused_details() const;

private:
    using Details =
        std::variant<SuccessDetails, WriteSuccessDetails, ParsingFailureDetails,
                     PolicyRejectedDetails, DatabaseFailureDetails,
                     MaskingRefusedDetails, InternalFailureDetails>;

    AuditRecord(std::int64_t timestamp_ms, std::uint64_t request_id,
                Details details);

    std::int64_t timestamp_ms_;
    std::uint64_t request_id_;
    Details details_;
};

}  // namespace core
