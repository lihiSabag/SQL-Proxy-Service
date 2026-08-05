#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include "core/policy_engine.h"
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

// How much referenced-table metadata a record carries.
//
// Absent is the fail-closed default: a record that was never given a table
// list reads as "not known", never as "no tables were referenced".
enum class AuditTableState {
    Absent,   // no analyzed table list was available
    Present,  // every reported name passed validation
    Omitted,  // a name or the count failed validation; nothing is kept
};

// Table names as the analyzer reported them. Validated on construction, so
// an unchecked list cannot reach a record. `tables` is non-empty only when
// state == Present.
struct AuditTableMetadata {
    AuditTableState state = AuditTableState::Absent;
    std::vector<std::string> tables;
};

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
// fact worth recording: it says how much changed.
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

struct MaskingRefusedDetails {     // NO PiiSummary, see PiiSummary comment
    StatementType statement_type;  // must be Select under the read-only policy
    std::size_t column_count = 0;
};

// No open text: an internal failure audits as the fact alone.
struct InternalFailureDetails {};

// One audit record per controlled request outcome. The outcome is derived
// from the active details alternative and never stored separately, so a
// record cannot contradict its own outcome.
//
// Not default-constructible; created only through the per-outcome factories
// below. Factories reject invalid combinations with std::invalid_argument:
//   - policy_rejected(): reason must not be None or UnparseableSql;
//   - success()/masking_refused(): statement_type must be Select, since
//     both describe a masked result set;
//   - write_success(): statement_type must be Insert, the only authorized
//     write;
//   - database_failure(): statement_type must be Select or Insert, because
//     execution can fail on either path.
//
// timestamp_ms is UTC epoch milliseconds supplied by the caller; the
// repository never decides event time. request_id is process-local and may
// repeat across restarts, so it carries no identity claim.
class AuditRecord {
public:
    AuditRecord() = delete;

    // Outcomes that follow a successful analysis take the analyzer's table
    // list. ParsingFailure and InternalFailure take no such parameter, so
    // their records are Absent by construction rather than by convention.
    static AuditRecord success(std::int64_t timestamp_ms,
                               std::uint64_t request_id, SuccessDetails details,
                               const std::vector<std::string>& referenced_tables = {});
    static AuditRecord write_success(std::int64_t timestamp_ms,
                                     std::uint64_t request_id,
                                     WriteSuccessDetails details,
                                     const std::vector<std::string>& referenced_tables = {});
    static AuditRecord parsing_failure(std::int64_t timestamp_ms,
                                       std::uint64_t request_id,
                                       ParsingFailureDetails details = {});
    static AuditRecord policy_rejected(std::int64_t timestamp_ms,
                                       std::uint64_t request_id,
                                       PolicyRejectedDetails details,
                                       const std::vector<std::string>& referenced_tables = {});
    static AuditRecord database_failure(std::int64_t timestamp_ms,
                                        std::uint64_t request_id,
                                        DatabaseFailureDetails details,
                                        const std::vector<std::string>& referenced_tables = {});
    static AuditRecord masking_refused(std::int64_t timestamp_ms,
                                       std::uint64_t request_id,
                                       MaskingRefusedDetails details,
                                       const std::vector<std::string>& referenced_tables = {});
    static AuditRecord internal_failure(std::int64_t timestamp_ms,
                                        std::uint64_t request_id,
                                        InternalFailureDetails details = {});

    AuditOutcome outcome() const;

    // Distinguishes the two alternatives that share AuditOutcome::Success:
    // a masked result set versus a completed write.
    bool is_write_success() const;
    std::int64_t timestamp_ms() const { return timestamp_ms_; }
    std::uint64_t request_id() const { return request_id_; }
    const AuditTableMetadata& referenced_tables() const { return referenced_tables_; }

    // Wrong-state access throws std::bad_variant_access, so a detail can never
    // be read from a record of a different outcome.
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

    // Validates referenced_tables; see classify_tables in the .cpp.
    AuditRecord(std::int64_t timestamp_ms, std::uint64_t request_id,
                Details details,
                const std::vector<std::string>& referenced_tables = {});

    std::int64_t timestamp_ms_;
    std::uint64_t request_id_;
    AuditTableMetadata referenced_tables_;
    Details details_;
};

}  // namespace core
