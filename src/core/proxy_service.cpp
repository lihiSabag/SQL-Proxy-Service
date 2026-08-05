#include "core/proxy_service.h"

#include <chrono>
#include <cstddef>
#include <stdexcept>
#include <utility>

#include "logging/system_log.h"

namespace core {

using std::size_t;
using std::string;

const char* to_string(ServiceFailure failure) {
    switch (failure) {
        case ServiceFailure::EmptyInput:
            return "empty_sql";
        case ServiceFailure::UnparseableSql:
            return "invalid_sql";
        case ServiceFailure::PolicyRejected:
            return "policy_rejected";
        case ServiceFailure::DatabaseUnavailable:
            return "database_unavailable";
        case ServiceFailure::QueryFailed:
            return "query_failed";
        case ServiceFailure::MaskingRefused:
            return "masking_refused";
        case ServiceFailure::InternalError:
            return "internal_error";
    }
    return "internal_error";
}

ServiceResult::ServiceResult(Value value) : value_(std::move(value)) {}

ServiceResult ServiceResult::success(MaskedQueryResult result) {
    return ServiceResult(Value(std::move(result)));
}

ServiceResult ServiceResult::write_success(WriteResult result) {
    return ServiceResult(Value(result));
}

ServiceResult ServiceResult::failure(ServiceFailure failure) {
    return ServiceResult(Value(failure));
}

bool ServiceResult::succeeded() const {
    // Anything that is not a failure is a success; there are two shapes.
    return !std::holds_alternative<ServiceFailure>(value_);
}

bool ServiceResult::is_write() const {
    return std::holds_alternative<WriteResult>(value_);
}

const MaskedQueryResult& ServiceResult::result() const {
    return std::get<MaskedQueryResult>(value_);
}

const WriteResult& ServiceResult::write_result() const {
    return std::get<WriteResult>(value_);
}

ServiceFailure ServiceResult::failure_reason() const {
    return std::get<ServiceFailure>(value_);
}

struct ProxyService::Processing {
    ServiceResult result;
    AuditRecord record;
};

namespace {

std::int64_t now_epoch_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// A negative count is a broken upstream contract, not a client error: it
// throws and becomes a controlled InternalFailure via the catch in handle().
size_t checked_count(long long value, const char* what) {
    if (value < 0) {
        throw std::invalid_argument(string(what) + " must not be negative");
    }
    return static_cast<size_t>(value);
}

PiiSummary summarize(const ClassificationResult& classification) {
    PiiSummary summary;
    for (const ColumnClassification& column : classification.columns) {
        if (column.data_class != ColumnDataClass::Pii ||
            !column.pii_category.has_value()) {
            continue;
        }
        switch (*column.pii_category) {
            case PiiCategory::Email:
                ++summary.email_columns;
                break;
            case PiiCategory::Phone:
                ++summary.phone_columns;
                break;
            case PiiCategory::CreditCard:
                ++summary.credit_card_columns;
                break;
        }
    }
    return summary;
}

MaskedQueryResult to_masked_result(const ports::ExecutionResult& masked) {
    MaskedQueryResult out;
    out.column_names.reserve(masked.columns.size());
    for (const ports::ColumnInfo& column : masked.columns) {
        out.column_names.push_back(column.name);  // duplicates preserved
    }
    out.rows = masked.rows;  // positional; NULL vs "" already distinguished
    return out;
}

// Empty input is the one denial the client may distinguish; it is a
// malformed request, not a security decision. Every other reason collapses
// to the same generic rejection, and a reason added later stays generic.
ServiceFailure client_failure_for(RejectReason reason) {
    switch (reason) {
        case RejectReason::EmptyInput:
            return ServiceFailure::EmptyInput;
        default:
            return ServiceFailure::PolicyRejected;
    }
}

}  // namespace

ProxyService::ProxyService(SqlAnalyzer& analyzer, ports::IQueryExecutor& executor,
                           ports::IAuditRepository& audit)
    : analyzer_(analyzer), executor_(executor), audit_(audit) {}

ProxyService::Processing ProxyService::process(const string& sql,
                                               std::int64_t timestamp_ms,
                                               std::uint64_t request_id) {
    const SqlAnalysis analysis = analyzer_.analyze(sql);
    const PolicyDecision decision = policy_.evaluate(analysis);

    if (!decision.allowed) {
        // A parser failure has exactly ONE audit representation:
        // AuditOutcome::ParsingFailure (the AuditRecord factory forbids
        // PolicyRejected + UNPARSEABLE_SQL). PolicyEngine remains the single
        // decision point, this is only the audit-side translation.
        if (decision.reason == RejectReason::UnparseableSql) {
            return Processing{
                ServiceResult::failure(ServiceFailure::UnparseableSql),
                AuditRecord::parsing_failure(timestamp_ms, request_id)};
        }
        return Processing{
            ServiceResult::failure(client_failure_for(decision.reason)),
            AuditRecord::policy_rejected(
                timestamp_ms, request_id,
                {decision.reason, analysis.statement_type,
                 checked_count(analysis.statement_count, "statement_count")},
                analysis.tables)};
    }

    ports::ExecutionResult execution = executor_.execute(sql);

    if (execution.status != ports::ExecutionStatus::Ok) {
        const bool connection =
            execution.status == ports::ExecutionStatus::ConnectionFailure;
        return Processing{
            ServiceResult::failure(connection ? ServiceFailure::DatabaseUnavailable
                                              : ServiceFailure::QueryFailed),
            AuditRecord::database_failure(
                timestamp_ms, request_id,
                {connection ? DbFailureCategory::ConnectionFailure
                            : DbFailureCategory::ExecutionFailure,
                 analysis.statement_type},
                analysis.tables)};
    }

    // An authorized write produces no result set, so classification and
    // masking do not apply and are skipped rather than run on an empty
    // result. Policy admits exactly one write shape, so StatementType is
    // enough to identify it here.
    if (analysis.statement_type == StatementType::Insert) {
        const size_t affected =
            checked_count(execution.affected_rows, "affected_rows");
        if (affected != 1) {
            // The one authorized shape inserts exactly one row. Any other
            // count means the statement did something the policy did not
            // authorize, so it is reported as an internal failure rather
            // than as a success the service cannot vouch for.
            return Processing{ServiceResult::failure(ServiceFailure::InternalError),
                              AuditRecord::internal_failure(timestamp_ms, request_id)};
        }
        return Processing{
            ServiceResult::write_success(WriteResult{affected}),
            AuditRecord::write_success(timestamp_ms, request_id,
                                       {analysis.statement_type, affected},
                                       analysis.tables)};
    }

    // Captured BEFORE the executor result is moved into the masker; the
    // moved-from object is never read again.
    const size_t row_count = checked_count(execution.row_count, "row_count");
    const size_t column_count = execution.columns.size();

    const ClassificationResult classification =
        classifier_.classify(analysis, execution.columns);

    const MaskingOutcome masked =
        masker_.mask(std::move(execution), classification);

    if (!masked.masked()) {
        if (masked.failure_reason() == MaskingFailureReason::UnattributedColumn) {
            // Expected fail-closed security outcome, not a defect.
            return Processing{
                ServiceResult::failure(ServiceFailure::MaskingRefused),
                AuditRecord::masking_refused(timestamp_ms, request_id,
                                             {analysis.statement_type, column_count},
                                             analysis.tables)};
        }
        // StructuralMismatch and InvalidClassification are upstream contract
        // violations, audited as internal failures.
        return Processing{ServiceResult::failure(ServiceFailure::InternalError),
                          AuditRecord::internal_failure(timestamp_ms, request_id)};
    }

    return Processing{
        ServiceResult::success(to_masked_result(masked.result())),
        AuditRecord::success(timestamp_ms, request_id,
                             {analysis.statement_type, row_count, column_count,
                              summarize(classification)},
                             analysis.tables)};
}

ports::AuditAppendResult ProxyService::append_safely(const AuditRecord& record) {
    try {
        return audit_.append(record);
    } catch (...) {
        // A throwing repository behaves exactly like a failing one; no
        // exception escapes toward the client, and no message text survives.
        return ports::AuditAppendResult::WriteFailure;
    }
}

ServiceResult ProxyService::handle(const string& sql) {
    // Serializes the whole pipeline; see the concurrency note in the header.
    std::lock_guard<std::mutex> lock(mutex_);

    const std::int64_t timestamp_ms = now_epoch_ms();
    const std::uint64_t request_id = next_request_id_++;

    Processing processing = [&]() -> Processing {
        try {
            return process(sql, timestamp_ms, request_id);
        } catch (...) {
            // One catch for the whole pipeline: any unexpected failure
            // (parser, executor, classifier, masker, count validation,
            // record construction) becomes one controlled outcome.
            return Processing{ServiceResult::failure(ServiceFailure::InternalError),
                              AuditRecord::internal_failure(timestamp_ms, request_id)};
        }
    }();

    // The ONLY audit append attempt in the service, reached by every outcome.
    const ports::AuditAppendResult appended = append_safely(processing.record);

    if (appended != ports::AuditAppendResult::Ok) {
        // Generic only: no SQL, values, column names, paths, or exception
        // text. The audit failure is never itself audited: there is no second
        // append call site to reach.
        if (auto log = system_log::logger()) {
            log->error("audit persistence failed ({})", ports::to_string(appended));
        }
        if (processing.result.succeeded()) {
            // A successful result may not leave the service unaudited.
            return ServiceResult::failure(ServiceFailure::InternalError);
        }
        // An already-failed request keeps its original outcome: no data was
        // leaving, and replacing the failure would destroy information.
    }

    return processing.result;
}

}  // namespace core
