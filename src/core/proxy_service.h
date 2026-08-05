#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "core/audit_record.h"
#include "core/data_classifier.h"
#include "core/pii_masker.h"
#include "core/policy_engine.h"
#include "core/sql_analyzer.h"
#include "ports/audit_repository.h"
#include "ports/query_executor.h"

namespace core {

// The ONLY result shape allowed to leave ProxyService toward a client.
// Deliberately NOT ports::ExecutionResult: a distinct type makes "a raw
// execution result can never reach the HTTP layer" a compile-time property
// rather than a convention (the HTTP adapter never includes the executor
// port). Rows stay positional, so column order and duplicate column names
// both survive; nullopt is SQL NULL and "" is an empty string.
struct MaskedQueryResult {
    std::vector<std::string> column_names;
    std::vector<std::vector<std::optional<std::string>>> rows;
};

// The outcome of an authorized write. No result set exists, so the only
// thing to report is how many rows changed.
struct WriteResult {
    std::size_t affected_rows = 0;
};

// Coarse, client-safe failure vocabulary, kept separate from RejectReason:
// the audit trail records the precise reason while the client sees only a
// category, so the rule set cannot be mapped by probing.
enum class ServiceFailure {
    EmptyInput,           // empty SQL, audited as PolicyRejected/EMPTY_INPUT
    UnparseableSql,
    PolicyRejected,       // every other typed rejection, generically
    DatabaseUnavailable,
    QueryFailed,
    MaskingRefused,
    InternalError,
};

const char* to_string(ServiceFailure failure);

// Success-or-failure by type: a failure cannot carry a result, so no caller
// can reach data through a failed request. Not default-constructible: a
// default would masquerade as a success the service never produced.
class ServiceResult {
public:
    ServiceResult() = delete;

    static ServiceResult success(MaskedQueryResult result);
    static ServiceResult write_success(WriteResult result);
    static ServiceResult failure(ServiceFailure failure);

    bool succeeded() const;

    // True for a completed write, which carries no rows or columns. Callers
    // must check this before reaching for result(): the two successes have
    // different shapes and neither can be read as the other.
    bool is_write() const;

    // Valid only in the matching state; wrong-state access throws
    // std::bad_variant_access and can never silently yield data.
    const MaskedQueryResult& result() const;
    const WriteResult& write_result() const;
    ServiceFailure failure_reason() const;

private:
    using Value = std::variant<MaskedQueryResult, WriteResult, ServiceFailure>;
    explicit ServiceResult(Value value);

    Value value_;
};

// The central orchestrator. A fixed, synchronous pipeline:
// analyze -> policy -> execute -> classify -> mask -> build AuditRecord ->
// append audit exactly once -> return a typed ServiceResult.
//
// Concurrency: handle() serializes the whole pipeline behind one mutex, so
// exactly one request is processed at a time. The executor opens a
// connection per call with no pool, and cpp-httplib may dispatch handlers
// concurrently.
//
// Dependencies are references; the caller owns lifetimes. SqlAnalyzer is
// injected because it owns the parser. PolicyEngine, DataClassifier and
// PiiMasker are stateless and owned by value.
class ProxyService {
public:
    ProxyService(SqlAnalyzer& analyzer, ports::IQueryExecutor& executor,
                 ports::IAuditRepository& audit);

    // The single public entry point. Event time and the process-local
    // request id are produced internally; every controlled request produces
    // exactly one audit append attempt.
    ServiceResult handle(const std::string& sql);

private:
    // Defined in the .cpp. Both members are non-default-constructible, so
    // every return path out of process() must produce BOTH a client result
    // and the audit record describing it, a path that forgets the record
    // does not compile.
    struct Processing;

    Processing process(const std::string& sql, std::int64_t timestamp_ms,
                       std::uint64_t request_id);
    ports::AuditAppendResult append_safely(const AuditRecord& record);

    SqlAnalyzer& analyzer_;
    ports::IQueryExecutor& executor_;
    ports::IAuditRepository& audit_;
    PolicyEngine policy_;
    DataClassifier classifier_;
    PiiMasker masker_;
    std::uint64_t next_request_id_ = 1;  // guarded by mutex_
    std::mutex mutex_;
};

}  // namespace core
