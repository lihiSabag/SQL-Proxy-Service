#pragma once

#include <cstdint>
#include <mutex>
#include <string>

#include "core/audit_record.h"
#include "core/data_classifier.h"
#include "core/pii_masker.h"
#include "core/policy_engine.h"
#include "core/service_result.h"
#include "core/sql_analyzer.h"
#include "ports/audit_repository.h"
#include "ports/query_executor.h"

namespace core {

// The central orchestrator: a fixed, synchronous pipeline —
// analyze -> policy -> execute -> classify -> mask -> build AuditRecord ->
// append audit exactly once -> return a typed ServiceResult.
//
// CONCURRENCY: handle() serializes the ENTIRE pipeline behind one
// mutex, so the service processes exactly one request at a time. This is
// deliberate, not an oversight: the query executor opens one connection per
// call with no pool, and cpp-httplib may dispatch handlers concurrently.
// Throughput is explicitly out of scope for this submission; a connection
// pool behind IQueryExecutor is the documented future step.
//
// Dependencies are references — the caller owns lifetimes. SqlAnalyzer is
// injected because it owns the parser (that is how a fake parser reaches the
// pipeline in tests). PolicyEngine, DataClassifier and PiiMasker are
// stateless concretes owned by value: nothing to substitute, three fewer
// constructor parameters.
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
    // and the audit record describing it — a path that forgets the record
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
