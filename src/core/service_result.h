#pragma once

#include <optional>
#include <string>
#include <variant>
#include <vector>

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

}  // namespace core
