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

// Coarse, client-safe failure vocabulary. Deliberately NOT RejectReason or
// AuditOutcome: the audit trail records the precise reason, while the client
// sees only a category — every policy denial except empty input is
// externally indistinguishable, so SYSTEM_TABLE_ACCESS and
// UNATTRIBUTABLE_PROJECTION cannot be probed for.
enum class ServiceFailure {
    EmptyInput,           // empty SQL — audited as PolicyRejected/EMPTY_INPUT
    UnparseableSql,
    PolicyRejected,       // every other typed rejection, generically
    DatabaseUnavailable,
    QueryFailed,
    MaskingRefused,
    InternalError,
};

const char* to_string(ServiceFailure failure);

// Success-or-failure by type: a failure cannot carry a result, so no caller
// can reach data through a failed request. Not default-constructible — a
// default variant would hold an empty MaskedQueryResult and masquerade as a
// success ProxyService never produced (the MaskingOutcome lesson).
class ServiceResult {
public:
    ServiceResult() = delete;

    static ServiceResult success(MaskedQueryResult result);
    static ServiceResult failure(ServiceFailure failure);

    bool succeeded() const;

    // Valid only in the matching state; wrong-state access throws
    // std::bad_variant_access and can never silently yield data.
    const MaskedQueryResult& result() const;
    ServiceFailure failure_reason() const;

private:
    using Value = std::variant<MaskedQueryResult, ServiceFailure>;
    explicit ServiceResult(Value value);

    Value value_;
};

}  // namespace core
