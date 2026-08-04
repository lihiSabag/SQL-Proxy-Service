#include "core/service_result.h"

#include <utility>

namespace core {

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

}  // namespace core
