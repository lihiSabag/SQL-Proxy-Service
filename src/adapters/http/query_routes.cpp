#include "adapters/http/query_routes.h"

#include <cstddef>
#include <string>

#include <nlohmann/json.hpp>

#include "core/service_result.h"

namespace http_adapter {

namespace {

// Transport-level guard. Oversized input is
// rejected before the pipeline; it is not a SQL request.
constexpr std::size_t kMaxSqlLength = 64 * 1024;

struct FailureResponse {
    int status;
    const char* code;
    const char* message;
};

// Fixed, generic messages only — never SQL, driver text, values, or names.
// Every policy denial except empty input maps to the same 403 response, so
// rejection reasons cannot be probed from outside.
FailureResponse response_for(core::ServiceFailure failure) {
    switch (failure) {
        case core::ServiceFailure::EmptyInput:
            return {400, "empty_sql", "The 'sql' field must not be empty."};
        case core::ServiceFailure::UnparseableSql:
            return {400, "invalid_sql", "The SQL statement could not be parsed."};
        case core::ServiceFailure::PolicyRejected:
            return {403, "policy_rejected", "The statement was rejected by policy."};
        case core::ServiceFailure::QueryFailed:
            return {400, "query_failed", "The database rejected the statement."};
        case core::ServiceFailure::DatabaseUnavailable:
            return {503, "database_unavailable",
                    "The database is currently unavailable."};
        case core::ServiceFailure::MaskingRefused:
            return {422, "masking_refused",
                    "Results could not be safely masked and were not returned."};
        case core::ServiceFailure::InternalError:
            return {500, "internal_error", "An internal error occurred."};
    }
    return {500, "internal_error", "An internal error occurred."};
}

void send_error(httplib::Response& response, int status, const char* code,
                const char* message) {
    const nlohmann::json body{{"error", code}, {"message", message}};
    response.status = status;
    response.set_content(body.dump(), "application/json");
}

}  // namespace

void handle_query_request(core::ProxyService& proxy, const httplib::Request& request,
                          httplib::Response& response) {
    // Transport-level validation runs BEFORE the pipeline. A malformed
    // request is not a controlled SQL request: it never reaches
    // ProxyService and is never audited.
    const std::string content_type = request.get_header_value("Content-Type");
    if (content_type.rfind("application/json", 0) != 0) {
        send_error(response, 400, "invalid_content_type",
                   "Content-Type must be application/json.");
        return;
    }

    const nlohmann::json body = nlohmann::json::parse(request.body, nullptr, false);
    if (body.is_discarded() || !body.is_object()) {
        send_error(response, 400, "invalid_json",
                   "Request body must be a JSON object.");
        return;
    }

    const auto sql_field = body.find("sql");
    if (sql_field == body.end() || !sql_field->is_string()) {
        send_error(response, 400, "invalid_request",
                   "Request body must contain a string 'sql' field.");
        return;
    }

    const std::string sql = sql_field->get<std::string>();
    if (sql.size() > kMaxSqlLength) {
        send_error(response, 400, "sql_too_large",
                   "The 'sql' field exceeds the maximum accepted length.");
        return;
    }

    // An EMPTY sql string IS a controlled SQL request: it enters the
    // pipeline, is rejected as EMPTY_INPUT, and is audited.
    const core::ServiceResult result = proxy.handle(sql);

    if (!result.succeeded()) {
        const FailureResponse failure = response_for(result.failure_reason());
        send_error(response, failure.status, failure.code, failure.message);
        return;
    }

    // An authorized write returns no rows or columns, only how many rows
    // changed. 200 keeps the single-endpoint contract: 201 would need a
    // Location the proxy cannot produce (RETURNING is never allowed, so the
    // new id is unknown), and 204 would discard the one useful fact.
    if (result.is_write()) {
        const nlohmann::json write_body{
            {"affected_rows", result.write_result().affected_rows}};
        response.status = 200;
        response.set_content(write_body.dump(), "application/json");
        return;
    }

    const core::MaskedQueryResult& masked = result.result();
    nlohmann::json rows = nlohmann::json::array();
    for (const auto& row : masked.rows) {
        nlohmann::json json_row = nlohmann::json::array();
        for (const auto& cell : row) {
            if (cell.has_value()) {
                json_row.push_back(*cell);  // "" stays an empty string
            } else {
                json_row.push_back(nullptr);  // SQL NULL becomes JSON null
            }
        }
        rows.push_back(std::move(json_row));
    }

    // Positional rows keep column order and duplicate column names intact;
    // column metadata survives even when zero rows are returned.
    const nlohmann::json body_out{{"columns", masked.column_names},
                                  {"rows", rows},
                                  {"row_count", masked.rows.size()}};
    response.status = 200;
    response.set_content(body_out.dump(), "application/json");
}

void register_query_routes(httplib::Server& server, core::ProxyService& proxy) {
    server.Post("/query",
                [&proxy](const httplib::Request& request, httplib::Response& response) {
                    handle_query_request(proxy, request, response);
                });
}

}  // namespace http_adapter
