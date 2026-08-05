#pragma once

#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>

#include <nlohmann/json.hpp>

#include "ports/audit_repository.h"

namespace audit_adapter {

// Deterministic ISO-8601 UTC with millisecond precision:
// YYYY-MM-DDTHH:MM:SS.mmmZ. gmtime_r-based (Linux target), locale- and
// timezone-independent. Formatting lives in the adapter, not the core
// record model. epoch_ms is expected to be non-negative.
std::string format_utc_timestamp(std::int64_t epoch_ms);

// Serializes one AuditRecord to its closed-schema JSON object. Field names
// are compile-time literals; values are enums (via the closed to_string
// tables) and integers — no user-controlled string can appear. Inapplicable
// fields are OMITTED entirely, never emitted as null/empty/zero
// placeholders. Exposed for tests; JsonlAuditRepository uses it internally.
nlohmann::json serialize(const core::AuditRecord& record);

// JSON Lines audit sink: one JSON object + one newline per append.
//
// Guarantees (stated honestly):
//   - append mode; the file is created if missing; existing contents are
//     preserved; a pre-existing malformed line never affects appends
//     (append-only — the file is never read); an empty file is valid;
//   - Ok only after write + flush to the OS stream (no fsync claim);
//   - thread-safe within ONE service process via an instance-owned mutex;
//     no multi-process atomicity, no crash-mid-write recovery (a torn
//     trailing line is possible and tolerated);
//   - no retries; failures are bare enums with no path or OS text.
class JsonlAuditRepository : public ports::IAuditRepository {
public:
    // The path is configuration; it is never echoed in results or logs.
    explicit JsonlAuditRepository(const std::string& file_path);

    ports::AuditAppendResult append(const core::AuditRecord& record) override;

private:
    std::ofstream stream_;
    std::mutex mutex_;
};

}  // namespace audit_adapter
