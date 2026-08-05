#pragma once

#include "core/audit_record.h"

namespace ports {

// Closed result vocabulary. A repository failure is a bare enum, it can
// never carry paths, record contents, OS text, errno strings, or exception
// messages (the same sanitization-by-type rule as every other port).
enum class AuditAppendResult {
    Ok,           // record written AND flushed to the OS stream
    OpenFailure,  // the sink could not be opened (configuration/permissions)
    WriteFailure, // writing or flushing the record failed (I/O)
};

inline const char* to_string(AuditAppendResult result) {
    switch (result) {
        case AuditAppendResult::Ok:
            return "OK";
        case AuditAppendResult::OpenFailure:
            return "OPEN_FAILURE";
        case AuditAppendResult::WriteFailure:
            return "WRITE_FAILURE";
    }
    return "WRITE_FAILURE";
}

// Persists audit records. Implementations must not throw, every failure
// is reported through AuditAppendResult (house rule: failures cross ports
// as values). Ok is returned only after the record has been written and
// flushed to the OS stream; this is NOT an fsync-level durability claim.
// Append is not retried by callers in the current scope.
class IAuditRepository {
public:
    virtual ~IAuditRepository() = default;
    virtual AuditAppendResult append(const core::AuditRecord& record) = 0;
};

}  // namespace ports
