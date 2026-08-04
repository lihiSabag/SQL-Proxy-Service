#pragma once

#include <vector>

#include "ports/audit_repository.h"

namespace fakes {

// Test fake only — no persistence. Records appended AuditRecords in order
// and returns a configurable result, so ProxyService tests can verify the
// audit-always invariant and the audit-failure policy without touching the
// filesystem.
class FakeAuditRepository : public ports::IAuditRepository {
public:
    ports::AuditAppendResult result_to_return = ports::AuditAppendResult::Ok;
    std::vector<core::AuditRecord> appended;

    ports::AuditAppendResult append(const core::AuditRecord& record) override {
        appended.push_back(record);
        return result_to_return;
    }
};

}  // namespace fakes
