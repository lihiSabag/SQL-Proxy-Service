// AuditRecord unit tests: closed enum vocabulary, factory-only
// construction, derived outcome, and the factory contracts that keep a
// record from misrepresenting the pipeline event it audits.

#include <stdexcept>
#include <string>
#include <type_traits>
#include <variant>

#include <gtest/gtest.h>

#include "core/audit_record.h"
#include "ports/audit_repository.h"

namespace {

core::SuccessDetails valid_success() {
    core::SuccessDetails d{core::StatementType::Select, 4, 5, {1, 1, 1}};
    return d;
}

// --- Closed vocabularies ------------------------------------------------------

TEST(AuditRecordTest, AuditOutcomeToStringValues) {
    EXPECT_STREQ(core::to_string(core::AuditOutcome::Success), "SUCCESS");
    EXPECT_STREQ(core::to_string(core::AuditOutcome::ParsingFailure),
                 "PARSING_FAILURE");
    EXPECT_STREQ(core::to_string(core::AuditOutcome::PolicyRejected),
                 "POLICY_REJECTED");
    EXPECT_STREQ(core::to_string(core::AuditOutcome::DatabaseFailure),
                 "DATABASE_FAILURE");
    EXPECT_STREQ(core::to_string(core::AuditOutcome::MaskingRefused),
                 "MASKING_REFUSED");
    EXPECT_STREQ(core::to_string(core::AuditOutcome::InternalFailure),
                 "INTERNAL_FAILURE");
}

TEST(AuditRecordTest, AuxiliaryEnumToStringValues) {
    EXPECT_STREQ(core::to_string(core::DbFailureCategory::ConnectionFailure),
                 "CONNECTION_FAILURE");
    EXPECT_STREQ(core::to_string(core::DbFailureCategory::ExecutionFailure),
                 "EXECUTION_FAILURE");
    EXPECT_STREQ(ports::to_string(ports::AuditAppendResult::Ok), "OK");
    EXPECT_STREQ(ports::to_string(ports::AuditAppendResult::OpenFailure),
                 "OPEN_FAILURE");
    EXPECT_STREQ(ports::to_string(ports::AuditAppendResult::WriteFailure),
                 "WRITE_FAILURE");
}

// --- Construction contract -----------------------------------------------------

TEST(AuditRecordTest, NotDefaultConstructibleAndWrongStateAccessThrows) {
    static_assert(!std::is_default_constructible_v<core::AuditRecord>,
                  "AuditRecord must be factory-only");

    const auto record = core::AuditRecord::policy_rejected(
        1000, 7,
        {core::RejectReason::DmlNotAllowed, core::StatementType::Delete, 1});
    EXPECT_NO_THROW(record.policy_rejected_details());
    EXPECT_THROW(record.success_details(), std::bad_variant_access);
    EXPECT_THROW(record.database_failure_details(), std::bad_variant_access);
}

TEST(AuditRecordTest, FactoriesDeriveCorrectOutcomeAndEnvelope) {
    const auto success = core::AuditRecord::success(1234, 1, valid_success());
    EXPECT_EQ(success.outcome(), core::AuditOutcome::Success);
    EXPECT_EQ(success.timestamp_ms(), 1234);
    EXPECT_EQ(success.request_id(), 1u);

    EXPECT_EQ(core::AuditRecord::parsing_failure(1, 2).outcome(),
              core::AuditOutcome::ParsingFailure);
    EXPECT_EQ(core::AuditRecord::policy_rejected(
                  1, 3,
                  {core::RejectReason::EmptyInput, core::StatementType::Unknown,
                   0})
                  .outcome(),
              core::AuditOutcome::PolicyRejected);
    EXPECT_EQ(core::AuditRecord::database_failure(
                  1, 4,
                  {core::DbFailureCategory::ConnectionFailure,
                   core::StatementType::Select})
                  .outcome(),
              core::AuditOutcome::DatabaseFailure);
    EXPECT_EQ(core::AuditRecord::masking_refused(
                  1, 5, {core::StatementType::Select, 2})
                  .outcome(),
              core::AuditOutcome::MaskingRefused);
    EXPECT_EQ(core::AuditRecord::internal_failure(1, 6).outcome(),
              core::AuditOutcome::InternalFailure);
}

// --- Factory validation ---------------------------------------------------------

TEST(AuditRecordTest, PolicyRejectedFactoryRejectsInvalidReasons) {
    // No real rejection reason.
    EXPECT_THROW(core::AuditRecord::policy_rejected(
                     1, 1,
                     {core::RejectReason::None, core::StatementType::Select, 1}),
                 std::invalid_argument);
    EXPECT_THROW(
        core::AuditRecord::policy_rejected(
            1, 1,
            {core::RejectReason::NotEvaluated, core::StatementType::Select, 1}),
        std::invalid_argument);
    // Parser failures are audited ONLY as ParsingFailure — never as
    // PolicyRejected + UNPARSEABLE_SQL (no duplicate representation).
    EXPECT_THROW(core::AuditRecord::policy_rejected(
                     1, 1,
                     {core::RejectReason::UnparseableSql,
                      core::StatementType::Unknown, 1}),
                 std::invalid_argument);
}

TEST(AuditRecordTest, SelectOnlyFactoriesRejectNonSelect) {
    // Success, DatabaseFailure, and MaskingRefused are reachable only for
    // SELECT under the read-only policy.
    core::SuccessDetails bad_success = valid_success();
    bad_success.statement_type = core::StatementType::Insert;
    EXPECT_THROW(core::AuditRecord::success(1, 1, bad_success),
                 std::invalid_argument);

    EXPECT_THROW(core::AuditRecord::database_failure(
                     1, 1,
                     {core::DbFailureCategory::ExecutionFailure,
                      core::StatementType::Drop}),
                 std::invalid_argument);

    EXPECT_THROW(core::AuditRecord::masking_refused(
                     1, 1, {core::StatementType::Update, 3}),
                 std::invalid_argument);
}

}  // namespace
