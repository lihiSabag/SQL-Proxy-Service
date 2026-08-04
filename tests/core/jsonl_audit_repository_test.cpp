// Serialization + JSONL repository tests. Serialization is checked
// against the exact closed schema per outcome — applicable fields present,
// inapplicable fields OMITTED, and no key outside the whitelist possible.
// Repository tests use unique temporary files, cleaned up per test.

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "adapters/audit/jsonl_audit_repository.h"
#include "core/audit_record.h"
#include "fake_audit_repository.h"
#include "ports/audit_repository.h"

namespace {

core::AuditRecord sample_success() {
    return core::AuditRecord::success(
        1785664800000, 42, {core::StatementType::Select, 4, 5, {1, 1, 1}});
}

std::set<std::string> keys_of(const nlohmann::json& j) {
    std::set<std::string> keys;
    for (auto it = j.begin(); it != j.end(); ++it) {
        keys.insert(it.key());
    }
    return keys;
}

// --- Serialization: exact schema per outcome ---------------------------------

TEST(AuditSerializationTest, SuccessHasExactFields) {
    const nlohmann::json j = audit_adapter::serialize(sample_success());
    EXPECT_EQ(keys_of(j),
              (std::set<std::string>{"timestamp", "request_id", "outcome",
                                     "statement_type", "row_count",
                                     "column_count", "pii_email_columns",
                                     "pii_phone_columns",
                                     "pii_credit_card_columns"}));
    EXPECT_EQ(j["outcome"], "SUCCESS");
    EXPECT_EQ(j["request_id"], 42);
    EXPECT_EQ(j["statement_type"], "SELECT");
    EXPECT_EQ(j["row_count"], 4);
    EXPECT_EQ(j["column_count"], 5);
    EXPECT_EQ(j["pii_email_columns"], 1);
    EXPECT_EQ(j["pii_phone_columns"], 1);
    EXPECT_EQ(j["pii_credit_card_columns"], 1);
}

TEST(AuditSerializationTest, EnvelopeOnlyOutcomes) {
    // ParsingFailure and InternalFailure carry the common fields and
    // NOTHING else — no invented statement info, no open text.
    for (const auto& record :
         {core::AuditRecord::parsing_failure(1000, 7),
          core::AuditRecord::internal_failure(1000, 8)}) {
        const nlohmann::json j = audit_adapter::serialize(record);
        EXPECT_EQ(keys_of(j), (std::set<std::string>{"timestamp", "request_id",
                                                     "outcome"}));
    }
}

TEST(AuditSerializationTest, PolicyRejectedHasExactFields) {
    // Includes the empty-input shape: EMPTY_INPUT with UNKNOWN type is the
    // honest record of what the analyzer produced.
    const auto record = core::AuditRecord::policy_rejected(
        2000, 9,
        {core::RejectReason::EmptyInput, core::StatementType::Unknown, 0});
    const nlohmann::json j = audit_adapter::serialize(record);
    EXPECT_EQ(keys_of(j),
              (std::set<std::string>{"timestamp", "request_id", "outcome",
                                     "reason", "statement_type",
                                     "statement_count"}));
    EXPECT_EQ(j["outcome"], "POLICY_REJECTED");
    EXPECT_EQ(j["reason"], "EMPTY_INPUT");
    EXPECT_EQ(j["statement_type"], "UNKNOWN");
    EXPECT_EQ(j["statement_count"], 0);
}

TEST(AuditSerializationTest, DatabaseFailureHasExactFields) {
    for (core::DbFailureCategory category :
         {core::DbFailureCategory::ConnectionFailure,
          core::DbFailureCategory::ExecutionFailure}) {
        const auto record = core::AuditRecord::database_failure(
            3000, 10, {category, core::StatementType::Select});
        const nlohmann::json j = audit_adapter::serialize(record);
        EXPECT_EQ(keys_of(j),
                  (std::set<std::string>{"timestamp", "request_id", "outcome",
                                         "category", "statement_type"}));
        EXPECT_EQ(j["category"], core::to_string(category));
    }
}

TEST(AuditSerializationTest, MaskingRefusedHasNoPiiFields) {
    const auto record = core::AuditRecord::masking_refused(
        4000, 11, {core::StatementType::Select, 2});
    const nlohmann::json j = audit_adapter::serialize(record);
    EXPECT_EQ(keys_of(j),
              (std::set<std::string>{"timestamp", "request_id", "outcome",
                                     "statement_type", "column_count"}));
    // Classification is incomplete in this outcome; counts could mislead
    // (CONCAT(name, email) would audit as pii_email_columns = 0).
    for (const auto& key : keys_of(j)) {
        EXPECT_EQ(key.rfind("pii_", 0), std::string::npos);
    }
    EXPECT_EQ(j["column_count"], 2);
}

TEST(AuditSerializationTest, ZeroRowZeroPiiSuccessIsValid) {
    const auto record = core::AuditRecord::success(
        5000, 12, {core::StatementType::Select, 0, 1, {0, 0, 0}});
    const nlohmann::json j = audit_adapter::serialize(record);
    // Applicable fields stay present with real zero values — zero is data
    // here, unlike inapplicable fields, which are omitted entirely.
    EXPECT_EQ(j["row_count"], 0);
    EXPECT_EQ(j["pii_email_columns"], 0);
}

TEST(AuditSerializationTest, AllKeysStayInsideClosedSchema) {
    const std::set<std::string> allowed{
        "timestamp",         "request_id",       "outcome",
        "statement_type",    "row_count",        "column_count",
        "pii_email_columns", "pii_phone_columns", "pii_credit_card_columns",
        "reason",            "statement_count",  "category"};
    const std::vector<core::AuditRecord> records = {
        sample_success(),
        core::AuditRecord::parsing_failure(1, 1),
        core::AuditRecord::policy_rejected(
            1, 2,
            {core::RejectReason::DdlNotAllowed, core::StatementType::Drop, 1}),
        core::AuditRecord::database_failure(
            1, 3,
            {core::DbFailureCategory::ExecutionFailure,
             core::StatementType::Select}),
        core::AuditRecord::masking_refused(1, 4,
                                           {core::StatementType::Select, 1}),
        core::AuditRecord::internal_failure(1, 5),
    };
    for (const auto& record : records) {
        for (const auto& key : keys_of(audit_adapter::serialize(record))) {
            EXPECT_TRUE(allowed.count(key) == 1)
                << "unexpected audit field: " << key;
        }
    }
}

TEST(AuditSerializationTest, TimestampFormattingIsDeterministic) {
    EXPECT_EQ(audit_adapter::format_utc_timestamp(0),
              "1970-01-01T00:00:00.000Z");
    EXPECT_EQ(audit_adapter::format_utc_timestamp(123),
              "1970-01-01T00:00:00.123Z");
    EXPECT_EQ(audit_adapter::format_utc_timestamp(86400000),
              "1970-01-02T00:00:00.000Z");
    // 2026-08-02T10:00:00.000Z
    EXPECT_EQ(audit_adapter::format_utc_timestamp(1785664800000),
              "2026-08-02T10:00:00.000Z");
}

// --- JSONL repository ---------------------------------------------------------

class JsonlAuditRepositoryTest : public ::testing::Test {
protected:
    void SetUp() override {
        const auto* info =
            ::testing::UnitTest::GetInstance()->current_test_info();
        dir_ = std::filesystem::temp_directory_path() /
               (std::string("sql_proxy_audit_") + info->name() + "_" +
                std::to_string(static_cast<long>(::getpid())));
        std::filesystem::create_directories(dir_);
        path_ = (dir_ / "audit.jsonl").string();
    }
    void TearDown() override { std::filesystem::remove_all(dir_); }

    std::vector<std::string> lines() const {
        std::vector<std::string> out;
        std::ifstream in(path_);
        std::string line;
        while (std::getline(in, line)) {
            out.push_back(line);
        }
        return out;
    }

    std::filesystem::path dir_;
    std::string path_;
};

TEST_F(JsonlAuditRepositoryTest, AppendWritesOneParsableJsonLine) {
    audit_adapter::JsonlAuditRepository repo(path_);
    EXPECT_EQ(repo.append(sample_success()), ports::AuditAppendResult::Ok);

    const auto written = lines();
    ASSERT_EQ(written.size(), 1u);
    const nlohmann::json j = nlohmann::json::parse(written[0]);
    EXPECT_EQ(j["outcome"], "SUCCESS");
    EXPECT_EQ(j["timestamp"], "2026-08-02T10:00:00.000Z");
    EXPECT_EQ(j["request_id"], 42);
}

TEST_F(JsonlAuditRepositoryTest, MultipleAppendsPreserveCountAndOrder) {
    audit_adapter::JsonlAuditRepository repo(path_);
    EXPECT_EQ(repo.append(core::AuditRecord::parsing_failure(1, 1)),
              ports::AuditAppendResult::Ok);
    EXPECT_EQ(repo.append(core::AuditRecord::internal_failure(2, 2)),
              ports::AuditAppendResult::Ok);
    EXPECT_EQ(repo.append(sample_success()), ports::AuditAppendResult::Ok);

    const auto written = lines();
    ASSERT_EQ(written.size(), 3u);
    EXPECT_EQ(nlohmann::json::parse(written[0])["outcome"], "PARSING_FAILURE");
    EXPECT_EQ(nlohmann::json::parse(written[1])["outcome"], "INTERNAL_FAILURE");
    EXPECT_EQ(nlohmann::json::parse(written[2])["outcome"], "SUCCESS");
}

TEST_F(JsonlAuditRepositoryTest,
       ExistingContentIsPreservedAndMalformedLinesDoNotBlockAppends) {
    {
        std::ofstream out(path_);
        out << "{\"outcome\":\"SUCCESS\"}\n";  // prior valid line
        out << "not-json at all {{{\n";        // torn/malformed line
    }
    audit_adapter::JsonlAuditRepository repo(path_);
    EXPECT_EQ(repo.append(core::AuditRecord::internal_failure(9, 9)),
              ports::AuditAppendResult::Ok);

    const auto written = lines();
    ASSERT_EQ(written.size(), 3u);
    EXPECT_EQ(written[1], "not-json at all {{{");  // untouched
    EXPECT_EQ(nlohmann::json::parse(written[2])["outcome"],
              "INTERNAL_FAILURE");
}

TEST_F(JsonlAuditRepositoryTest, NonexistentDirectoryIsOpenFailure) {
    const std::string bad_path =
        (dir_ / "no_such_subdir" / "audit.jsonl").string();
    audit_adapter::JsonlAuditRepository repo(bad_path);
    // Bare enum only — no path, no OS text, nothing to leak.
    EXPECT_EQ(repo.append(sample_success()),
              ports::AuditAppendResult::OpenFailure);
}

TEST_F(JsonlAuditRepositoryTest, EmptyExistingFileIsValid) {
    { std::ofstream out(path_); }  // create empty file
    audit_adapter::JsonlAuditRepository repo(path_);
    EXPECT_EQ(repo.append(sample_success()), ports::AuditAppendResult::Ok);
    EXPECT_EQ(lines().size(), 1u);
}

TEST_F(JsonlAuditRepositoryTest, FakeRecordsAndReturnsConfiguredResult) {
    fakes::FakeAuditRepository fake;
    EXPECT_EQ(fake.append(sample_success()), ports::AuditAppendResult::Ok);

    fake.result_to_return = ports::AuditAppendResult::WriteFailure;
    EXPECT_EQ(fake.append(core::AuditRecord::parsing_failure(1, 2)),
              ports::AuditAppendResult::WriteFailure);

    ASSERT_EQ(fake.appended.size(), 2u);  // order preserved
    EXPECT_EQ(fake.appended[0].outcome(), core::AuditOutcome::Success);
    EXPECT_EQ(fake.appended[1].outcome(), core::AuditOutcome::ParsingFailure);
}

}  // namespace
