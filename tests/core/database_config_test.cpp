#include <gtest/gtest.h>

#include "config/database_config.h"

TEST(DatabaseConfig, MissingUrlIsInvalid) {
    auto result = config::resolve_database_config(nullptr, nullptr);
    EXPECT_FALSE(result.valid);
    EXPECT_FALSE(result.error.empty());
}

TEST(DatabaseConfig, EmptyUrlIsInvalid) {
    auto result = config::resolve_database_config("", nullptr);
    EXPECT_FALSE(result.valid);
}

TEST(DatabaseConfig, ValidUrlWithDefaultTimeout) {
    auto result = config::resolve_database_config("postgresql://localhost/db", nullptr);
    ASSERT_TRUE(result.valid);
    EXPECT_EQ(result.config.connection_string, "postgresql://localhost/db");
    EXPECT_EQ(result.config.statement_timeout_ms, 5000);
}

TEST(DatabaseConfig, ExplicitTimeoutParsed) {
    auto result = config::resolve_database_config("postgresql://localhost/db", "2500");
    ASSERT_TRUE(result.valid);
    EXPECT_EQ(result.config.statement_timeout_ms, 2500);
}

TEST(DatabaseConfig, EmptyTimeoutIsInvalid) {
    auto result = config::resolve_database_config("postgresql://localhost/db", "");
    EXPECT_FALSE(result.valid);
}

TEST(DatabaseConfig, NonNumericTimeoutIsInvalid) {
    auto result = config::resolve_database_config("postgresql://localhost/db", "abc");
    EXPECT_FALSE(result.valid);
}

TEST(DatabaseConfig, ZeroTimeoutIsInvalid) {
    auto result = config::resolve_database_config("postgresql://localhost/db", "0");
    EXPECT_FALSE(result.valid);
}

TEST(DatabaseConfig, NegativeTimeoutIsInvalid) {
    auto result = config::resolve_database_config("postgresql://localhost/db", "-5");
    EXPECT_FALSE(result.valid);
}

TEST(DatabaseConfig, TrailingGarbageTimeoutIsInvalid) {
    auto result = config::resolve_database_config("postgresql://localhost/db", "5000x");
    EXPECT_FALSE(result.valid);
}

TEST(DatabaseConfig, MaxBoundaryTimeoutIsValid) {
    auto result = config::resolve_database_config("postgresql://localhost/db", "600000");
    ASSERT_TRUE(result.valid);
    EXPECT_EQ(result.config.statement_timeout_ms, 600000);
}

TEST(DatabaseConfig, AboveMaxTimeoutIsInvalid) {
    auto result = config::resolve_database_config("postgresql://localhost/db", "600001");
    EXPECT_FALSE(result.valid);
}

TEST(DatabaseConfig, ErrorsNeverContainTheSuppliedValue) {
    // Credential-secrecy rule: errors name variables, never values.
    auto result = config::resolve_database_config("postgresql://user:secret@host/db", "bogus!");
    ASSERT_FALSE(result.valid);
    EXPECT_EQ(result.error.find("secret"), std::string::npos);
    EXPECT_EQ(result.error.find("bogus"), std::string::npos);
}
