#include <gtest/gtest.h>

#include "config/server_config.h"

TEST(ServerConfig, MissingEnvUsesDefaultPort) {
    auto result = config::resolve_port(nullptr, 8080);
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.port, 8080);
    EXPECT_EQ(result.source, config::PortSource::Default);
}

TEST(ServerConfig, ValidEnvOverridesDefault) {
    auto result = config::resolve_port("9090", 8080);
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.port, 9090);
    EXPECT_EQ(result.source, config::PortSource::Environment);
}

TEST(ServerConfig, MinBoundaryPortIsValid) {
    auto result = config::resolve_port("1", 8080);
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.port, 1);
    EXPECT_EQ(result.source, config::PortSource::Environment);
}

TEST(ServerConfig, MaxBoundaryPortIsValid) {
    auto result = config::resolve_port("65535", 8080);
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.port, 65535);
    EXPECT_EQ(result.source, config::PortSource::Environment);
}

TEST(ServerConfig, NonNumericEnvIsInvalid) {
    auto result = config::resolve_port("abc", 8080);
    EXPECT_FALSE(result.valid);
    EXPECT_FALSE(result.error.empty());
}

TEST(ServerConfig, EmptyEnvIsInvalid) {
    auto result = config::resolve_port("", 8080);
    EXPECT_FALSE(result.valid);
}

TEST(ServerConfig, OutOfRangeEnvIsInvalid) {
    auto result = config::resolve_port("70000", 8080);
    EXPECT_FALSE(result.valid);
}

TEST(ServerConfig, ZeroEnvIsInvalid) {
    auto result = config::resolve_port("0", 8080);
    EXPECT_FALSE(result.valid);
}

TEST(ServerConfig, TrailingGarbageIsInvalid) {
    auto result = config::resolve_port("8080x", 8080);
    EXPECT_FALSE(result.valid);
}

TEST(ServerConfig, NegativeEnvIsInvalid) {
    auto result = config::resolve_port("-1", 8080);
    EXPECT_FALSE(result.valid);
}
