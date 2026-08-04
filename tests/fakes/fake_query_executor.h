#pragma once

#include <atomic>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "ports/query_executor.h"

namespace fakes {

// Test fake for IQueryExecutor: returns a configured result, records the SQL
// it received, can simulate an unexpected exception, and observes how many
// callers were inside execute() at once so serialization can be asserted.
class FakeQueryExecutor : public ports::IQueryExecutor {
public:
    ports::ExecutionResult result_to_return;
    bool throw_on_execute = false;
    int delay_ms = 0;  // widens the window in which overlap could be observed

    ports::ExecutionResult execute(const std::string& sql) override {
        const int current = ++in_flight_;
        int observed = max_in_flight_.load();
        while (current > observed &&
               !max_in_flight_.compare_exchange_weak(observed, current)) {
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            received_sql_.push_back(sql);
        }
        if (delay_ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        }
        --in_flight_;
        if (throw_on_execute) {
            throw std::runtime_error("simulated executor failure");
        }
        return result_to_return;
    }

    std::vector<std::string> received_sql() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return received_sql_;
    }

    std::size_t call_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return received_sql_.size();
    }

    int max_in_flight() const { return max_in_flight_.load(); }

private:
    mutable std::mutex mutex_;
    std::vector<std::string> received_sql_;
    std::atomic<int> in_flight_{0};
    std::atomic<int> max_in_flight_{0};
};

}  // namespace fakes
