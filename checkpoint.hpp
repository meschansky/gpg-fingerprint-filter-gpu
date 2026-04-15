#ifndef _CHECKPOINT_HPP_
#define _CHECKPOINT_HPP_

#include <chrono>
#include <string>

#include "gpg_helper.hpp"
#include "run_config.hpp"

struct RunStats {
    std::uint64_t tested_keys = 0;
    std::uint64_t total_candidates = 0;
    std::uint64_t matches_found = 0;
    std::uint64_t elapsed_ns = 0;
};

struct CheckpointState {
    RunConfig config;
    RunStats stats;
    bool has_active_key = false;
    GPGKeySnapshot active_key;
};

class CheckpointManager {
private:
    std::string path_;
    std::chrono::seconds interval_;
    std::chrono::steady_clock::time_point last_save_ = std::chrono::steady_clock::now();

    static void write_file(const std::string &path, const std::string &data);
    static std::string read_file(const std::string &path);

public:
    CheckpointManager(const std::string &path, unsigned long interval_sec);

    bool enabled() const;
    bool exists() const;
    CheckpointState load() const;
    void save(const CheckpointState &state, bool force = false);
    void remove() const;
};

bool same_resume_config(const RunConfig &lhs, const RunConfig &rhs);
std::string describe_resume_mismatch(const RunConfig &lhs, const RunConfig &rhs);

#endif
