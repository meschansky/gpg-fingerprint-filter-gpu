#include "checkpoint.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <vector>

extern "C" {
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
}

namespace {
constexpr std::uint32_t kVersion = 1;
const char kMagic[] = "GFFGPU_CHECKPOINT_V1";

class Reader {
private:
    const std::string &buf_;
    std::size_t pos_ = 0;

public:
    explicit Reader(const std::string &buf): buf_(buf) { }

    std::uint32_t u32() {
        if (pos_ + sizeof(std::uint32_t) > buf_.size())
            throw std::runtime_error("checkpoint truncated");
        std::uint32_t value = 0;
        for (int i = 0; i < 4; ++i)
            value |= static_cast<std::uint32_t>(
                static_cast<unsigned char>(buf_[pos_ + i])) << (i * 8);
        pos_ += sizeof(std::uint32_t);
        return value;
    }

    std::uint64_t u64() {
        if (pos_ + sizeof(std::uint64_t) > buf_.size())
            throw std::runtime_error("checkpoint truncated");
        std::uint64_t value = 0;
        for (int i = 0; i < 8; ++i)
            value |= static_cast<std::uint64_t>(
                static_cast<unsigned char>(buf_[pos_ + i])) << (i * 8);
        pos_ += sizeof(std::uint64_t);
        return value;
    }

    bool flag() {
        return u32() != 0;
    }

    std::string str() {
        auto len = u64();
        if (len > std::numeric_limits<std::size_t>::max())
            throw std::runtime_error("checkpoint string too large");
        if (pos_ + len > buf_.size())
            throw std::runtime_error("checkpoint truncated");
        std::string ret = buf_.substr(pos_, static_cast<std::size_t>(len));
        pos_ += static_cast<std::size_t>(len);
        return ret;
    }

    std::vector<std::uint8_t> bytes() {
        auto len = u64();
        if (len > std::numeric_limits<std::size_t>::max())
            throw std::runtime_error("checkpoint blob too large");
        if (pos_ + len > buf_.size())
            throw std::runtime_error("checkpoint truncated");
        std::vector<std::uint8_t> ret(
            buf_.begin() + static_cast<std::ptrdiff_t>(pos_),
            buf_.begin() + static_cast<std::ptrdiff_t>(pos_ + len));
        pos_ += static_cast<std::size_t>(len);
        return ret;
    }
};

void append_u32(std::string &out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<char>((value >> (i * 8)) & 0xff));
}

void append_u64(std::string &out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<char>((value >> (i * 8)) & 0xff));
}

void append_flag(std::string &out, bool value) {
    append_u32(out, value ? 1U : 0U);
}

void append_string(std::string &out, const std::string &value) {
    append_u64(out, value.size());
    out.append(value);
}

void append_bytes(std::string &out, const std::vector<std::uint8_t> &value) {
    append_u64(out, value.size());
    out.append(reinterpret_cast<const char*>(value.data()), value.size());
}

void append_params(
    std::string &out,
    const std::vector<std::vector<std::uint8_t>> &params) {
    append_u64(out, params.size());
    for (const auto &item: params)
        append_bytes(out, item);
}

std::vector<std::vector<std::uint8_t>> read_params(Reader &reader) {
    auto count = reader.u64();
    if (count > std::numeric_limits<std::size_t>::max())
        throw std::runtime_error("checkpoint parameter count too large");

    std::vector<std::vector<std::uint8_t>> params;
    params.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i)
        params.emplace_back(reader.bytes());
    return params;
}

std::string encode(const CheckpointState &state) {
    std::string out;
    out.reserve(4096);
    append_string(out, kMagic);
    append_u32(out, kVersion);

    append_string(out, state.config.prefix_pattern);
    append_string(out, state.config.suffix_pattern);
    append_string(out, state.config.output);
    append_string(out, state.config.algorithm);
    append_u64(out, state.config.time_offset);
    append_u64(out, state.config.thread_per_block);
    append_u64(out, state.config.gpg_thread);
    append_u64(out, state.config.base_time);
    append_flag(out, state.config.batch_mode);

    append_u64(out, state.stats.tested_keys);
    append_u64(out, state.stats.total_candidates);
    append_u64(out, state.stats.matches_found);
    append_u64(out, state.stats.elapsed_ns);

    append_flag(out, state.has_active_key);
    if (state.has_active_key) {
        append_u32(out, state.active_key.pk_algo);
        append_u32(out, state.active_key.creation_time);
        append_params(out, state.active_key.public_params);
        append_params(out, state.active_key.private_params);
    }

    return out;
}

CheckpointState decode(const std::string &data) {
    Reader reader(data);
    CheckpointState state;

    const auto magic = reader.str();
    if (magic != kMagic)
        throw std::runtime_error("invalid checkpoint header");
    if (reader.u32() != kVersion)
        throw std::runtime_error("unsupported checkpoint version");

    state.config.prefix_pattern = reader.str();
    state.config.suffix_pattern = reader.str();
    state.config.output = reader.str();
    state.config.algorithm = reader.str();
    state.config.time_offset = reader.u64();
    state.config.thread_per_block = reader.u64();
    state.config.gpg_thread = reader.u64();
    state.config.base_time = reader.u64();
    state.config.batch_mode = reader.flag();

    state.stats.tested_keys = reader.u64();
    state.stats.total_candidates = reader.u64();
    state.stats.matches_found = reader.u64();
    state.stats.elapsed_ns = reader.u64();

    state.has_active_key = reader.flag();
    if (state.has_active_key) {
        state.active_key.pk_algo = reader.u32();
        state.active_key.creation_time = reader.u32();
        state.active_key.public_params = read_params(reader);
        state.active_key.private_params = read_params(reader);
    }

    return state;
}
}

CheckpointManager::CheckpointManager(const std::string &path, unsigned long interval_sec):
        path_(path),
        interval_(std::chrono::seconds(interval_sec)) {
}

bool CheckpointManager::enabled() const {
    return !path_.empty();
}

bool CheckpointManager::exists() const {
    if (!enabled())
        return false;

    struct stat st;
    return stat(path_.c_str(), &st) == 0;
}

CheckpointState CheckpointManager::load() const {
    if (!enabled())
        throw std::runtime_error("checkpointing not enabled");
    return decode(read_file(path_));
}

void CheckpointManager::save(const CheckpointState &state, bool force) {
    if (!enabled())
        return;

    const auto now = std::chrono::steady_clock::now();
    if (!force && now - last_save_ < interval_)
        return;

    write_file(path_, encode(state));
    last_save_ = now;
}

void CheckpointManager::remove() const {
    if (!enabled())
        return;

    if (unlink(path_.c_str()) != 0 && errno != ENOENT) {
        std::ostringstream err;
        err << "unlink checkpoint failed: " << std::strerror(errno);
        throw std::runtime_error(err.str());
    }
}

void CheckpointManager::write_file(const std::string &path, const std::string &data) {
    std::string tmp_path = path + ".tmp.XXXXXX";
    std::vector<char> tmp_buf(tmp_path.begin(), tmp_path.end());
    tmp_buf.push_back('\0');

    const int fd = mkstemp(tmp_buf.data());
    if (fd < 0) {
        std::ostringstream err;
        err << "open checkpoint failed: " << std::strerror(errno);
        throw std::runtime_error(err.str());
    }
    tmp_path.assign(tmp_buf.data());

    if (fchmod(fd, 0600) != 0) {
        const auto saved_errno = errno;
        close(fd);
        unlink(tmp_path.c_str());
        std::ostringstream err;
        err << "chmod checkpoint failed: " << std::strerror(saved_errno);
        throw std::runtime_error(err.str());
    }

    ssize_t written = 0;
    while (written < static_cast<ssize_t>(data.size())) {
        const ssize_t ret = write(fd, data.data() + written, data.size() - written);
        if (ret < 0) {
            const auto saved_errno = errno;
            close(fd);
            unlink(tmp_path.c_str());
            std::ostringstream err;
            err << "write checkpoint failed: " << std::strerror(saved_errno);
            throw std::runtime_error(err.str());
        }
        written += ret;
    }

    if (fsync(fd) != 0) {
        const auto saved_errno = errno;
        close(fd);
        unlink(tmp_path.c_str());
        std::ostringstream err;
        err << "fsync checkpoint failed: " << std::strerror(saved_errno);
        throw std::runtime_error(err.str());
    }

    if (close(fd) != 0) {
        const auto saved_errno = errno;
        unlink(tmp_path.c_str());
        std::ostringstream err;
        err << "close checkpoint failed: " << std::strerror(saved_errno);
        throw std::runtime_error(err.str());
    }

    if (rename(tmp_path.c_str(), path.c_str()) != 0) {
        const auto saved_errno = errno;
        const bool tmp_exists = access(tmp_path.c_str(), F_OK) == 0;
        unlink(tmp_path.c_str());
        std::ostringstream err;
        err << "rename checkpoint failed: " << std::strerror(saved_errno)
            << " (tmp_exists=" << (tmp_exists ? "yes" : "no")
            << ", dst=" << path << ")";
        throw std::runtime_error(err.str());
    }
}

std::string CheckpointManager::read_file(const std::string &path) {
    std::ifstream fin(path, std::ios::binary);
    if (!fin)
        throw std::runtime_error("failed to open checkpoint file");

    std::ostringstream ss;
    ss << fin.rdbuf();
    if (!fin.good() && !fin.eof())
        throw std::runtime_error("failed to read checkpoint file");
    return ss.str();
}

bool same_resume_config(const RunConfig &lhs, const RunConfig &rhs) {
    return lhs.prefix_pattern == rhs.prefix_pattern &&
           lhs.suffix_pattern == rhs.suffix_pattern &&
           lhs.output == rhs.output &&
           lhs.algorithm == rhs.algorithm &&
           lhs.time_offset == rhs.time_offset &&
           lhs.thread_per_block == rhs.thread_per_block &&
           lhs.gpg_thread == rhs.gpg_thread &&
           lhs.base_time == rhs.base_time &&
           lhs.batch_mode == rhs.batch_mode;
}

std::string describe_resume_mismatch(const RunConfig &lhs, const RunConfig &rhs) {
    if (lhs.prefix_pattern != rhs.prefix_pattern)
        return "prefix pattern";
    if (lhs.suffix_pattern != rhs.suffix_pattern)
        return "suffix pattern";
    if (lhs.output != rhs.output)
        return "output path";
    if (lhs.algorithm != rhs.algorithm)
        return "algorithm";
    if (lhs.time_offset != rhs.time_offset)
        return "time offset";
    if (lhs.thread_per_block != rhs.thread_per_block)
        return "thread-per-block";
    if (lhs.gpg_thread != rhs.gpg_thread)
        return "gpg-thread";
    if (lhs.base_time != rhs.base_time)
        return "base-time";
    if (lhs.batch_mode != rhs.batch_mode)
        return "batch-mode";
    return "";
}
