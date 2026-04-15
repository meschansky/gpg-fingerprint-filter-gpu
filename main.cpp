#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <set>

#include <csignal>
#include <cstring>
#include <cstdint>

extern "C" {
#include <sys/stat.h>
#include <sys/sysinfo.h>
}

#include "key_test.hpp"
#include "gpg_helper.hpp"
#include "checkpoint.hpp"
#include "run_config.hpp"

volatile sig_atomic_t cleanup_flag = 0;

void signal_handler(int sig) {
    (void)sig;
    cleanup_flag = 1;
}

static void merge_resume_config(
        RunConfig &config,
        const RunConfig &checkpoint_config,
        const std::set<std::string> &explicit_args) {
    if (explicit_args.count("algorithm") == 0)
        config.algorithm = checkpoint_config.algorithm;
    if (explicit_args.count("prefix-pattern") == 0)
        config.prefix_pattern = checkpoint_config.prefix_pattern;
    if (explicit_args.count("suffix-pattern") == 0)
        config.suffix_pattern = checkpoint_config.suffix_pattern;
    if (explicit_args.count("output") == 0)
        config.output = checkpoint_config.output;
    if (explicit_args.count("base-time") == 0)
        config.base_time = checkpoint_config.base_time;
    if (explicit_args.count("time-offset") == 0)
        config.time_offset = checkpoint_config.time_offset;
    if (explicit_args.count("thread-per-block") == 0)
        config.thread_per_block = checkpoint_config.thread_per_block;
    if (explicit_args.count("gpg-thread") == 0)
        config.gpg_thread = checkpoint_config.gpg_thread;
    if (explicit_args.count("batch-mode") == 0)
        config.batch_mode = checkpoint_config.batch_mode;
}

int _main(const RunConfig &conf, const std::set<std::string> &explicit_args) {
    signal(SIGINT, signal_handler); 
    signal(SIGTERM, signal_handler); 
    umask(0077);

    CheckpointManager checkpoint(conf.checkpoint_file, conf.checkpoint_interval);
    CheckpointState state;
    state.config = conf;

    if (checkpoint.exists()) {
        state = checkpoint.load();
        auto merged = conf;
        merge_resume_config(merged, state.config, explicit_args);
        if (!same_resume_config(merged, state.config))
            throw std::runtime_error(
                "checkpoint config mismatch: " +
                describe_resume_mismatch(merged, state.config));
        state.config.checkpoint_file = conf.checkpoint_file;
        state.config.checkpoint_interval = conf.checkpoint_interval;
    }

    const int thread_per_block = state.config.thread_per_block;
    const int time_offset = state.config.time_offset;
    const int num_block = (time_offset + thread_per_block - 1) / thread_per_block;

    GPGWorker key_worker(state.config.gpg_thread, state.config.algorithm);
    CudaManager manager(num_block, thread_per_block, time_offset, state.config.base_time);
    manager.load_patterns(state.config.prefix_pattern, state.config.suffix_pattern);

    unsigned long long count = state.stats.total_candidates;
    auto t0 = std::chrono::steady_clock::now() -
              std::chrono::nanoseconds(state.stats.elapsed_ns);
    std::unique_ptr<GPGKey> active_key;

    if (state.has_active_key)
        active_key.reset(new GPGKey(state.active_key));

    while (true) {
        if (cleanup_flag) {
            state.stats.total_candidates = count;
            state.stats.elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - t0).count();
            checkpoint.save(state, true);
            fprintf(stderr, "\nSignal caught! Let's exit...\n");
            break;
        }

        if (!active_key) {
            active_key.reset(new GPGKey(key_worker.recv_key()));
            state.has_active_key = true;
            state.active_key = active_key->snapshot();
            state.stats.total_candidates = count;
            state.stats.elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - t0).count();
            checkpoint.save(state, true);
        }

        manager.test_key(active_key->load_fpr_hash_packet());
        u32 result_time = manager.get_result_time();
        state.stats.tested_keys += 1;

        if (result_time != UINT32_MAX) {
            active_key->set_creation_time(result_time);
            auto packet = active_key->load_seckey_packet();
            // add random to avoid collision
            auto filename = state.config.output + "/" + std::to_string(result_time) +
                            "." + std::to_string(rand()) + ".gpg";
            std::ofstream fout(filename, std::ios::binary);
            fout.write((char*)packet.data(), packet.size());

            // user-id packet
            fout.write("\xb4\x06NONAME", 8);

            puts("\nResult found!");
            printf("GPG key written to %s\n", filename.c_str());
            state.stats.matches_found += 1;
            state.stats.total_candidates = count;
            state.stats.elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - t0).count();
            checkpoint.save(state, true);

            if (!state.config.batch_mode) {
                checkpoint.remove();
                break;
            }
        }

        auto t1 = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = t1 - t0;
        count += time_offset;
        state.has_active_key = false;
        active_key.reset();
        state.stats.total_candidates = count;
        state.stats.elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            t1 - t0).count();
        checkpoint.save(state, false);
        printf("\rSpeed: %.4lf hashes / sec", count / elapsed.count());
    }

    key_worker.shutdown();
    return 0;
}

void print_help(std::map<std::string, std::string> arg_map) {
    printf("  gpg-fingerprint-filter-gpu [OPTIONS] <output>\n\n");
    printf("  <output>                    "
           "Save the secret key(s) to this folder\n");
    printf("  -a, --algorithm <ALGO>      "
           "PGP key algorithm [default: %s]\n",
           arg_map["algorithm"].c_str());
    printf("  -p, --prefix-pattern <PAT>  "
           "Fingerprint prefix filter in custom pattern syntax\n");
    printf("  -s, --suffix-pattern <PAT>  "
           "Fingerprint suffix filter in custom pattern syntax\n");
    printf("  -b, --base-time <N>         "
           "Base key timestamp in UNIX epoch [default: %s]\n",
           "now");
    printf("  -t, --time-offset <N>       "
           "Max key timestamp offset in seconds [default: %s]\n",
           arg_map["time-offset"].c_str());
    printf("  -w, --thread-per-block <N>  "
           "Number of CUDA threads per block [default: %s]\n",
           arg_map["thread-per-block"].c_str());
    printf("  -j, --gpg-thread <N>        "
           "Number of threads to generate keys [default: %s]\n",
           "# of CPUs");
    printf("  -m, --batch-mode <Y/N>      "
           "Continue to generate keys even if a match is found [default: %s]\n",
           "N");
    printf("  -c, --checkpoint-file <P>   "
           "Save resumable checkpoint state to this file\n");
    printf("  -i, --checkpoint-interval <N> "
           "Checkpoint update interval in seconds [default: %s]\n",
           arg_map["checkpoint-interval"].c_str());
    printf("  -h, --help\n");
}

int main(int argc, char* argv[]) {
    const std::string positional_args[] = { "output" };
    const std::string named_args[][2] = {
        { "a", "algorithm" },
        { "p", "prefix-pattern" },
        { "s", "suffix-pattern" },
        { "b", "base-time" },
        { "t", "time-offset" },
        { "w", "thread-per-block" },
        { "j", "gpg-thread" },
        { "m", "batch-mode" },
        { "c", "checkpoint-file" },
        { "i", "checkpoint-interval" },
    };

    // default args
    std::map<std::string, std::string> arg_map_default;
    arg_map_default["algorithm"] = "rsa";
    arg_map_default["base-time"] = std::to_string(time(NULL));
    arg_map_default["time-offset"] = "15552000";
    arg_map_default["thread-per-block"] = "512";
    arg_map_default["gpg-thread"] = std::to_string(std::max(get_nprocs(), 1));
    arg_map_default["batch-mode"] = "N";
    arg_map_default["checkpoint-interval"] = "60";

    auto arg_map = arg_map_default;
    std::string next_key = "";
    std::set<std::string> explicit_args;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_help(arg_map_default);
            return 0;
        }

        if (next_key != "") {
            arg_map[next_key] = arg;
            explicit_args.insert(next_key);
            next_key = "";
            continue;
        }

        for (auto &row: named_args)
            if (arg == "-" + row[0] || arg == "--" + row[1]) {
                next_key = row[1];
                break;
            }

        if (next_key == "") {
            bool parsed = false;

            for (auto &pos_arg: positional_args)
                if (arg_map.count(pos_arg) == 0) {
                    arg_map[pos_arg] = arg;
                    explicit_args.insert(pos_arg);
                    parsed = true;
                    break;
                }

            if (!parsed) {
                fprintf(stderr, "Unknown argument: %s\n\n", arg.c_str());
                print_help(arg_map_default);
                return EXIT_FAILURE;
            }
        }
    }

    RunConfig config;
    try {
        config.output = arg_map.at("output");
        config.algorithm = arg_map.at("algorithm");
        config.prefix_pattern = arg_map.count("prefix-pattern") ? arg_map.at("prefix-pattern") : "";
        config.suffix_pattern = arg_map.count("suffix-pattern") ? arg_map.at("suffix-pattern") : "";
        config.base_time = std::stoul(arg_map.at("base-time"));
        config.time_offset = std::stoul(arg_map.at("time-offset"));
        config.thread_per_block = std::stoul(arg_map.at("thread-per-block"));
        config.gpg_thread = std::stoul(arg_map.at("gpg-thread"));
        config.batch_mode = arg_map.at("batch-mode")[0] == 'Y' ||
                            arg_map.at("batch-mode")[0] == 'y';
        config.checkpoint_file = arg_map.count("checkpoint-file") ? arg_map.at("checkpoint-file") : "";
        config.checkpoint_interval = std::stoul(arg_map.at("checkpoint-interval"));
        if (config.prefix_pattern.empty() && config.suffix_pattern.empty())
            throw std::invalid_argument("missing filters");
    } catch (const std::invalid_argument &e) {
        fprintf(stderr, "Invalid argument value or missing filter!\n\n");
        print_help(arg_map_default);
        return EXIT_FAILURE;
    } catch (const std::out_of_range &e) {
        fprintf(stderr, "Missing argument!\n\n");
        print_help(arg_map_default);
        return EXIT_FAILURE;
    }

    try {
        mkdir(config.output.c_str(), 0700);
        return _main(config, explicit_args);
    } catch (const std::runtime_error &e) {
        // avoid annoying SIGABRT
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
