#ifndef _RUN_CONFIG_HPP_
#define _RUN_CONFIG_HPP_

#include <string>

struct RunConfig {
    std::string prefix_pattern;
    std::string suffix_pattern;
    std::string output;
    std::string algorithm;
    unsigned long time_offset;
    unsigned long thread_per_block;
    unsigned long gpg_thread;
    unsigned long base_time;
    bool batch_mode;
    std::string checkpoint_file;
    unsigned long checkpoint_interval;
};

#endif
