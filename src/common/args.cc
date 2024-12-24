/**
 * @file args.cc
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-24 19:16:02
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "args.h"

#include <getopt.h>

enum LONGOPT_RETURNS {
  LONGOPT_KERNEL_FILE = 1,
  LONGOPT_CALLSITES = 2,
  LONGOPT_KERNEL_TO_CALLSITES = 3,
  LONGOPT_MAX
};

const static struct option longopts[] = {
    {"help", no_argument, nullptr, 'h'},
    {"version", no_argument, nullptr, 'v'},
    {"kernel", required_argument, nullptr, LONGOPT_KERNEL_FILE},
    {"callsites", required_argument, nullptr, LONGOPT_CALLSITES},
    {"kernel_to_callsites", required_argument, nullptr,
     LONGOPT_KERNEL_TO_CALLSITES},
    {nullptr, 0, nullptr, 0}};

const static char *shortopts = "hv";

const char *help_msg = R"(
Usage: kcfp-ebpf [OPTION]

Options:
  -h, --help                    Show this help message and exit
  -v, --version                 Show version information and exit
  --kernel=FILE                 Specify the kernel file
  --callsites=FILE              Specify the callsites file
  --kernel_to_callsites=FILE    Convert kernel file to callsites file

)";

const char *version_msg = R"(
KCFP-eBPF v0.1.0
Co-Authored by Yijian Zheng, Zhenzhe Zhang, Boyu Li, Hanbo Zhang and Chengyu Bai
At SSPKU
)";

Args::Args(int argc, char **argv) {
  int longind = 1;
  const char *file = nullptr;
  int callsite_mode = 0;
  while (1) {
    // add hooks
    if (argv[longind] && argv[longind][0] != '-') {
      hooks_.push_back(argv[longind]);
      longind++;
      continue;
    }
    int ret = getopt_long(argc, argv, "hv", longopts, &longind);
    if (ret == -1) {
      mode_ = MODE_SHOW_HELP;
      return;
    }
    switch (ret) {
      case 'h': {
        mode_ = MODE_SHOW_HELP;
        return;
      }
      case 'v': {
        mode_ = MODE_SHOW_VERSION;
        return;
      }
      case LONGOPT_KERNEL_FILE: {
        callsite_mode = LONGOPT_KERNEL_FILE;
        mode_ = MODE_MONITORING;
        file = optarg;
        break;
      }
      case LONGOPT_CALLSITES: {
        callsite_mode = LONGOPT_CALLSITES;
        mode_ = MODE_MONITORING;
        file = optarg;
        break;
      }
      case LONGOPT_KERNEL_TO_CALLSITES: {
        callsite_mode = LONGOPT_KERNEL_TO_CALLSITES;
        mode_ = MODE_MONITORING;
        file = optarg;
        break;
      }
      default: {
        mode_ = MODE_SHOW_HELP;
        return;
      }
    }
  }
}