/**
 * @file main.cc
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-11-24 13:16:10
 *
 * @copyright Copyright (c) 2024
 *
 */

#include <csignal>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

#include "BPF.h"
#include "bcc_syms.h"
#include "bcc_version.h"
#include "common/args.h"
#include "common/log.h"
#include "common/objdump.h"
#include "wcfi/wcfi.h"

std::unique_ptr<WCFI> wcfi;

void wcfi_event_handler(void *cb_cookie, void *data, int data_size) {
  auto info = static_cast<wcfi_event_t *>(data);
  auto addrs = wcfi->get_stack_addr(info->kernel_stack_);
  bool log = true;

  if (data_size <= 0) {
    LOG(error) << "invaild perf event" << std::endl;
    log = true;
  }

  if (!addrs.size()) LOG(critical) << "stack exception" << std::endl;

  wcfi->ksyms_refresh();

  LOG(wcfi_ev) << "pid=" << info->head_.pid_ << " (" << info->head_.name_
               << ") "
               << "hook=" << wcfi->ksyms_resolve(info->head_.ip_)
               << " stack=" << info->kernel_stack_ << " sp=" << std::hex
               << info->reg_sp_ << " - " << info->current_sp_ << std::dec
               << std::endl;

  int addr_id = 0;
  for (auto addr : addrs) {
    LOG(info) << "addr #" << (addr_id++) << ": 0x" << std::hex << addr
              << std::dec << " " << wcfi->ksyms_resolve(addr) << std::endl;
  }
}

void sigint_handler(int sig) {
  LOG(critical) << "exiting due to signal SIGINT" << std::endl;
  exit(sig);
}

int main(int argc, char **argv) {
  signal(SIGINT, sigint_handler);

  Args args(argc, argv);
  if (args.mode() == Args::MODE_SHOW_HELP) {
    std::cout << help_msg << std::endl;
    exit(0);
  }
  if (args.mode() == Args::MODE_SHOW_VERSION) {
    std::cout << version_msg << std::endl;
    exit(0);
  }
  if (args.mode() != Args::MODE_MONITORING_BY_KERNEL) {
    std::cout << "Invalid arguments" << std::endl;
    exit(EXIT_FAILURE);
  }

  Logger::set_tag_ena(false);

  wcfi = std::make_unique<WCFI>(args.kernel_file(), args.hooks());

  if (!wcfi->perf_buffer_init("wcfi_events", &wcfi_event_handler)) {
    LOG(error) << "WCFI::perf_buffer_init failed" << std::endl;
    exit(EXIT_FAILURE);
  }

  int polls = 10000;
  while (polls--) {
    wcfi->perf_poll();
  }

  return 0;
}
