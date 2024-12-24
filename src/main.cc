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
  unsigned long start, end;

  Logger::set_tag_ena(false);

  signal(SIGINT, sigint_handler);

  wcfi = std::make_unique<WCFI>(BPF_WCFI_PROGRAM);

  if (!wcfi->hooks_init(argc, argv, "wcfi_dump_kstack")) {
    LOG(error) << "WCFI::hooks_init failed" << std::endl;
    exit(1);
  }

  wcfi->stack_init("kstack_table");
  if (!wcfi->ksyms_init()) {
    LOG(error) << "WCFI::ksyms_init failed" << std::endl;
    exit(1);
  }

  wcfi->text(&start, &end);

  std::vector<unsigned long> callsites = read_objdump(
      "/usr/lib/debug/boot/vmlinux-5.15.0-125-generic", start, &end, true);
  if (callsites.size() <= 0) {
    LOG(error) << "read_objdump failed" << std::endl;
    exit(1);
  }

  // refer to main.h BPF_WCFI_PROGRAM
  unsigned long init_stack = read_kallsyms("init_stack");
  wcfi->callsite_bitmap_init(start, end, init_stack);

  for (unsigned long addr : callsites) {
    wcfi->callsite_bitmap_update(addr, WCFI_CALLSITE_FLAG);
  }

  for (auto addr : wcfi->ksyms_list_address(asm_functions)) {
    wcfi->callsite_bitmap_update(addr, WCFI_CALLSITE_FLAG);
  }

  for (auto addr : wcfi->ksyms_list_address(exc_asm_functions)) {
    wcfi->callsite_bitmap_update(addr, WCFI_EXCASM_FLAG);
  }

  if (wcfi->perf_buffer_init("wcfi_events", &wcfi_event_handler)) {
    while (true) {
      wcfi->perf_poll();
    }
  }

  return 0;
}
