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
// Copyright (C) 2021-2024, HardenedVault (https://hardenedvault.net)

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

#include "BPF.h"
#include "bcc_syms.h"
#include "bcc_version.h"
#include "common/objdump.h"
#include "wcfi/wcfi.h"

WCFI *wcfi;

void handle_output(void *cb_cookie, void *data, int data_size) {
  auto info = static_cast<wcfi_event_t *>(data);
  auto addrs = wcfi->get_stack_addr(info->kernel_stack_);
  bool log = true;

  if (data_size <= 0) {
    std::cout << "invaild perf event" << std::endl;
    log = true;
  }

  if (!addrs.size()) std::cout << "stack may lost" << std::endl;

  wcfi->ksyms_refresh();

  std::cout << "[" << info->head_.time_ << "]: " << std::endl;
  std::cout << "PID:" << info->head_.pid_ << " (" << info->head_.name_ << ") "
            << std::endl;
  std::cout << "Hook function: " << wcfi->ksyms_resolve(info->head_.ip_) << " ("
            << std::hex << info->head_.ip_ << std::dec << ")" << std::endl;
  std::cout << "Stack pointer: " << std::hex << info->reg_sp_ << " - "
            << info->current_sp_ << std::dec << std::endl;
  std::cout << "Stack dump(" << info->kernel_stack_ << "):" << std::endl;

  for (auto addr : addrs) {
    std::cout << "    0x" << std::hex << addr << std::dec << " "
              << wcfi->ksyms_resolve(addr) << std::endl;
  }
  std::cout << std::endl;

  return;
}

int main(int argc, char **argv) {
  unsigned long start, end;

  wcfi = new WCFI(BPF_WCFI_PROGRAM);

  if (!wcfi->hooks_init(argc, argv, "wcfi_dump_kstack")) {
    std::cerr << "init bpf wcfi hooks failed" << std::endl;
    exit(1);
  }

  wcfi->stack_init("kstack_table");
  if (!wcfi->ksyms_init()) {
    std::cerr << "init bpf wcfi ksyms failed" << std::endl;
    exit(1);
  }

  wcfi->text(&start, &end);

  std::vector<unsigned long> callsites = read_objdump(
      "/usr/lib/debug/boot/vmlinux-5.15.0-125-generic", start, &end, true);
  if (callsites.size() <= 0) {
    std::cerr << "failed init callsite" << std::endl;
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

  if (wcfi->perf_buffer_init("wcfi_events", &handle_output)) {
    while (true) {
      wcfi->perf_poll();
    }
  }

  return 0;
}
