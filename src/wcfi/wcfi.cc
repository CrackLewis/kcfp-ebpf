/**
 * @file wcfi.cc
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-20 17:38:46
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "wcfi.h"

#include <iostream>

#include "BPF.h"
#include "common/log.h"
#include "common/objdump.h"

struct WCFI::Impl {
  std::unique_ptr<ebpf::BPF> bpf_;

  std::vector<std::string> hooks_;

  std::unique_ptr<ebpf::BPFStackTable> stacks_;
  ebpf::BPFPerfBuffer *perf_buffer_;
  std::unique_ptr<ebpf::BPFHashTable<unsigned, uint8_t>> callsite_bitmap_;

  unsigned long kstext_;
  unsigned long ketext_;

  std::unique_ptr<std::vector<unsigned>> callsite_;

  void *ksyms_;
};

WCFI::WCFI(const std::string &kernel_file,
           const std::vector<std::string> &hooks)
    : impl_(new Impl) {
  impl_->bpf_ = std::make_unique<ebpf::BPF>();

  auto res = impl_->bpf_->init(BPF_WCFI_PROGRAM);
  if (!res.ok()) {
    LOG(critical) << "BPF::init failed: " << res.msg() << std::endl;
    exit(1);
  }

  if (!hooks_init(hooks)) {
    LOG(error) << "WCFI::hooks_init failed" << std::endl;
    exit(1);
  }

  stack_init("kstack_table");
  if (!ksyms_init()) {
    LOG(error) << "WCFI::ksyms_init failed" << std::endl;
    exit(1);
  }

  unsigned long start, end;
  text(&start, &end);

  std::vector<unsigned long> callsites =
      read_objdump(kernel_file.data(), start, &end, true);
  if (callsites.size() <= 0) {
    LOG(error) << "read_objdump failed" << std::endl;
    exit(1);
  }

  // refer to main.h BPF_WCFI_PROGRAM
  unsigned long init_stack = read_kallsyms("init_stack");
  callsite_bitmap_init(start, end, init_stack);

  for (unsigned long addr : callsites) {
    callsite_bitmap_update(addr, WCFI_CALLSITE_FLAG);
  }

  for (auto addr : ksyms_list_address(asm_functions)) {
    callsite_bitmap_update(addr, WCFI_CALLSITE_FLAG);
  }

  for (auto addr : ksyms_list_address(exc_asm_functions)) {
    callsite_bitmap_update(addr, WCFI_EXCASM_FLAG);
  }
}

WCFI::~WCFI() {
  // DO NOT delete perf_buffer_ or ksyms_, or a segmentation fault may occur.
}

int WCFI::hooks_init(const std::vector<std::string> &hooks) {
  if (!hooks.size()) {
    LOG(error) << "no kernel function specified" << std::endl;
    return 0;
  }

  impl_->bpf_->get_syscall_fnname("");

  if (1) {
    std::string ostr = "hooks: ";
    int comma = 0;
    for (auto hook : hooks) {
      comma ? (ostr += ", ", 0) : comma = 1;
      ostr += hook;
    }
    LOG(info) << ostr << std::endl;
  }

  if (impl_->bpf_) {
    for (auto func : hooks) {
      auto res = impl_->bpf_->attach_kprobe(func, "wcfi_dump_kstack");
      if (!res.ok()) {
        LOG(error) << "attach: " << res.msg() << std::endl;
        return 0;
      }
    }
  } else {
    LOG(error) << "bpf is invaild" << std::endl;
    return 0;
  }
  return 1;
}

void WCFI::stack_init(std::string stack_name) {
  impl_->stacks_ = std::make_unique<ebpf::BPFStackTable>(
      impl_->bpf_->get_stack_table(stack_name));

  if (!impl_->stacks_)
    LOG(error) << "wcfi stacks: " << stack_name << "init failed" << std::endl;
}

int WCFI::callsite_bitmap_init(unsigned min, unsigned max,
                               unsigned long init_stack) {
  impl_->callsite_bitmap_ =
      std::make_unique<ebpf::BPFHashTable<unsigned, uint8_t>>(
          impl_->bpf_->get_hash_table<unsigned, uint8_t>(
              "wcfi_callsite_bitmap"));

  if (!impl_->callsite_bitmap_)
    LOG(error) << "callsite_bitmap_ init failed" << std::endl;

  auto wcfi_callsite_bitmap_maxmin = new ebpf::BPFHashTable<unsigned, unsigned>(
      impl_->bpf_->get_hash_table<unsigned, unsigned>(
          "wcfi_callsite_bitmap_maxmin"));
  if (!wcfi_callsite_bitmap_maxmin)
    LOG(error) << "wcfi_callsite_bitmap_maxmin init failed" << std::endl;

  auto res =
      wcfi_callsite_bitmap_maxmin->update_value(0xffff, max & 0xffffffff);
  if (!res.ok())
    LOG(error) << "callsite_bitmap max: " << res.msg() << std::endl;

  res = wcfi_callsite_bitmap_maxmin->update_value(0x0, min & 0xffffffff);
  if (!res.ok())
    LOG(error) << "callsite_bitmap min: " << res.msg() << std::endl;

  auto wcfi_init_stack = new ebpf::BPFHashTable<int, unsigned long>(
      impl_->bpf_->get_hash_table<int, unsigned long>("wcfi_init_stack"));
  if (!wcfi_init_stack)
    LOG(error) << "wcfi_init_stack init failed" << std::endl;

  res = wcfi_init_stack->update_value(0x0, init_stack);
  if (!res.ok())
    LOG(error) << "wcfi_init_stack update_value: " << res.msg() << std::endl;

  return 1;
}

void WCFI::callsite_bitmap_update(unsigned long addr, uint8_t new_flag) {
  unsigned idx = (unsigned)(addr & 0xffffffff);
  uint8_t flag = 0;

  if (impl_->callsite_bitmap_) {
    auto res = impl_->callsite_bitmap_->update_value(idx, new_flag);
    if (!res.ok())
      LOG(error) << "set callsite bitmap: " << res.msg() << std::endl;
  } else
    LOG(error) << "set callsite bitmap: callsite bitmap not inited"
               << std::endl;
}

std::vector<uintptr_t> WCFI::get_stack_addr(int id) {
  return impl_->stacks_->get_stack_addr(id);
}

int WCFI::ksyms_init(void) {
  impl_->ksyms_ = bcc_symcache_new(-1, nullptr);

  if (!impl_->ksyms_) {
    LOG(error) << "failed to create symcache" << std::endl;
    return 0;
  }

  impl_->kstext_ = ksyms_resolve_name("", "_stext");

  if (!impl_->kstext_) {
    LOG(error) << "failed to initialize _stext" << std::endl;
    return 0;
  }

  impl_->ketext_ = ksyms_resolve_name("", "_etext");

  if (!impl_->ketext_) {
    LOG(error) << "failed to initialize _etext" << std::endl;
    return 0;
  }

  return 1;
}

void WCFI::ksyms_refresh() {
  if (impl_->ksyms_) bcc_symcache_refresh(impl_->ksyms_);
}

std::string WCFI::ksyms_info(unsigned long ip) {
  bcc_symbol sym;

  if (bcc_symcache_resolve(impl_->ksyms_, ip, &sym) != 0)
    return "[UNKNOWN]";
  else
    return sym.name + std::string("(") +
           /*std::string(sym.offset) +*/ std::string(") ") + std::string("[") +
           sym.module + std::string("]");
}

std::string WCFI::ksyms_resolve(unsigned long ip) {
  bcc_symbol sym;

  if (bcc_symcache_resolve(impl_->ksyms_, ip, &sym) != 0)
    return "[UNKNOWN]";
  else
    return sym.name;
}

void WCFI::text(unsigned long *start, unsigned long *end) {
  if (start && impl_->kstext_ != 0) *start = impl_->kstext_;
  if (end && impl_->ketext_ != 0) *end = impl_->ketext_;
}

unsigned long WCFI::ksyms_resolve_name(const char *modname,
                                       const char *symname) {
  unsigned long addr = 0;

  if (bcc_symcache_resolve_name(impl_->ksyms_, modname, symname, &addr) == 0)
    return addr;
  else
    return 0;
}

std::vector<unsigned long> WCFI::ksyms_list_address(
    std::map<std::string, bool> funcs) {
  std::vector<unsigned long> addrs;

  for (unsigned long ip = impl_->kstext_; ip < impl_->ketext_; ip++) {
    std::string name = ksyms_resolve(ip);
    if (funcs.find(name) != funcs.end()) {
      addrs.push_back(ip);
    }
  }

  return addrs;
}

int WCFI::perf_buffer_init(std::string stack,
                           void (*handle_output)(void *, void *, int)) {
  auto res =
      impl_->bpf_->open_perf_buffer(stack, handle_output, NULL, NULL, 0x1000);

  if (!res.ok()) {
    LOG(error) << res.msg() << std::endl;
    return 0;
  }

  impl_->perf_buffer_ = impl_->bpf_->get_perf_buffer(stack);

  if (!impl_->perf_buffer_) {
    LOG(error) << "BPF::get_perf_buffer failed" << std::endl;
    return 0;
  }

  return 1;
}

void WCFI::perf_poll(void) {
  if (impl_->perf_buffer_ != nullptr) {
    impl_->perf_buffer_->poll(100);
  }
}
