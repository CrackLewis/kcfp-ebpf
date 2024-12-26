/**
 * @file wcfi.h
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-20 13:49:00
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef _WCFI_H
#define _WCFI_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "wcfi/bpf_wcfi_asmf.h"
#include "wcfi/bpf_wcfi_prog.h"
#include "wcfi/wcfi_event.h"

#define WCFI_CALLSITE_FLAG 0x1
#define WCFI_EXCASM_FLAG 0x2

class WCFI {
 public:
  explicit WCFI(const std::string &kernel_file,
                const std::vector<std::string> &hooks);
  ~WCFI();

  // 初始化wCFI钩子。
  int hooks_init(const std::vector<std::string> &hooks);

  void stack_init(std::string stack);
  std::vector<uintptr_t> get_stack_addr(int id);

  int callsite_bitmap_init(unsigned stext, unsigned etext,
                           unsigned long init_stack);
  void callsite_bitmap_update(unsigned long addr, uint8_t flags);

  int ksyms_init(void);
  void ksyms_refresh(void);
  std::string ksyms_resolve(unsigned long ip);
  std::string ksyms_info(unsigned long ip);
  unsigned long ksyms_resolve_name(const char *module, const char *name);
  std::vector<unsigned long> ksyms_list_address(std::map<std::string, bool>);

  void text(unsigned long *start, unsigned long *end);

  int perf_buffer_init(std::string stack, void (*)(void *, void *, int));
  void perf_poll(void);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

#endif