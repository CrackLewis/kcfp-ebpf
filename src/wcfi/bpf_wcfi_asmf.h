/**
 * @file bpf_wcfi_asmf.h
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-20 13:51:18
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef _BPF_WCFI_ASMF_H
#define _BPF_WCFI_ASMF_H

#include <map>
#include <string>

extern std::map<std::string, bool> asm_functions;
extern std::map<std::string, bool> exc_asm_functions;

#endif  // _BPF_WCFI_ASMF_H