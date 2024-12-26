/**
 * @file objdump.h
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-20 13:54:03
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef _OBJDUMP_H
#define _OBJDUMP_H

#include <string>
#include <vector>

std::vector<unsigned long> read_objdump(const char* objfile,
                                        unsigned long start, unsigned long* end,
                                        bool kcore);
unsigned long read_kallsyms(std::string obj_sym);

#endif  // _OBJDUMP_H