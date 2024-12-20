/**
 * @file wcfi_event.h
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-20 16:01:02
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef _WCFI_EVENT_H
#define _WCFI_EVENT_H

#include "common/event.h"

struct wcfi_event_t {
  event_head head_;
  int kernel_stack_;
  unsigned long reg_sp_;
  unsigned long current_sp_;
};

#endif  // _WCFI_EVENT_H