/**
 * @file event.h
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-20 15:08:53
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef _EVENT_H
#define _EVENT_H

// clang-format off
enum event_type { 
  EVENT_NONE = 0, 
  EVENT_WCFI, 
  EVENT_PSD, 
  EVENT_MAX 
};
// clang-format on

struct event_head {
  int pid_;
  event_type type_;
  char name_[32];
  unsigned long ip_;
  unsigned long time_;
};

#endif  // _EVENT_H