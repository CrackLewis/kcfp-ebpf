/**
* @file psd_event.h
* @author CrackLewis (ghxx040406@163.com)
* @brief 
* @version 0.1.0
* @date 2024-12-20 15:39:27
* 
* @copyright Copyright (c) 2024
* 
*/

#ifndef _PSD_EVENT_H
#define _PSD_EVENT_H

#include "common/event.h"

struct psd_event_t {
  event_head head_;
  unsigned long cred_p_;
  unsigned long cred_hash_;
  unsigned long user_namespace_hash_;
};

#endif 