/**
 * @file psd.h
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-20 13:59:00
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef _PSD_H
#define _PSD_H

#include <memory>

#include "psd_event.h"

class PSD {
 public:
  explicit PSD(const char* psd_prog);
  ~PSD();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

#endif  // _PSD_H