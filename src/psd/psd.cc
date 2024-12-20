/**
 * @file psd.cc
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-20 18:25:41
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "psd.h"

#include "BPF.h"

struct PSD::Impl {
  std::unique_ptr<ebpf::BPF> bpf_;
};

PSD::PSD(const char *psd_prog) : impl_(new Impl) {
  impl_->bpf_ = std::make_unique<ebpf::BPF>();

  auto res = impl_->bpf_->init(psd_prog);
  if (!res.ok()) throw std::runtime_error(res.msg());
}

PSD::~PSD() {}
