/**
 * @file args.h
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-24 19:15:06
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef _ARGS_H
#define _ARGS_H

#include <memory>
#include <string>
#include <vector>

class Args {
 public:
  Args(int argc, char** argv);

  enum ProgramMode {
    MODE_ABORT,
    MODE_SHOW_HELP,
    MODE_SHOW_VERSION,
    MODE_MONITORING_BY_KERNEL,
    MODE_MAX
  };

  ProgramMode mode() const;

  const std::vector<std::string>& hooks() const;

  const std::string& kernel_file() const;

 private:
  std::vector<std::string> hooks_;
  ProgramMode mode_ = MODE_MONITORING_BY_KERNEL;
  std::string file_ = "/usr/lib/debug/boot/vmlinux-5.15.0-125-generic";
};

extern const std::string help_msg;
extern const std::string version_msg;

#endif  // _ARGS_H