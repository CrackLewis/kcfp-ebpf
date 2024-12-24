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
    MODE_CONVERT_KERNEL_TO_CALLSITES,
    MODE_MONITORING,
    MODE_MAX
  };

  ProgramMode mode() const;

  const std::vector<unsigned long>& callsites() const;

  const std::vector<std::string>& hooks() const;

 private:
  std::vector<unsigned long> callsites_;
  std::vector<std::string> hooks_;
  ProgramMode mode_ = MODE_SHOW_HELP;
};

#endif  // _ARGS_H