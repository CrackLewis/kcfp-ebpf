/**
 * @file log.h
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-20 23:20:14
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef _LOG_H
#define _LOG_H

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>

namespace OC {
static const char* BG_RED = "\033[41m";
static const char* BG_GREEN = "\033[42m";
static const char* BG_YELLOW = "\033[43m";
static const char* BG_BLUE = "\033[44m";
static const char* BG_MAGENTA = "\033[45m";
static const char* BG_CYAN = "\033[46m";
static const char* BG_WHITE = "\033[47m";
static const char* FG_RED = "\033[31m";
static const char* FG_GREEN = "\033[32m";
static const char* FG_YELLOW = "\033[33m";
static const char* FG_BLUE = "\033[34m";
static const char* FG_MAGENTA = "\033[35m";
static const char* FG_CYAN = "\033[36m";
static const char* FG_WHITE = "\033[37m";
static const char* RESET = "\033[0m";
};  // namespace OC

// a singleton class to log messages
class Logger {
 public:
  static std::ostream& critical(const char* func, int line) {
    return instance().log("ALERT", "\033[41m\033[37m", func, line);
  }
  static std::ostream& error(const char* func, int line) {
    return instance().log("ERROR", OC::FG_RED, func, line);
  }
  static std::ostream& warning(const char* func, int line) {
    return instance().log("WARNING", OC::FG_YELLOW, func, line);
  }
  static std::ostream& info(const char* func, int line) {
    return instance().log("INFO", OC::FG_BLUE, func, line);
  }
  // custom
  static std::ostream& wcfi_ev(const char* func, int line) {
    return instance().log("WCFI", "\033[42m\033[37m", func, line);
  }
  static std::ostream& psd_ev(const char* func, int line) {
    return instance().log("PSD", "\033[46m\033[37m", func, line);
  }

  static std::ostream& custom(const char* func, int line, const char* label,
                              const char* oc) {
    return instance().log(label, oc, func, line);
  }

  static void set_datetime_ena(bool enable) {
    instance().datetime_enabled_ = enable;
  }
  static void set_date_ena(bool enable) { instance().date_enabled_ = enable; }
  static void set_tag_ena(bool enable) { instance().tag_enabled_ = enable; }
  static void set_tag_width(unsigned int width) {
    instance().tag_width_ = width;
  }

 private:
  Logger() {}
  ~Logger() {}
  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

  std::ostream& log(const char* level, const char* oc, const char* tag,
                    int line) {
    std::lock_guard<std::mutex> lck(mtx_);

    // output current time in format yyyy-mm-dd hh:mm:ss.us
    if (datetime_enabled_) {
      auto now = std::chrono::system_clock::now();
      auto now_c = std::chrono::system_clock::to_time_t(now);
      auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                        now.time_since_epoch()) %
                    1000000;
      cout_s_ << "["
              << std::put_time(std::localtime(&now_c), date_enabled_
                                                           ? "%Y-%m-%d %H:%M:%S"
                                                           : "%H:%M:%S");
      cout_s_ << "] ";
    }

    if (tag_enabled_) {
      cout_s_ << "[" << std::setw(tag_width_) << tag << ":" << std::setw(4)
              << line << "] ";
    }
    cout_s_ << oc << "[" << std::setw(8) << level << "]" << OC::RESET << ' ';
    return cout_s_;
  }

  static Logger& instance() {
    static Logger logger;
    return logger;
  }

 private:
  std::mutex mtx_;
  bool date_enabled_ = true;
  bool datetime_enabled_ = true;
  bool tag_enabled_ = true;
  unsigned int tag_width_ = 12u;

  std::ostream& cout_s_ = std::cout;
};

#define LOG(level) (Logger::level(__FILE__, __LINE__))

#endif /* UTILS_HPP_ */