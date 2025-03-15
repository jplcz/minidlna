/* MiniDLNA media server
 * Copyright (C) 2008-2010 NETGEAR, Inc. All Rights Reserved.
 *
 * This file is part of MiniDLNA.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __ERR_H__
#define __ERR_H__

#include <spdlog/spdlog.h>

#define E_OFF 0
#define E_FATAL 1
#define E_ERROR 2
#define E_WARN 3
#define E_INFO 4
#define E_DEBUG 5
#define E_MAXDEBUG 6

enum _log_facility {
  L_GENERAL = 0,
  L_ARTWORK,
  L_DB_SQL,
  L_INOTIFY,
  L_SCANNER,
  L_METADATA,
  L_HTTP,
  L_SSDP,
  L_TIVO,
  L_MAX
};

extern int log_level[L_MAX];
extern int log_init(const char *debug);
extern void log_close(void);
extern void log_reopen(void);
extern void log_err(int level, enum _log_facility facility, const char *fname,
                    int lineno, const char *func, const char *fmt, ...)
    __attribute__((__format__(__printf__, 6, 7)));

constexpr inline spdlog::level::level_enum to_spdlog_level(const int level) {
  spdlog::level::level_enum spdlog_level = spdlog::level::trace;

  switch (level) {
  case E_OFF:
    spdlog_level = spdlog::level::trace;
    break;
  case E_FATAL:
    spdlog_level = spdlog::level::critical;
    break;
  case E_ERROR:
    spdlog_level = spdlog::level::err;
    break;
  case E_WARN:
    spdlog_level = spdlog::level::warn;
    break;
  case E_INFO:
    spdlog_level = spdlog::level::info;
    break;
  case E_DEBUG:
    spdlog_level = spdlog::level::debug;
    break;
  default:
    spdlog_level = spdlog::level::trace;
    break;
  }

  return spdlog_level;
}

template <typename... Args>
void cxx_log_err(const int level, enum _log_facility facility,
                 const spdlog::source_loc &loc,
                 spdlog::format_string_t<Args...> fmt, Args &&...args) {
  if (level && level > log_level[facility] && level > E_FATAL)
    return;
  const auto spdlog_level = to_spdlog_level(level);
  spdlog::default_logger_raw()->log(loc, spdlog_level, fmt,
                                    std::forward<Args>(args)...);
  if (level == E_FATAL) {
    spdlog::default_logger_raw()->flush();
    exit(-1);
  }
}

#define DPRINTF(level, facility, fmt, arg...)                                  \
  do {                                                                         \
    log_err(level, facility, __FILE__, __LINE__, __FUNCTION__, fmt, ##arg);    \
  } while (0)
#define DPRINTX(level, facility, fmt, arg...)                                  \
  do {                                                                         \
    cxx_log_err(level, facility,                                               \
                spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},       \
                FMT_STRING(fmt), ##arg);                                       \
  } while (0)

#endif /* __ERR_H__ */
