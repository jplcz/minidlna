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
#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "upnpglobalvars.h"

#include <spdlog/spdlog.h>

#ifdef CONFIG_LOG_SYSTEMD
#include <spdlog/sinks/systemd_sink.h>
#endif

#ifdef CONFIG_LOG_SYSLOG
#include <spdlog/sinks/syslog_sink.h>
#endif

#ifdef CONFIG_LOG_ANDROID
#include <spdlog/sinks/android_sink.h>
#endif

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/dist_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

static std::shared_ptr<spdlog::sinks::basic_file_sink_mt> log_fp_sink;
static const int _default_log_level = E_WARN;
int log_level[L_MAX];

const char *facility_name[] = {"general", "artwork",  "database", "inotify",
                               "scanner", "metadata", "http",     "ssdp",
                               "tivo",    0};

const char *level_name[] = {"off",      // E_OFF
                            "fatal",    // E_FATAL
                            "error",    // E_ERROR
                            "warn",     // E_WARN
                            "info",     // E_INFO
                            "debug",    // E_DEBUG
                            "maxdebug", // E_MAXDEBUG
                            0};

void log_close(void) {
  if (log_fp_sink)
    log_fp_sink->flush();
}

void log_reopen(void) {
  if (log_path[0] && log_fp_sink) {
    log_fp_sink->truncate();
    DPRINTF(E_INFO, L_GENERAL, "Reopened log file\n");
  }
}

int find_matching_name(const char *str, const char *names[]) {
  const char *start;
  int level, c;

  if (!str)
    return -1;

  start = strpbrk(str, ",=");
  c = start ? start - str : strlen(str);
  for (level = 0; names[level] != 0; level++) {
    if (!strncasecmp(names[level], str, c))
      return level;
  }
  return -1;
}

int log_init(const char *debug) {
  int i;

  int level = find_matching_name(debug, level_name);
  int default_log_level = (level == -1) ? _default_log_level : level;

  for (i = 0; i < L_MAX; i++)
    log_level[i] = default_log_level;

  auto primary_sink = std::make_shared<spdlog::sinks::dist_sink_mt>();

  if (!debug) {
    // Use stdio logger in debug launch mode
    // as used will probably want to see messages in console
#ifdef CONFIG_LOG_SYSTEMD
    auto sink = std::make_shared<spdlog::sinks::systemd_sink_mt>("minidlna");
    sink->set_level(spdlog::level::trace);
    primary_sink->add_sink(sink);
#elif defined(CONFIG_LOG_SYSLOG)
    auto sink = std::make_shared<spdlog::sinks::syslog_sink_mt>("minidlna", 0,
                                                                LOG_USER, true);
    sink->set_level(spdlog::level::trace);
    primary_sink->add_sink(sink);
#elif defined(CONFIG_LOG_ANDROID)
    auto sink = std::make_shared<spdlog::sinks::android_sink_mt>("minidlna");
    sink->set_level(spdlog::level::trace);
    primary_sink->add_sink(sink);
#endif
  }

  if (primary_sink->sinks().empty()) {
    auto sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    sink->set_level(spdlog::level::trace);
    primary_sink->add_sink(sink);
  }

  spdlog::set_default_logger(
      std::make_shared<spdlog::logger>("minidlna", primary_sink));

  if (debug) {
    const char *rhs, *lhs, *nlhs;
    int level, facility;

    rhs = nlhs = debug;
    while (rhs && (rhs = strchr(rhs, '='))) {
      rhs++;
      level = find_matching_name(rhs, level_name);
      if (level == -1) {
        DPRINTF(E_WARN, L_GENERAL, "unknown level in debug string: %s", debug);
        continue;
      }

      lhs = nlhs;
      rhs = nlhs = strchr(rhs, ',');
      do {
        if (*lhs == ',')
          lhs++;
        facility = find_matching_name(lhs, facility_name);
        if (facility == -1) {
          DPRINTF(E_WARN, L_GENERAL,
                  "unknown debug facility in debug string: %s", debug);
        } else {
          log_level[facility] = level;
        }

        lhs = strpbrk(lhs, ",=");
      } while (*lhs && *lhs == ',');
    }
  }

  if (log_path[0]) {
    std::string path(log_path);
    path.append("/");
    path.append(LOGFILE_NAME);
    log_fp_sink =
        std::make_shared<spdlog::sinks::basic_file_sink_mt>(path, true);
    log_fp_sink->set_level(spdlog::level::trace);
    primary_sink->add_sink(log_fp_sink);
  }

  return 0;
}

void log_err(int level, enum _log_facility facility, const char *fname,
             int lineno, const char *func, const char *fmt, ...) {
  va_list ap;

  if (level && level > log_level[facility] && level > E_FATAL)
    return;

  spdlog::level::level_enum spdlog_level = to_spdlog_level(level);

  spdlog::source_loc loc;
  loc.filename = fname;
  loc.line = lineno;
  loc.funcname = func;

  char temp_buffer[1024];
  va_start(ap, fmt);
  vsnprintf(temp_buffer, sizeof(temp_buffer), fmt, ap);
  va_end(ap);

  std::string_view to_print(temp_buffer);

  if (to_print.ends_with('\n'))
    to_print.remove_suffix(1);

  spdlog::default_logger_raw()->log(loc, spdlog_level, to_print);

  if (level == E_FATAL) {
    spdlog::default_logger_raw()->flush();
    exit(-1);
  }
}
