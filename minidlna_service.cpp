/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) Jarosław Pelczar <jarek@jpelczar.com>
 */

#include "minidlna_service.h"
#include "log.h"
#include "upnpglobalvars.h"
#include <spdlog/fmt/ostr.h>

minidlna_service::minidlna_service(size_t num_threads)
    : m_thread_pool(num_threads) {
  for (size_t i = 0; i < num_threads; i++) {
    m_thread_pool.emplace_back(&minidlna_service::run, this);
  }
  m_http_server = std::make_shared<upnp_http_service>(get_io_context());
  m_http_server->start(runtime_vars.port);
}

minidlna_service::~minidlna_service() {
  m_io_context.stop();

  for (auto &td : m_thread_pool)
    td.join();
}

void minidlna_service::run() {
  DPRINTX(E_DEBUG, L_GENERAL, "Starting asio thread {}",
          fmt::streamed(std::this_thread::get_id()));
  auto guard = make_work_guard(m_io_context);
  m_io_context.run();
  DPRINTX(E_DEBUG, L_GENERAL, "Exiting asio thread {}",
          fmt::streamed(std::this_thread::get_id()));
}
void minidlna_service::stop() { m_io_context.stop(); }
