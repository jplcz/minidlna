/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) Jarosław Pelczar <jarek@jpelczar.com>
 */
#ifndef MINIDLNA_SERVICE_H
#define MINIDLNA_SERVICE_H

#include <boost/asio.hpp>
#include "upnp_http_service.h"

/**
 * Main class for the MiniDLNA service
 */
struct minidlna_service {
  minidlna_service(size_t num_threads = 1U);
  ~minidlna_service();

  minidlna_service(const minidlna_service &) = delete;
  minidlna_service &operator=(const minidlna_service &) = delete;

  void run();
  void stop();

  boost::asio::io_context &get_io_context() { return m_io_context; }

private:
  boost::asio::io_context m_io_context;
  std::vector<std::thread> m_thread_pool;
  std::shared_ptr<upnp_http_service> m_http_server;
};

#endif // MINIDLNA_SERVICE_H
