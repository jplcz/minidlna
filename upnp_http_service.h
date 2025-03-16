/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) Jarosław Pelczar <jarek@jpelczar.com>
 */

#ifndef UPNP_HTTP_SERVICE_H
#define UPNP_HTTP_SERVICE_H

#include <boost/asio/ip/tcp.hpp>

struct upnp_http_service : boost::asio::ip::tcp::acceptor,
                           std::enable_shared_from_this<upnp_http_service> {
  upnp_http_service(boost::asio::io_context &ctx);
  ~upnp_http_service();

  void start(unsigned short port);

private:
  void accept_next();
  static void socket_accepted(boost::asio::ip::tcp::socket s);

private:
  boost::asio::io_context& m_io_context;
  boost::asio::ip::tcp::socket m_accept_socket;
};

#endif // UPNP_HTTP_SERVICE_H
