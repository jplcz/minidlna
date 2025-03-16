/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) Jarosław Pelczar <jarek@jpelczar.com>
 */

#include "upnp_http_service.h"
#include "log.h"
#include "upnphttp.h"

upnp_http_service::upnp_http_service(boost::asio::io_context &ctx)
    : boost::asio::ip::tcp::acceptor(ctx), m_io_context(ctx),
      m_accept_socket(ctx) {}

upnp_http_service::~upnp_http_service() {}

void upnp_http_service::start(unsigned short port) {
  open(protocol_type::v4());
  boost::asio::socket_base::reuse_address option(true);
  set_option(option);
  bind(endpoint_type(protocol_type::v4(), port));
  listen(16);
  accept_next();
}

void upnp_http_service::accept_next() {
  m_accept_socket = boost::asio::ip::tcp::socket(m_io_context);
  async_accept(m_accept_socket, [self = shared_from_this()](
                                    boost::system::error_code ec) {
    if (ec) {
      DPRINTX(E_ERROR, L_GENERAL, "accept(http): {}", ec.what());
    } else {
      self->socket_accepted(std::move(self->m_accept_socket));
    }
    self->accept_next();
  });
}

void upnp_http_service::socket_accepted(boost::asio::ip::tcp::socket s) {
  boost::system::error_code ec;
  auto remote_ep = s.remote_endpoint(ec);

  if (ec) {
    DPRINTX(E_ERROR, L_GENERAL, "Remote endpoint died while querying: {}",
            ec.what());
    return;
  }

  ec = {};
  std::string remote_name = remote_ep.address().to_string(ec);

  if (ec) {
    DPRINTX(E_ERROR, L_GENERAL, "Could not fetch remote name: {}",
            ec.what());
    return;
  }

  DPRINTX(E_DEBUG, L_GENERAL, "HTTP connection from {}", remote_name);
  auto conn = New_upnphttp(std::move(s));
  conn->issue_read();
}
