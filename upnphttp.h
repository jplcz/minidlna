/* MiniDLNA project
 *
 * http://sourceforge.net/projects/minidlna/
 *
 * MiniDLNA media server
 * Copyright (C) 2008-2012  Justin Maggard
 *
 * This file is part of MiniDLNA.
 *
 * MiniDLNA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * MiniDLNA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MiniDLNA. If not, see <http://www.gnu.org/licenses/>.
 *
 * Portions of the code from the MiniUPnP project:
 *
 * Copyright (c) 2006-2007, Thomas Bernard
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * The name of the author may not be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __UPNPHTTP_H__
#define __UPNPHTTP_H__

#include <boost/intrusive/list.hpp>
#include <netinet/in.h>
#include <sys/queue.h>

#include "config.h"
#include "minidlnatypes.h"

#include <boost/asio/ip/tcp.hpp>

/* server: HTTP header returned in all HTTP responses : */
#define MINIDLNA_SERVER_STRING                                                 \
  OS_VERSION " DLNADOC/1.50 UPnP/1.0 " SERVER_NAME "/" MINIDLNA_VERSION

/*
 states :
  0 - waiting for data to read
  1 - waiting for HTTP Post Content.
  ...
  >= 100 - to be deleted
*/
enum httpCommands {
  EUnknown = 0,
  EGet,
  EPost,
  EHead,
  ESubscribe,
  EUnSubscribe
};

struct upnphttp : std::enable_shared_from_this<upnphttp> {
  boost::asio::ip::tcp::socket sock;
  struct in_addr clientaddr{}; /* client address */
  int iface = 0;
  int state = 0;
  char HttpVer[16]{};
  /* request */
  char *req_buf = nullptr;
  int req_buflen = 0;
  int req_contentlen = 0;
  int req_contentoff = 0; /* header length */
  enum httpCommands req_command = EUnknown;
  struct client_cache_s *req_client = nullptr;
  const char *req_soapAction = nullptr;
  int req_soapActionLen = 0;
  const char *req_Host = nullptr; /* Host: header */
  int req_HostLen = 0;
  const char *req_Callback = nullptr; /* For SUBSCRIBE */
  int req_CallbackLen = 0;
  const char *req_NT = nullptr;
  int req_NTLen = 0;
  int req_Timeout = 0;
  const char *req_SID = nullptr; /* For UNSUBSCRIBE */
  int req_SIDLen = 0;
  off_t req_RangeStart = 0;
  off_t req_RangeEnd = 0;
  long int req_chunklen = 0;
  uint32_t reqflags = 0;
  /* response */
  char *res_buf = nullptr;
  int res_buflen = 0;
  int res_buf_alloclen = 0;
  uint32_t respflags = 0;
  /*int res_contentlen;*/
  /*int res_contentoff;*/ /* header length */

  upnphttp(boost::asio::ip::tcp::socket s);
  ~upnphttp();

  upnphttp(const upnphttp &) = delete;
  upnphttp &operator=(const upnphttp &) = delete;

  void issue_read();
  void handle_rx(std::size_t size);
  void send_file(int fd, off_t offset, off_t end_offset);

private:
  bool send_next_file_chunk();

private:
  std::array<char, 2048> rx_buffer;
  int sending_fd = -1;
  off_t sending_offset = 0;
  off_t sending_end_offset = 0;
  std::vector<char> sendfile_buffer;
};

#define FLAG_TIMEOUT 0x00000001
#define FLAG_SID 0x00000002
#define FLAG_RANGE 0x00000004
#define FLAG_HOST 0x00000008
#define FLAG_LANGUAGE 0x00000010

#define FLAG_INVALID_REQ 0x00000040
#define FLAG_HTML 0x00000080

#define FLAG_CHUNKED 0x00000100
#define FLAG_TIMESEEK 0x00000200
#define FLAG_REALTIMEINFO 0x00000400
#define FLAG_PLAYSPEED 0x00000800
#define FLAG_XFERSTREAMING 0x00001000
#define FLAG_XFERINTERACTIVE 0x00002000
#define FLAG_XFERBACKGROUND 0x00004000
#define FLAG_CAPTION 0x00008000

#ifndef MSG_MORE
#define MSG_MORE 0
#endif

/* New_upnphttp() */
std::shared_ptr<upnphttp> New_upnphttp(boost::asio::ip::tcp::socket s);

/* BuildHeader_upnphttp()
 * build the header for the HTTP Response
 * also allocate the buffer for body data */
void BuildHeader_upnphttp(struct upnphttp *h, int respcode, const char *respmsg,
                          int bodylen);

/* BuildResp_upnphttp()
 * fill the res_buf buffer with the complete
 * HTTP 200 OK response from the body passed as argument */
void BuildResp_upnphttp(struct upnphttp *, const char *, int);

/* BuildResp2_upnphttp()
 * same but with given response code/message */
void BuildResp2_upnphttp(struct upnphttp *h, int respcode, const char *respmsg,
                         const char *body, int bodylen);

void SendResp_upnphttp_and_finish(struct upnphttp *h);

/* Error messages */
void Send500(struct upnphttp *);
void Send501(struct upnphttp *);

#endif
