/* MiniDLNA media server
 * Copyright (C) 2013  NETGEAR
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
 */
#if defined(HAVE_LINUX_SENDFILE_API)

#include <sys/sendfile.h>

ssize_t sys_sendfile(int sock, int sendfd, off_t *offset, off_t len) {
  return sendfile(sock, sendfd, offset, len);
}

#elif defined(HAVE_DARWIN_SENDFILE_API)

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

ssize_t sys_sendfile(int sock, int sendfd, off_t *offset, off_t len) {
  ssize_t ret;

  ret = sendfile(sendfd, sock, *offset, &len, NULL, 0);
  *offset += len;

  return ret;
}

#elif defined(HAVE_FREEBSD_SENDFILE_API)

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

ssize_t sys_sendfile(int sock, int sendfd, off_t *offset, off_t len) {
  int ret;
  size_t nbytes = len;

  ssize_t = sendfile(sendfd, sock, *offset, nbytes, NULL, &len, 0);
  *offset += len;

  return ret;
}

#else

#include <errno.h>

ssize_t sys_sendfile(int sock, int sendfd, off_t *offset, off_t len) {
  errno = EINVAL;
  return -1;
}

#endif
