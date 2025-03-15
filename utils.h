/* Utility functions
 *
 * Project : minidlna
 * Website : http://sourceforge.net/projects/minidlna/
 * Author  : Justin Maggard
 *
 * MiniDLNA media server
 * Copyright (C) 2008-2017  Justin Maggard
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
#ifndef __UTILS_H__
#define __UTILS_H__

#include <cstring>
#include <dirent.h>
#include <stdarg.h>
#include <sys/param.h>

#include <filesystem>
#include <memory>
#include <string>

#include "minidlnatypes.h"

/* String functions */
/* We really want this one inlined, since it has a major performance impact */
static inline int __attribute__((__format__(__printf__, 2, 3)))
strcatf(struct string_s *str, const char *fmt, ...) {
  int ret;
  int size;
  va_list ap;

  if (str->off >= str->size)
    return 0;

  va_start(ap, fmt);
  size = str->size - str->off;
  ret = vsnprintf(str->data + str->off, size, fmt, ap);
  str->off += MIN(ret, size);
  va_end(ap);

  return ret;
}
static inline void strncpyt(char *dst, const char *src, size_t len) {
  const std::string_view source(src);
  const size_t copy_length = std::min(len - 1, source.size());
  memcpy(dst, source.data(), copy_length);
  dst[copy_length] = '\0';
}
static inline int is_reg([[maybe_unused]] const struct dirent *d) {
#if HAVE_STRUCT_DIRENT_D_TYPE
  return (d->d_type == DT_REG);
#else
  return -1;
#endif
}
static inline int is_dir([[maybe_unused]] const struct dirent *d) {
#if HAVE_STRUCT_DIRENT_D_TYPE
  return (d->d_type == DT_DIR);
#else
  return -1;
#endif
}
int xasprintf(char **strp, const char *fmt, ...)
    __attribute__((__format__(__printf__, 2, 3)));
int ends_with(const char *haystack, const char *needle);
char *trim(char *str);
const char *strstrc(const char *s, const char *p, const char t);
const char *strcasestrc(const char *s, const char *p, const char t);
char *modifyString(char *string, const char *before, const char *after,
                   int noalloc);
char *escape_tag(const char *tag, int force_alloc);
char *unescape_tag(const char *tag, int force_alloc);
char *duration_str(int msec);
char *strip_ext(char *name);

/* Metadata functions */
int is_video(const char *file);
int is_audio(const char *file);
int is_image(const char *file);
int is_playlist(const char *file);
int is_caption(const char *file);
#define is_nfo(file) ends_with(file, ".nfo")
media_types get_media_type(const char *file);
media_types valid_media_types(const char *path);

int is_album_art(const char *name);
file_types resolve_unknown_type(const char *path, media_types dir_type);
const char *mime_to_ext(const char *mime);

/* Others */
int make_dir(char *path, mode_t mode);
unsigned int DJBHash(uint8_t *data, unsigned int len);

/* Timeval manipulations */
void timevaladd(struct timeval *t1, const struct timeval *t2);
void timevalsub(struct timeval *t1, const struct timeval *t2);
#define timevalcmp(tvp, uvp, cmp)                                              \
  (((tvp)->tv_sec == (uvp)->tv_sec) ? ((tvp)->tv_usec cmp(uvp)->tv_usec)       \
                                    : ((tvp)->tv_sec cmp(uvp)->tv_sec))

#endif
