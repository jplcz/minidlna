/* Image manipulation functions
 *
 * Project : minidlna
 * Website : http://sourceforge.net/projects/minidlna/
 * Author  : Justin Maggard
 *
 * MiniDLNA media server
 * Copyright (C) 2009  Justin Maggard
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
#include <inttypes.h>
#include <memory>
#include <vector>

#define ROTATE_NONE 0x0
#define ROTATE_90 0x1
#define ROTATE_180 0x2
#define ROTATE_270 0x4

typedef uint32_t pix;

typedef struct {
  int32_t width;
  int32_t height;
  pix *buf;
} image_s;

int image_get_jpeg_date_xmp(const char *path, char **date);

int image_get_jpeg_resolution(const char *path, int *width, int *height);

std::shared_ptr<image_s> image_new_from_jpeg(const char *path, int is_file,
                                             const uint8_t *ptr, int size,
                                             int scale, int resize);

std::shared_ptr<image_s> image_resize(image_s *src_image, int32_t width,
                                      int32_t height);

struct jpeg_buffer {
  unsigned char *data = nullptr;
  size_t size = 0;

  constexpr jpeg_buffer() noexcept = default;

  ~jpeg_buffer() { free(data); }

  jpeg_buffer(const jpeg_buffer &) = delete;
  jpeg_buffer &operator=(const jpeg_buffer &) = delete;
};

std::shared_ptr<jpeg_buffer> image_save_to_jpeg_buf(image_s *pimage);

char *image_save_to_jpeg_file(image_s *pimage, char *path);
