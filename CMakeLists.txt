cmake_minimum_required(VERSION 3.25)
project(minidlna)

include(CheckSymbolExists)
include(CheckSourceCompiles)
include(GNUInstallDirs)
include(cmake/get_cpm.cmake)

find_package(Threads REQUIRED)
find_package(PkgConfig)

set(OS_URL
    "https://github.com/jplcz/minidlna"
    CACHE STRING "")
set(ROOTDEV_MANUFACTURER
    "Jaroslaw Pelczar"
    CACHE STRING "")
set(ROOTDEV_MANUFACTURERURL
    "https://github.com/jplcz/minidlna"
    CACHE STRING "")
set(ROOTDEV_MODELNAME
    "Windows Media Connect compatible (MiniDLNA)"
    CACHE STRING "")
set(ROOTDEV_MODELDESCRIPTION "MiniDLNA on ${CMAKE_SYSTEM_NAME}")
set(ROOTDEV_MODELURL
    "${OS_URL}"
    CACHE STRING "")
set(OS_VERSION CACHE STRING "")
set(DEFAULT_LOG_PATH
    "/var/log"
    CACHE STRING "")
set(DEFAULT_DB_PATH
    "/var/cache/minidlna"
    CACHE STRING "")
set(OS_NAME
    ""
    CACHE STRING "")

if(OS_VERSION STREQUAL "")
  execute_process(
    COMMAND uname -r
    OUTPUT_VARIABLE OS_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

if(OS_NAME STREQUAL "")
  execute_process(
    COMMAND uname -s
    OUTPUT_VARIABLE OS_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

check_symbol_exists(clock_gettime "time.h" HAVE_CLOCK_GETTIME)
check_symbol_exists(kqueue "sys/event.h" HAVE_KQUEUE)

check_source_compiles(
  C
  "
    #include <netinet/in.h>

    int main(void) {
        struct ip_mreqn mreq;
        mreq.imr_address.s_addr = 0;
        return 0;
    }
"
  HAVE_STRUCT_IP_MREQN)

check_source_compiles(
  C
  "
    #include <netinet/in.h>

    int main(void) {
        struct ip_mreq mreq;
        mreq.imr_interface.s_addr = 0;
        return 0;
    }"
  HAVE_STRUCT_IP_MREQ)

check_source_compiles(
  C
  "
    #include <linux/netlink.h>

    int main(void) {
        return 0;
    }
"
  HAVE_NETLINK)

check_source_compiles(
  C
  "
    #include <stdlib.h>
    #include <unistd.h>

    int main(void) {
        return daemon(0, 0);
    }
"
  USE_DAEMON)

check_source_compiles(
  C
  "
    #include <stdlib.h>
    #include <sys/types.h>
    #include <dirent.h>
    int filter(const struct dirent *d) {
        return 0;
    }
    int main(void) {
        struct dirent **ptr = NULL;
        char *name = NULL;
        (void)scandir(name, &ptr, filter, alphasort);
    }"
  SCANDIR_CONST)

check_source_compiles(
  C
  "
    #include <sys/types.h>
    #include <sys/sendfile.h>
    int main(void) {
        int tofd = 0, fromfd = 0;
        off_t offset;
        size_t total = 0;
        ssize_t nwritten = sendfile(tofd, fromfd, &offset, total);
        return nwritten;
    }"
  HAVE_LINUX_SENDFILE_API)

check_source_compiles(
  C
  "
    #include <stdlib.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/uio.h>
    int main(void) {
        int fd = 0, s = 0;
        off_t offset = 0, len;
        struct sf_hdtr *hdtr = NULL;
        int flags = 0;
        int ret;
        ret = sendfile(fd, s, offset, &len, hdtr, flags);
        return ret;
    }"
  HAVE_DARWIN_SENDFILE_API)

check_source_compiles(
  C
  "
    #include <stdlib.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/uio.h>
    int main(void) {
        int fromfd=0, tofd=0, ret, total=0;
        off_t offset=0, nwritten;
        struct sf_hdtr hdr;
        struct iovec hdtrl;
        hdr.headers = &hdtrl;
        hdr.hdr_cnt = 1;
        hdr.trailers = NULL;
        hdr.trl_cnt = 0;
        hdtrl.iov_base = NULL;
        hdtrl.iov_len = 0;
        ret = sendfile(fromfd, tofd, offset, total, &hdr, &nwritten, 0);
        return 0;
    }"
  HAVE_DARWIN_SENDFILE_API)

check_source_compiles(
  C
  "
    #include <sys/inotify.h>

    int main(void) {
        return 0;
    }"
  HAVE_SYS_INOTIFY_H)

if(HAVE_SYS_INOTIFY_H)
  set(HAVE_INOTIFY ON)
endif()

option(TIVO_SUPPORT "whether to enable TiVo support" OFF)
option(NETGEAR "whether to enable generic NETGEAR device support" OFF)
option(READYNAS "whether to enable generic NETGEAR device support" OFF)

if(NETGEAR)
  set(OS_URL "http://www.netgear.com/")
  set(ROOTDEV_MANUFACTURERURL "http://www.netgear.com/")
  set(ROOTDEV_MANUFACTURER "NETGEAR")
  set(ROOTDEV_MODELNAME "Windows Media Connect compatible (ReadyDLNA)")
  set(ROOTDEV_MODELDESCRIPTION "ReadyDLNA")
endif()

if(READYNAS)
  set(NETGEAR ON)
  set(TIVO_SUPPORT ON)
  set(OS_URL "http://www.readynas.com/")
  set(ROOTDEV_MANUFACTURERURL "http://www.netgear.com/")
  set(ROOTDEV_MANUFACTURER "NETGEAR")
  set(ROOTDEV_MODELNAME "Windows Media Connect compatible (ReadyDLNA)")
  set(ROOTDEV_MODELDESCRIPTION "ReadyDLNA")
endif()

if(NOT HAVE_STRUCT_IP_MREQN AND NOT HAVE_STRUCT_IP_MREQ)
  message(FATAL_ERROR "No multicast support")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
  set(OS_URL "http://www.freebsd.org/")
elseif(CMAKE_SYSTEM_NAME MATCHES "kfreebsd")
  set(OS_URL "http://www.debian.org/")
elseif(CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
  set(OS_URL "http://www.openbsd.org/")
endif()

pkg_check_modules(libavutil REQUIRED IMPORTED_TARGET libavutil)
pkg_check_modules(libavcodec REQUIRED IMPORTED_TARGET libavcodec)
pkg_check_modules(libavformat REQUIRED IMPORTED_TARGET libavformat)
pkg_check_modules(libjpeg REQUIRED IMPORTED_TARGET libjpeg)
pkg_check_modules(sqlite3 REQUIRED IMPORTED_TARGET sqlite3)
pkg_check_modules(libexif REQUIRED IMPORTED_TARGET libexif)
pkg_check_modules(id3tag REQUIRED IMPORTED_TARGET id3tag)
pkg_check_modules(ogg REQUIRED IMPORTED_TARGET ogg)
pkg_check_modules(vorbis REQUIRED IMPORTED_TARGET vorbis)
pkg_check_modules(flac REQUIRED IMPORTED_TARGET flac)
pkg_check_modules(vorbisfile IMPORTED_TARGET vorbisfile)
pkg_check_modules(avahi-client IMPORTED_TARGET avahi-client)

add_executable(minidlnad)

if(vorbisfile_FOUND)
  set(HAVE_VORBISFILE ON)
  target_link_libraries(minidlnad PRIVATE PkgConfig::vorbisfile)
endif()

if(avahi-client_FOUND)
  set(HAVE_AVAHI ON)
  target_link_libraries(minidlnad PRIVATE PkgConfig::avahi-client)
endif()

configure_file(config.h.in config.h)

target_sources(
  minidlnad
  PRIVATE minidlna.c
          upnphttp.c
          upnpdescgen.c
          upnpsoap.c
          upnpreplyparse.c
          minixml.c
          clients.c
          getifaddr.c
          process.c
          upnpglobalvars.c
          options.c
          minissdp.c
          uuid.c
          upnpevents.c
          sql.c
          utils.c
          metadata.c
          scanner.c
          monitor.c
          tivo_utils.c
          tivo_beacon.c
          tivo_commands.c
          playlist.c
          image_utils.c
          albumart.c
          log.c
          containers.c
          avahi.c
          tagutils/tagutils.c)

if(HAVE_SYS_INOTIFY_H)
  target_sources(minidlnad PRIVATE monitor_inotify.c)
endif()

if(HAVE_KQUEUE)
  target_sources(minidlnad PRIVATE kqueue.c monitor_kqueue.c)
else()
  target_sources(minidlnad PRIVATE select.c)
endif()

target_include_directories(minidlnad PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(minidlnad PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(minidlnad PRIVATE Threads::Threads)

target_link_libraries(minidlnad PRIVATE PkgConfig::libavutil)
target_link_libraries(minidlnad PRIVATE PkgConfig::libavcodec)
target_link_libraries(minidlnad PRIVATE PkgConfig::libavformat)
target_link_libraries(minidlnad PRIVATE PkgConfig::libjpeg)
target_link_libraries(minidlnad PRIVATE PkgConfig::sqlite3)
target_link_libraries(minidlnad PRIVATE PkgConfig::libexif)
target_link_libraries(minidlnad PRIVATE PkgConfig::id3tag)
target_link_libraries(minidlnad PRIVATE PkgConfig::ogg)
target_link_libraries(minidlnad PRIVATE PkgConfig::vorbis)
target_link_libraries(minidlnad PRIVATE PkgConfig::flac)
