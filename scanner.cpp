/* MiniDLNA media server
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
#include <dirent.h>
#include <inttypes.h>
#include <libgen.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "config.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#endif
#include "libav.h"
#include <sqlite3.h>

#include "albumart.h"
#include "containers.h"
#include "log.h"
#include "metadata.h"
#include "monitor.h"
#include "playlist.h"
#include "scanner.h"
#include "scanner_sqlite.h"
#include "sql.h"
#include "upnpglobalvars.h"
#include "utils.h"

#if SCANDIR_CONST
typedef const struct dirent scan_filter;
#else
typedef struct dirent scan_filter;
#endif
#ifndef AV_LOG_PANIC
#define AV_LOG_PANIC AV_LOG_FATAL
#endif

int valid_cache = 0;

struct virtual_item {
  int64_t objectID;
  char parentID[80];
  char name[256];
};

int64_t get_next_available_id(const char *table, const char *parentID) {
  char *ret, *base;
  int64_t objectID = 0;

  ret = sql_get_text_field(db,
                           "SELECT OBJECT_ID from %s where ID = "
                           "(SELECT max(ID) from %s where PARENT_ID = '%s')",
                           table, table, parentID);
  if (ret) {
    base = strrchr(ret, '$');
    if (base)
      objectID = strtoll(base + 1, NULL, 16) + 1;
    sqlite3_free(ret);
  }

  return objectID;
}

int insert_container(const char *item, const char *rootParent,
                     const char *refID, const char *klass, const char *artist,
                     const char *genre, const char *album_art,
                     int64_t *objectID, int64_t *parentID) {
  char *result;
  char *base;
  int ret = 0;

  result = sql_get_text_field(db,
                              "SELECT OBJECT_ID from OBJECTS o "
                              "left join DETAILS d on (o.DETAIL_ID = d.ID)"
                              " where o.PARENT_ID = '%s'"
                              " and o.NAME like '%q'"
                              " and d.ARTIST %s %Q"
                              " and o.CLASS = 'container.%s' limit 1",
                              rootParent, item, artist ? "like" : "is", artist,
                              klass);
  if (result) {
    base = strrchr(result, '$');
    if (base)
      *parentID = strtoll(base + 1, NULL, 16);
    else
      *parentID = 0;
    *objectID = get_next_available_id("OBJECTS", result);
  } else {
    int64_t detailID = 0;
    *objectID = 0;
    *parentID = get_next_available_id("OBJECTS", rootParent);
    if (refID) {
      result = sql_get_text_field(
          db, "SELECT DETAIL_ID from OBJECTS where OBJECT_ID = %Q", refID);
      if (result)
        detailID = strtoll(result, NULL, 10);
    }
    if (!detailID) {
      detailID =
          GetFolderMetadata(item, NULL, artist, genre,
                            (album_art ? strtoll(album_art, NULL, 10) : 0));
    }
    ret = sql_exec(db,
                   "INSERT into OBJECTS"
                   " (OBJECT_ID, PARENT_ID, REF_ID, DETAIL_ID, CLASS, NAME) "
                   "VALUES"
                   " ('%s$%llX', '%s', %Q, %lld, 'container.%s', '%q')",
                   rootParent, (long long)*parentID, rootParent, refID,
                   (long long)detailID, klass, item);
  }
  sqlite3_free(result);

  return ret;
}

static void insert_containers(const char *name, const char *, const char *refID,
                              const char *klass, int64_t detailID) {
  char sql[128];
  char **result;
  int ret;
  int cols, row;
  int64_t objectID, parentID;

  if (strstr(klass, "imageItem")) {
    char *date_taken = NULL, *camera = NULL;
    static struct virtual_item last_date;
    static struct virtual_item last_cam;
    static struct virtual_item last_camdate;
    static long long last_all_objectID = 0;

    snprintf(sql, sizeof(sql),
             "SELECT DATE, CREATOR from DETAILS where ID = %lld",
             (long long)detailID);
    ret = sql_get_table(db, sql, &result, &row, &cols);
    if (ret == SQLITE_OK) {
      date_taken = result[2];
      camera = result[3];
    }
    if (date_taken)
      date_taken[10] = '\0';
    else
      date_taken = (char *)_("Unknown Date");
    if (!camera)
      camera = (char *)_("Unknown Camera");

    if (valid_cache && strcmp(last_date.name, date_taken) == 0) {
      last_date.objectID++;
      // DEBUG DPRINTF(E_DEBUG, L_SCANNER, "Using last date item: %s/%s/%X\n",
      // last_date.name, last_date.parentID, last_date.objectID);
    } else {
      insert_container(date_taken, IMAGE_DATE_ID, NULL, "album.photoAlbum",
                       NULL, NULL, NULL, &objectID, &parentID);
      sprintf(last_date.parentID, IMAGE_DATE_ID "$%llX",
              (unsigned long long)parentID);
      last_date.objectID = objectID;
      strncpyt(last_date.name, date_taken, sizeof(last_date.name));
      // DEBUG DPRINTF(E_DEBUG, L_SCANNER, "Creating cached date item:
      // %s/%s/%X\n", last_date.name, last_date.parentID, last_date.objectID);
    }
    sql_exec(db,
             "INSERT into OBJECTS"
             " (OBJECT_ID, PARENT_ID, REF_ID, CLASS, DETAIL_ID, NAME) "
             "VALUES"
             " ('%s$%llX', '%s', '%s', '%s', %lld, %Q)",
             last_date.parentID, (long long)last_date.objectID,
             last_date.parentID, refID, klass, (long long)detailID, name);

    if (!valid_cache || strcmp(camera, last_cam.name) != 0) {
      insert_container(camera, IMAGE_CAMERA_ID, NULL, "storageFolder", NULL,
                       NULL, NULL, &objectID, &parentID);
      sprintf(last_cam.parentID, IMAGE_CAMERA_ID "$%llX", (long long)parentID);
      strncpyt(last_cam.name, camera, sizeof(last_cam.name));
      /* Invalidate last_camdate cache */
      last_camdate.name[0] = '\0';
    }
    if (valid_cache && strcmp(last_camdate.name, date_taken) == 0) {
      last_camdate.objectID++;
      // DEBUG DPRINTF(E_DEBUG, L_SCANNER, "Using last camdate item:
      // %s/%s/%s/%X\n", camera, last_camdate.name, last_camdate.parentID,
      // last_camdate.objectID);
    } else {
      insert_container(date_taken, last_cam.parentID, NULL, "album.photoAlbum",
                       NULL, NULL, NULL, &objectID, &parentID);
      sprintf(last_camdate.parentID, "%.63s$%llX", last_cam.parentID,
              (long long)parentID);
      last_camdate.objectID = objectID;
      strncpyt(last_camdate.name, date_taken, sizeof(last_camdate.name));
      // DEBUG DPRINTF(E_DEBUG, L_SCANNER, "Creating cached camdate item:
      // %s/%s/%s/%X\n", camera, last_camdate.name, last_camdate.parentID,
      // last_camdate.objectID);
    }
    sql_exec(db,
             "INSERT into OBJECTS"
             " (OBJECT_ID, PARENT_ID, REF_ID, CLASS, DETAIL_ID, NAME) "
             "VALUES"
             " ('%s$%llX', '%s', '%s', '%s', %lld, %Q)",
             last_camdate.parentID, last_camdate.objectID,
             last_camdate.parentID, refID, klass, (long long)detailID, name);
    /* All Images */
    if (!last_all_objectID) {
      last_all_objectID = get_next_available_id("OBJECTS", IMAGE_ALL_ID);
    }
    sql_exec(db,
             "INSERT into OBJECTS"
             " (OBJECT_ID, PARENT_ID, REF_ID, CLASS, DETAIL_ID, NAME) "
             "VALUES"
             " ('" IMAGE_ALL_ID "$%llX', '" IMAGE_ALL_ID
             "', '%s', '%s', %lld, %Q)",
             last_all_objectID++, refID, klass, (long long)detailID, name);
  } else if (strstr(klass, "audioItem")) {
    snprintf(
        sql, sizeof(sql),
        "SELECT ALBUM, ARTIST, GENRE, ALBUM_ART from DETAILS where ID = %lld",
        (long long)detailID);
    ret = sql_get_table(db, sql, &result, &row, &cols);
    if (ret != SQLITE_OK)
      return;
    if (!row) {
      sqlite3_free_table(result);
      return;
    }
    char *album = result[4], *artist = result[5], *genre = result[6];
    char *album_art = result[7];
    static struct virtual_item last_album;
    static struct virtual_item last_artist;
    static struct virtual_item last_artistAlbum;
    static struct virtual_item last_artistAlbumAll;
    static struct virtual_item last_genre;
    static struct virtual_item last_genreArtist;
    static struct virtual_item last_genreArtistAll;
    static long long last_all_objectID = 0;

    if (album) {
      if (valid_cache && strcmp(album, last_album.name) == 0) {
        last_album.objectID++;
        // DEBUG DPRINTF(E_DEBUG, L_SCANNER, "Using last album item:
        // %s/%s/%X\n", last_album.name, last_album.parentID,
        // last_album.objectID);
      } else {
        strncpyt(last_album.name, album, sizeof(last_album.name));
        insert_container(album, MUSIC_ALBUM_ID, NULL, "album.musicAlbum",
                         artist, genre, album_art, &objectID, &parentID);
        sprintf(last_album.parentID, MUSIC_ALBUM_ID "$%llX",
                (long long)parentID);
        last_album.objectID = objectID;
        // DEBUG DPRINTF(E_DEBUG, L_SCANNER, "Creating cached album item:
        // %s/%s/%X\n", last_album.name, last_album.parentID,
        // last_album.objectID);
      }
      sql_exec(db,
               "INSERT into OBJECTS"
               " (OBJECT_ID, PARENT_ID, REF_ID, CLASS, DETAIL_ID, NAME) "
               "VALUES"
               " ('%s$%llX', '%s', '%s', '%s', %lld, %Q)",
               last_album.parentID, last_album.objectID, last_album.parentID,
               refID, klass, (long long)detailID, name);
    }
    if (artist) {
      if (!valid_cache || strcmp(artist, last_artist.name) != 0) {
        insert_container(artist, MUSIC_ARTIST_ID, NULL, "person.musicArtist",
                         NULL, genre, NULL, &objectID, &parentID);
        sprintf(last_artist.parentID, MUSIC_ARTIST_ID "$%llX",
                (long long)parentID);
        strncpyt(last_artist.name, artist, sizeof(last_artist.name));
        last_artistAlbum.name[0] = '\0';
        /* Add this file to the "- All Albums -" container as well */
        insert_container(_("- All Albums -"), last_artist.parentID, NULL,
                         "album", artist, genre, NULL, &objectID, &parentID);
        sprintf(last_artistAlbumAll.parentID, "%.63s$%llX",
                last_artist.parentID, (long long)parentID);
        last_artistAlbumAll.objectID = objectID;
      } else {
        last_artistAlbumAll.objectID++;
      }
      if (valid_cache && strcmp(album ? album : _("Unknown Album"),
                                last_artistAlbum.name) == 0) {
        last_artistAlbum.objectID++;
        // DEBUG DPRINTF(E_DEBUG, L_SCANNER, "Using last artist/album item:
        // %s/%s/%X\n", last_artist.name, last_artist.parentID,
        // last_artist.objectID);
      } else {
        insert_container(album ? album : _("Unknown Album"),
                         last_artist.parentID,
                         album ? last_album.parentID : NULL, "album.musicAlbum",
                         artist, genre, album_art, &objectID, &parentID);
        sprintf(last_artistAlbum.parentID, "%.63s$%llX", last_artist.parentID,
                (long long)parentID);
        last_artistAlbum.objectID = objectID;
        strncpyt(last_artistAlbum.name, album ? album : _("Unknown Album"),
                 sizeof(last_artistAlbum.name));
        // DEBUG DPRINTF(E_DEBUG, L_SCANNER, "Creating cached artist/album item:
        // %s/%s/%X\n", last_artist.name, last_artist.parentID,
        // last_artist.objectID);
      }
      sql_exec(db,
               "INSERT into OBJECTS"
               " (OBJECT_ID, PARENT_ID, REF_ID, CLASS, DETAIL_ID, NAME) "
               "VALUES"
               " ('%s$%llX', '%s', '%s', '%s', %lld, %Q)",
               last_artistAlbum.parentID, last_artistAlbum.objectID,
               last_artistAlbum.parentID, refID, klass, (long long)detailID,
               name);
      sql_exec(db,
               "INSERT into OBJECTS"
               " (OBJECT_ID, PARENT_ID, REF_ID, CLASS, DETAIL_ID, NAME) "
               "VALUES"
               " ('%s$%llX', '%s', '%s', '%s', %lld, %Q)",
               last_artistAlbumAll.parentID, last_artistAlbumAll.objectID,
               last_artistAlbumAll.parentID, refID, klass, (long long)detailID,
               name);
    }
    if (genre) {
      if (!valid_cache || strcmp(genre, last_genre.name) != 0) {
        insert_container(genre, MUSIC_GENRE_ID, NULL, "genre.musicGenre", NULL,
                         NULL, NULL, &objectID, &parentID);
        sprintf(last_genre.parentID, MUSIC_GENRE_ID "$%llX",
                (long long)parentID);
        strncpyt(last_genre.name, genre, sizeof(last_genre.name));
        /* Add this file to the "- All Artists -" container as well */
        insert_container(_("- All Artists -"), last_genre.parentID, NULL,
                         "person", NULL, genre, NULL, &objectID, &parentID);
        sprintf(last_genreArtistAll.parentID, "%.63s$%llX", last_genre.parentID,
                (long long)parentID);
        last_genreArtistAll.objectID = objectID;
      } else {
        last_genreArtistAll.objectID++;
      }
      if (valid_cache && strcmp(artist ? artist : _("Unknown Artist"),
                                last_genreArtist.name) == 0) {
        last_genreArtist.objectID++;
      } else {
        insert_container(
            artist ? artist : _("Unknown Artist"), last_genre.parentID,
            artist ? last_artist.parentID : NULL, "person.musicArtist", NULL,
            genre, NULL, &objectID, &parentID);
        sprintf(last_genreArtist.parentID, "%.63s$%llX", last_genre.parentID,
                (long long)parentID);
        last_genreArtist.objectID = objectID;
        strncpyt(last_genreArtist.name, artist ? artist : _("Unknown Artist"),
                 sizeof(last_genreArtist.name));
        // DEBUG DPRINTF(E_DEBUG, L_SCANNER, "Creating cached genre/artist item:
        // %s/%s/%X\n", last_genreArtist.name, last_genreArtist.parentID,
        // last_genreArtist.objectID);
      }
      sql_exec(db,
               "INSERT into OBJECTS"
               " (OBJECT_ID, PARENT_ID, REF_ID, CLASS, DETAIL_ID, NAME) "
               "VALUES"
               " ('%s$%llX', '%s', '%s', '%s', %lld, %Q)",
               last_genreArtist.parentID, last_genreArtist.objectID,
               last_genreArtist.parentID, refID, klass, (long long)detailID,
               name);
      sql_exec(db,
               "INSERT into OBJECTS"
               " (OBJECT_ID, PARENT_ID, REF_ID, CLASS, DETAIL_ID, NAME) "
               "VALUES"
               " ('%s$%llX', '%s', '%s', '%s', %lld, %Q)",
               last_genreArtistAll.parentID, last_genreArtistAll.objectID,
               last_genreArtistAll.parentID, refID, klass, (long long)detailID,
               name);
    }
    /* All Music */
    if (!last_all_objectID) {
      last_all_objectID = get_next_available_id("OBJECTS", MUSIC_ALL_ID);
    }
    sql_exec(db,
             "INSERT into OBJECTS"
             " (OBJECT_ID, PARENT_ID, REF_ID, CLASS, DETAIL_ID, NAME) "
             "VALUES"
             " ('" MUSIC_ALL_ID "$%llX', '" MUSIC_ALL_ID
             "', '%s', '%s', %lld, %Q)",
             last_all_objectID++, refID, klass, (long long)detailID, name);
  } else if (strstr(klass, "videoItem")) {
    static long long last_all_objectID = 0;

    /* All Videos */
    if (!last_all_objectID) {
      last_all_objectID = get_next_available_id("OBJECTS", VIDEO_ALL_ID);
    }
    sql_exec(db,
             "INSERT into OBJECTS"
             " (OBJECT_ID, PARENT_ID, REF_ID, CLASS, DETAIL_ID, NAME) "
             "VALUES"
             " ('" VIDEO_ALL_ID "$%llX', '" VIDEO_ALL_ID
             "', '%s', '%s', %lld, %Q)",
             last_all_objectID++, refID, klass, (long long)detailID, name);
    return;
  } else {
    return;
  }
  sqlite3_free_table(result);
  valid_cache = 1;
}

int64_t insert_directory(const char *name, const char *path, const char *base,
                         const char *parentID, int objectID) {
  int64_t detailID = 0;
  static const char klass[] = "container.storageFolder";
  char *result, *p;
  static char last_found[256] = "-1";

  if (strcmp(base, BROWSEDIR_ID) != 0) {
    int found = 0;
    char id_buf[64], parent_buf[64], refID[64];
    char *dir_buf, *dir;

    dir_buf = strdup(path);
    dir = dirname(dir_buf);
    snprintf(refID, sizeof(refID), "%s%s$%X", BROWSEDIR_ID, parentID, objectID);
    snprintf(id_buf, sizeof(id_buf), "%s%s$%X", base, parentID, objectID);
    snprintf(parent_buf, sizeof(parent_buf), "%s%s", base, parentID);
    while (!found) {
      if (valid_cache && strcmp(id_buf, last_found) == 0)
        break;
      if (sql_get_int_field(
              db, "SELECT count(*) from OBJECTS where OBJECT_ID = '%s'",
              id_buf) > 0) {
        strcpy(last_found, id_buf);
        break;
      }
      /* Does not exist.  Need to create, and may need to create parents also */
      result = sql_get_text_field(
          db, "SELECT DETAIL_ID from OBJECTS where OBJECT_ID = '%s'", refID);
      if (result) {
        detailID = strtoll(result, NULL, 10);
        sqlite3_free(result);
      }
      sql_exec(db,
               "INSERT into OBJECTS"
               " (OBJECT_ID, PARENT_ID, REF_ID, DETAIL_ID, CLASS, NAME) "
               "VALUES"
               " ('%s', '%s', %Q, %lld, '%s', '%q')",
               id_buf, parent_buf, refID, detailID, klass,
               strrchr(dir, '/') + 1);
      if ((p = strrchr(id_buf, '$')))
        *p = '\0';
      if ((p = strrchr(parent_buf, '$')))
        *p = '\0';
      if ((p = strrchr(refID, '$')))
        *p = '\0';
      dir = dirname(dir);
    }
    free(dir_buf);
    return 0;
  }

  detailID =
      GetFolderMetadata(name, path, NULL, NULL, find_album_art(path, NULL, 0));
  sql_exec(db,
           "INSERT into OBJECTS"
           " (OBJECT_ID, PARENT_ID, DETAIL_ID, CLASS, NAME) "
           "VALUES"
           " ('%s%s$%X', '%s%s', %lld, '%s', '%q')",
           base, parentID, objectID, base, parentID, detailID, klass, name);

  return detailID;
}

int insert_file(const char *name, const char *path, const char *parentID,
                int object, media_types types) {
  const char *klass;
  char objectID[64];
  int64_t detailID = 0;
  char base[8];
  char *typedir_parentID;
  char *baseid;
  char *objname;
  media_types mtype = get_media_type(name);

  if (mtype == TYPE_IMAGE && (types & TYPE_IMAGE)) {
    if (is_album_art(name))
      return -1;
    strcpy(base, IMAGE_DIR_ID);
    klass = "item.imageItem.photo";
    detailID = GetImageMetadata(path, name);
  } else if (mtype == TYPE_VIDEO && (types & TYPE_VIDEO)) {
    strcpy(base, VIDEO_DIR_ID);
    klass = "item.videoItem";
    detailID = GetVideoMetadata(path, name);
  } else if (mtype == TYPE_PLAYLIST && (types & TYPE_PLAYLIST)) {
    if (insert_playlist(path, name) == 0)
      return 1;
  }
  /* Some file extensions can be used for both audio and video.
  ** Fall back to audio on these files if video parsing fails. */
  if (!detailID && (types & TYPE_AUDIO) && is_audio(name)) {
    strcpy(base, MUSIC_DIR_ID);
    klass = "item.audioItem.musicTrack";
    detailID = GetAudioMetadata(path, name);
  }
  if (!detailID) {
    DPRINTF(E_WARN, L_SCANNER, "Unsuccessful getting details for %s\n", path);
    return -1;
  }

  snprintf(objectID, sizeof(objectID), "%s%s$%X", BROWSEDIR_ID, parentID,
           object);
  objname = strdup(name);
  strip_ext(objname);

  sql_exec(db,
           "INSERT into OBJECTS"
           " (OBJECT_ID, PARENT_ID, CLASS, DETAIL_ID, NAME) "
           "VALUES"
           " ('%s', '%s%s', '%s', %lld, '%q')",
           objectID, BROWSEDIR_ID, parentID, klass, detailID, objname);

  if (*parentID) {
    int typedir_objectID = 0;
    typedir_parentID = strdup(parentID);
    baseid = strrchr(typedir_parentID, '$');
    if (baseid) {
      typedir_objectID = strtol(baseid + 1, NULL, 16);
      *baseid = '\0';
    }
    insert_directory(objname, path, base, typedir_parentID, typedir_objectID);
    free(typedir_parentID);
  }
  sql_exec(db,
           "INSERT into OBJECTS"
           " (OBJECT_ID, PARENT_ID, REF_ID, CLASS, DETAIL_ID, NAME) "
           "VALUES"
           " ('%s%s$%X', '%s%s', '%s', '%s', %lld, '%q')",
           base, parentID, object, base, parentID, objectID, klass, detailID,
           objname);

  insert_containers(objname, path, objectID, klass, detailID);
  free(objname);

  return 0;
}

int CreateDatabase(void) {
  int ret, i;
  const char *containers[] = {"0",
                              "-1",
                              "root",
                              MUSIC_ID,
                              "0",
                              _("Music"),
                              MUSIC_ALL_ID,
                              MUSIC_ID,
                              _("All Music"),
                              MUSIC_GENRE_ID,
                              MUSIC_ID,
                              _("Genre"),
                              MUSIC_ARTIST_ID,
                              MUSIC_ID,
                              _("Artist"),
                              MUSIC_ALBUM_ID,
                              MUSIC_ID,
                              _("Album"),
                              MUSIC_DIR_ID,
                              MUSIC_ID,
                              _("Folders"),
                              MUSIC_PLIST_ID,
                              MUSIC_ID,
                              _("Playlists"),

                              VIDEO_ID,
                              "0",
                              _("Video"),
                              VIDEO_ALL_ID,
                              VIDEO_ID,
                              _("All Video"),
                              VIDEO_DIR_ID,
                              VIDEO_ID,
                              _("Folders"),

                              IMAGE_ID,
                              "0",
                              _("Pictures"),
                              IMAGE_ALL_ID,
                              IMAGE_ID,
                              _("All Pictures"),
                              IMAGE_DATE_ID,
                              IMAGE_ID,
                              _("Date Taken"),
                              IMAGE_CAMERA_ID,
                              IMAGE_ID,
                              _("Camera"),
                              IMAGE_DIR_ID,
                              IMAGE_ID,
                              _("Folders"),

                              BROWSEDIR_ID,
                              "0",
                              _("Browse Folders"),
                              0};

  ret = sql_exec(db, create_objectTable_sqlite);
  if (ret != SQLITE_OK)
    goto sql_failed;
  ret = sql_exec(db, create_detailTable_sqlite);
  if (ret != SQLITE_OK)
    goto sql_failed;
  ret = sql_exec(db, create_albumArtTable_sqlite);
  if (ret != SQLITE_OK)
    goto sql_failed;
  ret = sql_exec(db, create_captionTable_sqlite);
  if (ret != SQLITE_OK)
    goto sql_failed;
  ret = sql_exec(db, create_bookmarkTable_sqlite);
  if (ret != SQLITE_OK)
    goto sql_failed;
  ret = sql_exec(db, create_playlistTable_sqlite);
  if (ret != SQLITE_OK)
    goto sql_failed;
  ret = sql_exec(db, create_settingsTable_sqlite);
  if (ret != SQLITE_OK)
    goto sql_failed;
  ret = sql_exec(db, "INSERT into SETTINGS values ('UPDATE_ID', '0')");
  if (ret != SQLITE_OK)
    goto sql_failed;
  for (i = 0; containers[i]; i = i + 3) {
    ret = sql_exec(
        db,
        "INSERT into OBJECTS (OBJECT_ID, PARENT_ID, DETAIL_ID, CLASS, NAME)"
        " values "
        "('%s', '%s', %lld, 'container.storageFolder', '%q')",
        containers[i], containers[i + 1],
        GetFolderMetadata(containers[i + 2], NULL, NULL, NULL, 0),
        containers[i + 2]);
    if (ret != SQLITE_OK)
      goto sql_failed;
  }
  for (i = 0; magic_containers[i].objectid_match; i++) {
    struct magic_container_s *magic = &magic_containers[i];
    if (!magic->name)
      continue;
    if (sql_get_int_field(db, "SELECT 1 from OBJECTS where OBJECT_ID = '%s'",
                          magic->objectid_match) == 0) {
      char *parent = strdup(magic->objectid_match);
      if (strrchr(parent, '$'))
        *strrchr(parent, '$') = '\0';
      ret = sql_exec(
          db,
          "INSERT into OBJECTS (OBJECT_ID, PARENT_ID, DETAIL_ID, CLASS, NAME)"
          " values "
          "('%s', '%s', %lld, 'container.storageFolder', '%q')",
          magic->objectid_match, parent,
          GetFolderMetadata(_(magic->name), NULL, NULL, NULL, 0),
          _(magic->name));
      free(parent);
      if (ret != SQLITE_OK)
        goto sql_failed;
    }
  }
  sql_exec(db, "create INDEX IDX_OBJECTS_OBJECT_ID ON OBJECTS(OBJECT_ID);");
  sql_exec(db, "create INDEX IDX_OBJECTS_PARENT_ID ON OBJECTS(PARENT_ID);");
  sql_exec(db, "create INDEX IDX_OBJECTS_DETAIL_ID ON OBJECTS(DETAIL_ID);");
  sql_exec(db, "create INDEX IDX_OBJECTS_CLASS ON OBJECTS(CLASS);");
  sql_exec(db, "create INDEX IDX_DETAILS_PATH ON DETAILS(PATH);");
  sql_exec(db, "create INDEX IDX_DETAILS_ID ON DETAILS(ID);");
  sql_exec(db, "create INDEX IDX_ALBUM_ART ON ALBUM_ART(ID);");
  sql_exec(
      db,
      "create INDEX IDX_SCANNER_OPT ON OBJECTS(PARENT_ID, NAME, OBJECT_ID);");

sql_failed:
  if (ret != SQLITE_OK)
    DPRINTF(E_ERROR, L_DB_SQL, "Error creating SQLite3 database!\n");
  return (ret != SQLITE_OK);
}

static inline int filter_hidden(scan_filter *d) {
  return (d->d_name[0] != '.');
}

static int filter_type([[maybe_unused]] scan_filter *d) {
#if HAVE_STRUCT_DIRENT_D_TYPE
  return ((d->d_type == DT_DIR) || (d->d_type == DT_LNK) ||
          (d->d_type == DT_UNKNOWN));
#else
  return 1;
#endif
}

static int filter_a(scan_filter *d) {
  return (filter_hidden(d) &&
          (filter_type(d) ||
           (is_reg(d) && (is_audio(d->d_name) || is_playlist(d->d_name)))));
}

static int filter_av(scan_filter *d) {
  return (filter_hidden(d) &&
          (filter_type(d) ||
           (is_reg(d) && (is_audio(d->d_name) || is_video(d->d_name) ||
                          is_playlist(d->d_name)))));
}

static int filter_ap(scan_filter *d) {
  return (filter_hidden(d) &&
          (filter_type(d) ||
           (is_reg(d) && (is_audio(d->d_name) || is_image(d->d_name) ||
                          is_playlist(d->d_name)))));
}

static int filter_v(scan_filter *d) {
  return (filter_hidden(d) &&
          (filter_type(d) || (is_reg(d) && is_video(d->d_name))));
}

static int filter_vp(scan_filter *d) {
  return (filter_hidden(d) &&
          (filter_type(d) ||
           (is_reg(d) && (is_video(d->d_name) || is_image(d->d_name)))));
}

static int filter_p(scan_filter *d) {
  return (filter_hidden(d) &&
          (filter_type(d) || (is_reg(d) && is_image(d->d_name))));
}

static int filter_avp(scan_filter *d) {
  return (filter_hidden(d) &&
          (filter_type(d) ||
           (is_reg(d) && (is_audio(d->d_name) || is_image(d->d_name) ||
                          is_video(d->d_name) || is_playlist(d->d_name)))));
}

static void ScanDirectory(const char *dir, const char *parent,
                          media_types dir_types) {
  struct dirent **namelist;
  int i, n, startID = 0;
  char *full_path;
  char *name = NULL;
  static long long unsigned int fileno = 0;
  enum file_types type;

  DPRINTF(parent ? E_INFO : E_WARN, L_SCANNER, _("Scanning %s\n"), dir);
  switch (dir_types) {
  case ALL_MEDIA:
    n = scandir(dir, &namelist, filter_avp, alphasort);
    break;
  case TYPE_AUDIO:
    n = scandir(dir, &namelist, filter_a, alphasort);
    break;
  case TYPE_AUDIO | TYPE_VIDEO:
    n = scandir(dir, &namelist, filter_av, alphasort);
    break;
  case TYPE_AUDIO | TYPE_IMAGE:
    n = scandir(dir, &namelist, filter_ap, alphasort);
    break;
  case TYPE_VIDEO:
    n = scandir(dir, &namelist, filter_v, alphasort);
    break;
  case TYPE_VIDEO | TYPE_IMAGE:
    n = scandir(dir, &namelist, filter_vp, alphasort);
    break;
  case TYPE_IMAGE:
    n = scandir(dir, &namelist, filter_p, alphasort);
    break;
  default:
    n = -1;
    errno = EINVAL;
    break;
  }
  if (n < 0) {
    DPRINTF(E_WARN, L_SCANNER, "Error scanning %s [%s]\n", dir,
            strerror(errno));
    return;
  }

  full_path = (char *)malloc(PATH_MAX);
  if (!full_path) {
    DPRINTF(E_ERROR, L_SCANNER, "Memory allocation failed scanning %s\n", dir);
    return;
  }

  if (!parent) {
    startID = get_next_available_id("OBJECTS", BROWSEDIR_ID);
  }

  for (i = 0; i < n; i++) {
#if !USE_FORK
    if (quitting)
      break;
#endif
    type = TYPE_UNKNOWN;
    snprintf(full_path, PATH_MAX, "%s/%s", dir, namelist[i]->d_name);
    name = escape_tag(namelist[i]->d_name, 1);
    if (is_dir(namelist[i]) == 1) {
      type = TYPE_DIR;
    } else if (is_reg(namelist[i]) == 1) {
      type = TYPE_FILE;
    } else {
      type = resolve_unknown_type(full_path, dir_types);
    }
    if ((type == TYPE_DIR) && (access(full_path, R_OK | X_OK) == 0)) {
      char *parent_id;
      insert_directory(name, full_path, BROWSEDIR_ID, THISORNUL(parent),
                       i + startID);
      xasprintf(&parent_id, "%s$%X", THISORNUL(parent), i + startID);
      ScanDirectory(full_path, parent_id, dir_types);
      free(parent_id);
    } else if (type == TYPE_FILE && (access(full_path, R_OK) == 0)) {
      if (insert_file(name, full_path, THISORNUL(parent), i + startID,
                      dir_types) == 0)
        fileno++;
    }
    free(name);
    free(namelist[i]);
  }
  free(namelist);
  free(full_path);
  if (!parent) {
    DPRINTF(E_WARN, L_SCANNER, _("Scanning %s finished (%llu files)!\n"), dir,
            fileno);
  }
}

/* rescan functions added by shrimpkin@sourceforge.net */
static int cb_orphans(void *, int, char **argv, char **) {
  const char *path = argv[0];
  const char *mime = argv[1];

  /* If we can't access the path, remove it */
  if (access(path, R_OK) != 0) {
    DPRINTF(E_DEBUG, L_SCANNER, "Removing %s [%s]\n", path,
            mime ? "file" : "dir");
    if (mime)
      monitor_remove_file(path);
    else
      monitor_remove_directory(0, path);
  }

  return 0;
}

void start_rescan(void) {
  struct media_dir_s *media_path;
  char *esc_name = NULL;
  char *zErrMsg;
  const char *sql_files = "SELECT path, mime FROM details WHERE path NOT NULL "
                          "AND mime IS NOT NULL;";
  const char *sql_dir =
      "SELECT path, mime FROM details WHERE path NOT NULL AND mime IS NULL;";
  int changes = sqlite3_total_changes(db);
  const char *summary;
  int ret;

  DPRINTF(E_INFO, L_SCANNER, "Starting rescan\n");

  /* Find and remove any dead directory links */
  ret = sqlite3_exec(db, sql_dir, cb_orphans, NULL, &zErrMsg);
  if (ret != SQLITE_OK) {
    DPRINTF(E_MAXDEBUG, L_SCANNER, "SQL error: %s\nBAD SQL: %s\n", zErrMsg,
            sql_dir);
    sqlite3_free(zErrMsg);
  }

  /* Find and remove any dead file links */
  ret = sqlite3_exec(db, sql_files, cb_orphans, NULL, &zErrMsg);
  if (ret != SQLITE_OK) {
    DPRINTF(E_MAXDEBUG, L_SCANNER, "SQL error: %s\nBAD SQL: %s\n", zErrMsg,
            sql_files);
    sqlite3_free(zErrMsg);
  }

  /* Rescan media_paths for new and/or modified files */
  for (media_path = media_dirs; media_path != NULL;
       media_path = media_path->next) {
    char path[MAXPATHLEN], buf[MAXPATHLEN];
    strncpyt(path, media_path->path, sizeof(path));
    strncpyt(buf, media_path->path, sizeof(buf));
    esc_name = escape_tag(basename(buf), 1);
    monitor_insert_directory(0, esc_name, path);
    free(esc_name);
  }
  fill_playlists();

  if (sqlite3_total_changes(db) != changes)
    summary = "changes found";
  else
    summary = "no changes";
  DPRINTF(E_INFO, L_SCANNER, "Rescan completed. (%s)\n", summary);
}
/* end rescan functions */

void start_scanner(void) {
  struct media_dir_s *media_path;
  char path[MAXPATHLEN];

  if (setpriority(PRIO_PROCESS, 0, 15) == -1)
    DPRINTF(E_WARN, L_INOTIFY, "Failed to reduce scanner thread priority\n");

  setlocale(LC_COLLATE, "");
  lav_register_all();
  av_log_set_level(AV_LOG_PANIC);

  if (GETFLAG(RESCAN_MASK))
    return start_rescan();

  for (media_path = media_dirs; media_path != NULL;
       media_path = media_path->next) {
    int64_t id;
    char *bname, *parent = NULL;
    char buf[8];
    strncpyt(path, media_path->path, sizeof(path));
    bname = basename(path);
    /* If there are multiple media locations, add a level to the
     * ContentDirectory */
    if (!GETFLAG(MERGE_MEDIA_DIRS_MASK) && media_dirs->next) {
      int startID = get_next_available_id("OBJECTS", BROWSEDIR_ID);
      id = insert_directory(bname, path, BROWSEDIR_ID, "", startID);
      snprintf(buf, sizeof(buf), "$%X", startID);
      parent = buf;
    } else
      id = GetFolderMetadata(bname, media_path->path, NULL, NULL, 0);
    /* Use TIMESTAMP to store the media type */
    sql_exec(db, "UPDATE DETAILS set TIMESTAMP = %d where ID = %lld",
             media_path->types, (long long)id);
    ScanDirectory(media_path->path, parent, media_path->types);
    sql_exec(db, "INSERT into SETTINGS values (%Q, %Q)", "media_dir",
             media_path->path);
  }
  /* Create this index after scanning, so it doesn't slow down the scanning
   * process. This index is very useful for large libraries used with an XBox360
   * (or any client that uses UPnPSearch on large containers). */
  sql_exec(
      db,
      "create INDEX IDX_SEARCH_OPT ON OBJECTS(OBJECT_ID, CLASS, DETAIL_ID);");

  fill_playlists();

  DPRINTF(E_DEBUG, L_SCANNER, "Initial file scan completed\n");
  // JM: Set up a db version number, so we know if we need to rebuild due to a
  // new structure.
  sql_exec(db, "pragma user_version = %d;", DB_VERSION);
}
