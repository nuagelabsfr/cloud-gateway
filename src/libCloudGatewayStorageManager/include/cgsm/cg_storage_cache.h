/*
 * This file is part of Nuage Labs SAS's Cloud Gateway.
 *
 * Copyright (C) 2011-2017  Nuage Labs SAS
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#ifndef CLOUD_GATEWAY_STORAGE_CACHE_H_
#define CLOUD_GATEWAY_STORAGE_CACHE_H_

#include <stdbool.h>
#include <sys/stat.h>

#include "cg_storage_object.h"

typedef struct cg_storage_cache cg_storage_cache;

#include "cg_storage_filesystem.h"

int cg_storage_cache_init(cg_storage_filesystem * fs,
                          char const * cache_root,
                          cg_storage_cache ** cache);

void cg_storage_cache_free(cg_storage_cache * this);

int cg_storage_cache_truncate(cg_storage_cache * cache,
                              uint64_t inode_number,
                              off_t offset);

int cg_storage_cache_create_file(cg_storage_cache * cache,
                                 uint64_t inode_number,
                                 char ** cache_path,
                                 int * fd);

int cg_storage_cache_get_existing_path(cg_storage_cache const * cache,
                                       uint64_t inode_number,
                                       bool const creation,
                                       char ** cache_path,
                                       size_t * cache_path_len);

/*
   Check that the entry in cache is at least as fresh as we expect from the
   database metadata.
*/
int cg_storage_cache_check_freshness(cg_storage_cache const * cache,
                                     cg_storage_object const * object,
                                     char const * path_in_cache,
                                     bool * valid);

/*
   Check that the entry in cache is at least as fresh as we expect from the
   database metadata.
*/
int cg_storage_cache_check_freshness_stats(cg_storage_cache const * cache,
                                           struct stat const * st,
                                           char const * path_in_cache,
                                           bool * valid);

/*
   Check that the entry in cache has not been updated since the last sync,
   ie if the metadata is the same as what we have in DB.
*/
int cg_storage_cache_check_expungeable_stats(cg_storage_cache * cache,
                                             struct stat const * st,
                                             char const * path_in_cache,
                                             bool * valid);

int cg_storage_cache_unlink_file(cg_storage_cache * cache,
                                 uint64_t inode_number);

/* Used for downloading file to a temporary location.
   If the download is successful, cg_storage_cache_move_temporary_to_final() is called.
*/
int cg_storage_cache_get_temporary_path(cg_storage_cache * cache,
                                        uint64_t inode_number,
                                        char ** cache_path,
                                        size_t * cache_path_len,
                                        int * fd);

int cg_storage_cache_move_temporary_to_final(cg_storage_cache * cache,
                                             uint64_t inode_number,
                                             char const * temporary_path,
                                             char ** final_path);

int cg_storage_cache_utimens(cg_storage_cache * cache,
                             uint64_t inode_number,
                             struct timespec const * ts);

int cg_storage_cache_get_usage(cg_storage_cache const * cache,
                               uint64_t * total,
                               uint64_t * free,
                               uint64_t * non_priv_free);

int cg_storage_cache_refresh_stats_from_cache_if_needed(struct stat * st,
                                                        char const * path_in_cache);

int cg_storage_cache_refresh_db_stats(cg_storage_cache const * cache,
                                      cgdb_entry * entry);

#endif /* CLOUD_GATEWAY_STORAGE_CACHE_H_ */
