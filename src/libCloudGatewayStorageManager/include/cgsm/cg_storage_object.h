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

#ifndef CLOUD_GATEWAY_STORAGE_OBJECT_H_
#define CLOUD_GATEWAY_STORAGE_OBJECT_H_

typedef struct cg_storage_object cg_storage_object;

#include <cgdb/cgdb.h>
#include <cgsm/cg_storage_filesystem.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cg_storage_object_new(cg_storage_filesystem * fs,
                          char const * name,
                          cgdb_entry_type type,
                          mode_t mode,
                          time_t atime,
                          time_t ctime,
                          time_t mtime,
                          time_t last_usage,
                          time_t last_modification,
                          uid_t owner,
                          gid_t group,
                          char const * link_to,
                          cg_storage_object ** obj);

int cg_storage_object_init_from_entry(cg_storage_filesystem * fs,
                                      cgdb_entry const * entry,
                                      cg_storage_object ** obj);

int cg_storage_object_init_from_inode(cg_storage_filesystem * fs,
                                      cgdb_inode const * inode,
                                      char const * name,
                                      cgdb_entry_type type,
                                      cg_storage_object ** obj);

void cg_storage_object_free(cg_storage_object * obj);

cgdb_entry_type cg_storage_object_mode_to_type(mode_t mode);

char const * cg_storage_object_get_entry_name(cg_storage_object const * obj) COMPILER_PURE_FUNCTION;
char const * cg_storage_object_get_link_to(cg_storage_object const * obj) COMPILER_PURE_FUNCTION;
uint64_t cg_storage_object_get_entry_id(cg_storage_object const * obj) COMPILER_PURE_FUNCTION;

int cg_storage_object_get_stat(cg_storage_object const * object,
                               struct stat * st_out);

uint64_t cg_storage_object_get_inode_number(cg_storage_object const * object);

bool cg_storage_object_is_inode_marked_as_in_cache(cg_storage_object const * object);

bool cg_storage_object_is_symlink(cg_storage_object const * object) COMPILER_PURE_FUNCTION;
bool cg_storage_object_is_file(cg_storage_object const * object) COMPILER_PURE_FUNCTION;
bool cg_storage_object_is_directory(cg_storage_object const * object) COMPILER_PURE_FUNCTION;

int cg_storage_object_get_entry(cg_storage_object * object,
                                cgdb_entry ** entry);

int cg_storage_object_get_inode(cg_storage_object * object,
                                cgdb_inode const ** inode);

cg_storage_filesystem * cg_storage_object_get_filesystem(cg_storage_object const * this);

size_t cg_storage_object_get_size(cg_storage_object const * object) COMPILER_PURE_FUNCTION;
size_t cg_storage_object_get_nlink(cg_storage_object const * object) COMPILER_PURE_FUNCTION;
time_t cg_storage_object_get_atime(cg_storage_object const * object) COMPILER_PURE_FUNCTION;
time_t cg_storage_object_get_mtime(cg_storage_object const * object) COMPILER_PURE_FUNCTION;

int cg_storage_object_get_inode_digest(cg_storage_object const * object,
                                       cgutils_crypto_digest_algorithm * algo,
                                       void const ** digest,
                                       size_t * digest_size);

int cg_storage_object_refresh_from_cache_if_needed(cg_storage_object * object,
                                                   char const * path_in_cache);

size_t cg_storage_object_get_dirty_writers_count(cg_storage_object const * object) COMPILER_PURE_FUNCTION;

void cg_storage_object_set_in_cache(cg_storage_object * this,
                                    bool in_cache);

void cg_storage_object_inc_dirty_writers_count(cg_storage_object * this);

void cg_storage_object_set_inode_number(cg_storage_object * this,
                                        uint64_t inode_number);

int cg_storage_object_fix_entry_block(cg_storage_filesystem const * fs,
                                      cgdb_entry * entry);

int cg_storage_object_fix_block(cg_storage_object * this);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_STORAGE_OBJECT_H_ */
