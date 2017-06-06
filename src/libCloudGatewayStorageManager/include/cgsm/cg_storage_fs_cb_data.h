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

#ifndef CG_STORAGE_FILESYSTEM_CB_DATA_H_
#define CG_STORAGE_FILESYSTEM_CB_DATA_H_

typedef struct cg_storage_fs_cb_data cg_storage_fs_cb_data;

typedef void (cg_storage_filesystem_handler)(int const status,
                                             cg_storage_fs_cb_data * data);

#include <cgsm/cg_storage_filesystem_common.h>
#include <cloudutils/cloudutils_vector.h>

void cg_storage_fs_cb_data_free(cg_storage_fs_cb_data * data);

static inline void cg_storage_fs_cb_data_delete(void * data)
{
    cg_storage_fs_cb_data_free(data);
}

int cg_storage_fs_cb_data_init(cg_storage_filesystem * const fs,
                               cg_storage_fs_cb_data ** out);

void cg_storage_fs_cb_data_set_error(cg_storage_fs_cb_data * this,
                                     int error);

void cg_storage_fs_cb_data_set_callback(cg_storage_fs_cb_data * this,
                                        void * cb,
                                        void * cb_data);

void cg_storage_fs_cb_data_set_object(cg_storage_fs_cb_data * this,
                                      cg_storage_object * object);

void cg_storage_fs_cb_data_set_handler(cg_storage_fs_cb_data * this,
                                       cg_storage_filesystem_handler * handler);

int cg_storage_fs_cb_data_set_path_dup(cg_storage_fs_cb_data * this,
                                       char const * path);

void cg_storage_fs_cb_data_set_path_to(cg_storage_fs_cb_data * this,
                                       char * path_to);

int cg_storage_fs_cb_data_set_path_to_dup(cg_storage_fs_cb_data * this,
                                          char const * path_to);

int cg_storage_fs_cb_data_set_symlink_to_dup(cg_storage_fs_cb_data * this,
                                             char const * symlink_to);

void cg_storage_fs_cb_data_set_symlink_to(cg_storage_fs_cb_data * this,
                                          char * symlink_to);

void cg_storage_fs_cb_data_set_path_in_cache(cg_storage_fs_cb_data * this,
                                             char * path_in_cache);

void cg_storage_fs_cb_data_set_inode_instance_in_use(cg_storage_fs_cb_data * this,
                                                     cgdb_inode_instance * obj);

void cg_storage_fs_cb_data_set_entries_vector(cg_storage_fs_cb_data * this,
                                              cgutils_vector * entries);

void cg_storage_fs_cb_data_set_available_instances(cg_storage_fs_cb_data * this,
                                                   /* llist of cgdb_inode_instance * */
                                                   cgutils_llist * llist);

void cg_storage_fs_cb_data_set_fd(cg_storage_fs_cb_data * this,
                                  int fd);

void cg_storage_fs_cb_data_set_file_size(cg_storage_fs_cb_data * this,
                                         size_t file_size);

void cg_storage_fs_cb_data_set_entries_count(cg_storage_fs_cb_data * this,
                                             size_t entries_count);

void cg_storage_fs_cb_data_set_returning_id(cg_storage_fs_cb_data * this,
                                            uint64_t id);

void cg_storage_fs_cb_data_set_mtime(cg_storage_fs_cb_data * this,
                                     struct timespec const * mtime);

void cg_storage_fs_cb_data_set_uid(cg_storage_fs_cb_data * this,
                                   uid_t uid);

void cg_storage_fs_cb_data_set_gid(cg_storage_fs_cb_data * this,
                                   gid_t gid);

void cg_storage_fs_cb_data_set_mode(cg_storage_fs_cb_data * this,
                                    mode_t mode);

void cg_storage_fs_cb_data_set_flags(cg_storage_fs_cb_data * this,
                                    int flags);

void cg_storage_fs_cb_data_set_inode_number(cg_storage_fs_cb_data * this,
                                            uint64_t inode_number);

void cg_storage_fs_cb_data_set_parent_inode_number(cg_storage_fs_cb_data * this,
                                                   uint64_t inode_number);

void cg_storage_fs_cb_data_set_state(cg_storage_fs_cb_data * this,
                                     cg_storage_filesystem_handler_state state);

void cg_storage_fs_cb_data_set_compressed(cg_storage_fs_cb_data * this,
                                          bool compressed);

void cg_storage_fs_cb_data_set_encrypted(cg_storage_fs_cb_data * this,
                                         bool encrypted);

void cg_storage_fs_cb_data_set_digest(cg_storage_fs_cb_data * this,
                                      cgutils_crypto_digest_algorithm algo,
                                      void * digest,
                                      size_t digest_size);

void cg_storage_fs_cb_data_set_stats(cg_storage_fs_cb_data * this,
                                     struct stat const * st);

void cg_storage_fs_cb_data_set_dirty_writers_count_increased(cg_storage_fs_cb_data * this,
                                                             bool increased);

void cg_storage_fs_cb_data_set_file_size_changed(cg_storage_fs_cb_data * this,
                                                 bool changed);

void cg_storage_fs_cb_data_set_object_been_deleted(cg_storage_fs_cb_data * this,
                                                   bool deleted);

void cg_storage_fs_cb_data_dec_references(cg_storage_fs_cb_data * this);
void cg_storage_fs_cb_data_inc_references(cg_storage_fs_cb_data * this);

size_t cg_storage_fs_cb_data_get_references_count(cg_storage_fs_cb_data const * this);

void * cg_storage_fs_cb_data_get_callback(cg_storage_fs_cb_data const * this);
void * cg_storage_fs_cb_data_get_callback_data(cg_storage_fs_cb_data const * this);

cg_storage_filesystem * cg_storage_fs_cb_data_get_fs(cg_storage_fs_cb_data const * this);
cg_storage_object * cg_storage_fs_cb_data_get_object(cg_storage_fs_cb_data const * this);
cgdb_inode_instance * cg_storage_fs_cb_data_get_inode_instance_in_use(cg_storage_fs_cb_data const * this);
cgutils_vector * cg_storage_fs_cb_data_get_entries_vector(cg_storage_fs_cb_data const * this);

cg_storage_filesystem_handler * cg_storage_fs_cb_data_get_handler(cg_storage_fs_cb_data const * this);

char const * cg_storage_fs_cb_data_get_path(cg_storage_fs_cb_data const * this);
char * cg_storage_fs_cb_data_get_path_to(cg_storage_fs_cb_data const * this);
char * cg_storage_fs_cb_data_get_symlink_to(cg_storage_fs_cb_data const * this);
char * cg_storage_fs_cb_data_get_path_in_cache(cg_storage_fs_cb_data const * this);

size_t cg_storage_fs_cb_data_get_file_size(cg_storage_fs_cb_data const * this);
size_t cg_storage_fs_cb_data_get_returning_id(cg_storage_fs_cb_data const * this);
size_t cg_storage_fs_cb_data_get_entries_count(cg_storage_fs_cb_data const * this);

uint64_t cg_storage_fs_cb_data_get_inode_number(cg_storage_fs_cb_data const * this);
uint64_t cg_storage_fs_cb_data_get_parent_inode_number(cg_storage_fs_cb_data const * this);

int cg_storage_fs_cb_data_get_fd(cg_storage_fs_cb_data const * this);

int cg_storage_fs_cb_data_get_error(cg_storage_fs_cb_data const * this);

cg_storage_filesystem_handler_state cg_storage_fs_cb_data_get_state(cg_storage_fs_cb_data const * this);

struct timespec const * cg_storage_fs_cb_data_get_mtime(cg_storage_fs_cb_data const * this);
uid_t cg_storage_fs_cb_data_get_uid(cg_storage_fs_cb_data const * this);
gid_t cg_storage_fs_cb_data_get_gid(cg_storage_fs_cb_data const * this);
mode_t cg_storage_fs_cb_data_get_mode(cg_storage_fs_cb_data const * this);
int cg_storage_fs_cb_data_get_flags(cg_storage_fs_cb_data const * this);

/* Returns a llist of cgdb_inode_instance * */
cgutils_llist * cg_storage_fs_cb_data_get_available_instances(cg_storage_fs_cb_data const * this);

bool cg_storage_fs_cb_data_get_dirty_writers_count_increased(cg_storage_fs_cb_data const * this);

bool cg_storage_fs_cb_data_get_compressed(cg_storage_fs_cb_data const * this);
bool cg_storage_fs_cb_data_get_encrypted(cg_storage_fs_cb_data const * this);

void cg_storage_fs_cb_data_get_digest(cg_storage_fs_cb_data const * this,
                                      cgutils_crypto_digest_algorithm * algo,
                                      void ** digest,
                                      size_t * digest_size);

bool cg_storage_fs_cb_data_is_delayed_expunge_entry(cg_storage_fs_cb_data const * this);
void cg_storage_fs_cb_data_set_delayed_expunge_entry(cg_storage_fs_cb_data * this,
                                                     bool value);

bool cg_storage_fs_cb_data_get_file_size_changed(cg_storage_fs_cb_data const * this);

bool cg_storage_fs_cb_data_has_object_been_deleted(cg_storage_fs_cb_data const * this);

struct stat const * cg_storage_fs_cb_data_get_stats(cg_storage_fs_cb_data const * this);

#endif /* CG_STORAGE_FILESYSTEM_CB_DATA_H_ */
