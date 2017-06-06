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

#ifndef CLOUD_GATEWAY_STORAGE_FILESYSTEM_H_
#define CLOUD_GATEWAY_STORAGE_FILESYSTEM_H_

typedef struct cg_storage_filesystem cg_storage_filesystem;

#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_file.h>

#include "cg_storage_instance.h"
#include "cg_storage_manager_data.h"
#include "cg_storage_object.h"

typedef enum
{
#define TYPE(type, str) type,
#include <cgsm/cg_st_filesystem_type.itm>
#undef TYPE
} cg_storage_filesystem_type;

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cg_storage_filesystem_init(cg_storage_manager_data * data,
                               cgutils_configuration const * filesystem_conf,
                               cg_storage_filesystem ** filesystem);

int cg_storage_filesystem_setup(cg_storage_filesystem * this,
                                cg_storage_manager_data * data);

cg_storage_filesystem_type cg_storage_filesystem_get_type(cg_storage_filesystem const *) COMPILER_PURE_FUNCTION;

void cg_storage_filesystem_free(cg_storage_filesystem * );

static inline void cg_storage_filesystem_delete(void * data)
{
    cg_storage_filesystem_free(data);
}

char const * cg_storage_filesystem_get_name(cg_storage_filesystem const * filesystem) COMPILER_PURE_FUNCTION;
uint64_t cg_storage_filesystem_get_id(cg_storage_filesystem const * filesystem) COMPILER_PURE_FUNCTION;

typedef int (cg_storage_filesystem_returning_inode_number_cb)(int status,
                                                              uint64_t inode_number,
                                                              void * cb_data);

typedef int (cg_storage_filesystem_returning_renamed_and_deleted_inode_number_cb)(int status,
                                                                                  uint64_t renamed_ino,
                                                                                  uint64_t deleted_ino,
                                                                                  void * cb_data);

typedef int (cg_storage_filesystem_entry_object_cb)(int status,
                                                    cg_storage_object const * obj,
                                                    void * cb_data);

typedef int (cg_storage_filesystem_entry_object_and_path_cb)(int status,
                                                             cg_storage_object const * obj,
                                                             char * path_in_cache,
                                                             void * cb_data);

typedef int (cg_storage_filesystem_entry_get_path_cb)(int status,
                                                      char * path,
                                                      void * cb_data);

typedef int (cg_storage_filesystem_status_cb)(int status,
                                              void * cb_data);

typedef int (cg_storage_filesystem_dir_cb)(int status,
                                           size_t entries_count,
                                           /* vector of cgdb_entry *, freed by the callback */
                                           cgutils_vector * entries,
                                           void * cb_data);

typedef int (cg_storage_filesystem_entry_readlink_cb)(int status,
                                                      /* link_to is freed by the callback */
                                                      char * link_to,
                                                      void * cb_data);

typedef int (cg_storage_filesystem_entry_delayed_entries_cb)(int status,
                                                             /* llist of cgdb_delayed_expunge_entry *, freed by the callback */
                                                             cgutils_llist * entries,
                                                             void * cb_data);

int cg_storage_filesystem_file_create_and_open(cg_storage_filesystem * fs,
                                               uint64_t parent,
                                               char const * path,
                                               uid_t uid,
                                               gid_t gid,
                                               mode_t mode,
                                               int flags,
                                               cg_storage_filesystem_entry_object_and_path_cb * cb,
                                               void * cb_data);

int cg_storage_filesystem_file_inode_get_path_in_cache(cg_storage_filesystem * fs,
                                                       uint64_t inode,
                                                       int flags,
                                                       cg_storage_filesystem_entry_get_path_cb * cb,
                                                       void * cb_data);

int cg_storage_filesystem_file_inode_released(cg_storage_filesystem *fs,
                                              uint64_t ino,
                                              bool dirty,
                                              cg_storage_filesystem_status_cb * cb,
                                              void * cb_data);

int cg_storage_filesystem_file_inode_notify_write(cg_storage_filesystem * this,
                                                  uint64_t ino,
                                                  cg_storage_filesystem_status_cb * cb,
                                                  void * cb_data);

/* this function only gets info on a given object, it does not download the object,
   nor create the root entry if there is none. */
int cg_storage_filesystem_entry_get_object_info_by_path(cg_storage_filesystem * fs,
                                                       char const * path,
                                                       cg_storage_filesystem_entry_object_cb * cb,
                                                       void * cb_data);

int cg_storage_filesystem_entry_get_object_by_inode(cg_storage_filesystem * fs,
                                                    uint64_t inode,
                                                    cg_storage_filesystem_entry_object_cb * cb,
                                                    void * cb_data);

int cg_storage_filesystem_entry_get_child(cg_storage_filesystem * fs,
                                          uint64_t parent_inode,
                                          char const * name,
                                          cg_storage_filesystem_entry_object_cb * cb,
                                          void * cb_data);

int cg_storage_filesystem_entry_get_delayed_entries(cg_storage_filesystem * fs,
                                                    char const * path,
                                                    uint64_t deleted_after,
                                                    cg_storage_filesystem_entry_delayed_entries_cb * cb,
                                                    void * cb_data);

int cg_storage_filesystem_entry_get_expired_delayed_entries(cg_storage_filesystem * fs,
                                                            cg_storage_filesystem_entry_delayed_entries_cb * cb,
                                                            void * cb_data);

int cg_storage_filesystem_entry_remove_delayed_entry(cg_storage_filesystem * fs,
                                                     cg_storage_object const * object,
                                                     cg_storage_filesystem_status_cb * cb,
                                                     void * cb_data);

int cg_storage_filesystem_entry_inode_hardlink(cg_storage_filesystem * this,
                                               uint64_t existing_ino,
                                               uint64_t new_parent_ino,
                                               char const * new_name,
                                               cg_storage_filesystem_entry_object_cb * cb,
                                               void * cb_data);

int cg_storage_filesystem_entry_inode_symlink(cg_storage_filesystem * this,
                                              uint64_t new_parent_ino,
                                              char const * new_name,
                                              char const * link_to,
                                              uid_t owner,
                                              gid_t group,
                                              cg_storage_filesystem_entry_object_cb * cb,
                                              void * cb_data);

int cg_storage_filesystem_entry_readlink(cg_storage_filesystem * this,
                                         uint64_t inode_number,
                                         cg_storage_filesystem_entry_readlink_cb * cb,
                                         void * cb_data);

int cg_storage_filesystem_entry_inode_unlink(cg_storage_filesystem * fs,
                                             uint64_t parent_ino,
                                             char const * name,
                                             cg_storage_filesystem_returning_inode_number_cb * cb,
                                             void * cb_data);

int cg_storage_filesystem_entry_inode_rename(cg_storage_filesystem * this,
                                             uint64_t old_parent_ino,
                                             char const * old_name,
                                             uint64_t new_parent_ino,
                                             char const * new_name,
                                             cg_storage_filesystem_returning_renamed_and_deleted_inode_number_cb * cb,
                                             void * cb_data);

int cg_storage_filesystem_dir_inode_mkdir(cg_storage_filesystem * fs,
                                          uint64_t parent,
                                          char const * path,
                                          uid_t uid,
                                          gid_t gid,
                                          mode_t mode,
                                          cg_storage_filesystem_entry_object_cb * cb,
                                          void * cb_data);

int cg_storage_filesystem_dir_inode_rmdir(cg_storage_filesystem * fs,
                                          uint64_t parent,
                                          char const * path,
                                          cg_storage_filesystem_returning_inode_number_cb * cb,
                                          void * cb_data);

int cg_storage_filesystem_dir_get_entries_by_inode(cg_storage_filesystem * fs,
                                                   uint64_t inode,
                                                   cg_storage_filesystem_dir_cb * cb,
                                                   void * cb_data);

int cg_storage_filesystem_check_cache(cg_storage_filesystem const * filesystem,
                                      bool * full);

int cg_storage_filesystem_instance_put_inode(cg_storage_filesystem * this,
                                             cgdb_inode_instance * inode_instance,
                                             cg_storage_filesystem_status_cb * cb,
                                             void * cb_data);

int cg_storage_filesystem_instance_delete_inode(cg_storage_filesystem * this,
                                                cgdb_inode_instance * inode_instance,
                                                cg_storage_filesystem_status_cb * cb,
                                                void * cb_data);

int cg_storage_filesystem_entry_inode_setattr(cg_storage_filesystem * this,
                                              uint64_t inode_number,
                                              struct stat const * st,
                                              bool file_size_changed,
                                              cg_storage_filesystem_status_cb * cb,
                                              void * cb_data);

int cg_storage_filesystem_entry_expunge_inode_from_cache_if_all_instances_valid(cg_storage_filesystem * fs,
                                                                                cgdb_inode const * inode,
                                                                                cg_storage_filesystem_status_cb * cb,
                                                                                void * cb_data);

uint64_t cg_storage_filesystem_get_clean_max_access_offset(cg_storage_filesystem const * fs) COMPILER_PURE_FUNCTION;
uint64_t cg_storage_filesystem_get_clean_min_file_size(cg_storage_filesystem const * fs) COMPILER_PURE_FUNCTION;
uint32_t cg_storage_filesystem_get_io_block_size(cg_storage_filesystem const * fs) COMPILER_PURE_FUNCTION;

bool cg_storage_filesystem_has_auto_expunge(cg_storage_filesystem const * fs) COMPILER_PURE_FUNCTION;

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_STORAGE_FILESYSTEM_H_ */
