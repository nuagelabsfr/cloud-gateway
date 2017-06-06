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

#ifndef CG_STORAGE_FILESYSTEM_DB_H_
#define CG_STORAGE_FILESYSTEM_DB_H_

#include <time.h>

#include <cgsm/cg_storage_filesystem_common.h>

int cg_storage_filesystem_db_get_entry_info(cg_storage_filesystem * fs,
                                            char const * const entry_path,
                                            cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_get_or_create_root_inode(cg_storage_filesystem * fs,
                                                      cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_get_inode_info(cg_storage_filesystem * fs,
                                            uint64_t inode_number,
                                            cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_get_child_inode_info(cg_storage_filesystem * fs,
                                                  uint64_t parent_inode_number,
                                                  char const * child_name,
                                                  cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_create_file_entry(cg_storage_filesystem * fs,
                                               uid_t owner,
                                               gid_t group,
                                               mode_t mode,
                                               int flags,
                                               cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_create_dir_entry(cg_storage_filesystem * fs,
                                              uid_t owner,
                                              gid_t group,
                                              mode_t mode,
                                              cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_create_symlink_entry(cg_storage_filesystem * fs,
                                                  uid_t owner,
                                                  gid_t group,
                                                  mode_t mode,
                                                  cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_add_delayed_expunge_entry(cg_storage_filesystem * fs,
                                                       uint64_t inode_number,
                                                       char const * path,
                                                       time_t delete_after,
                                                       time_t deletion_time,
                                                       cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_remove_dir_entry(cg_storage_filesystem * fs,
                                              uint64_t parent_inode_number,
                                              char const * entry_name,
                                              cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_remove_inode_entry(cg_storage_filesystem * fs,
                                                uint64_t parent_inode_number,
                                                char const * entry_name,
                                                cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_set_inode_instance_uploading_in_progress(cg_storage_filesystem * fs,
                                                                      cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_clear_inode_instance_dirty_status(cg_storage_filesystem * fs,
                                                               bool compressed,
                                                               bool encrypted,
                                                               cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_set_inode_digest(cg_storage_filesystem * fs,
                                              uint64_t inode_number,
                                              cgutils_crypto_digest_algorithm digest_algo,
                                              char const * digest,
                                              size_t digest_size,
                                              uint64_t max_mtime,
                                              cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_set_inode_instance_uploading_done(cg_storage_filesystem * fs,
                                                               bool error_occured,
                                                               cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_remove_inode_instance(cg_storage_filesystem * fs,
                                                   cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_add_inode_instance(cg_storage_filesystem * fs,
                                                uint64_t instance_id,
                                                uint64_t inode_number,
                                                char const * id_in_instance,
                                                cg_storage_instance_status status,
                                                cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_set_inode_instance_delete_in_progress(cg_storage_filesystem * fs,
                                                                   cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_set_inode_instance_deleting_failed(cg_storage_filesystem * fs,
                                                                cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_get_inode_dirty_instances_count(cg_storage_filesystem * fs,
                                                             cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_get_dir_entries_by_inode(cg_storage_filesystem * fs,
                                                      uint64_t inode,
                                                      cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_update_cache_status(cg_storage_filesystem * fs,
                                                 uint64_t inode_number,
                                                 bool in_cache,
                                                 cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_get_valid_inode_instances(cg_storage_filesystem * fs,
                                                       cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_update_inode_counter(cg_storage_filesystem * fs,
                                                  uint64_t inode_number,
                                                  bool increment,
                                                  cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_rename_inode_entry(cg_storage_filesystem * fs,
                                                uint64_t old_parent_ino,
                                                char const * old_entry_name,
                                                uint64_t new_parent_ino,
                                                char const * new_entry_name,
                                                cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_add_inode_hardlink(cg_storage_filesystem * fs,
                                                uint64_t existing_ino,
                                                uint64_t new_parent_ino,
                                                char const * new_entry_name,
                                                cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_readlink(cg_storage_filesystem * fs,
                                      uint64_t ino,
                                      cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_release_inode(cg_storage_filesystem * fs,
                                           bool altered,
                                           time_t mtime,
                                           time_t last_modification,
                                           cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_set_inode_dirty(cg_storage_filesystem * fs,
                                             uint64_t inode_number,
                                             time_t mtime,
                                             time_t ctime,
                                             time_t last_modification,
                                             cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_update_cache_and_dirty_writers_status(cg_storage_filesystem * fs,
                                                                   uint64_t inode_number,
                                                                   bool in_cache,
                                                                   bool increase_dirty_writers,
                                                                   cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_get_inode_cache_status_updating_writers(cg_storage_filesystem * fs,
                                                                     uint64_t inode_number,
                                                                     bool increase_dirty_writers,
                                                                     cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_decrease_dirty_writers_count(cg_storage_filesystem * fs,
                                                          uint64_t inode_number,
                                                          cg_storage_fs_cb_data * data);

int cg_storage_filesystem_db_update_inode_attributes(cg_storage_filesystem * fs,
                                                     uint64_t inode_number,
                                                     mode_t mode,
                                                     uid_t uid,
                                                     gid_t gid,
                                                     time_t atime,
                                                     time_t mtime,
                                                     size_t size,
                                                     cg_storage_fs_cb_data * data);

#endif /* CG_STORAGE_FILESYSTEM_DB_H_ */
