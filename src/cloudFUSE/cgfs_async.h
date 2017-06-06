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
#ifndef CGFS_ASYNC_H_
#define CGFS_ASYNC_H_

#include <cgfs.h>
#include <cgfs_file_handler.h>
#include <sys/statvfs.h>

typedef void (cgfs_async_stat_cb)(void * cb_data,
                                  cgfs_inode * inode);

typedef void (cgfs_async_error_cb)(int error,
                                   void * cb_data);

typedef void (cgfs_async_status_cb)(int status,
                                    void * cb_data);

typedef void (cgfs_async_open_cb)(void * cb_data,
                                  cgfs_file_handler * file_handler);

typedef void (cgfs_async_create_and_open_cb)(void * cb_data,
                                             cgfs_inode * inode,
                                             cgfs_file_handler * file_handler);

typedef void (cgfs_async_read_cb)(void * cb_data,
                                  void * buffer,
                                  size_t buffer_size);

typedef void (cgfs_async_write_cb)(void * cb_data,
                                   size_t written);

typedef void (cgfs_async_statfs_cb)(void * cb_data,
                                    struct statvfs const * vfs);

typedef void (cgfs_async_readlink_cb)(void * cb_data,
                                      char const * link_to);

void cgfs_async_lookup(cgfs_data * data,
                       uint64_t parent_ino,
                       char const * name,
                       cgfs_async_stat_cb * cb,
                       cgfs_async_error_cb * error_cb,
                       void * req);

void cgfs_async_getattr(cgfs_data * data,
                        uint64_t ino,
                        cgfs_async_stat_cb * cb,
                        cgfs_async_error_cb * error_cb,
                        void * req);

void cgfs_async_opendir(cgfs_data * data,
                        uint64_t ino,
                        cgfs_async_open_cb * cb,
                        cgfs_async_error_cb * error_cb,
                        void * req);

int cgfs_async_get_dir_entry(cgfs_data * data,
                             uint64_t ino,
                             cgfs_file_handler * file_handler,
                             size_t idx,
                             char const ** name_out,
                             struct stat const ** st_out);

size_t cgfs_async_get_remaining_dir_entries_count(cgfs_data * data,
                                                  uint64_t ino,
                                                  cgfs_file_handler * file_handler,
                                                  size_t idx);

size_t cgfs_async_get_remaining_dir_entries_name_len(cgfs_data * data,
                                                     uint64_t ino,
                                                     cgfs_file_handler * file_handler,
                                                     size_t idx,
                                                     size_t max_size);

void cgfs_async_releasedir(cgfs_data * data,
                           uint64_t ino,
                           cgfs_file_handler * file_handler);

void cgfs_async_create_and_open(cgfs_data * data,
                                uint64_t parent,
                                char const * name,
                                uid_t owner,
                                gid_t group,
                                mode_t mode,
                                int flags,
                                cgfs_async_create_and_open_cb * cb,
                                cgfs_async_error_cb * error_cb,
                                void * req);

void cgfs_async_file_handler_release(cgfs_data * data,
                                     uint64_t ino,
                                     cgfs_file_handler * file_handler);

int cgfs_async_get_fd_for_writing(cgfs_data * data,
                                  cgfs_file_handler * file_handler,
                                  uint64_t ino,
                                  int * fd_out);

void cgfs_async_forget_inode(cgfs_data * data,
                             uint64_t ino,
                             size_t lookup_count);

void cgfs_async_open(cgfs_data * data,
                     uint64_t ino,
                     int flags,
                     cgfs_async_open_cb * cb,
                     cgfs_async_error_cb * error_cb,
                     void * req);

void cgfs_async_read(cgfs_data * data,
                     cgfs_file_handler * file_handler,
                     uint64_t ino,
                     size_t size,
                     off_t off,
                     cgfs_async_read_cb * cb,
                     cgfs_async_error_cb * error_cb,
                     void * req);

void cgfs_async_write(cgfs_data * data,
                      cgfs_file_handler * file_handler,
                      uint64_t ino,
                      char const * buffer,
                      size_t buffer_size,
                      off_t off,
                      cgfs_async_write_cb * cb,
                      cgfs_async_error_cb * error_cb,
                      void * req);

void cgfs_async_setattr(cgfs_data * data,
                        uint64_t ino,
                        cgfs_file_handler * file_handler,
                        struct stat const * attr,
                        int cgfs_to_set,
                        cgfs_async_stat_cb * cb,
                        cgfs_async_error_cb * error_cb,
                        void * req);

void cgfs_async_mkdir(cgfs_data * data,
                      uint64_t parent,
                      char const * name,
                      uid_t owner,
                      gid_t group,
                      mode_t mode,
                      cgfs_async_stat_cb * cb,
                      cgfs_async_error_cb * error_cb,
                      void * req);

void cgfs_async_rmdir(cgfs_data * data,
                      uint64_t parent,
                      char const * name,
                      cgfs_async_status_cb * cb,
                      cgfs_async_error_cb * error_cb,
                      void * req);

void cgfs_async_statfs(cgfs_data * data,
                       uint64_t ino,
                       cgfs_async_statfs_cb * cb,
                       cgfs_async_error_cb * error_cb,
                       void * req);

void cgfs_async_fsync(cgfs_data * data,
                      cgfs_file_handler * file_handler,
                      uint64_t ino,
                      int datasync,
                      cgfs_async_status_cb * cb,
                      cgfs_async_error_cb * error_cb,
                      void * req);

void cgfs_async_unlink(cgfs_data * data,
                       uint64_t parent,
                       char const * name,
                       cgfs_async_status_cb * cb,
                       cgfs_async_error_cb * error_cb,
                       void * req);

void cgfs_async_rename(cgfs_data * data,
                       uint64_t parent,
                       char const * name,
                       uint64_t newparent,
                       char const * newname,
                       cgfs_async_status_cb * cb,
                       cgfs_async_error_cb * error_cb,
                       void * req);

void cgfs_async_hardlink(cgfs_data * data,
                         uint64_t existing_ino,
                         uint64_t new_parent,
                         char const * new_name,
                         cgfs_async_stat_cb * cb,
                         cgfs_async_error_cb * error_cb,
                         void * cb_data);

void cgfs_async_symlink(cgfs_data * data,
                        char const * link_to,
                        uint64_t new_parent,
                        char const * new_name,
                        uid_t owner,
                        gid_t group,
                        cgfs_async_stat_cb * cb,
                        cgfs_async_error_cb * error_cb,
                        void * cb_data);

void cgfs_async_readlink(cgfs_data * data,
                         uint64_t ino,
                         cgfs_async_readlink_cb * cb,
                         cgfs_async_error_cb * error_cb,
                         void * cb_data);

#endif /* CGFS_ASYNC_H_ */
