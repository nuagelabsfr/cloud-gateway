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

#ifndef CGFS_FILE_HANDLER_H_
#define CGFS_FILE_HANDLER_H_

#include <stdbool.h>

typedef enum
{
    cgfs_file_handler_type_none = 0,
    cgfs_file_handler_type_file,
    cgfs_file_handler_type_dir,
    cgfs_file_handler_type_count
} cgfs_file_handler_type;

typedef struct cgfs_file_handler cgfs_file_handler;

#include <cgfs.h>
#include <cgfs_inode.h>
#include <cgsmclient/cgsmc_async.h>

int  cgfs_file_handler_create_fd(int fd,
                                 int flags,
                                 cgfs_inode * inode,
                                 cgfs_file_handler ** out);

int  cgfs_file_handler_create_dir(cgsmc_async_entry * entries,
                                  size_t entries_count,
                                  bool use_dir_index,
                                  cgfs_inode * inode,
                                  cgfs_file_handler ** out);

void cgfs_file_handler_free(cgfs_file_handler * this);

cgfs_file_handler_type cgfs_file_handler_get_type(cgfs_file_handler const * fh);

cgfs_inode * cgfs_file_handler_get_inode(cgfs_file_handler const * fh);

uint64_t cgfs_file_handler_get_inode_number(cgfs_file_handler const * fh);

void cgfs_file_handler_update_mtime(cgfs_file_handler * fh);

/* FILE */

bool cgfs_file_handler_file_need_to_notify_release(cgfs_file_handler const * handler);

int cgfs_file_handler_file_get_fd_for_writing(cgfs_file_handler * fh,
                                              int * fd_out);

int cgfs_file_handler_file_get_fd_for_reading(cgfs_file_handler * fh,
                                              int * fd_out);

bool cgfs_file_handler_file_need_to_notify_write(cgfs_data * data,
                                                 cgfs_file_handler const * fh);

int cgfs_file_handler_file_truncate(cgfs_file_handler * fh,
                                    off_t size);

int cgfs_file_handler_file_set_mode(cgfs_file_handler * fh,
                                    mode_t mode);

int cgfs_file_handler_file_set_atime(cgfs_file_handler * fh,
                                     time_t new_time);

int cgfs_file_handler_file_set_mtime(cgfs_file_handler * fh,
                                     time_t new_time);

int cgfs_file_handler_file_refresh_inode_attributes_from_fd(cgfs_file_handler * fh);

void cgfs_file_handler_file_set_dirty(cgfs_file_handler * fh);

bool cgfs_file_handler_file_is_dirty(cgfs_file_handler const * fh);

/* DIR */

size_t cgfs_file_handler_dir_get_entries_count(cgfs_file_handler const * fh);

cgsmc_async_entry * cgfs_file_handler_dir_get_entries(cgfs_file_handler const * fh);

int cgfs_file_handler_dir_get_child_ino(cgfs_file_handler const * fh,
                                        char const * name,
                                        uint64_t * ino);

#endif /* CGFS_FILE_HANDLER_H_ */
