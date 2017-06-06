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
#ifndef CGSMC_ASYNC_H_
#define CGSMC_ASYNC_H_

#include <stdint.h>
#include <sys/stat.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_event.h>

typedef struct cgsmc_async_data cgsmc_async_data;

typedef struct
{
    struct stat st;
    char * name;
    /* can be used to store additional data */
    void * data;
    size_t name_len;
} cgsmc_async_entry;

typedef void (cgsmc_async_status_cb)(int status,
                                     void * cb_data);

typedef void (cgsmc_async_stat_cb)(int status,
                                   struct stat * st,
                                   void * cb_data);

typedef void (cgsmc_async_returning_inode_number_cb)(int status,
                                                     uint64_t inode_number,
                                                     void * cb_data);

typedef void (cgsmc_async_readdir_cb)(int status,
                                      cgsmc_async_entry * entries,
                                      size_t entries_count,
                                      bool use_dir_index,
                                      void * cb_data);

typedef void (cgsmc_async_create_and_open_cb)(int status,
                                              struct stat * st,
                                              char * filename,
                                              void * cb_data);

typedef void (cgsmc_async_open_cb)(int status,
                                   char * filename,
                                   void * cb_data);

typedef void (cgsmc_async_returning_renamed_and_deleted_inode_number_cb)(int status,
                                                                         uint64_t renamed_inode_number,
                                                                         uint64_t deleted_inode_number,
                                                                         void * cb_data);

typedef void (cgsmc_async_readlink_cb)(int status,
                                       char * link_to,
                                       void * cb_data);

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgsmc_async_data_init(char const * const fs_name,
                          char const * const configuration_file_path,
                          cgutils_event_data * const event_data,
                          cgsmc_async_data ** const out);

void cgsmc_async_data_free(cgsmc_async_data * this);

int cgsmc_async_lookup_child(cgsmc_async_data * data,
                             uint64_t ino,
                             char const * name,
                             cgsmc_async_stat_cb * cb,
                             void * cb_data);

int cgsmc_async_getattr(cgsmc_async_data * data,
                        uint64_t ino,
                        cgsmc_async_stat_cb * cb,
                        void * cb_data);

int cgsmc_async_readdir(cgsmc_async_data * data,
                        uint64_t ino,
                        cgsmc_async_readdir_cb * cb,
                        void * cb_data);

int cgsmc_async_create_and_open(cgsmc_async_data * data,
                                uint64_t parent,
                                char const * name,
                                uid_t owner,
                                gid_t group,
                                mode_t mode,
                                int flags,
                                cgsmc_async_create_and_open_cb * cb,
                                void * cb_data);

int cgsmc_async_open(cgsmc_async_data * data,
                     uint64_t ino,
                     int flags,
                     cgsmc_async_open_cb * cb,
                     void * cb_data);

int cgsmc_async_release(cgsmc_async_data * data,
                        uint64_t inode,
                        bool dirty,
                        cgsmc_async_status_cb * cb,
                        void * cb_data);

int cgsmc_async_notify_write(cgsmc_async_data * data,
                             uint64_t inode,
                             cgsmc_async_status_cb * cb,
                             void * cb_data);

int cgsmc_async_setattr(cgsmc_async_data * data,
                        uint64_t inode,
                        struct stat const * st,
                        bool file_size_changed,
                        cgsmc_async_status_cb * cb,
                        void * cb_data);

bool cgsmc_async_need_to_notify_write(cgsmc_async_data * data,
                                      size_t elapsed);

int cgsmc_async_mkdir(cgsmc_async_data * data,
                      uint64_t parent,
                      char const * name,
                      uid_t owner,
                      gid_t group,
                      mode_t mode,
                      cgsmc_async_stat_cb * cb,
                      void * cb_data);

int cgsmc_async_rmdir(cgsmc_async_data * data,
                      uint64_t parent,
                      char const * name,
                      cgsmc_async_returning_inode_number_cb * cb,
                      void * cb_data);

int cgsmc_async_unlink(cgsmc_async_data * data,
                       uint64_t parent,
                       char const * name,
                       cgsmc_async_returning_inode_number_cb * cb,
                       void * cb_data);

int cgsmc_async_rename(cgsmc_async_data * data,
                       uint64_t old_parent,
                       char const * old_name,
                       uint64_t const new_parent,
                       char const * new_name,
                       cgsmc_async_returning_renamed_and_deleted_inode_number_cb * cb,
                       void * cb_data);

int cgsmc_async_hardlink(cgsmc_async_data * data,
                         uint64_t existing_ino,
                         uint64_t new_parent_ino,
                         char const * new_name,
                         cgsmc_async_stat_cb * cb,
                         void * cb_data);

int cgsmc_async_symlink(cgsmc_async_data * data,
                        uint64_t new_parent_ino,
                        char const * new_name,
                        char const * link_to,
                        uid_t owner,
                        gid_t group,
                        cgsmc_async_stat_cb * cb,
                        void * cb_data);

int cgsmc_async_readlink(cgsmc_async_data * data,
                         uint64_t ino,
                         cgsmc_async_readlink_cb * cb,
                         void * cb_data);

unsigned long cgsmc_async_get_block_size(cgsmc_async_data * data);
unsigned long cgsmc_async_get_name_max(cgsmc_async_data * data);

void cgsmc_async_entry_free(cgsmc_async_entry * this);
void cgsmc_async_entry_clean(cgsmc_async_entry * this);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CGSMC_ASYNC_H_ */
