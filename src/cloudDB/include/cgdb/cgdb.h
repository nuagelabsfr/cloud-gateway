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
#ifndef CLOUD_GATEWAY_DATABASE_H_
#define CLOUD_GATEWAY_DATABASE_H_

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_event.h>
#include <cloudutils/cloudutils_vector.h>

typedef struct cgdb_data cgdb_data;

typedef struct cgdb_cursor cgdb_cursor;

typedef enum
{
    CGDB_OBJECT_TYPE_FILE = 0,
    CGDB_OBJECT_TYPE_SYMLINK = 1,
    CGDB_OBJECT_TYPE_DIRECTORY = 2,
    CGDB_OBJECT_TYPE_INVALID = 4,
} cgdb_entry_type;

typedef struct
{
    struct stat st;

    void * digest;
    size_t digest_size;

    uint64_t inode_number;
    uint64_t dirty_writers;

    uint64_t last_usage;
    uint64_t last_modification;

    uint8_t digest_type;

    bool in_cache;
} cgdb_inode;

typedef struct
{
    cgdb_inode inode;
    char * name;
    char * link_to;

    uint64_t entry_id;
    uint64_t fs_id;

    cgdb_entry_type type;
} cgdb_entry;

typedef struct cgdb_inode_instance
{
    char * id_in_instance;
    uint64_t fs_id;
    uint64_t inode_number;
    uint64_t instance_id;
    uint64_t upload_time;
    /* inode instance has no last modification,
       but in certain cases (e.g. get_inodes_instances_by_status - Syncer),
       the inode's last modification is fetched as well. */
    uint64_t inode_last_modification;
    /* inode instance has no mtime,
       but in certain cases (e.g. get_inodes_instances_by_status - Syncer),
       the inode's mtime is fetched as well. */
    uint64_t inode_mtime;
    /* inode instance has no dirty_writers,
       but in certain cases (e.g. get_inodes_instances_by_status - Syncer),
       the inode's dirty_writers is fetched as well. */
    uint64_t inode_dirty_writers;
    /* inode instance has no size,
       but in certain cases (e.g. get_inodes_instances_by_status - Syncer),
       the inode's size is fetched as well. */
    size_t inode_size;
    uint8_t inode_digest_type;
    uint8_t status;
    bool uploading;
    bool deleting;
    bool compressed;
    bool encrypted;
} cgdb_inode_instance;

typedef struct
{
    cgdb_entry entry;

    char * full_path;

    uint64_t deletion_time;
    uint64_t delete_after;
} cgdb_delayed_expunge_entry;

typedef int (cgdb_entry_getter_cb)(int status,
                                   cgdb_entry * entry,
                                   void * cb_data);

typedef int (cgdb_inode_getter_cb)(int status,
                                   cgdb_inode * inode,
                                   void * cb_data);

typedef int (cgdb_delayed_expunge_entry_getter_cb)(int status,
                                                   cgdb_delayed_expunge_entry * entry,
                                                   void * cb_data);

typedef int (cgdb_status_cb)(int status,
                             void * cb_data);

typedef int (cgdb_status_returning_cb)(int status,
                                       uint64_t id,
                                       void * cb_data);

typedef int (cgdb_status_returning_id_and_deletion_status_cb)(int status,
                                                              uint64_t id,
                                                              bool deleted,
                                                              void * cb_data);

typedef int (cgdb_inode_rename_status_cb)(int status,
                                          uint64_t renamed_id,
                                          uint64_t deleted_id,
                                          /* whether the inode has really been removed
                                             (eg, st_nlink == 0) */
                                          bool deleted,
                                          void * cb_data);

typedef int (cgdb_count_cb)(int status,
                            size_t count,
                            void * cb_data);

typedef int (cgdb_multiple_entries_getter_cb)(int status,
                                              size_t entries_count,
                                              /* vector of cgdb_entry * */
                                              cgutils_vector * entries,
                                              void * cb_data);

typedef int (cgdb_multiple_inode_instances_getter_cb)(int status,
                                                      /* llist of cgdb_inode_instance * */
                                                      cgutils_llist * inode_instances,
                                                      void * cb_data);

typedef int (cgdb_multiple_delayed_expunge_entries_getter_cb)(int status,
                                                              /* llist of cgdb_delayed_expunge_entry * */
                                                              cgutils_llist * entries,
                                                              void * cb_data);

typedef int (cgdb_cursor_cb)(int status,
                             cgdb_cursor * cursor,
                             void * cb_data);

typedef int (cgdb_readlink_cb)(int status,
                               char * link_to,
                               void * cb_data);

typedef int64_t cgdb_limit_type;
typedef int64_t cgdb_skip_type;

#define CGDB_LIMIT_NONE ((cgdb_limit_type) -1)
#define CGDB_SKIP_NONE ((cgdb_skip_type) -1)

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgdb_data_init(char const * backends_path,
                   cgutils_configuration * config,
                   cgutils_event_data * event_data,
                   cgdb_data ** out);

void cgdb_data_free(cgdb_data *);

int cgdb_get_entry_info_recursive(cgdb_data * db,
                                  uint64_t fs_id,
                                  char const * name,
                                  cgdb_entry_getter_cb *cb,
                                  void * cb_data);

int cgdb_get_or_create_root_inode(cgdb_data * db,
                                  uint64_t fs_id,
                                  cgdb_inode const * inode,
                                  cgdb_inode_getter_cb * cb,
                                  void * cb_data);

int cgdb_get_inode_info(cgdb_data * db,
                        uint64_t fs_id,
                        uint64_t ino,
                        cgdb_inode_getter_cb * cb,
                        void * cb_data);

int cgdb_get_inode_info_updating_times_and_writers(cgdb_data * db,
                                                   uint64_t fs_id,
                                                   uint64_t ino,
                                                   uint64_t atime_min,
                                                   uint64_t ctime_min,
                                                   uint64_t last_usage,
                                                   bool increase_writers,
                                                   cgdb_inode_getter_cb * cb,
                                                   void * cb_data);

int cgdb_get_child_inode_info(cgdb_data * db,
                              uint64_t fs_id,
                              uint64_t parent_ino,
                              char const * child_name,
                              cgdb_inode_getter_cb * cb,
                              void * cb_data);

int cgdb_add_new_entry_and_inode(cgdb_data * db,
                                 uint64_t parent_inode_number,
                                 cgdb_entry const * entry,
                                 cgdb_status_returning_cb * cb,
                                 void * cb_data);

int cgdb_add_hardlink(cgdb_data * db,
                      uint64_t fs_id,
                      uint64_t existing_ino,
                      uint64_t new_parent_ino,
                      char const * new_name,
                      uint8_t type,
                      cgdb_inode_getter_cb * cb,
                      void * cb_data);

int cgdb_release_inode(cgdb_data * db,
                       uint64_t fs_id,
                       uint64_t ino,
                       uint64_t min_mtime,
                       uint64_t ctime,
                       uint64_t last_modification,
                       size_t size,
                       uint8_t old_status,
                       uint8_t new_status,
                       cgdb_status_cb * cb,
                       void * cb_data);

int cgdb_add_delayed_expunge_entry(cgdb_data * db,
                                   uint64_t fs_id,
                                   uint64_t inode_number,
                                   char const * path,
                                   uint64_t delete_after,
                                   uint64_t deletion_time,
                                   cgdb_status_cb * cb,
                                   void * cb_data);

int cgdb_update_inode_counter(cgdb_data * db,
                              uint64_t fs_id,
                              uint64_t inode_number,
                              uint32_t value,
                              bool increment,
                              cgdb_status_cb * cb,
                              void * cb_data);

int cgdb_update_inode_attributes(cgdb_data * db,
                                 uint64_t fs_id,
                                 uint64_t inode_number,
                                 mode_t mode,
                                 uid_t uid,
                                 gid_t gid,
                                 uint64_t atime,
                                 uint64_t mtime,
                                 size_t file_size,
                                 cgdb_status_cb * cb,
                                 void * cb_data);

int cgdb_update_inode_cache_status(cgdb_data * db,
                                   uint64_t fs_id,
                                   uint64_t inode_number,
                                   bool in_cache,
                                   cgdb_status_cb * cb,
                                   void * cb_data);

int cgdb_update_inode_cache_status_and_increase_dirty_writers(cgdb_data * db,
                                                              uint64_t fs_id,
                                                              uint64_t inode_number,
                                                              bool in_cache,
                                                              cgdb_status_cb * cb,
                                                              void * cb_data);

int cgdb_update_inode_digest(cgdb_data * db,
                             uint64_t fs_id,
                             uint64_t inode_number,
                             uint8_t digest_type,
                             char const * digest,
                             size_t digest_size,
                             uint64_t max_mtime,
                             cgdb_status_cb * cb,
                             void * cb_data);

int cgdb_get_not_dirty_entries_by_type_size_last_usage_cached(cgdb_data * db,
                                                              uint64_t fs_id,
                                                              cgdb_entry_type type,
                                                              size_t min_size,
                                                              uint64_t max_usage,
                                                              uint16_t dirty_status,
                                                              cgdb_limit_type limit,
                                                              cgdb_skip_type skip,
                                                              cgdb_multiple_entries_getter_cb * cb,
                                                              void * cb_data);

int cgdb_rename_inode(cgdb_data * db,
                      uint64_t fs_id,
                      uint64_t old_parent_inode_number,
                      char const * old_name,
                      uint64_t new_parent_inode_number,
                      char const * new_name,
                      cgdb_inode_rename_status_cb * cb,
                      void * cb_data);

int cgdb_add_inode_instance(cgdb_data * db,
                            uint64_t fs_id,
                            uint64_t instance_id,
                            uint64_t inode_number,
                            char const * id_in_instance,
                            uint8_t status,
                            cgdb_status_cb * cb,
                            void * cb_data);

int cgdb_remove_inode_instance(cgdb_data * db,
                               uint64_t fs_id,
                               uint64_t instance_id,
                               uint64_t inode_number,
                               char const * id_in_instance,
                               uint8_t const status,
                               cgdb_status_cb * cb,
                               void * cb_data);

int cgdb_readlink(cgdb_data * db,
                  uint64_t fs_id,
                  uint64_t inode_number,
                  cgdb_entry_type type,
                  cgdb_readlink_cb * cb,
                  void * cb_data);

int cgdb_update_inode_instance_set_uploading(cgdb_data * db,
                                             uint64_t fs_id,
                                             uint64_t instance_id,
                                             uint64_t inode_number,
                                             char const * id_in_instance,
                                             cgdb_status_cb * cb,
                                             void * cb_data);

int cgdb_update_inode_instance_set_uploading_done(cgdb_data * db,
                                                  uint64_t fs_id,
                                                  uint64_t instance_id,
                                                  uint64_t inode_number,
                                                  char const * id_in_instance,
                                                  bool error,
                                                  cgdb_status_cb * cb,
                                                  void * cb_data);

int cgdb_update_inode_instance_clear_dirty_status(cgdb_data * db,
                                                  uint64_t fs_id,
                                                  uint64_t instance_id,
                                                  uint64_t inode_number,
                                                  char const * id_in_instance,
                                                  uint8_t old_status,
                                                  uint8_t new_status,
                                                  bool compressed,
                                                  bool encrypted,
                                                  cgdb_status_cb * cb,
                                                  void * cb_data);

int cgdb_update_inode_instance_set_delete_in_progress(cgdb_data * db,
                                                      uint64_t fs_id,
                                                      uint64_t instance_id,
                                                      uint64_t inode_number,
                                                      char const * id_in_instance,
                                                      cgdb_status_cb * cb,
                                                      void * cb_data);

int cgdb_update_inode_instance_set_deleting_failed(cgdb_data * db,
                                                   uint64_t fs_id,
                                                   uint64_t instance_id,
                                                   uint64_t inode_number,
                                                   char const * id_in_instance,
                                                   cgdb_status_cb * cb,
                                                   void * cb_data);

int cgdb_set_inode_and_all_inodes_instances_dirty(cgdb_data * db,
                                                  uint64_t fs_id,
                                                  uint64_t inode_number,
                                                  time_t min_mtime,
                                                  time_t min_ctime,
                                                  time_t last_modification,
                                                  uint8_t old_status,
                                                  uint8_t new_status,
                                                  cgdb_status_cb *cb,
                                                  void * cb_data);

int cgdb_get_inode_valid_instances(cgdb_data * db,
                                   uint64_t fs_id,
                                   uint64_t inode_number,
                                   uint8_t old_status_not_equal_to,
                                   cgdb_multiple_inode_instances_getter_cb * cb,
                                   void * cb_data);

int cgdb_get_inode_instances(cgdb_data * db,
                             uint64_t fs_id,
                             uint64_t inode_number,
                             cgdb_multiple_inode_instances_getter_cb * cb,
                             void * cb_data);

int cgdb_get_inode_entries(cgdb_data * db,
                           uint64_t fs_id,
                           uint64_t directory_inode_id,
                           cgdb_multiple_entries_getter_cb * cb,
                           void * cb_data);

int cgdb_get_cursor_inode_entries(cgdb_data * db,
                                  uint64_t fs_id,
                                  uint64_t directory_inode_id,
                                  cgdb_cursor_cb * cb,
                                  void * cb_data);

int cgdb_get_delayed_expunge_entries(cgdb_data * db,
                                     uint64_t fs_id,
                                     char const * path,
                                     uint64_t deleted_after,
                                     cgdb_multiple_delayed_expunge_entries_getter_cb * cb,
                                     void * cb_data);

int cgdb_get_expired_delayed_expunge_entries(cgdb_data * db,
                                             uint64_t fs_id,
                                             cgdb_multiple_delayed_expunge_entries_getter_cb * cb,
                                             void * cb_data);

int cgdb_get_inode_instances_by_status(cgdb_data * db,
                                       uint8_t status,
                                       cgdb_limit_type const limit,
                                       cgdb_skip_type const skip,
                                       cgdb_multiple_inode_instances_getter_cb * cb,
                                       void * cb_data);

int cgdb_count_inode_instances_by_status(cgdb_data * db,
                                         uint64_t fs_id,
                                         uint64_t inode_number,
                                         uint8_t status,
                                         cgdb_count_cb * cb,
                                         void * cb_data);

int cgdb_remove_dir_entry(cgdb_data * db,
                          uint64_t fs_id,
                          uint64_t parent_inode_number,
                          char const * entry_name,
                          cgdb_status_returning_cb * cb,
                          void * cb_data);

int cgdb_remove_inode_entry(cgdb_data * db,
                            uint64_t fs_id,
                            uint64_t parent_inode_number,
                            char const * entry_name,
                            cgdb_status_returning_id_and_deletion_status_cb * cb,
                            void * cb_data);

int cgdb_remove_delayed_expunge_entry(cgdb_data * db,
                                      uint64_t fs_id,
                                      uint64_t inode_number,
                                      cgdb_status_cb * cb,
                                      void * cb_data);

int cgdb_clear_inodes_instances_flags(cgdb_data * db,
                                      cgdb_status_cb * cb,
                                      void * cb_data);

int cgdb_clear_inodes_dirty_writers(cgdb_data * db,
                                    cgdb_status_cb * cb,
                                    void * cb_data);

int cgdb_sync_get_filesystem_id(cgdb_data * db,
                                char const * name,
                                uint64_t * id);

int cgdb_sync_get_instance_id(cgdb_data * db,
                              char const * name,
                              uint64_t * id);

int cgdb_sync_get_version(cgdb_data * db,
                          char ** version);

int cgdb_sync_test_credentials(cgdb_data * db,
                               char ** error_str);

void cgdb_inode_instance_free(cgdb_inode_instance * this);
void cgdb_inode_clean(cgdb_inode * this);
void cgdb_inode_free(cgdb_inode * this);
void cgdb_entry_free(cgdb_entry * this);
void cgdb_entry_clean(cgdb_entry * this);
void cgdb_delayed_expunge_entry_free(cgdb_delayed_expunge_entry * this);

int cgdb_add_person(cgdb_data * db,
                    uint64_t id,
                    char const * name,
                    uint64_t age,
                    cgdb_status_returning_cb * cb,
                    void * cb_data);

int cgdb_get_person(cgdb_data * db,
                    uint64_t id,
                    cgdb_status_cb * cb,
                    void * cb_data);

int cgdb_remove_person(cgdb_data * db,
                       uint64_t id,
                       cgdb_status_cb * cb,
                       void * cb_data);


COMPILER_BLOCK_VISIBILITY_END

static inline void cgdb_entry_delete(void * this)
{
    cgdb_entry_free(this);
}

static inline void cgdb_inode_delete(void * this)
{
    cgdb_inode_free(this);
}

static inline void cgdb_inode_instance_delete(void * this)
{
    cgdb_inode_instance_free(this);
}

static inline void cgdb_delayed_expunge_entry_delete(void * this)
{
    cgdb_delayed_expunge_entry_free(this);
}

#endif /* CLOUD_GATEWAY_DATABASE_H_ */
