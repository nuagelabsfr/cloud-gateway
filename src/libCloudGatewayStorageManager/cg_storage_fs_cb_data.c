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

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <inttypes.h>

#include <cgsm/cg_storage_filesystem.h>
#include <cgsm/cg_storage_filesystem_common.h>
#include <cgsm/cg_storage_object.h>
#include <cgsm/cg_storage_instance.h>

#include <cgsm/cg_storage_fs_cb_data.h>

struct cg_storage_fs_cb_data
{
    cg_storage_filesystem * fs;
    cg_storage_object * object;
    /* vector of cgdb_entries * */
    cgutils_vector * entries_vector;
    /* llist of cgdb_inode_instance * */
    cgutils_llist * available_instances;
    cgdb_inode_instance * inode_instance_in_use;

    /* Virtual path, aka path in the FS */
    char * path;

    /* Virtual path to (rename for example) */
    char * path_to;

    /* Path of the file (path) in the cache arborescence */
    char * path_in_cache;

    /* symlink's destination */
    char * symlink_to;

    struct stat const * stats;

    void * digest;

    void * cb;
    void * cb_data;

    cg_storage_filesystem_handler * handler;

    size_t references_counter;
    size_t file_size;

    size_t digest_size;

    /* For DB request retuning entries count */
    size_t entries_count;

    /* For DB request returning an ID */
    uint64_t id;

    uint64_t inode_number;
    uint64_t parent_inode_number;

    /* State */
    cg_storage_filesystem_handler_state state;

    cgutils_crypto_digest_algorithm digest_algo;

    /* flags for open (get_path_in_cache) */
    int flags;

    int fd;

    int error;

    bool compressed;
    bool encrypted;

    bool is_delayed_expunge_entry;
    bool dirty_writers_count_increased;
    bool file_size_changed;
    bool object_deleted;
};

void cg_storage_fs_cb_data_free(cg_storage_fs_cb_data * data)
{
    if (data != NULL)
    {
        if (data->references_counter <= 1)
        {
            if (data->object != NULL)
            {
                cg_storage_object_free(data->object), data->object = NULL;
            }

            if (data->available_instances != NULL)
            {
                cgutils_llist_free(&(data->available_instances), &cgdb_inode_instance_delete);
            }

            if (data->available_instances != NULL)
            {
                cgutils_llist_free(&(data->available_instances), &cgdb_inode_instance_delete);
            }

            if (data->fd >= 0)
            {
                cgutils_file_close(data->fd), data->fd = -1;
            }

            CGUTILS_FREE(data->path);
            CGUTILS_FREE(data->path_to);
            CGUTILS_FREE(data->path_in_cache);
            CGUTILS_FREE(data->symlink_to);
            CGUTILS_FREE(data->digest);

            (*data) = (cg_storage_fs_cb_data) { 0 };

            data->fd = -1;

            CGUTILS_FREE(data);
        }
        else
        {
            (data->references_counter)--;
        }
    }
}

int cg_storage_fs_cb_data_init(cg_storage_filesystem * const fs,
                               cg_storage_fs_cb_data ** const out)
{
    int result = EINVAL;

    if (fs != NULL &&
        out != NULL)
    {
        CGUTILS_ALLOCATE_STRUCT(*out);

        if (*out != NULL)
        {
            result = 0;

            (*out)->fs = fs;
            (*out)->fd = -1;

            (*out)->references_counter = 1;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

void cg_storage_fs_cb_data_set_callback(cg_storage_fs_cb_data * const this,
                                        void * const cb,
                                        void * const cb_data)
{
    CGUTILS_ASSERT(this != NULL);
    this->cb = cb;
    this->cb_data = cb_data;
}

void cg_storage_fs_cb_data_set_object(cg_storage_fs_cb_data * const this,
                                      cg_storage_object * const object)
{
    CGUTILS_ASSERT(this != NULL);
    this->object = object;
}

void cg_storage_fs_cb_data_set_handler(cg_storage_fs_cb_data * const this,
                                       cg_storage_filesystem_handler * const handler)
{
    CGUTILS_ASSERT(this != NULL);
    this->handler = handler;
}

int cg_storage_fs_cb_data_set_path_dup(cg_storage_fs_cb_data * const this,
                                       char const * const path)
{
    int result = 0;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(path != NULL);

    this->path = cgutils_strdup(path);

    if (this->path == NULL)
    {
        result = ENOMEM;
    }

    return result;
}

void cg_storage_fs_cb_data_set_path_to(cg_storage_fs_cb_data * const this,
                                       char * const path_to)
{
    CGUTILS_ASSERT(this != NULL);

    this->path_to = path_to;
}

int cg_storage_fs_cb_data_set_path_to_dup(cg_storage_fs_cb_data * const this,
                                          char const * const path_to)
{
    int result = 0;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(path_to != NULL);

    this->path_to = cgutils_strdup(path_to);

    if (this->path_to == NULL)
    {
        result = ENOMEM;
    }

    return result;
}

int cg_storage_fs_cb_data_set_symlink_to_dup(cg_storage_fs_cb_data * const this,
                                             char const * const symlink_to)
{
    int result = 0;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(symlink_to != NULL);

    this->symlink_to = cgutils_strdup(symlink_to);

    if (this->symlink_to == NULL)
    {
        result = ENOMEM;
    }

    return result;
}

void cg_storage_fs_cb_data_set_symlink_to(cg_storage_fs_cb_data * const this,
                                          char * const symlink_to)
{
    CGUTILS_ASSERT(this != NULL);
    this->symlink_to = symlink_to;
}

void cg_storage_fs_cb_data_set_path_in_cache(cg_storage_fs_cb_data * const this,
                                             char * const path_in_cache)
{
    CGUTILS_ASSERT(this != NULL);
    this->path_in_cache = path_in_cache;
}

void cg_storage_fs_cb_data_set_inode_instance_in_use(cg_storage_fs_cb_data * const this,
                                                     cgdb_inode_instance * const obj)
{
    CGUTILS_ASSERT(this != NULL);
    this->inode_instance_in_use = obj;
}

void cg_storage_fs_cb_data_set_entries_vector(cg_storage_fs_cb_data * const this,
                                              cgutils_vector * const entries_vector)
{
    CGUTILS_ASSERT(this != NULL);
    this->entries_vector = entries_vector;
}

void cg_storage_fs_cb_data_set_available_instances(cg_storage_fs_cb_data * const this,
                                                   /* llist of cgdb_inode_instance * */
                                                   cgutils_llist * const llist)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->available_instances == NULL);
    this->available_instances = llist;
}

void cg_storage_fs_cb_data_set_fd(cg_storage_fs_cb_data * const this,
                                  int const fd)
{
    CGUTILS_ASSERT(this != NULL);
    this->fd = fd;
}

void cg_storage_fs_cb_data_set_file_size(cg_storage_fs_cb_data * const this,
                                         size_t const file_size)
{
    CGUTILS_ASSERT(this != NULL);
    this->file_size = file_size;
}

void cg_storage_fs_cb_data_set_returning_id(cg_storage_fs_cb_data * const this,
                                            uint64_t const id)
{
    CGUTILS_ASSERT(this != NULL);
    this->id = id;
}

void cg_storage_fs_cb_data_set_entries_count(cg_storage_fs_cb_data * const this,
                                             size_t const entries_count)
{
    CGUTILS_ASSERT(this != NULL);
    this->entries_count = entries_count;
}

void cg_storage_fs_cb_data_set_inode_number(cg_storage_fs_cb_data * const this,
                                            uint64_t const inode_number)
{
    CGUTILS_ASSERT(this != NULL);
    this->inode_number = inode_number;
}

void cg_storage_fs_cb_data_set_parent_inode_number(cg_storage_fs_cb_data * const this,
                                                   uint64_t const inode_number)
{
    CGUTILS_ASSERT(this != NULL);
    this->parent_inode_number = inode_number;
}

void cg_storage_fs_cb_data_set_flags(cg_storage_fs_cb_data * const this,
                                     int const flags)
{
    CGUTILS_ASSERT(this != NULL);
    this->flags = flags;
}

void cg_storage_fs_cb_data_set_state(cg_storage_fs_cb_data * const this,
                                     cg_storage_filesystem_handler_state const state)
{
    CGUTILS_ASSERT(this != NULL);
    this->state = state;
}

void cg_storage_fs_cb_data_set_compressed(cg_storage_fs_cb_data * const this,
                                          bool const compressed)
{
    CGUTILS_ASSERT(this != NULL);
    this->compressed = compressed;
}

void cg_storage_fs_cb_data_set_encrypted(cg_storage_fs_cb_data * const this,
                                         bool const encrypted)
{
    CGUTILS_ASSERT(this != NULL);
    this->encrypted = encrypted;
}

void cg_storage_fs_cb_data_set_digest(cg_storage_fs_cb_data * const this,
                                      cgutils_crypto_digest_algorithm const algo,
                                      void * const digest,
                                      size_t const digest_size)
{
    CGUTILS_ASSERT(this != NULL);
    this->digest_algo = algo;
    this->digest = digest;
    this->digest_size = digest_size;
}

void cg_storage_fs_cb_data_dec_references(cg_storage_fs_cb_data * const this)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->references_counter > 0);
    this->references_counter--;
}

void cg_storage_fs_cb_data_inc_references(cg_storage_fs_cb_data * const this)
{
    CGUTILS_ASSERT(this != NULL);
    this->references_counter++;
}

size_t cg_storage_fs_cb_data_get_references_count(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->references_counter;
}

void * cg_storage_fs_cb_data_get_callback(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->cb;
}

void * cg_storage_fs_cb_data_get_callback_data(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->cb_data;
}

cg_storage_filesystem * cg_storage_fs_cb_data_get_fs(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->fs;
}

cg_storage_object * cg_storage_fs_cb_data_get_object(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->object;
}

cgdb_inode_instance * cg_storage_fs_cb_data_get_inode_instance_in_use(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->inode_instance_in_use;
}

cgutils_vector * cg_storage_fs_cb_data_get_entries_vector(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->entries_vector;
}

char const * cg_storage_fs_cb_data_get_path(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->path;
}

char * cg_storage_fs_cb_data_get_path_to(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->path_to;
}

char * cg_storage_fs_cb_data_get_symlink_to(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->symlink_to;
}

char * cg_storage_fs_cb_data_get_path_in_cache(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->path_in_cache;
}

size_t cg_storage_fs_cb_data_get_file_size(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->file_size;
}

size_t cg_storage_fs_cb_data_get_returning_id(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->id;
}

size_t cg_storage_fs_cb_data_get_entries_count(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->entries_count;
}

uint64_t cg_storage_fs_cb_data_get_inode_number(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->inode_number;
}

uint64_t cg_storage_fs_cb_data_get_parent_inode_number(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->parent_inode_number;
}

int cg_storage_fs_cb_data_get_fd(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->fd;
}

cg_storage_filesystem_handler_state cg_storage_fs_cb_data_get_state(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->state;
}

int cg_storage_fs_cb_data_get_flags(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->flags;
}

/* Returns a llist of cgdb_inode_instance * */
cgutils_llist * cg_storage_fs_cb_data_get_available_instances(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->available_instances;
}

cg_storage_filesystem_handler * cg_storage_fs_cb_data_get_handler(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->handler;
}

bool cg_storage_fs_cb_data_get_compressed(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->compressed;
}

bool cg_storage_fs_cb_data_get_encrypted(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->encrypted;
}

void cg_storage_fs_cb_data_get_digest(cg_storage_fs_cb_data const * const this,
                                      cgutils_crypto_digest_algorithm * const algo,
                                      void ** const digest,
                                      size_t * const digest_size)
{
    CGUTILS_ASSERT(this != NULL);
    *algo = this->digest_algo;
    *digest = this->digest;
    *digest_size = this->digest_size;
}

bool cg_storage_fs_cb_data_is_delayed_expunge_entry(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->is_delayed_expunge_entry;
}

void cg_storage_fs_cb_data_set_delayed_expunge_entry(cg_storage_fs_cb_data * const this,
                                                     bool const value)
{
    CGUTILS_ASSERT(this != NULL);

    this->is_delayed_expunge_entry = value;
}

void cg_storage_fs_cb_data_set_error(cg_storage_fs_cb_data * const this,
                                     int const error)
{
    CGUTILS_ASSERT(this != NULL);
    this->error = error;
}

int cg_storage_fs_cb_data_get_error(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->error;
}

void cg_storage_fs_cb_data_set_dirty_writers_count_increased(cg_storage_fs_cb_data * const this,
                                                             bool const increased)
{
    CGUTILS_ASSERT(this != NULL);

    this->dirty_writers_count_increased = increased;
}

bool cg_storage_fs_cb_data_get_dirty_writers_count_increased(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->dirty_writers_count_increased;
}

bool cg_storage_fs_cb_data_get_file_size_changed(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->file_size_changed;
}

void cg_storage_fs_cb_data_set_file_size_changed(cg_storage_fs_cb_data * const this,
                                                 bool const changed)
{
    CGUTILS_ASSERT(this != NULL);

    this->file_size_changed = changed;
}

void cg_storage_fs_cb_data_set_stats(cg_storage_fs_cb_data * const this,
                                     struct stat const * const st)
{
    CGUTILS_ASSERT(this != NULL);
    this->stats = st;
}

struct stat const * cg_storage_fs_cb_data_get_stats(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return this->stats;
}

void cg_storage_fs_cb_data_set_object_been_deleted(cg_storage_fs_cb_data * const this,
                                                   bool const deleted)
{
    CGUTILS_ASSERT(this != NULL);
    this->object_deleted = deleted;
}

bool cg_storage_fs_cb_data_has_object_been_deleted(cg_storage_fs_cb_data const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->object_deleted;

}
