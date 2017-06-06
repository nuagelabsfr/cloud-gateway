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
#include <inttypes.h>
#include <stdint.h>
#include <strings.h>
#include <string.h>
#include <time.h>

#include <cgsm/cg_storage_cache.h>
#include <cgsm/cg_storage_filesystem_db.h>
#include <cgsm/cg_storage_filesystem_common.h>
#include <cgsm/cg_storage_filesystem_transfer_queue.h>
#include <cgsm/cg_storage_filesystem_utils.h>

#include <cloudutils/cloudutils_crypto.h>
#include <cloudutils/cloudutils_encoding.h>

static int cg_storage_filesystem_entry_remove_inode_from_cache(cg_storage_filesystem * const fs,
                                                               uint64_t const inode_number)
{
    int result = EINVAL;

    if (fs != NULL &&
        inode_number > 0)
    {
        result = cg_storage_cache_unlink_file(fs->cache,
                                              inode_number);
    }

    return result;
}

static int cg_storage_filesystem_entry_try_ex_lock_inode_in_cache(cg_storage_filesystem * const this,
                                                                  uint64_t const inode_number,
                                                                  int * const fd_out)
{
    int result = EINVAL;

    if (this != NULL &&
        inode_number > 0
        && fd_out != NULL)
    {
        char * path_in_cache = NULL;
        size_t path_in_cache_len = 0;

        result = cg_storage_cache_get_existing_path(this->cache,
                                                    inode_number,
                                                    false,
                                                    &path_in_cache,
                                                    &path_in_cache_len);

        if (result == 0)
        {
            result = cgutils_file_open(path_in_cache,
                                       O_RDONLY,
                                       0,
                                       fd_out);

            if (result == 0)
            {
                result = cgutils_file_flock(*fd_out,
                                            LOCK_EX | LOCK_NB);

                if (result != 0 && result == EWOULDBLOCK)
                {
                    cgutils_file_close(*fd_out), *fd_out = -1;
                }
            }
            else if (result != ENOENT)
            {
                CGUTILS_ERROR("Error opening file from cache: %d", result);
            }

            CGUTILS_FREE(path_in_cache);
        }
        else
        {
            CGUTILS_ERROR("Error getting path in cache: %d", result);
        }
    }

    return result;
}

static int cg_storage_filesystem_entry_check_inode_cache_expungeable(cg_storage_filesystem * const fs,
                                                                     cgdb_inode const * const inode,
                                                                     bool * const valid)
{
    int result = EINVAL;

    if (fs != NULL &&
        inode != NULL &&
        valid != NULL)
    {
        char * path_in_cache = NULL;
        size_t path_in_cache_len = 0;

        result = cg_storage_cache_get_existing_path(fs->cache,
                                                    inode->inode_number,
                                                    false,
                                                    &path_in_cache,
                                                    &path_in_cache_len);

        if (result == 0)
        {
            result = cg_storage_cache_check_expungeable_stats(fs->cache,
                                                              &(inode->st),
                                                              path_in_cache,
                                                              valid);

            CGUTILS_FREE(path_in_cache);
        }
    }

    return result;
}

static void cg_storage_filesystem_entry_expunge_inode_from_cache_if_all_instances_valid_handler(int const status,
                                                                                                cg_storage_fs_cb_data * data)
{
    int result = status;
    assert(data != NULL);
    cg_storage_filesystem * fs = cg_storage_fs_cb_data_get_fs(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    assert(fs != NULL);
    uint64_t const inode_number = cg_storage_fs_cb_data_get_inode_number(data);

    if (result == 0)
    {
        switch(state)
        {
        case cg_storage_filesystem_state_fetching_inode_instances:
        {
            size_t const dirty_instances = cg_storage_fs_cb_data_get_entries_count(data);

            if (dirty_instances == 0)
            {
                /* All instances synced, expunging from cache */
                result = cg_storage_filesystem_entry_remove_inode_from_cache(fs,
                                                                             inode_number);

                if (result == 0)
                {
                    /* Update the cache status in database */

                    cg_storage_fs_cb_data_set_state(data,
                                                    cg_storage_filesystem_state_updating_cache_status);

                    result = cg_storage_filesystem_db_update_cache_status(fs,
                                                                          inode_number,
                                                                          false,
                                                                          data);
                    if (result != 0)
                    {
                        CGUTILS_WARN("Error while trying to update cache status for inode %"PRIu64", fs %s: %d",
                                     inode_number,
                                     cg_storage_filesystem_get_name(fs),
                                     result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error while removing inode %"PRIu64" on FS %s from cache: %d",
                                  inode_number,
                                  cg_storage_filesystem_get_name(fs),
                                  result);
                }
            }
            else
            {
                /* At least one instance is not synced yet, doing nothing. */

                cg_storage_filesystem_status_cb * cb = cg_storage_fs_cb_data_get_callback(data);

                if (cb != NULL)
                {
                    (*cb)(result,
                          cg_storage_fs_cb_data_get_callback_data(data));
                }

                cg_storage_fs_cb_data_free(data), data = NULL;
            }

            break;
        }
        case cg_storage_filesystem_state_updating_cache_status:
        {
            cg_storage_filesystem_status_cb * cb = cg_storage_fs_cb_data_get_callback(data);

            if (cb != NULL)
            {
                (*cb)(result,
                      cg_storage_fs_cb_data_get_callback_data(data));
            }

            cg_storage_fs_cb_data_free(data), data = NULL;

            break;
        }
        default:
            CGUTILS_ERROR("Error, state %d is not handled", state);
            result = ENOSYS;
        }
    }

    if (result != 0)
    {
        cg_storage_filesystem_status_cb * cb = cg_storage_fs_cb_data_get_callback(data);

        CGUTILS_ERROR("Error expunging inode %"PRIu64" of fs %s from cache, state %s: %d",
                      inode_number,
                      fs->name,
                      cg_storage_filesystem_state_to_str(state),
                      result);

        if (cb != NULL)
        {
            (*cb)(result,
                  cg_storage_fs_cb_data_get_callback_data(data));
        }

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

int cg_storage_filesystem_entry_expunge_inode_from_cache_if_all_instances_valid(cg_storage_filesystem * const fs,
                                                                                cgdb_inode const * const inode,
                                                                                cg_storage_filesystem_status_cb * const cb,
                                                                                void * const cb_data)
{
    int result = EINVAL;

    if (fs != NULL &&
        inode != NULL)
    {
        cg_storage_fs_cb_data * data = NULL;

        result = cg_storage_fs_cb_data_init(fs,
                                            &data);

        if (result == 0)
        {
            cg_storage_fs_cb_data_set_handler(data,
                                              &cg_storage_filesystem_entry_expunge_inode_from_cache_if_all_instances_valid_handler);

            cg_storage_fs_cb_data_set_callback(data,
                                               cb,
                                               cb_data);

            cg_storage_fs_cb_data_set_inode_number(data,
                                                   inode->inode_number);

            int fd = -1;

            result = cg_storage_filesystem_entry_try_ex_lock_inode_in_cache(fs,
                                                                            inode->inode_number,
                                                                            &fd);

            if (result == 0)
            {
                bool expungeable = false;

                cg_storage_fs_cb_data_set_fd(data, fd);
                fd = -1;

                result = cg_storage_filesystem_entry_check_inode_cache_expungeable(fs,
                                                                                   inode,
                                                                                   &expungeable);

                if (result == 0)
                {
                    if (expungeable == true)
                    {
                        cg_storage_fs_cb_data_set_state(data,
                                                        cg_storage_filesystem_state_fetching_inode_instances);


                        result = cg_storage_filesystem_db_get_inode_dirty_instances_count(fs,
                                                                                          data);

                        if (result != 0)
                        {
                            CGUTILS_ERROR("Error getting dirty instances for inode %"PRIu64" on fs %s: %d",
                                          inode->inode_number,
                                          fs->name,
                                          result);
                        }
                    }
                    else
                    {
                        /* Cache is not expungeable, probably modified under our feet. */
                        CGUTILS_WARN("Expunge prevented because cache entry has been modified (%"PRIu64") on fs %s",
                                     inode->inode_number,
                                     fs->name);

                        if (cb != NULL)
                        {
                            (*cb)(result,
                                  cg_storage_fs_cb_data_get_callback_data(data));
                        }

                        cg_storage_fs_cb_data_free(data), data = NULL;
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error checking cache validity: %d", result);
                }
            }
            else if (result == EWOULDBLOCK)
            {
                /* Failed to lock the file, it is probably in use, skip it. */
            }
            else if (result == ENOENT)
            {

                CGUTILS_INFO("Inode %"PRIu64", %s is marked in DB as being present in cache but is not.",
                             inode->inode_number,
                             cg_storage_filesystem_get_name(fs));

                cg_storage_fs_cb_data_set_state(data,
                                                cg_storage_filesystem_state_updating_cache_status);

                result = cg_storage_filesystem_db_update_cache_status(fs,
                                                                      inode->inode_number,
                                                                      false,
                                                                      data);
                if (result != 0)
                {
                    CGUTILS_WARN("Error while trying to update cache status for inode %"PRIu64", fs %s: %d",
                                 inode->inode_number,
                                 cg_storage_filesystem_get_name(fs),
                                 result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error while trying to lock the file: %d", result);
            }

            if (result != 0)
            {
                cg_storage_fs_cb_data_free(data), data = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating cb data: %d", result);
        }
    }

    return result;
}

static void cg_storage_filesystem_entry_get_object_info_by_path_handler(int const status,
                                                                        cg_storage_fs_cb_data * data)
{
    int result = status;
    assert(data != NULL);
    cg_storage_filesystem * this = cg_storage_fs_cb_data_get_fs(data);
    char const * const path = cg_storage_fs_cb_data_get_path(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    cg_storage_object * object = cg_storage_fs_cb_data_get_object(data);
    assert(this != NULL);
    assert(path != NULL);

    switch(state)
    {
    case cg_storage_filesystem_state_fetching_entry:
    {
        if (result == 0)
        {
            cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);

            if (cb != NULL)
            {
                (*cb)(result,
                      object,
                      cg_storage_fs_cb_data_get_callback_data(data));
            }

            cg_storage_fs_cb_data_free(data), data = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error while looking up entry for path %s of fs %s: %d",
                          path,
                          this->name,
                          result);
        }

        break;
    }
    default:
            CGUTILS_ERROR("Error, state %d is not handled", state);
            result = ENOSYS;
    }

    if (result != 0)
    {
        cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);

        if (cb != NULL)
        {
            (*cb)(result,
                  NULL,
                  cg_storage_fs_cb_data_get_callback_data(data));
        }

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

/* Get the stats of the given entry */
int cg_storage_filesystem_entry_get_object_info_by_path(cg_storage_filesystem * const this,
                                                        char const * const path,
                                                        cg_storage_filesystem_entry_object_cb * const cb,
                                                        void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL &&
        path != NULL)
    {
        cg_storage_fs_cb_data * data = NULL;

        result = cg_storage_fs_cb_data_init(this,
                                            &data);

        if (result == 0)
        {
            result = cg_storage_fs_cb_data_set_path_dup(data,
                                                        path);

            if (result == 0)
            {
                cg_storage_fs_cb_data_set_handler(data,
                                                  &cg_storage_filesystem_entry_get_object_info_by_path_handler);

                cg_storage_fs_cb_data_set_callback(data,
                                                   cb,
                                                   cb_data);

                cg_storage_fs_cb_data_set_state(data,
                                                cg_storage_filesystem_state_fetching_entry);


                /* First, we fetch the corresponding entry. */
                result = cg_storage_filesystem_db_get_entry_info(this,
                                                                 path,
                                                                 data);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error getting entry for %s on fs %s: %d",
                                  path,
                                  this->name,
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error allocating memory for path %s of fs %s: %d",
                              path,
                              this->name,
                              result);
            }

            if (result != 0)
            {
                cg_storage_fs_cb_data_free(data), data = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating cb data: %d", result);
        }
    }

    return result;
}

static void cg_storage_filesystem_entry_get_object_by_inode_handler(int const status,
                                                                    cg_storage_fs_cb_data * data)
{
    int result = status;
    assert(data != NULL);
    cg_storage_filesystem * this = cg_storage_fs_cb_data_get_fs(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    cg_storage_object * object = cg_storage_fs_cb_data_get_object(data);
    uint64_t const inode_number = cg_storage_fs_cb_data_get_inode_number(data);
    assert(this != NULL);

    switch(state)
    {
    case cg_storage_filesystem_state_fetching_entry:
    {
        if (COMPILER_LIKELY(result == 0))
        {
            cgdb_entry * entry = NULL;

            result = cg_storage_object_get_entry(object,
                                                 &entry);

            if (result == 0)
            {
                result = cg_storage_cache_refresh_db_stats(this->cache,
                                                           entry);

                if (result != 0)
                {
                    CGUTILS_WARN("Error checking cache validity for inode %"PRIu64" on fs %s: %d",
                                 cg_storage_object_get_inode_number(object),
                                 this->name,
                                 result);
                }
            }
            else
            {
                CGUTILS_WARN("Error getting entry from object for inode %"PRIu64" on fs %s: %d",
                             cg_storage_object_get_inode_number(object),
                             this->name,
                             result);
            }

            cg_storage_object_fix_block(object);
            result = 0;

            /* Phew, that was easy. */
            cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            CGUTILS_ASSERT(cb != NULL);

            (*cb)(result,
                  object,
                  cg_storage_fs_cb_data_get_callback_data(data));

            cg_storage_fs_cb_data_free(data), data = NULL;
        }
        else if (result != ENOENT)
        {
            CGUTILS_ERROR("Error while looking up entry for inode %"PRIu64" of fs %s: %d",
                          inode_number,
                          this->name,
                          result);
        }

        break;
    }
    default:
            CGUTILS_ERROR("Error, state %d is not handled", state);
            result = ENOSYS;
    }

    if (result != 0)
    {
        cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);
        CGUTILS_ASSERT(cb != NULL);

        (*cb)(result,
              NULL,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

static void cg_storage_filesystem_entry_get_root_object_handler(int const status,
                                                                cg_storage_fs_cb_data * data)
{
    int result = status;
    assert(data != NULL);
    cg_storage_filesystem * this = cg_storage_fs_cb_data_get_fs(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    cg_storage_object * object = cg_storage_fs_cb_data_get_object(data);
    assert(this != NULL);

    switch(state)
    {
    case cg_storage_filesystem_state_fetching_entry:
    {
        if (COMPILER_LIKELY(result == 0))
        {
            /* Phew, that was easy. */
            cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            CGUTILS_ASSERT(cb != NULL);

            (*cb)(result,
                  object,
                  cg_storage_fs_cb_data_get_callback_data(data));

            cg_storage_fs_cb_data_free(data), data = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error while looking up root entry of fs %s: %d",
                          this->name,
                          result);
        }

        break;
    }
    default:
            CGUTILS_ERROR("Error, state %d is not handled", state);
            result = ENOSYS;
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);
        CGUTILS_ASSERT(cb != NULL);

        (*cb)(result,
              NULL,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

/* Get the stats of the given entry from an inode number */
int cg_storage_filesystem_entry_get_object_by_inode(cg_storage_filesystem * const this,
                                                    uint64_t const inode,
                                                    cg_storage_filesystem_entry_object_cb * const cb,
                                                    void * const cb_data)
{
    int result = 0;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(cb != NULL);

    cg_storage_fs_cb_data * data = NULL;

    result = cg_storage_fs_cb_data_init(this,
                                        &data);

    if (COMPILER_LIKELY(result == 0))
    {
        cg_storage_fs_cb_data_set_inode_number(data, inode);

        cg_storage_fs_cb_data_set_callback(data,
                                           cb,
                                           cb_data);

        cg_storage_fs_cb_data_set_state(data,
                                        cg_storage_filesystem_state_fetching_entry);


        /* First, we fetch the corresponding entry. */
        if (COMPILER_UNLIKELY(inode == 1))
        {
            cg_storage_object * object = NULL;
            /* See mkfs for the defaults perms */
            mode_t const default_root_perms = S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
            time_t const now = time(NULL);

            result = cg_storage_object_new(this,
                                           "",
                                           CGDB_OBJECT_TYPE_DIRECTORY,
                                           default_root_perms,
                                           now,
                                           now,
                                           now,
                                           now,
                                           now,
                                           (uid_t) 0, /* root */
                                           (gid_t) 0, /* root */
                                           NULL,
                                           &object);

            if (COMPILER_LIKELY(result == 0))
            {
                cg_storage_fs_cb_data_set_object(data, object);

                cg_storage_fs_cb_data_set_handler(data,
                                                  &cg_storage_filesystem_entry_get_root_object_handler);

                result = cg_storage_filesystem_db_get_or_create_root_inode(this,
                                                                           data);

            }
            else
            {
                CGUTILS_ERROR("Error creating root object on fs %s: %d",
                              this->name,
                              result);
            }
        }
        else
        {
            cg_storage_fs_cb_data_set_handler(data,
                                              &cg_storage_filesystem_entry_get_object_by_inode_handler);

            result = cg_storage_filesystem_db_get_inode_info(this,
                                                             inode,
                                                             data);
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error getting entry for inode %zu on fs %s: %d",
                          inode,
                          this->name,
                          result);
            cg_storage_fs_cb_data_free(data), data = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Error allocating cb data: %d", result);
    }

    return result;
}

static void cg_storage_filesystem_entry_get_child_handler(int const status,
                                                          cg_storage_fs_cb_data * data)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    cg_storage_filesystem * this = cg_storage_fs_cb_data_get_fs(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    cg_storage_object * object = cg_storage_fs_cb_data_get_object(data);
    uint64_t const parent_inode_number = cg_storage_fs_cb_data_get_inode_number(data);
    char const * const child_name = cg_storage_fs_cb_data_get_path(data);
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(child_name != NULL);

    switch(state)
    {
    case cg_storage_filesystem_state_fetching_entry:
    {
        if (COMPILER_LIKELY(result == 0))
        {
            cgdb_entry * entry = NULL;

            result = cg_storage_object_get_entry(object,
                                                 &entry);

            if (result == 0)
            {
                result = cg_storage_cache_refresh_db_stats(this->cache,
                                                           entry);

                if (result != 0)
                {
                    CGUTILS_WARN("Error checking cache validity for inode %"PRIu64" on fs %s: %d",
                                 cg_storage_object_get_inode_number(object),
                                 this->name,
                                 result);
                }
            }
            else
            {
                CGUTILS_WARN("Error getting entry from object for inode %"PRIu64" on fs %s: %d",
                             cg_storage_object_get_inode_number(object),
                             this->name,
                             result);
            }

            cg_storage_object_fix_block(object);
            result = 0;

            /* Phew, that was easy. */
            cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            CGUTILS_ASSERT(cb != NULL);

            (*cb)(result,
                  object,
                  cg_storage_fs_cb_data_get_callback_data(data));

            cg_storage_fs_cb_data_free(data), data = NULL;
        }
        else if (result != ENOENT)
        {
            CGUTILS_ERROR("Error while looking up child entry named %s of inode %"PRIu64" of fs %s: %d",
                          child_name,
                          parent_inode_number,
                          this->name,
                          result);
        }

        break;
    }
    default:
            CGUTILS_ERROR("Error, state %d is not handled", state);
            result = ENOSYS;
    }

    if (result != 0)
    {
        cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);
        CGUTILS_ASSERT(cb != NULL);

        (*cb)(result,
              NULL,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

int cg_storage_filesystem_entry_get_child(cg_storage_filesystem * const this,
                                          uint64_t const parent_inode,
                                          char const * const name,
                                          cg_storage_filesystem_entry_object_cb * const cb,
                                          void * const cb_data)
{
    int result = 0;
    cg_storage_fs_cb_data * data = NULL;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(name != NULL);
    CGUTILS_ASSERT(cb != NULL);

    result = cg_storage_fs_cb_data_init(this,
                                        &data);

    if (COMPILER_LIKELY(result == 0))
    {
        cg_storage_fs_cb_data_set_inode_number(data, parent_inode);

        result = cg_storage_fs_cb_data_set_path_dup(data, name);

        if (COMPILER_LIKELY(result == 0))
        {
            cg_storage_fs_cb_data_set_callback(data,
                                               cb,
                                               cb_data);

            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_fetching_entry);


            cg_storage_fs_cb_data_set_handler(data,
                                              &cg_storage_filesystem_entry_get_child_handler);

            result = cg_storage_filesystem_db_get_child_inode_info(this,
                                                                   parent_inode,
                                                                   name,
                                                                   data);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error getting entry for child of inode %zu name %s on fs %s: %d",
                              parent_inode,
                              name,
                              this->name,
                              result);
                cg_storage_fs_cb_data_free(data), data = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating memory for name %s of fs %s: %d",
                          name,
                          this->name,
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error allocating cb data: %d", result);
    }

    return result;
}

int cg_storage_filesystem_entry_get_delayed_entries(cg_storage_filesystem * const fs,
                                                    char const * const path,
                                                    uint64_t const deleted_after,
                                                    cg_storage_filesystem_entry_delayed_entries_cb * const cb,
                                                    void * const cb_data)
{
    int result = EINVAL;

    if (fs != NULL &&
        path != NULL &&
        cb != NULL)
    {
        result = cgdb_get_delayed_expunge_entries(fs->db,
                                                  fs->id,
                                                  path,
                                                  deleted_after,
                                                  cb,
                                                  cb_data);
    }

    return result;
}

int cg_storage_filesystem_entry_get_expired_delayed_entries(cg_storage_filesystem * const fs,
                                                            cg_storage_filesystem_entry_delayed_entries_cb * const cb,
                                                            void * const cb_data)
{
    int result = EINVAL;

    if (fs != NULL &&
        cb != NULL)
    {
        result = cgdb_get_expired_delayed_expunge_entries(fs->db,
                                                          fs->id,
                                                          cb,
                                                          cb_data);
    }

    return result;
}

int cg_storage_filesystem_entry_remove_delayed_entry(cg_storage_filesystem * const fs,
                                                     cg_storage_object const * const object,
                                                     cg_storage_filesystem_status_cb * const cb,
                                                     void * const cb_data)
{
    int result = EINVAL;

    if (fs != NULL &&
        object != NULL &&
        cb != NULL)
    {
        uint64_t const inode_number = cg_storage_object_get_inode_number(object);

        result = cgdb_remove_delayed_expunge_entry(fs->db,
                                                   fs->id,
                                                   inode_number,
                                                   cb,
                                                   cb_data);

        if (result == 0)
        {
            size_t const nlink = cg_storage_object_get_nlink(object);

            if (nlink <= 1)
            {
                result = cg_storage_cache_unlink_file(fs->cache,
                                                      inode_number);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error deleting cache file for delayed entry %"PRIu64" on fs %s: %d",
                                  inode_number,
                                  fs->name,
                                  result);
                }
            }
        }
    }

    return result;
}

static void cg_storage_filesystem_entry_unlink_inode_handler(int const status,
                                                             cg_storage_fs_cb_data * data)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    cg_storage_filesystem * fs = cg_storage_fs_cb_data_get_fs(data);
    char const * const path = cg_storage_fs_cb_data_get_path(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    uint64_t const parent = cg_storage_fs_cb_data_get_parent_inode_number(data);
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(path != NULL);

    if (result == 0)
    {
        switch(state)
        {
        case cg_storage_filesystem_state_removing_entry:
        {
            cg_storage_filesystem_returning_inode_number_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            uint64_t const inode_number = cg_storage_fs_cb_data_get_returning_id(data);

            if (cg_storage_fs_cb_data_has_object_been_deleted(data) == true)
            {
                int res = cg_storage_cache_unlink_file(fs->cache,
                                                       inode_number);

                if (res != 0)
                {
                    CGUTILS_ERROR("Error deleting cache file for inode %"PRIu64" on fs %s: %d",
                                  inode_number,
                                  fs->name,
                                  res);
                }
            }

            CGUTILS_ASSERT(cb != NULL);
            (*cb)(result,
                  inode_number,
                  cg_storage_fs_cb_data_get_callback_data(data));

            cg_storage_fs_cb_data_free(data), data = NULL;

            break;
        }
        default:
            CGUTILS_ERROR("Error, state %d is not handled", state);
            result = ENOSYS;
        }
    }

    if (result != 0)
    {
        CGUTILS_ERROR("Error removing entry %s from parent %"PRIu64" on fs %s, state %s: %d",
                      path,
                      parent,
                      fs->name,
                      cg_storage_filesystem_state_to_str(state),
                      result);

        cg_storage_filesystem_returning_inode_number_cb * cb = cg_storage_fs_cb_data_get_callback(data);
        CGUTILS_ASSERT(cb != NULL);

        (*cb)(result,
              0,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

int cg_storage_filesystem_entry_inode_unlink(cg_storage_filesystem * const fs,
                                             uint64_t const parent_ino,
                                             char const * const name,
                                             cg_storage_filesystem_returning_inode_number_cb * const cb,
                                             void * const cb_data)
{
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(parent_ino > 0);
    CGUTILS_ASSERT(name != NULL);
    CGUTILS_ASSERT(cb != NULL);

    cg_storage_fs_cb_data * data = NULL;

    int result = cg_storage_fs_cb_data_init(fs,
                                            &data);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cg_storage_fs_cb_data_set_path_dup(data, name);

        if (COMPILER_LIKELY(result == 0))
        {
            cg_storage_fs_cb_data_set_parent_inode_number(data, parent_ino);

            cg_storage_fs_cb_data_set_handler(data,
                                              &cg_storage_filesystem_entry_unlink_inode_handler);

            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_removing_entry);

            cg_storage_fs_cb_data_set_callback(data,
                                                   cb,
                                               cb_data);

            result = cg_storage_filesystem_db_remove_inode_entry(fs,
                                                                 parent_ino,
                                                                 name,
                                                                 data);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error removing entry %s from parent inode %"PRIu64 " on fs %s: %d",
                              name,
                              parent_ino,
                              fs->name,
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating memory for path %s of fs %s: %d",
                          name,
                          fs->name,
                          result);
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            cg_storage_fs_cb_data_free(data), data = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Error allocating cb data: %d", result);
    }

    return result;
}

static void cg_storage_filesystem_entry_inode_rename_handler(int const status,
                                                             cg_storage_fs_cb_data * data)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    cg_storage_filesystem * this = cg_storage_fs_cb_data_get_fs(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    uint64_t const renamed_inode_number = cg_storage_fs_cb_data_get_returning_id(data);
    uint64_t const deleted_inode_number = cg_storage_fs_cb_data_get_parent_inode_number(data);

    CGUTILS_ASSERT(this != NULL);

    if (result == 0)
    {
        switch(state)
        {
        case cg_storage_filesystem_state_renaming_entry:
        {
            if (cg_storage_fs_cb_data_has_object_been_deleted(data) == true)
            {
                /* An existing entry/inode has been removed (nlink == 0) */
                int res = cg_storage_cache_unlink_file(this->cache,
                                                       deleted_inode_number);

                if (res != 0 &&
                    res != ENOENT)
                {
                    CGUTILS_ERROR("Error removing inode %"PRIu64" of fs %s from cache: %d",
                                  deleted_inode_number,
                                  this->name,
                                  result);
                }
            }

            /* Done. */
            cg_storage_filesystem_returning_renamed_and_deleted_inode_number_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            CGUTILS_ASSERT(cb != NULL);

            (*cb)(result,
                  renamed_inode_number,
                  deleted_inode_number,
                  cg_storage_fs_cb_data_get_callback_data(data));

            cg_storage_fs_cb_data_free(data), data = NULL;

            break;
        }
        default:
            CGUTILS_ERROR("Error, state %d is not handled", state);
            result = ENOSYS;
        }
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_filesystem_returning_renamed_and_deleted_inode_number_cb * cb = cg_storage_fs_cb_data_get_callback(data);
        CGUTILS_ASSERT(cb != NULL);

        if (result != ENOTEMPTY)
        {
            CGUTILS_ERROR("Error renaming entry named %s of parent %"PRIu64", to %s on parent %"PRIu64" on fs %s, state %s: %d",
                          cg_storage_fs_cb_data_get_path(data),
                          cg_storage_fs_cb_data_get_inode_number(data),
                          cg_storage_fs_cb_data_get_path_to(data),
                          cg_storage_fs_cb_data_get_parent_inode_number(data),
                          this->name,
                          cg_storage_filesystem_state_to_str(state),
                          result);
        }

        (*cb)(result,
              0,
              0,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

int cg_storage_filesystem_entry_inode_rename(cg_storage_filesystem * const this,
                                             uint64_t const old_parent_ino,
                                             char const * const old_name,
                                             uint64_t const new_parent_ino,
                                             char const * const new_name,
                                             cg_storage_filesystem_returning_renamed_and_deleted_inode_number_cb * const cb,
                                             void * const cb_data)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(old_parent_ino > 0);
    CGUTILS_ASSERT(old_name != NULL);
    CGUTILS_ASSERT(new_parent_ino > 0);
    CGUTILS_ASSERT(new_name != NULL);
    CGUTILS_ASSERT(cb != NULL);
    cg_storage_fs_cb_data * data = NULL;

    int result = cg_storage_fs_cb_data_init(this,
                                            &data);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cg_storage_fs_cb_data_set_path_dup(data,
                                                    old_name);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cg_storage_fs_cb_data_set_path_to_dup(data,
                                                           new_name);

            if (COMPILER_LIKELY(result == 0))
            {
                cg_storage_fs_cb_data_set_inode_number(data,
                                                       old_parent_ino);

                cg_storage_fs_cb_data_set_parent_inode_number(data,
                                                              new_parent_ino);

                cg_storage_fs_cb_data_set_handler(data,
                                                  &cg_storage_filesystem_entry_inode_rename_handler);

                cg_storage_fs_cb_data_set_callback(data,
                                                   cb,
                                                   cb_data);

                cg_storage_fs_cb_data_set_state(data,
                                                cg_storage_filesystem_state_renaming_entry);


                result = cg_storage_filesystem_db_rename_inode_entry(this,
                                                                     old_parent_ino,
                                                                     old_name,
                                                                     new_parent_ino,
                                                                     new_name,
                                                                     data);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error renaming entry %s from parent inode %"PRIu64" to %s on parent inode %"PRIu64", on fs %s: %d",
                                  old_name,
                                  old_parent_ino,
                                  new_name,
                                  new_parent_ino,
                                  this->name,
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error allocating memory for path %s of fs %s: %d",
                              new_name,
                              this->name,
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating memory for path %s of fs %s: %d",
                          old_name,
                          this->name,
                          result);
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            cg_storage_fs_cb_data_free(data), data = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Error allocating cb data: %d", result);
    }

    return result;
}

static void cg_storage_filesystem_entry_inode_hardlink_handler(int const status,
                                                               cg_storage_fs_cb_data * data)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    cg_storage_filesystem * this = cg_storage_fs_cb_data_get_fs(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    cg_storage_object * const obj = cg_storage_fs_cb_data_get_object(data);

    CGUTILS_ASSERT(this != NULL);

    if (result == 0)
    {
        switch(state)
        {
        case cg_storage_filesystem_state_inserting_entry:
        {
            /* Done. */
            cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            CGUTILS_ASSERT(cb != NULL);
            CGUTILS_ASSERT(obj != NULL);

            (*cb)(result,
                  obj,
                  cg_storage_fs_cb_data_get_callback_data(data));

            cg_storage_fs_cb_data_free(data), data = NULL;

            break;
        }
        default:
            CGUTILS_ERROR("Error, state %d is not handled", state);
            result = ENOSYS;
        }
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);
        CGUTILS_ASSERT(cb != NULL);

        if (result != EEXIST &&
            result != ENOENT &&
            result != ENOTDIR)
        {
            CGUTILS_ERROR("Error hardlinking existing inode %"PRIu64" to %"PRIu64"->%s on fs %s, state %s: %d",
                          cg_storage_fs_cb_data_get_inode_number(data),
                          cg_storage_fs_cb_data_get_parent_inode_number(data),
                          cg_storage_fs_cb_data_get_path(data),
                          this->name,
                          cg_storage_filesystem_state_to_str(state),
                          result);
        }

        (*cb)(result,
              NULL,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

int cg_storage_filesystem_entry_inode_hardlink(cg_storage_filesystem * const this,
                                               uint64_t const existing_ino,
                                               uint64_t const new_parent_ino,
                                               char const * const new_name,
                                               cg_storage_filesystem_entry_object_cb * const cb,
                                               void * const cb_data)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(existing_ino > 0);
    CGUTILS_ASSERT(new_parent_ino > 0);
    CGUTILS_ASSERT(new_name != NULL);
    CGUTILS_ASSERT(cb != NULL);
    cg_storage_fs_cb_data * data = NULL;

    int result = cg_storage_fs_cb_data_init(this,
                                            &data);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cg_storage_fs_cb_data_set_path_dup(data,
                                                    new_name);

        if (COMPILER_LIKELY(result == 0))
        {
            cg_storage_fs_cb_data_set_inode_number(data,
                                                   existing_ino);

            cg_storage_fs_cb_data_set_parent_inode_number(data,
                                                          new_parent_ino);

            cg_storage_fs_cb_data_set_handler(data,
                                              &cg_storage_filesystem_entry_inode_hardlink_handler);

            cg_storage_fs_cb_data_set_callback(data,
                                               cb,
                                               cb_data);

            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_inserting_entry);


            result = cg_storage_filesystem_db_add_inode_hardlink(this,
                                                                 existing_ino,
                                                                 new_parent_ino,
                                                                 new_name,
                                                                 data);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error hardlinking existing inode %"PRIu64" to %"PRIu64"->%s, on fs %s: %d",
                              existing_ino,
                              new_parent_ino,
                              new_name,
                              this->name,
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating memory for path %s of fs %s: %d",
                          new_name,
                          this->name,
                          result);
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            cg_storage_fs_cb_data_free(data), data = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Error allocating cb data: %d", result);
    }

    return result;
}

static void cg_storage_filesystem_entry_inode_symlink_handler(int const status,
                                                              cg_storage_fs_cb_data * data)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    cg_storage_filesystem * this = cg_storage_fs_cb_data_get_fs(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    cg_storage_object * const obj = cg_storage_fs_cb_data_get_object(data);

    CGUTILS_ASSERT(this != NULL);

    if (result == 0)
    {
        switch(state)
        {
        case cg_storage_filesystem_state_inserting_entry:
        {
            /* Done. */
            cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            CGUTILS_ASSERT(cb != NULL);
            CGUTILS_ASSERT(obj != NULL);

            /* The created inode number returned from the DB */
            cg_storage_object_set_inode_number(obj,
                                               cg_storage_fs_cb_data_get_returning_id(data));

            (*cb)(result,
                  obj,
                  cg_storage_fs_cb_data_get_callback_data(data));

            cg_storage_fs_cb_data_free(data), data = NULL;

            break;
        }
        default:
            CGUTILS_ERROR("Error, state %d is not handled", state);
            result = ENOSYS;
        }
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);
        CGUTILS_ASSERT(cb != NULL);

        if (result != EEXIST &&
            result != ENOENT &&
            result != ENOTDIR)
        {
            CGUTILS_ERROR("Error symlinking %"PRIu64"->%s to %s on fs %s, state %s: %d",
                          cg_storage_fs_cb_data_get_parent_inode_number(data),
                          cg_storage_fs_cb_data_get_path(data),
                          cg_storage_fs_cb_data_get_path_to(data),
                          this->name,
                          cg_storage_filesystem_state_to_str(state),
                          result);
        }

        (*cb)(result,
              NULL,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

int cg_storage_filesystem_entry_inode_symlink(cg_storage_filesystem * const this,
                                              uint64_t const new_parent_ino,
                                              char const * const new_name,
                                              char const * const link_to,
                                              uid_t const owner,
                                              gid_t const group,
                                              cg_storage_filesystem_entry_object_cb * const cb,
                                              void * const cb_data)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(new_parent_ino > 0);
    CGUTILS_ASSERT(new_name != NULL);
    CGUTILS_ASSERT(link_to != NULL);
    CGUTILS_ASSERT(cb != NULL);
    cg_storage_fs_cb_data * data = NULL;

    int result = cg_storage_fs_cb_data_init(this,
                                            &data);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cg_storage_fs_cb_data_set_path_dup(data,
                                                    new_name);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cg_storage_fs_cb_data_set_symlink_to_dup(data,
                                                              link_to);

            if (COMPILER_LIKELY(result == 0))
            {
                cg_storage_fs_cb_data_set_parent_inode_number(data,
                                                              new_parent_ino);

                cg_storage_fs_cb_data_set_handler(data,
                                                  &cg_storage_filesystem_entry_inode_symlink_handler);

                cg_storage_fs_cb_data_set_callback(data,
                                                   cb,
                                                   cb_data);

                cg_storage_fs_cb_data_set_state(data,
                                                cg_storage_filesystem_state_inserting_entry);


                result = cg_storage_filesystem_db_create_symlink_entry(this,
                                                                       owner,
                                                                       group,
                                                                       S_IFLNK|S_IRWXU|S_IRWXG|S_IRWXO,
                                                                       data);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error symlinking %"PRIu64"->%s to %s, on fs %s: %d",
                                  new_parent_ino,
                                  new_name,
                                  link_to,
                                  this->name,
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error allocating memory for link_to path %s of fs %s: %d",
                              link_to,
                              this->name,
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating memory for path %s of fs %s: %d",
                          new_name,
                          this->name,
                          result);
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            cg_storage_fs_cb_data_free(data), data = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Error allocating cb data: %d", result);
    }

    return result;
}

static void cg_storage_filesystem_entry_readlink_handler(int const status,
                                                         cg_storage_fs_cb_data * data)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    cg_storage_filesystem * this = cg_storage_fs_cb_data_get_fs(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    CGUTILS_ASSERT(this != NULL);

    if (result == 0)
    {
        switch(state)
        {
        case cg_storage_filesystem_state_fetching_entry:
        {
            /* Done. */
            cg_storage_filesystem_entry_readlink_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            char * link_to = cg_storage_fs_cb_data_get_symlink_to(data);
            CGUTILS_ASSERT(link_to != NULL);
            CGUTILS_ASSERT(cb != NULL);

            (*cb)(result,
                  link_to,
                  cg_storage_fs_cb_data_get_callback_data(data));

            cg_storage_fs_cb_data_set_symlink_to(data, NULL);
            cg_storage_fs_cb_data_free(data), data = NULL;

            break;
        }
        default:
            CGUTILS_ERROR("Error, state %d is not handled", state);
            result = ENOSYS;
        }
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_filesystem_entry_readlink_cb * cb = cg_storage_fs_cb_data_get_callback(data);
        CGUTILS_ASSERT(cb != NULL);

        if (result != EINVAL &&
            result != ENOENT)
        {
            CGUTILS_ERROR("Error reading link %"PRIu64" on fs %s, state %s: %d",
                          cg_storage_fs_cb_data_get_inode_number(data),
                          this->name,
                          cg_storage_filesystem_state_to_str(state),
                          result);
        }

        (*cb)(result,
              NULL,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

int cg_storage_filesystem_entry_readlink(cg_storage_filesystem * const this,
                                         uint64_t const inode_number,
                                         cg_storage_filesystem_entry_readlink_cb * const cb,
                                         void * const cb_data)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(inode_number > 0);
    CGUTILS_ASSERT(cb != NULL);
    cg_storage_fs_cb_data * data = NULL;

    int result = cg_storage_fs_cb_data_init(this,
                                            &data);

    if (COMPILER_LIKELY(result == 0))
    {
        cg_storage_fs_cb_data_set_parent_inode_number(data,
                                                      inode_number);

        cg_storage_fs_cb_data_set_handler(data,
                                          &cg_storage_filesystem_entry_readlink_handler);

        cg_storage_fs_cb_data_set_callback(data,
                                           cb,
                                           cb_data);

        cg_storage_fs_cb_data_set_state(data,
                                        cg_storage_filesystem_state_fetching_entry);


        result = cg_storage_filesystem_db_readlink(this,
                                                   inode_number,
                                                   data);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error reading link %"PRIu64", on fs %s: %d",
                          inode_number,
                          this->name,
                          result);
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            cg_storage_fs_cb_data_free(data), data = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Error allocating cb data: %d", result);
    }

    return result;
}

static int cg_storage_filesystem_entry_inode_setattr_in_cache(char const * const path_in_cache,
                                                              uint64_t const inode_number,
                                                              struct stat const * const st,
                                                              bool const update_size)
{
    int result = 0;

    CGUTILS_ASSERT(path_in_cache != NULL);
    CGUTILS_ASSERT(st != NULL);

    if (update_size == true)
    {
        result = cgutils_file_truncate(path_in_cache,
                                       st->st_size);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error truncating file in cache for inode %"PRIu64" (%s): %d",
                          inode_number,
                          path_in_cache,
                          result);
        }
    }

    if (result == 0)
    {
        struct timespec const ts[2] =
            {
                { .tv_sec = st->st_atime, .tv_nsec = 0 },
                { .tv_sec = st->st_mtime, .tv_nsec = 0 },
            };

        result = cgutils_file_utimens(path_in_cache,
                                      ts);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error updating times for file in cache / inode %"PRIu64" (%s): %d",
                          inode_number,
                          path_in_cache,
                          result);
        }
    }

    return result;
}

static void cg_storage_filesystem_entry_inode_setattr_handler(int const status,
                                                              cg_storage_fs_cb_data * data);

static int cg_storage_filesystem_entry_inode_setattr_released_cb(int const status,
                                                                 void * cb_data)
{
    cg_storage_filesystem_entry_inode_setattr_handler(status,
                                                      cb_data);

    return status;
}

static int cg_storage_filesystem_entry_inode_setattr_notify_write_cb(int const status,
                                                                     void * cb_data)
{
    cg_storage_filesystem_entry_inode_setattr_handler(status,
                                                      cb_data);

    return status;
}

static void cg_storage_filesystem_entry_inode_setattr_handler(int const status,
                                                              cg_storage_fs_cb_data * data)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    uint64_t const inode_number = cg_storage_fs_cb_data_get_inode_number(data);
    cg_storage_filesystem * fs = cg_storage_fs_cb_data_get_fs(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    char const * const path_in_cache = cg_storage_fs_cb_data_get_path_in_cache(data);
    struct stat const * st = cg_storage_fs_cb_data_get_stats(data);
    bool const file_size_changed = cg_storage_fs_cb_data_get_file_size_changed(data);
    CGUTILS_ASSERT(st != NULL);
    CGUTILS_ASSERT(fs != NULL);

    if (result == 0)
    {
        switch(state)
        {
        case cg_storage_filesystem_state_setting_dirty:
        {
            CGUTILS_ASSERT(path_in_cache != NULL);

            cg_storage_filesystem_entry_inode_setattr_in_cache(path_in_cache,
                                                               inode_number,
                                                               st,
                                                               file_size_changed);

            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_updating_inode_attributes);

            result = cg_storage_filesystem_db_update_inode_attributes(fs,
                                                                      inode_number,
                                                                      st->st_mode,
                                                                      st->st_uid,
                                                                      st->st_gid,
                                                                      st->st_atime,
                                                                      st->st_mtime,
                                                                      (size_t) st->st_size,
                                                                      data);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error in cg_storage_filesystem_db_update_inode_attributes for %"PRIu64" (%s): %d",
                              inode_number,
                              path_in_cache,
                              result);
            }

            break;
        }
        case cg_storage_filesystem_state_updating_inode_attributes:
        {
            if (COMPILER_UNLIKELY(file_size_changed == true))
            {
                CGUTILS_ASSERT(path_in_cache != NULL);

                /* We had to truncate the file, so we need to release it. */

                cg_storage_fs_cb_data_set_state(data,
                                                cg_storage_filesystem_state_releasing);

                result = cg_storage_filesystem_file_inode_released(fs,
                                                                   inode_number,
                                                                   true,
                                                                   &cg_storage_filesystem_entry_inode_setattr_released_cb,
                                                                   data);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error releasing inode %"PRIu64" (%s) after truncation: %d",
                                  inode_number,
                                  path_in_cache,
                                  result);
                }

                break;
            }
            /* fall-through */
            COMPILER_FALLTHROUGH;
        }
        case cg_storage_filesystem_state_releasing:
        {
            cg_storage_filesystem_status_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            CGUTILS_ASSERT(cb != NULL);

            (*cb)(result,
                  cg_storage_fs_cb_data_get_callback_data(data));

            cg_storage_fs_cb_data_free(data), data = NULL;

            break;
        }
        default:
            CGUTILS_ERROR("Error, state %d is not handled", state);
            result = ENOSYS;
        }
    }

    if (result != 0)
    {
        cg_storage_filesystem_status_cb * cb = cg_storage_fs_cb_data_get_callback(data);
        CGUTILS_ASSERT(cb != NULL);

        CGUTILS_ERROR("Error setting attributes for inode %"PRIu64" of fs %s, state %s: %d",
                      inode_number,
                      fs->name,
                      cg_storage_filesystem_state_to_str(state),
                      result);

        (*cb)(result,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}


static int cg_storage_filesystem_entry_inode_setattr_get_path_in_cache_cb(int const status,
                                                                          char * path_in_cache,
                                                                          void * cb_data)
{
    int result = status;
    cg_storage_fs_cb_data * data = cb_data;
    CGUTILS_ASSERT(data != NULL);
    cg_storage_filesystem * fs = cg_storage_fs_cb_data_get_fs(data);
    CGUTILS_ASSERT(fs != NULL);
    uint64_t const inode_number = cg_storage_fs_cb_data_get_inode_number(data);

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(path_in_cache != NULL);

        cg_storage_fs_cb_data_set_path_in_cache(data,
                                                path_in_cache);

        cg_storage_fs_cb_data_set_state(data,
                                        cg_storage_filesystem_state_setting_dirty);

        result = cg_storage_filesystem_file_inode_notify_write(fs,
                                                               inode_number,
                                                               &cg_storage_filesystem_entry_inode_setattr_notify_write_cb,
                                                               data);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error notifying write before truncating inode %"PRIu64": %d",
                          inode_number,
                          result);
        }
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_filesystem_status_cb * cb = cg_storage_fs_cb_data_get_callback(data);

        if (cb != NULL)
        {
            (*cb)(result,
                  cg_storage_fs_cb_data_get_callback_data(data));
        }

        cg_storage_fs_cb_data_free(data), data = NULL;
    }

    return result;
}

int cg_storage_filesystem_entry_inode_setattr(cg_storage_filesystem * const this,
                                              uint64_t const inode_number,
                                              struct stat const * const st,
                                              bool const file_size_changed,
                                              cg_storage_filesystem_status_cb * const cb,
                                              void * const cb_data)
{
    int result = 0;
    cg_storage_fs_cb_data * data = NULL;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(inode_number > 0);

    result = cg_storage_fs_cb_data_init(this,
                                        &data);

    if (COMPILER_LIKELY(result == 0))
    {
        cg_storage_fs_cb_data_set_inode_number(data,
                                               inode_number);

        cg_storage_fs_cb_data_set_file_size_changed(data,
                                                    file_size_changed);

        cg_storage_fs_cb_data_set_stats(data,
                                        st);

        cg_storage_fs_cb_data_set_handler(data,
                                          &cg_storage_filesystem_entry_inode_setattr_handler);

        cg_storage_fs_cb_data_set_callback(data,
                                           cb,
                                           cb_data);

        if (file_size_changed == true)
        {
            /* Ok, we will need to retrieve the file from the cloud provider.. */
            result = cg_storage_filesystem_file_inode_get_path_in_cache(this,
                                                                        inode_number,
                                                                        O_WRONLY,
                                                                        &cg_storage_filesystem_entry_inode_setattr_get_path_in_cache_cb,
                                                                        data);

            if (COMPILER_LIKELY(result != 0))
            {
                CGUTILS_ERROR("Error in cg_storage_filesystem_file_inode_get_path_in_cache for inode %"PRIu64": %d",
                                      inode_number,
                              result);
            }
        }
        else
        {
            char * cache_path = NULL;
            size_t cache_path_len = 0;

            result = cg_storage_cache_get_existing_path(this->cache,
                                                        inode_number,
                                                        false,
                                                        &cache_path,
                                                        &cache_path_len);

            if (COMPILER_LIKELY(result == 0))
            {
                struct stat cache_st = (struct stat) { 0 };

                result = cgutils_file_stat(cache_path,
                                           &cache_st);

                if (result == 0)
                {
                    /* File is in cache, update it */

                    cg_storage_filesystem_entry_inode_setattr_in_cache(cache_path,
                                                                       inode_number,
                                                                       st,
                                                                       file_size_changed);
                    /* we don't fail the request if the cache file has not been correctly updated */
                }

                result = 0;

                CGUTILS_FREE(cache_path);
            }

            if (result == 0)
            {
                cg_storage_fs_cb_data_set_state(data,
                                                cg_storage_filesystem_state_updating_inode_attributes);

                result = cg_storage_filesystem_db_update_inode_attributes(this,
                                                                          inode_number,
                                                                          st->st_mode,
                                                                          st->st_uid,
                                                                          st->st_gid,
                                                                          st->st_atime,
                                                                          st->st_mtime,
                                                                          (size_t) st->st_size,
                                                                          data);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error in cg_storage_filesystem_db_update_inode_attributes for %"PRIu64": %d",
                                  inode_number,
                                  result);
                }
            }
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            cg_storage_fs_cb_data_free(data), data = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Error allocating cb data: %d", result);
    }

    return result;
}
