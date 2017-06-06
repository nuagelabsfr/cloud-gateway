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

#include <cgsm/cg_storage_filesystem_db.h>
#include <cgsm/cg_storage_filesystem_common.h>
#include <cgsm/cg_storage_cache.h>

static void cg_storage_filesystem_dir_get_entries_by_inode_handler(int const status,
                                                                   cg_storage_fs_cb_data * data)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    cg_storage_filesystem * this = cg_storage_fs_cb_data_get_fs(data);
    uint64_t const parent_inode_number = cg_storage_fs_cb_data_get_inode_number(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(parent_inode_number >= 1);

    if (result == 0)
    {
        switch(state)
        {
        case cg_storage_filesystem_state_fetching_dir_entries:
        {
            /* Vector of cgdb_entry * */
            cgutils_vector * entries = cg_storage_fs_cb_data_get_entries_vector(data);
            size_t const entries_count = cgutils_vector_count(entries);

            for (size_t idx = 0;
                 idx < entries_count;
                 idx++)
            {
                cgdb_entry * entry = NULL;

                int res = cgutils_vector_get(entries,
                                             idx,
                                             (void **) &entry);

                if (res == 0)
                {
                    CGUTILS_ASSERT(entry != NULL);

                    res = cg_storage_cache_refresh_db_stats(this->cache,
                                                            entry);

                    if (res != 0)
                    {
                        CGUTILS_WARN("Error checking cache validity for inode %"PRIu64" on fs %s: %d",
                                     entry->inode.inode_number,
                                     this->name,
                                     res);
                    }

                    cg_storage_object_fix_entry_block(this, entry);
                }
                else
                {
                    CGUTILS_WARN("Error accessing entries %zu / %zu for inode %"PRIu64" on fs %s: %d",
                                 idx,
                                 entries_count,
                                 entry->inode.inode_number,
                                 this->name,
                                 res);
                }
            }

            cg_storage_filesystem_dir_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            CGUTILS_ASSERT(cb != NULL);

            (*cb)(result,
                  (entries != NULL) ? cgutils_vector_count(entries) : 0,
                  entries,
                  cg_storage_fs_cb_data_get_callback_data(data));

            cg_storage_fs_cb_data_set_entries_vector(data, NULL);

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
        cg_storage_filesystem_dir_cb * cb = cg_storage_fs_cb_data_get_callback(data);

        CGUTILS_ERROR("Error getting entries from directory inode %"PRIu64" of fs %s, state %s: %d",
                      parent_inode_number,
                      this->name,
                      cg_storage_filesystem_state_to_str(state),
                      result);

        CGUTILS_ASSERT(cb != NULL);

        (*cb)(result,
              0,
              NULL,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

int cg_storage_filesystem_dir_get_entries_by_inode(cg_storage_filesystem * const fs,
                                                   uint64_t const inode,
                                                   cg_storage_filesystem_dir_cb * const cb,
                                                   void * const cb_data)
{
    int result = 0;
    cg_storage_fs_cb_data * data = NULL;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(inode >= 1);
    CGUTILS_ASSERT(cb != NULL);

    result = cg_storage_fs_cb_data_init(fs,
                                        &data);

    if (result == 0)
    {
        cg_storage_fs_cb_data_set_inode_number(data, inode);

        cg_storage_fs_cb_data_set_handler(data,
                                          &cg_storage_filesystem_dir_get_entries_by_inode_handler);

        cg_storage_fs_cb_data_set_callback(data,
                                           cb,
                                           cb_data);

        cg_storage_fs_cb_data_set_state(data,
                                        cg_storage_filesystem_state_fetching_dir_entries);


        result = cg_storage_filesystem_db_get_dir_entries_by_inode(fs,
                                                                   inode,
                                                                   data);

        if (result != 0)
        {
            CGUTILS_ERROR("Error getting children entries of inode %zu on fs %s: %d",
                          inode,
                          fs->name,
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

    return result;
}

static void cg_storage_filesystem_dir_mkdir_inode_handler(int const status,
                                                          cg_storage_fs_cb_data * data)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    cg_storage_filesystem * fs = cg_storage_fs_cb_data_get_fs(data);
    char const * const path = cg_storage_fs_cb_data_get_path(data);
    cg_storage_object * object = cg_storage_fs_cb_data_get_object(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    uint64_t const parent = cg_storage_fs_cb_data_get_parent_inode_number(data);
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(path != NULL);

    if (result == 0)
    {
        switch(state)
        {
        case cg_storage_filesystem_state_inserting_entry:
        {
            /* The created inode number returned from the DB */
            cg_storage_object_set_inode_number(object,
                                               cg_storage_fs_cb_data_get_returning_id(data));

            cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            CGUTILS_ASSERT(cb != NULL);
            (*cb)(result,
                  object,
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
        CGUTILS_ERROR("Error creating dir entry %s of parent %"PRIu64" on fs %s, state %s: %d",
                      path,
                      parent,
                      fs->name,
                      cg_storage_filesystem_state_to_str(state),
                      result);

        cg_storage_filesystem_entry_object_cb * cb = cg_storage_fs_cb_data_get_callback(data);
        CGUTILS_ASSERT(cb != NULL);

        (*cb)(result,
              object,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

int cg_storage_filesystem_dir_inode_mkdir(cg_storage_filesystem * const fs,
                                          uint64_t const parent,
                                          char const * const path,
                                          uid_t const uid,
                                          gid_t const gid,
                                          mode_t const mode,
                                          cg_storage_filesystem_entry_object_cb * const cb,
                                          void * const cb_data)
{
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(parent > 0);
    CGUTILS_ASSERT(path != NULL);
    cg_storage_fs_cb_data * data = NULL;

    int result = cg_storage_fs_cb_data_init(fs,
                                            &data);

    if (result == 0)
    {
        result = cg_storage_fs_cb_data_set_path_dup(data, path);

        if (result == 0)
        {
            cg_storage_fs_cb_data_set_parent_inode_number(data, parent);

            cg_storage_fs_cb_data_set_handler(data,
                                              &cg_storage_filesystem_dir_mkdir_inode_handler);

            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_inserting_entry);

            cg_storage_fs_cb_data_set_callback(data,
                                                   cb,
                                               cb_data);

            result = cg_storage_filesystem_db_create_dir_entry(fs,
                                                               uid,
                                                               gid,
                                                               mode,
                                                               data);

            if (result != 0)
            {
                CGUTILS_ERROR("Error creating dir entry %s on parent inode %"PRIu64 " on fs %s: %d",
                              path,
                              parent,
                              fs->name,
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating memory for path %s of fs %s: %d",
                          path,
                          fs->name,
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

    return result;
}

static void cg_storage_filesystem_dir_rmdir_inode_handler(int const status,
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
            CGUTILS_ASSERT(cb != NULL);
            (*cb)(result,
                  cg_storage_fs_cb_data_get_returning_id(data),
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
        cg_storage_filesystem_returning_inode_number_cb * cb = cg_storage_fs_cb_data_get_callback(data);
        CGUTILS_ASSERT(cb != NULL);

        if (COMPILER_UNLIKELY(result != ENOENT &&
                              result != ENOTDIR &&
                              result != ENOTEMPTY))
        {
            CGUTILS_ERROR("Error removing dir entry %s from parent %"PRIu64" on fs %s, state %s: %d",
                          path,
                          parent,
                          fs->name,
                          cg_storage_filesystem_state_to_str(state),
                          result);
        }

        (*cb)(result,
              0,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

int cg_storage_filesystem_dir_inode_rmdir(cg_storage_filesystem * const fs,
                                          uint64_t const parent,
                                          char const * const name,
                                          cg_storage_filesystem_returning_inode_number_cb * const cb,
                                          void * const cb_data)
{
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(parent > 0);
    CGUTILS_ASSERT(name != NULL);
    cg_storage_fs_cb_data * data = NULL;

    int result = cg_storage_fs_cb_data_init(fs,
                                            &data);

    if (result == 0)
    {
        result = cg_storage_fs_cb_data_set_path_dup(data, name);

        if (result == 0)
        {
            cg_storage_fs_cb_data_set_parent_inode_number(data, parent);

            cg_storage_fs_cb_data_set_handler(data,
                                              &cg_storage_filesystem_dir_rmdir_inode_handler);

            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_removing_entry);

            cg_storage_fs_cb_data_set_callback(data,
                                                   cb,
                                               cb_data);

            result = cg_storage_filesystem_db_remove_dir_entry(fs,
                                                               parent,
                                                               name,
                                                               data);

            if (result != 0)
            {
                CGUTILS_ERROR("Error removing dir entry %s from parent inode %"PRIu64 " on fs %s: %d",
                              name,
                              parent,
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

        if (result != 0)
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
