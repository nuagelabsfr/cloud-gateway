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

#include <cloudutils/cloudutils_encoding.h>

#include <cgsm/cg_storage_cache.h>
#include <cgsm/cg_storage_filesystem_db.h>
#include <cgsm/cg_storage_filesystem_common.h>
#include <cgsm/cg_storage_filesystem_transfer_queue.h>
#include <cgsm/cg_storage_filesystem_utils.h>

static int cg_storage_filesystem_file_create_related_inode_instances(cg_storage_filesystem * const fs,
                                                                     char const * const path,
                                                                     uint64_t const parent,
                                                                     cg_storage_object * const object,
                                                                     cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(object != NULL);
    CGUTILS_ASSERT(path != NULL);
    CGUTILS_ASSERT(data != NULL);

    cgutils_llist * instances_to_up = NULL;

    result = cg_storage_filesystem_monitor_pick_instances_to(fs, &instances_to_up);

    if (result == 0)
    {
        CGUTILS_ASSERT(instances_to_up != NULL);

        for (cgutils_llist_elt * elt = cgutils_llist_get_iterator(instances_to_up);
             result == 0 &&
                 elt != NULL;
             elt = cgutils_llist_elt_get_next(elt))
        {
            cg_storage_instance * const instance = cgutils_llist_elt_get_object(elt);
            char * object_id = NULL;

            CGUTILS_ASSERT(instance != NULL);

            result = cgutils_asprintf(&object_id,
                                      "%"PRIu64"-%"PRIu64,
                                      fs->id,
                                      cg_storage_fs_cb_data_get_returning_id(data));


            if (result == 0)
            {
                char * id_in_instance = NULL;

                result = cg_storage_instance_get_object_id(instance,
                                                           object_id,
                                                           &id_in_instance);

                if (result == 0)
                {
                    cg_storage_fs_cb_data_inc_references(data);

                    result = cg_storage_filesystem_db_add_inode_instance(fs,
                                                                         cg_storage_instance_get_id(instance),
                                                                         cg_storage_object_get_inode_number(object),
                                                                         id_in_instance,
                                                                         cg_storage_instance_status_dirty,
                                                                         data);
                    if (result != 0)
                    {
                        cg_storage_fs_cb_data_dec_references(data);

                        CGUTILS_ERROR("Error adding inode instance entry %s of parent inode %"PRIu64", fs %s, instance %s: %d",
                                      path,
                                      parent,
                                      fs->name,
                                      cg_storage_instance_get_name(instance),
                                      result);
                    }

                    CGUTILS_FREE(id_in_instance);
                }
                else
                {
                    CGUTILS_ERROR("Error getting an id for entry %s of parent %"PRIu64", fs %s, instance %s: %d",
                                  path,
                                  parent,
                                  fs->name,
                                  cg_storage_instance_get_name(instance),
                                  result);
                }

                CGUTILS_FREE(object_id);
            }
            else
            {
                CGUTILS_ERROR("Error getting an object id for entry %s of parent %"PRIu64", fs %s: %d",
                              path,
                              parent,
                              fs->name,
                              result);
            }
        }

        cgutils_llist_free(&instances_to_up, NULL);
    }
    else
    {
        CGUTILS_ERROR("Error getting instance to upload entry %s of parent %"PRIu64", fs %s to: %d",
                      path,
                      parent,
                      fs->name,
                      result);
    }

    return result;
}

static void cg_storage_filesystem_file_create_and_open_handler(int const status,
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
            /* Entry inserted, we need to create the file in cache */
            char * path_in_cache = NULL;
            int fd_in_cache = -1;

            /* The created inode number returned from the DB */
            cg_storage_object_set_inode_number(object,
                                               cg_storage_fs_cb_data_get_returning_id(data));

            result = cg_storage_cache_create_file(fs->cache,
                                                  cg_storage_object_get_inode_number(object),
                                                  &path_in_cache,
                                                  &fd_in_cache);

            if (result == 0)
            {
                cg_storage_fs_cb_data_set_path_in_cache(data,
                                                        path_in_cache);
                path_in_cache = NULL;

                cg_storage_fs_cb_data_set_state(data,
                                                cg_storage_filesystem_state_adding_inode_instances);


                /* We have now to add inode instances
                   in order for the syncer to do its job. */

                result = cg_storage_filesystem_file_create_related_inode_instances(fs,
                                                                                   path,
                                                                                   parent,
                                                                                   object,
                                                                                   data);

                /* After this call, data refcount will be > 1 if there any DB operation (insert) pending,
                   1 otherwise. */

                if (cg_storage_fs_cb_data_get_references_count(data) == 1)
                {
                    cg_storage_filesystem_entry_object_and_path_cb * cb = cg_storage_fs_cb_data_get_callback(data);
                    CGUTILS_ASSERT(cb != NULL);
                    (*cb)(result,
                          object,
                          cg_storage_fs_cb_data_get_path_in_cache(data),
                          cg_storage_fs_cb_data_get_callback_data(data));

                    if (COMPILER_LIKELY(result == 0))
                    {
                        /* Path will be freed by the callback */
                        cg_storage_fs_cb_data_set_path_in_cache(data, NULL);
                    }
                }

                cg_storage_fs_cb_data_free(data), data = NULL;

                cgutils_file_close(fd_in_cache), fd_in_cache = -1;
            }
            else
            {
                CGUTILS_ERROR("Error creating inode (%"PRIu64") in cache for entry %s of parent %"PRIu64", on fs %s: %d",
                              cg_storage_object_get_inode_number(object),
                              path,
                              parent,
                              fs->name,
                              result);
            }

            break;
        }
        case cg_storage_filesystem_state_adding_inode_instances:
        {
            if (cg_storage_fs_cb_data_get_references_count(data) == 1)
            {
                cg_storage_filesystem_entry_object_and_path_cb * cb = cg_storage_fs_cb_data_get_callback(data);
                CGUTILS_ASSERT(cb != NULL);
                (*cb)(result,
                      object,
                      cg_storage_fs_cb_data_get_path_in_cache(data),
                      cg_storage_fs_cb_data_get_callback_data(data));

                if (COMPILER_LIKELY(result == 0))
                {
                    /* Path will be freed by the callback */
                    cg_storage_fs_cb_data_set_path_in_cache(data, NULL);
                }
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
        CGUTILS_ERROR("Error creating entry %s of parent %"PRIu64" on fs %s, state %s: %d",
                      path,
                      parent,
                      fs->name,
                      cg_storage_filesystem_state_to_str(state),
                      result);

        if (cg_storage_fs_cb_data_get_references_count(data) == 1)
        {
            cg_storage_filesystem_entry_object_and_path_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            CGUTILS_ASSERT(cb != NULL);

            (*cb)(result,
                  object,
                  cg_storage_fs_cb_data_get_path_in_cache(data),
                  cg_storage_fs_cb_data_get_callback_data(data));
        }

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

int cg_storage_filesystem_file_create_and_open(cg_storage_filesystem * const fs,
                                               uint64_t const parent,
                                               char const * const path,
                                               uid_t const uid,
                                               gid_t const gid,
                                               mode_t const mode,
                                               int const flags,
                                               cg_storage_filesystem_entry_object_and_path_cb * const cb,
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
            cg_storage_fs_cb_data_set_flags(data, flags);

            cg_storage_fs_cb_data_set_handler(data,
                                              &cg_storage_filesystem_file_create_and_open_handler);

            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_inserting_entry);

            cg_storage_fs_cb_data_set_callback(data,
                                                   cb,
                                               cb_data);

            result = cg_storage_filesystem_db_create_file_entry(fs,
                                                                uid,
                                                                gid,
                                                                mode,
                                                                flags,
                                                                data);

            if (result != 0)
            {
                CGUTILS_ERROR("Error creating entry %s on parent inode %"PRIu64 " on fs %s: %d",
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

static void cg_storage_filesystem_file_inode_released_handler(int const status,
                                                              cg_storage_fs_cb_data * data)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    uint64_t const inode = cg_storage_fs_cb_data_get_inode_number(data);
    cg_storage_filesystem * fs = cg_storage_fs_cb_data_get_fs(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    CGUTILS_ASSERT(fs != NULL);

    if (result == 0)
    {
        switch(state)
        {
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

        CGUTILS_ERROR("Error releasing inode %"PRIu64" of fs %s, state %s: %d",
                      inode,
                      fs->name,
                      cg_storage_filesystem_state_to_str(state),
                      result);

        (*cb)(result,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

int cg_storage_filesystem_file_inode_released(cg_storage_filesystem * const fs,
                                              uint64_t const inode,
                                              bool const altered,
                                              cg_storage_filesystem_status_cb * const cb,
                                              void * const cb_data)
{
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(inode > 0);
    cg_storage_fs_cb_data * data = NULL;

    int result = cg_storage_fs_cb_data_init(fs,
                                            &data);

    if (result == 0)
    {
        time_t mtime = 0;
        char * path_in_cache = NULL;
        size_t path_in_cache_len = 0;
        cg_storage_fs_cb_data_set_inode_number(data,
                                               inode);

        cg_storage_fs_cb_data_set_handler(data,
                                          &cg_storage_filesystem_file_inode_released_handler);

        cg_storage_fs_cb_data_set_callback(data,
                                           cb,
                                           cb_data);

        if (altered == true)
        {
            result  = cg_storage_cache_get_existing_path(fs->cache,
                                                         inode,
                                                         false,
                                                         &path_in_cache,
                                                         &path_in_cache_len);

            if (result == 0)
            {
                struct stat st = (struct stat) { 0 };

                result = cgutils_file_stat(path_in_cache,
                                           &st);

                if (result == 0)
                {
                    COMPILER_STATIC_ASSERT(sizeof (size_t) >= sizeof (off_t),
                                           "Off_t is bigger than size_t, we might overflow");

                    size_t const file_size = (size_t) st.st_size;
                    mtime = st.st_mtime;
                    cg_storage_fs_cb_data_set_file_size(data, file_size);
                }
                else if (result == ENOENT)
                {
                    /* the file may have been removed
                       then written to */
                    result = 0;
                }
                else
                {
                    CGUTILS_ERROR("Error looking for inode %"PRIu64" in cache, on fs %s: %d",
                                  inode,
                                  fs->name,
                                  result);
                }

                CGUTILS_FREE(path_in_cache);
            }
            else
            {
                CGUTILS_ERROR("Error getting the path of the inode %"PRIu64" in cache on fs %s: %d",
                              inode,
                              fs->name,
                              result);
            }
        }

        if (COMPILER_LIKELY(result == 0))
        {
            time_t const now = time(NULL);
            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_releasing);

            /*
              - Update inode's mtime and size if altered
              - Set all inodes_instances dirty if altered
              - Decrement inode's dirty count
            */
            /* Note that we absoultely can't use the mtime of the cache file
               since it might have been altered by a call to utime() (rsync,
               looking at you) and thus be set in the past.
               This means we can set a last_modification time quite later than
               the last real alteration, but we have no way to know that until
               we somehow make the FUSE process pass this info on to us.
               Still if the file has not been altered at all, altered is false
               and the last_modification field will not be updated so no issue there.
               Let's play it safe for now.
            */
            result = cg_storage_filesystem_db_release_inode(fs,
                                                            altered,
                                                            mtime,
                                                            now,
                                                            data);

            if (result != 0)
            {
                CGUTILS_ERROR("Error releasing inode %"PRIu64" (on fs %s): %d",
                              inode,
                              fs->name,
                              result);

            }
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

static void cg_storage_filesystem_file_inode_notify_write_handler(int const status,
                                                                  cg_storage_fs_cb_data * data)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    cg_storage_filesystem * fs = cg_storage_fs_cb_data_get_fs(data);
    uint64_t const inode_number = cg_storage_fs_cb_data_get_inode_number(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(inode_number > 0);

    if (COMPILER_LIKELY(result == 0))
    {
        switch(state)
        {
        case cg_storage_filesystem_state_setting_dirty:
        {
            cg_storage_filesystem_status_cb * const cb = cg_storage_fs_cb_data_get_callback(data);
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

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_filesystem_status_cb * cb = cg_storage_fs_cb_data_get_callback(data);
        CGUTILS_ASSERT(cb != NULL);

        CGUTILS_ERROR("Error setting dirty inode %"PRIu64" of fs %s, state %s: %d",
                      inode_number,
                      fs->name,
                      cg_storage_filesystem_state_to_str(state),
                      result);

        (*cb)(result,
              cg_storage_fs_cb_data_get_callback_data(data));

        cg_storage_fs_cb_data_free(data), data = NULL;
    }
}

int cg_storage_filesystem_file_inode_notify_write(cg_storage_filesystem * const fs,
                                                  uint64_t const inode_number,
                                                  cg_storage_filesystem_status_cb * const cb,
                                                  void * const cb_data)
{
    int result = 0;
    cg_storage_fs_cb_data * data = NULL;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(inode_number > 0);

    result = cg_storage_fs_cb_data_init(fs,
                                        &data);

    if (COMPILER_LIKELY(result == 0))
    {
        time_t const now = time(NULL);

        cg_storage_fs_cb_data_set_inode_number(data,
                                               inode_number);

        cg_storage_fs_cb_data_set_handler(data,
                                          &cg_storage_filesystem_file_inode_notify_write_handler);

        cg_storage_fs_cb_data_set_state(data,
                                        cg_storage_filesystem_state_setting_dirty);

        cg_storage_fs_cb_data_set_callback(data,
                                           cb,
                                           cb_data);

        result = cg_storage_filesystem_db_set_inode_dirty(fs,
                                                          inode_number,
                                                          now,
                                                          now,
                                                          now,
                                                          data);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error setting inode %"PRIu64" of fs %s dirty: %d",
                          inode_number,
                          fs->name,
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

static int cg_storage_filesystem_file_get_path_in_cache_transfer_cb(int const status,
                                                                    cg_storage_instance_infos * const infos,
                                                                    void * cb_data);

static int cg_storage_filesystem_file_retrieve_data_from_next_instance(cg_storage_filesystem * const this,
                                                                       cg_storage_fs_cb_data * const data)
{
    int result = 0;
    cgdb_inode_instance * selected_inode_instance = NULL;
    cg_storage_instance * selected_instance = NULL;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(data != NULL);
    cgutils_llist * available_instances = cg_storage_fs_cb_data_get_available_instances(data);
    cgdb_inode_instance * inode_instance_in_use = cg_storage_fs_cb_data_get_inode_instance_in_use(data);
    CGUTILS_ASSERT(available_instances != NULL);
    uint64_t const inode_number = cg_storage_fs_cb_data_get_inode_number(data);
    CGUTILS_ASSERT(inode_number > 0);

    /* First, we remove the temporary file we used if any */
    char const * const temporary_file_in_cache = cg_storage_fs_cb_data_get_path_to(data);
    cg_storage_object * object = cg_storage_fs_cb_data_get_object(data);

    if (temporary_file_in_cache != NULL)
    {
        cgutils_file_unlink(temporary_file_in_cache);
    }

    if (inode_instance_in_use != NULL)
    {
        int res = cgutils_llist_remove_by_object(available_instances,
                                                 inode_instance_in_use);

        if (res != 0)
        {
            CGUTILS_ERROR("Error removing inode instances (%s, %"PRIu64") from the list of available instances, "
                          "while retrieving the data of inode %"PRIu64" of fs %s: %d",
                          inode_instance_in_use->id_in_instance,
                          inode_instance_in_use->instance_id,
                          inode_number,
                          this->name,
                          res);
        }

        cgdb_inode_instance_free(inode_instance_in_use), inode_instance_in_use = NULL;
        cg_storage_fs_cb_data_set_inode_instance_in_use(data, NULL);
    }

    result = cg_storage_filesystem_monitor_pick_instance_from(this,
                                                              available_instances,
                                                              &(selected_inode_instance),
                                                              &(selected_instance));

    if (result == 0)
    {
        int temporary_fd = -1;
        char * temp_path = NULL;
        size_t temp_path_len = 0;
        assert(object != NULL);

        cg_storage_fs_cb_data_set_inode_instance_in_use(data,
                                                        selected_inode_instance);

        result = cg_storage_cache_get_temporary_path(this->cache,
                                                     inode_number,
                                                     &temp_path,
                                                     &temp_path_len,
                                                     &temporary_fd);

        if (result == 0)
        {
            int old_fd = cg_storage_fs_cb_data_get_fd(data);
            char * old_temporary_path = cg_storage_fs_cb_data_get_path_to(data);
            void const * existing_hash = NULL;
            size_t existing_hash_size = 0;
            cgutils_crypto_digest_algorithm algo = cgutils_crypto_digest_algorithm_none;

            if (old_temporary_path != NULL)
            {
                CGUTILS_FREE(old_temporary_path);
            }

            if (old_fd != -1)
            {
                cgutils_file_close(old_fd), old_fd = -1;
            }

            cg_storage_fs_cb_data_set_path_to(data,
                                              temp_path);

            cg_storage_fs_cb_data_set_fd(data, temporary_fd);


            /* If we have an existing digest, it makes sense to compute the
               digest of the received file to be able to compare it. */

            result = cg_storage_object_get_inode_digest(object,
                                                        &algo,
                                                        &existing_hash,
                                                        &existing_hash_size);

            if (result != 0)
            {
                algo = cgutils_crypto_digest_algorithm_none;
            }

            assert(selected_inode_instance != NULL);

            result = cg_storage_instance_get_file(selected_instance,
                                                  selected_inode_instance->id_in_instance,
                                                  temporary_fd,
                                                  algo,
                                                  &cg_storage_filesystem_file_get_path_in_cache_transfer_cb,
                                                  data);

            if (result != 0)
            {
                CGUTILS_ERROR("Error asking for data retrieval from instance %s, for inode %"PRIu64 " of fs %s: %d",
                              cg_storage_instance_get_name(selected_instance),
                              inode_number,
                              this->name,
                              result);
                result = EIO;

                cgutils_file_unlink(temp_path);
            }
        }
        else
        {
            CGUTILS_ERROR("Error getting temporary path for retrieving data of inode %"PRIu64 " on fs %s: %d",
                          inode_number,
                          this->name,
                          result);
        }
    }
    else if (result == ENOENT)
    {
        CGUTILS_ERROR("No instance available for retrieving data of inode %"PRIu64 " on fs %s: %d",
                      inode_number,
                      this->name,
                      result);
    }
    else
    {
        CGUTILS_ERROR("Error looking for a valid instance in order to retrieve data of inode %"PRIu64 " on fs %s: %d",
                      inode_number,
                      this->name,
                      result);
    }

    return result;
}

/* Callback from cg_storage_instance_get_file() */
static int cg_storage_filesystem_file_get_path_in_cache_transfer_cb(int const status,
                                                                    cg_storage_instance_infos * const infos,
                                                                    void * cb_data)
{
    int result = status;
    cg_storage_fs_cb_data * data = cb_data;
    bool finished = true;
    CGUTILS_ASSERT(data != NULL);
    cg_storage_filesystem * const this = cg_storage_fs_cb_data_get_fs(data);
    CGUTILS_ASSERT(this != NULL);
    uint64_t const inode_number = cg_storage_fs_cb_data_get_inode_number(data);
    CGUTILS_ASSERT(inode_number > 0);
    bool const is_delayed_expunge_entry = cg_storage_fs_cb_data_is_delayed_expunge_entry(data);

    (void) is_delayed_expunge_entry;

    if (result == 0 &&
        infos != NULL &&
        infos->algo != cgutils_crypto_digest_algorithm_none &&
        infos->digest != NULL &&
        infos->digest_size > 0)
    {
        /* We have a digest, this means that we asked for it so we probably have a previous digest
           to check. */
        cgutils_crypto_digest_algorithm existing_algo = cgutils_crypto_digest_algorithm_none;
        void const * existing_digest = NULL;
        size_t existing_digest_size = 0;

        cg_storage_object * object = cg_storage_fs_cb_data_get_object(data);
        CGUTILS_ASSERT(object != NULL);

        result = cg_storage_object_get_inode_digest(object,
                                                    &existing_algo,
                                                    &existing_digest,
                                                    &existing_digest_size);

        if (result == 0)
        {
            if (infos->algo == existing_algo)
            {
                char * digest_b64 = NULL;
                size_t digest_b64_size = 0;

                result = cgutils_encoding_base64_encode(infos->digest,
                                                        infos->digest_size,
                                                        (void **) &digest_b64,
                                                        &digest_b64_size);

                if (result == 0)
                {
                    if (digest_b64_size == existing_digest_size)
                    {
                        if (memcmp(digest_b64, existing_digest, digest_b64_size) == 0)
                        {
                            CGUTILS_DEBUG("Digest matches!");
                        }
                        else
                        {
                            CGUTILS_WARN("Received file digest does not match the existing one ! %s / %s",
                                         digest_b64,
                                         (char *) existing_digest);
                            result = EIO;
                        }
                    }
                    else
                    {
                        CGUTILS_WARN("Received file digest computed, but the existing object "
                                     "have a different digest size (%zu / %zu)",
                                     digest_b64_size,
                                     existing_digest_size);
                    }

                    CGUTILS_FREE(digest_b64);
                }
                else
                {
                    CGUTILS_WARN("Error while encoding computed hash to base64: %d", result);
                    result = 0;
                }
            }
            else
            {
                CGUTILS_WARN("Received file digest computed, "
                             "but the existing object have a different kind of digest (%d / %d)",
                             infos->algo,
                             existing_algo);
            }
        }
        else
        {
            CGUTILS_WARN("Received file digest computed, but the existing object does not seem to have one: %d",
                         result);
            result = 0;
        }

        CGUTILS_FREE(infos->digest);
    }

    if (result != 0)
    {
        /* The transfer failed, remove the faulty instance from the list of available ones
           and retry. */
        cgdb_inode_instance * inode_instance_in_use = cg_storage_fs_cb_data_get_inode_instance_in_use(data);
        assert(inode_instance_in_use);

        CGUTILS_INFO("Unable to retrieve data for inode %"PRIu64 " of fs %s from instance %"PRIu64": %d",
                     inode_number,
                     this->name,
                     inode_instance_in_use->instance_id,
                     status);

        do
        {
            result = cg_storage_filesystem_file_retrieve_data_from_next_instance(this,
                                                                                 data);
        }
        while(result == EIO);

        if (result != 0)
        {
            result = EIO;
        }
        else
        {
            finished = false;
        }
    }

    if (finished == true)
    {
        if (result == 0)
        {
            cg_storage_object * object = cg_storage_fs_cb_data_get_object(data);
            char * temporary_file_in_cache = cg_storage_fs_cb_data_get_path_to(data);
            char * final_path = NULL;
            struct timespec ts[2] =
                {
                    (struct timespec) { 0 },
                    (struct timespec) { 0 },
                };

            CGUTILS_ASSERT(temporary_file_in_cache != NULL);
            CGUTILS_ASSERT(object != NULL);

            /* Move temporary to final,
               update object cache status,
               then call cg_storage_filesystem_transfer_queue_done
            */
            cg_storage_filesystem_time_to_timespec(cg_storage_object_get_atime(object),
                                                   &(ts[0]));
            cg_storage_filesystem_time_to_timespec(cg_storage_object_get_mtime(object),
                                                   &(ts[1]));

            result = cgutils_file_utimens(temporary_file_in_cache,
                                          ts);

            if (result != 0 &&
                result != ENOENT)
            {
                CGUTILS_WARN("Error while updating times for cache file of inode %"PRIu64 " of fs %s: %d",
                             inode_number,
                             this->name,
                             result);
            }

            result = cg_storage_cache_move_temporary_to_final(this->cache,
                                                              inode_number,
                                                              temporary_file_in_cache,
                                                              &final_path);

            if (result == 0)
            {
                char * old_path_in_cache = cg_storage_fs_cb_data_get_path_in_cache(data);

                bool const need_to_increase_dirty_writers = cg_storage_fs_cb_data_get_dirty_writers_count_increased(data) == false &&
                    cgutils_file_are_writable_flags(cg_storage_fs_cb_data_get_flags(data)) == true;

                CGUTILS_ASSERT(old_path_in_cache != NULL);
                CGUTILS_ASSERT(strcmp(old_path_in_cache, final_path) == 0);
                CGUTILS_FREE(old_path_in_cache);
                CGUTILS_FREE(temporary_file_in_cache);

                cg_storage_fs_cb_data_set_path_to(data,
                                                  NULL);
                cg_storage_fs_cb_data_set_path_in_cache(data, final_path);
                cg_storage_fs_cb_data_set_state(data,
                                                cg_storage_filesystem_state_updating_cache_status_after_retrieval);

                result = cg_storage_filesystem_db_update_cache_and_dirty_writers_status(this,
                                                                                        inode_number,
                                                                                        true, /* in cache */
                                                                                        need_to_increase_dirty_writers,
                                                                                        data);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error updating cache status for inode %"PRIu64 " of fs %s: %d",
                                  inode_number,
                                  this->name,
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error moving temporary file for inode %"PRIu64 " of fs %s to final emplacement in cache: %d",
                              inode_number,
                              this->name,
                              result);
            }
        }

        if (result != 0)
        {
            /* Request failed. */
            result = cg_storage_filesystem_transfer_queue_done(this,
                                                               data,
                                                               result);

            if (result != 0)
            {
                cg_storage_filesystem_entry_get_path_cb * cb = cg_storage_fs_cb_data_get_callback(data);
                CGUTILS_ASSERT(cb != NULL);
                (*cb)(result,
                      NULL,
                      cg_storage_fs_cb_data_get_callback_data(data));

                cg_storage_fs_cb_data_free(data), data = NULL;
            }
        }
    }

    return result;
}

static int cg_storage_filesystem_file_retrieve_data(cg_storage_filesystem * const this,
                                                    cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(data != NULL);

    do
    {
        result = cg_storage_filesystem_file_retrieve_data_from_next_instance(this,
                                                                             data);
    }
    while(result == EIO);

    if (result != 0)
    {
        /* The handler will be called from queue_done,
           error handling will be done then. */

        result = cg_storage_filesystem_transfer_queue_done(this,
                                                           data,
                                                           EIO);
    }

    return result;
}

static void cg_storage_filesystem_file_inode_get_path_in_cache_execute_callback(int const result,
                                                                                cg_storage_fs_cb_data * data)
{
    cg_storage_filesystem_entry_get_path_cb * const cb = cg_storage_fs_cb_data_get_callback(data);
    CGUTILS_ASSERT(cb != NULL);

    (*cb)(result,
          result == 0 ? cg_storage_fs_cb_data_get_path_in_cache(data) : NULL,
          cg_storage_fs_cb_data_get_callback_data(data));

    if (result == 0)
    {
        cg_storage_fs_cb_data_set_path_in_cache(data,
                                                NULL);
    }

    cg_storage_fs_cb_data_free(data), data = NULL;
}

static void cg_storage_filesystem_file_inode_get_path_in_cache_handler(int const status,
                                                                       cg_storage_fs_cb_data * data)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    cg_storage_filesystem * this = cg_storage_fs_cb_data_get_fs(data);
    CGUTILS_ASSERT(this != NULL);
    uint64_t const inode_number = cg_storage_fs_cb_data_get_inode_number(data);
    CGUTILS_ASSERT(inode_number > 0);
    cg_storage_object * object = cg_storage_fs_cb_data_get_object(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);

    if (result == 0)
    {
        switch(state)
        {
        case cg_storage_filesystem_state_retrieving_inode:
        {
            bool in_cache = false;
            /* Ok, atime/ctime has been updated.
               Time to check if the inode is in cache. */

            CGUTILS_ASSERT(object != NULL);
            CGUTILS_ASSERT(cg_storage_object_get_inode_number(object) == inode_number);

            if (cg_storage_object_is_inode_marked_as_in_cache(object) == true)
            {
                char * path_in_cache = NULL;
                size_t path_in_cache_len = 0;

                /* As the inode is marked as cached in the database,
                   the DB call will have increased the dirty writers count if
                   the open() call contains writable flags.
                   We need to remember this so as not to increase it twice.
                */
                if (cgutils_file_are_writable_flags(cg_storage_fs_cb_data_get_flags(data)) == true)
                {
                    cg_storage_fs_cb_data_set_dirty_writers_count_increased(data, true);
                }

                result = cg_storage_cache_get_existing_path(this->cache,
                                                            inode_number,
                                                            false,
                                                            &path_in_cache,
                                                            &path_in_cache_len);

                if (result == 0)
                {
                    cg_storage_fs_cb_data_set_path_in_cache(data,
                                                            path_in_cache);

                    result = cg_storage_cache_check_freshness(this->cache,
                                                              object,
                                                              path_in_cache,
                                                              &in_cache);

                    if (COMPILER_UNLIKELY(result != 0))
                    {
                        CGUTILS_ERROR("Error checking cache validity for inode %"PRIu64" of fs %s: %d",
                                      inode_number,
                                      this->name,
                                      result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error getting path in cache for inode %"PRIu64" of fs %s: %d",
                                  inode_number,
                                  this->name,
                                  result);
                }
            }

            if (result == 0)
            {
                if (in_cache == true)
                {
                    CGUTILS_ASSERT(cg_storage_fs_cb_data_get_path_in_cache(data) != NULL);

                    cg_storage_filesystem_file_inode_get_path_in_cache_execute_callback(result, data);

                    data = NULL;
                }
                else
                {
                    /* Wait, maybe it's an empty file? */

                    if (cg_storage_object_get_size(object) == 0)
                    {
                        char * cache_path = NULL;
                        int fd = -1;

                        result = cg_storage_cache_create_file(this->cache,
                                                              inode_number,
                                                              &cache_path,
                                                              &fd);

                        if (result == 0 ||
                            result == EEXIST)
                        {
                            bool const need_to_increase_dirty_writers = cg_storage_fs_cb_data_get_dirty_writers_count_increased(data) == false &&
                                cgutils_file_are_writable_flags(cg_storage_fs_cb_data_get_flags(data)) == true;

                            if (cg_storage_fs_cb_data_get_path_in_cache(data) != NULL)
                            {
                                CGUTILS_FREE(cache_path);
                            }
                            else
                            {
                                cg_storage_fs_cb_data_set_path_in_cache(data,
                                                                        cache_path);
                            }

                            cgutils_file_close(fd), fd = -1;

                            /* Okay, we just created an empty file in cache.
                               We need to let the database layer know.
                            */

                            cg_storage_fs_cb_data_set_state(data,
                                                            cg_storage_filesystem_state_updating_cache_status);

                            result = cg_storage_filesystem_db_update_cache_and_dirty_writers_status(this,
                                                                                                    inode_number,
                                                                                                    true, /* in cache */
                                                                                                    need_to_increase_dirty_writers,
                                                                                                    data);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error updating cache status for inode %"PRIu64" of fs %s: %d",
                                              inode_number,
                                              this->name,
                                              result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error creating cache for inode %"PRIu64" of fs %s: %d",
                                          inode_number,
                                          this->name,
                                          result);
                        }
                    }
                    else
                    {
                        /* Aww, crap. We need to retrieve the file from one of the providers.
                         */

                        /* Are we already trying to retrieve that file for another request? */
                        if (cg_storage_filesystem_transfer_queue_is_pending(this,
                                                                            object) == true)
                        {
                            cg_storage_fs_cb_data_set_state(data,
                                                            cg_storage_filesystem_state_queued);

                            /* Adding ourself to the waiting queue, so we are woken up when the
                               data has been retrieved. */
                            result = cg_storage_filesystem_transfer_queue_add(this,
                                                                              data);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error adding this request to the request queue for inode %"PRIu64" of fs %s: %d",
                                              inode_number,
                                              this->name,
                                              result);
                            }
                        }
                        else
                        {
                            /* Okay, okay, we really have to get it, see which provider has it. */

                            result = cg_storage_filesystem_transfer_queue_add(this,
                                                                              data);

                            if (result == 0)
                            {
                                cg_storage_fs_cb_data_set_state(data,
                                                                cg_storage_filesystem_state_fetching_inode_instances);

                                result = cg_storage_filesystem_db_get_valid_inode_instances(this,
                                                                                            data);
                            }
                            else
                            {
                                CGUTILS_ERROR("Error adding this request to the request queue for inode number %"PRIu64 " of fs %s: %d",
                                              cg_storage_fs_cb_data_get_inode_number(data),
                                              this->name,
                                              result);
                            }
                        }
                    }
                }
            }

            break;
        }
        case cg_storage_filesystem_state_fetching_inode_instances:
        {
            /* We are the one doing the retrieving (ie, the queue was empty),
               we now have the list of valid instances having the data we need. */
            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_retrieving_data);

            result = cg_storage_filesystem_file_retrieve_data(this,
                                                              data);
            break;
        }
        case cg_storage_filesystem_state_updating_cache_status_after_retrieval:
        {
            /* We have retrieved the data from an instance, and have just updated the cache
               status in database. We now need to wake up everybody who is waiting in the queue
               (including us, therefore we are going back here with a different status, beware. */

            if (cgutils_file_are_writable_flags(cg_storage_fs_cb_data_get_flags(data)) == true)
            {
                cg_storage_fs_cb_data_set_dirty_writers_count_increased(data, true);
            }

            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_retrieving_data);

            result = cg_storage_filesystem_transfer_queue_done(this,
                                                               data,
                                                               0);

            break;
        }
        case cg_storage_filesystem_state_retrieving_data:
        case cg_storage_filesystem_state_queued:
        {
            /* We are here because either:
               - we just retrieved the data from an instance, and have updated the cache status ;
               - or we have been queued (another request was active) and the request has succeeded.
               Anyway we now we have the needed data in cache. */

            if (cg_storage_fs_cb_data_get_dirty_writers_count_increased(data) == false &&
                cgutils_file_are_writable_flags(cg_storage_fs_cb_data_get_flags(data)))
            {
                /* The file has been opened in write mode, we need to inc
                   the dirty writers of the related inode */

                cg_storage_fs_cb_data_set_state(data,
                                                cg_storage_filesystem_state_updating_dirty_writers);

                result = cg_storage_filesystem_db_update_inode_counter(this,
                                                                       inode_number,
                                                                       true,
                                                                       data);
                if (result != 0)
                {
                    CGUTILS_ERROR("Error updating inode dirty writers counter: %d", result);
                }

                break;
            }
            /* Fall through */
            COMPILER_FALLTHROUGH;
        }
        case cg_storage_filesystem_state_updating_cache_status:
        case cg_storage_filesystem_state_updating_dirty_writers:
        {
            CGUTILS_ASSERT(cg_storage_fs_cb_data_get_path_in_cache(data) != NULL);

            cg_storage_filesystem_file_inode_get_path_in_cache_execute_callback(result, data);

            data = NULL;

            break;
        }
        case cg_storage_filesystem_state_rolling_back_dirty_writers_after_error:
        {
            /* We are here because something failed after
               we increased the dirty writers count, so we needed to decrease it.
               That's now done.
            */
            int const saved_result = cg_storage_fs_cb_data_get_error(data);

            cg_storage_filesystem_file_inode_get_path_in_cache_execute_callback(saved_result,
                                                                                data);

            data = NULL;

            break;
        }
        default:
            CGUTILS_ERROR("Error, state %d is not handled", state);
            result = ENOSYS;
        }
    }

    if (result != 0)
    {
        cg_storage_filesystem_handler_state const saved_state = cg_storage_fs_cb_data_get_state(data);

        int res = 0;

        if (saved_state == cg_storage_filesystem_state_updating_cache_status_after_retrieval)
        {
            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_retrieving_data);

            res = cg_storage_filesystem_transfer_queue_done(this,
                                                            data,
                                                            0);
        }

        if (saved_state != cg_storage_filesystem_state_updating_cache_status_after_retrieval ||
            res != 0)
        {
            bool const dirty_writers_increased = cg_storage_fs_cb_data_get_dirty_writers_count_increased(data);

            if (dirty_writers_increased &&
                (state == cg_storage_filesystem_state_queued ||
                 state == cg_storage_filesystem_state_fetching_inode_instances))
            {
                cg_storage_fs_cb_data_set_error(data,
                                                result);

                cg_storage_fs_cb_data_set_state(data,
                                                cg_storage_filesystem_state_rolling_back_dirty_writers_after_error);

                res = cg_storage_filesystem_db_decrease_dirty_writers_count(this,
                                                                            inode_number,
                                                                            data);
            }
        }

        if (saved_state != cg_storage_filesystem_state_updating_cache_status_after_retrieval ||
            res != 0)
        {
            CGUTILS_ERROR("Error getting inode %"PRIu64" of fs %s, state %s: %d",
                          inode_number,
                          this->name,
                          cg_storage_filesystem_state_to_str(saved_state),
                          result);

            cg_storage_filesystem_file_inode_get_path_in_cache_execute_callback(result, data);

            data = NULL;
        }
    }
}

/* This function retrieves the file from a provider if needed,
   and then provides the path to the cached data.
*/
int cg_storage_filesystem_file_inode_get_path_in_cache(cg_storage_filesystem * const this,
                                                       uint64_t const inode_number,
                                                       int const flags,
                                                       cg_storage_filesystem_entry_get_path_cb * const cb,
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

        cg_storage_fs_cb_data_set_flags(data,
                                        flags);

        cg_storage_fs_cb_data_set_handler(data,
                                          &cg_storage_filesystem_file_inode_get_path_in_cache_handler);

        cg_storage_fs_cb_data_set_callback(data,
                                           cb,
                                           cb_data);

        cg_storage_fs_cb_data_set_state(data,
                                        cg_storage_filesystem_state_retrieving_inode);


        /* First, we fetch the corresponding inode, updating the atime/ctime in the meantime,
           and the dirty_writers count as well if the inode is marked as being present in cache.
        */

        result = cg_storage_filesystem_db_get_inode_cache_status_updating_writers(this,
                                                                                  inode_number,
                                                                                  cgutils_file_are_writable_flags(flags),
                                                                                  data);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error getting inode cache status for inode %"PRIu64" on fs %s: %d",
                          inode_number,
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
