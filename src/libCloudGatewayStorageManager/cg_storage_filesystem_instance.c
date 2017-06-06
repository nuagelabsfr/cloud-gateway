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
#include <cgsm/cg_storage_filesystem_common.h>
#include <cgsm/cg_storage_filesystem_db.h>
#include <cgsm/cg_storage_filesystem_utils.h>

#include <cloudutils/cloudutils_encoding.h>

static int cg_storage_filesystem_instance_put_cb(int const status,
                                                 cg_storage_instance_infos * const infos,
                                                 void * const cb_data)
{
    cg_storage_fs_cb_data * data = cb_data;
    assert(data != NULL);

    if (infos != NULL)
    {
        cg_storage_fs_cb_data_set_compressed(data, infos->compressed);
        cg_storage_fs_cb_data_set_encrypted(data, infos->encrypted);

        cg_storage_fs_cb_data_set_digest(data, infos->algo, infos->digest, infos->digest_size);
    }

    cg_storage_filesystem_return_to_handler(status, data);

    return status;
}

static int cg_storage_filesystem_instance_generic_cb(int const status,
                                                     void * const cb_data)
{
    cg_storage_fs_cb_data * data = cb_data;
    assert(data != NULL);

    cg_storage_filesystem_return_to_handler(status, data);

    return status;
}

static void cg_storage_filesystem_instance_put_handler(int const status,
                                                       cg_storage_fs_cb_data * data)
{
    int result = status;
    assert(data != NULL);
    cg_storage_filesystem * fs = cg_storage_fs_cb_data_get_fs(data);
    cgdb_inode_instance * inode_instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    assert(fs != NULL);
    assert(inode_instance != NULL);

    if (result == 0)
    {
        switch(state)
        {
        case cg_storage_filesystem_state_setting_upload_in_progress:
        {
            cg_storage_instance * inst = NULL;

            /* Flag set to uploading */

            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_uploading_inode);

            result = cg_storage_manager_data_get_instance_by_id(fs->data,
                                                                inode_instance->instance_id,
                                                                &inst);

            if (result == 0)
            {
                int fd = -1;

                /* Set the new upload_time here, it will be used to check that the computed digest is usable. */
                inode_instance->upload_time = (uint64_t) time(NULL);

                result = cgutils_file_open(cg_storage_fs_cb_data_get_path_in_cache(data),
                                           O_RDONLY,
                                           0,
                                           &fd);

                if (result == 0)
                {
                    size_t file_size = 0;

                    assert((unsigned long) file_size <= SIZE_MAX);

                    result = cgutils_file_get_size(fd,
                                                   &file_size);

                    if (result == 0)
                    {
                        cgutils_llist * metadata = NULL;
                        cgutils_crypto_digest_algorithm algo = cgutils_crypto_digest_algorithm_none;

                        if (inode_instance->inode_digest_type == cgutils_crypto_digest_algorithm_none &&
                            inode_instance->inode_dirty_writers == 0 &&
                            file_size > 0)
                        {
                            /* We don't have a digest for this inode
                               and no one has an open fd on it,
                               ask for a new digest to be computed */
                            algo = fs->digest_algorithm;

                        }

                        cg_storage_fs_cb_data_set_fd(data, fd);

                        result = cg_storage_instance_put_file(inst,
                                                              inode_instance->id_in_instance,
                                                              fd,
                                                              file_size,
                                                              metadata,
                                                              algo,
                                                              &cg_storage_filesystem_instance_put_cb,
                                                              data);
                        if (result != 0)
                        {
                            CGUTILS_ERROR("Error uploading inode %"PRIu64" (%s on %s) on fs %s: %d",
                                          inode_instance->inode_number,
                                          inode_instance->id_in_instance,
                                          cg_storage_instance_get_name(inst),
                                          fs->name,
                                          result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error getting size for file %s, inode %"PRIu64" (%s on %s), fs %s: %d",
                                      cg_storage_fs_cb_data_get_path_in_cache(data),
                                      inode_instance->inode_number,
                                      inode_instance->id_in_instance,
                                      cg_storage_instance_get_name(inst),
                                      fs->name,
                                      result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error opening cache file %s, inode %"PRIu64" (%s on %s), fs %s: %d",
                                  cg_storage_fs_cb_data_get_path_in_cache(data),
                                  inode_instance->inode_number,
                                  inode_instance->id_in_instance,
                                  cg_storage_instance_get_name(inst),
                                  fs->name,
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Unable to find instance with an id of %"PRIu64": %d",
                              inode_instance->instance_id,
                              result);
            }

            break;
        }
        case cg_storage_filesystem_state_uploading_inode:
        {
            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_dirty_status_cleared);

            result = cg_storage_filesystem_db_clear_inode_instance_dirty_status(fs,
                                                                                cg_storage_fs_cb_data_get_compressed(data),
                                                                                cg_storage_fs_cb_data_get_encrypted(data),
                                                                                data);

            if (result != 0)
            {
                CGUTILS_ERROR("Error clearing dirty status for inode %"PRIu64" from DB (%s) on fs %s: %d",
                              inode_instance->inode_number,
                              inode_instance->id_in_instance,
                              fs->name,
                              result);
            }

            break;
        }
        case cg_storage_filesystem_state_dirty_status_cleared:
        {
            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_setting_upload_done);

            result = cg_storage_filesystem_db_set_inode_instance_uploading_done(fs,
                                                                                /* no error occured */
                                                                                false,
                                                                                data);

            if (result != 0)
            {
                CGUTILS_ERROR("Error setting upload done for inode %"PRIu64" from DB (%s) on fs %s: %d",
                              inode_instance->inode_number,
                              inode_instance->id_in_instance,
                              fs->name,
                              result);
            }

            break;
        }
        case cg_storage_filesystem_state_setting_upload_done:
        {
            cgutils_crypto_digest_algorithm algo = cgutils_crypto_digest_algorithm_none;
            void * digest = NULL;
            size_t digest_size = 0;

            cg_storage_fs_cb_data_get_digest(data,
                                             &algo,
                                             &digest,
                                             &digest_size);

            if (algo != cgutils_crypto_digest_algorithm_none)
            {
                /* Looks like we received a new digest, update the DB */
                char * digest_char = NULL;
                size_t digest_char_size = 0;

                result = cgutils_encoding_base64_encode(digest,
                                                        digest_size,
                                                        (void **) &digest_char,
                                                        &digest_char_size);

                if (result == 0)
                {
                    cg_storage_fs_cb_data_set_digest(data,
                                                     algo,
                                                     digest_char,
                                                     digest_char_size);
                    CGUTILS_FREE(digest);

                    cg_storage_fs_cb_data_set_state(data,
                                                    cg_storage_filesystem_state_inode_digest_updated);

                    result = cg_storage_filesystem_db_set_inode_digest(fs,
                                                                       inode_instance->inode_number,
                                                                       algo,
                                                                       digest_char,
                                                                       digest_char_size,
                                                                       inode_instance->upload_time,
                                                                       data);

                    if (result == 0)
                    {
                        break;
                    }
                    else
                    {
                        CGUTILS_WARN("Error updating digest for inode %"PRIu64" on fs %s: %d",
                                     inode_instance->inode_number,
                                     fs->name,
                                     result);
                    }
                }
                else
                {
                    CGUTILS_WARN("Error encoding digest to base64 for inode %"PRIu64" on fs %s: %d",
                                     inode_instance->inode_number,
                                     fs->name,
                                     result);
                }

                result = 0;
                /* Fall through */
            }
            else
            {
                /* Nothing to do, so:
                   Fall through */
            }
            COMPILER_FALLTHROUGH;
        }
        case cg_storage_filesystem_state_inode_digest_updated:
        {
            cg_storage_filesystem_status_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            cgdb_inode_instance * instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);

            if (cb != NULL)
            {

                (*cb)(result,
                      cg_storage_fs_cb_data_get_callback_data(data));
            }

            cgdb_inode_instance_free(instance), instance = NULL;
            cg_storage_fs_cb_data_set_inode_instance_in_use(data, NULL);

            cg_storage_fs_cb_data_free(data), data = NULL;

            break;
        }
        case cg_storage_filesystem_state_handling_error:
        {
            /* An error occured, we cleared this instance inode state (not uploading anymore) */
            cg_storage_filesystem_status_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            cgdb_inode_instance * instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);

            int const error = cg_storage_fs_cb_data_get_error(data);

            CGUTILS_DEBUG("handling error for instance inode %"PRIu64" of fs %s, cb is %p, result is %d",
                          inode_instance->inode_number,
                          fs->name,
                          cb,
                          error);

            if (cb != NULL)
            {
                (*cb)(error,
                      cg_storage_fs_cb_data_get_callback_data(data));
            }

            cgdb_inode_instance_free(instance), instance = NULL;
            cg_storage_fs_cb_data_set_inode_instance_in_use(data, NULL);

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
        CGUTILS_ERROR("Error uploading instance inode %"PRIu64" of fs %s, state %s: %d",
                      inode_instance->inode_number,
                      fs->name,
                      cg_storage_filesystem_state_to_str(state),
                      result);

        if (state != cg_storage_filesystem_state_handling_error)
        {
            CGUTILS_DEBUG("Setting uploading to false for instance inode %"PRIu64" of fs %s",
                          inode_instance->inode_number,
                          fs->name);

            cg_storage_fs_cb_data_set_error(data, result);

            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_handling_error);

            result = cg_storage_filesystem_db_set_inode_instance_uploading_done(fs,
                                                                                /* an error occured */
                                                                                true,
                                                                                data);
        }

        if (result != 0)
        {
            cg_storage_filesystem_status_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            cgdb_inode_instance * instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);

            if (cb != NULL)
            {
                (*cb)(result,
                      cg_storage_fs_cb_data_get_callback_data(data));
            }

            cgdb_inode_instance_free(instance), instance = NULL;
            cg_storage_fs_cb_data_set_inode_instance_in_use(data, NULL);

            cg_storage_fs_cb_data_free(data), data = NULL;
        }
    }
}

int cg_storage_filesystem_instance_put_inode(cg_storage_filesystem * const this,
                                             cgdb_inode_instance * inode_instance,
                                             cg_storage_filesystem_status_cb * const cb,
                                             void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL &&
        inode_instance != NULL)
    {
        char * cache_path = NULL;
        size_t cache_path_len = 0;

        result = cg_storage_cache_get_existing_path(this->cache,
                                                    inode_instance->inode_number,
                                                    false,
                                                    &cache_path,
                                                    &cache_path_len);

        if (result == 0)
        {
            cg_storage_fs_cb_data * data = NULL;

            result = cg_storage_fs_cb_data_init(this,
                                                &data);

            if (result == 0)
            {
                cg_storage_fs_cb_data_set_inode_instance_in_use(data,
                                                                inode_instance);

                cg_storage_fs_cb_data_set_path_in_cache(data,
                                                        cache_path);
                cache_path = NULL;

                cg_storage_fs_cb_data_set_handler(data,
                                                  &cg_storage_filesystem_instance_put_handler);

                cg_storage_fs_cb_data_set_callback(data,
                                                   cb,
                                                   cb_data);

                cg_storage_fs_cb_data_set_state(data,
                                                cg_storage_filesystem_state_setting_upload_in_progress);

                result = cg_storage_filesystem_db_set_inode_instance_uploading_in_progress(this,
                                                                                           data);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error setting inode instance's uploading flag for %"PRIu64" on fs %s: %d",
                                  inode_instance->inode_number,
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

            CGUTILS_FREE(cache_path);
        }
        else
        {
            CGUTILS_ERROR("Error getting file from cache for inode %"PRIu64", fs %s: %d",
                          inode_instance->inode_number,
                          this->name,
                          result);
        }
    }

    if (result != 0)
    {
        cgdb_inode_instance_free(inode_instance), inode_instance = NULL;
    }

    return result;
}

static void cg_storage_filesystem_instance_delete_handler(int const status,
                                                          cg_storage_fs_cb_data * data)
{
    int result = status;
    assert(data != NULL);
    cg_storage_filesystem * fs = cg_storage_fs_cb_data_get_fs(data);
    cgdb_inode_instance * inode_instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);
    cg_storage_filesystem_handler_state state = cg_storage_fs_cb_data_get_state(data);
    assert(fs != NULL);
    assert(inode_instance != NULL);

    if (state == cg_storage_filesystem_state_deleting_inode &&
        result == ENOENT)
    {
        /* File not found at the storage provider.
           This should not happen, but if it happens anyway,
           remove the entry from the database to prevent a ghost. */
        result = 0;

        CGUTILS_WARN("Inode to be deleted (%"PRIu64" in FS %s, id in instance %s) not found at the storage instance %"PRIu64". Oh, well.",
                     inode_instance->inode_number,
                     fs->name,
                     inode_instance->id_in_instance,
                     inode_instance->instance_id);
    }

    if (result == 0)
    {
        switch(state)
        {
        case cg_storage_filesystem_state_setting_delete_in_progress:
        {
            cg_storage_instance * inst = NULL;
            /* Flag set to deleting */

            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_deleting_inode);

            result = cg_storage_manager_data_get_instance_by_id(fs->data,
                                                                inode_instance->instance_id,
                                                                &inst);

            if (result == 0)
            {
                result = cg_storage_instance_delete_file(inst,
                                                         inode_instance->id_in_instance,
                                                         &cg_storage_filesystem_instance_generic_cb,
                                                         data);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error deleting inode %"PRIu64" (%s on %s) on fs %s: %d",
                                  inode_instance->inode_number,
                                  inode_instance->id_in_instance,
                                  cg_storage_instance_get_name(inst),
                                  fs->name,
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Unable to find instance with an id of %"PRIu64": %d",
                              inode_instance->instance_id,
                              result);
            }

            break;
        }
        case cg_storage_filesystem_state_deleting_inode:
        {
            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_deleting_inode_from_db);

            result = cg_storage_filesystem_db_remove_inode_instance(fs,
                                                                    data);

            if (result != 0)
            {
                CGUTILS_ERROR("Error deleting inode %"PRIu64" from DB (%s) on fs %s: %d",
                              inode_instance->inode_number,
                              inode_instance->id_in_instance,
                              fs->name,
                              result);
            }

            break;
        }
        case cg_storage_filesystem_state_deleting_inode_from_db:
        {
            cg_storage_filesystem_status_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            cgdb_inode_instance * instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);

            if (cb != NULL)
            {
                (*cb)(result,
                      cg_storage_fs_cb_data_get_callback_data(data));
            }

            cgdb_inode_instance_free(instance), instance = NULL;
            cg_storage_fs_cb_data_set_inode_instance_in_use(data, NULL);

            cg_storage_fs_cb_data_free(data), data = NULL;

            break;
        }
        case cg_storage_filesystem_state_handling_error:
        {
            /* An error occured, we cleared this instance inode state (not deleting anymore) */
            cg_storage_filesystem_status_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            cgdb_inode_instance * instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);

            int const error = cg_storage_fs_cb_data_get_error(data);

            CGUTILS_DEBUG("handling error for instance inode %"PRIu64" of fs %s, cb is %p, result is %d",
                          inode_instance->inode_number,
                          fs->name,
                          cb,
                          error);

            if (cb != NULL)
            {
                (*cb)(error,
                      cg_storage_fs_cb_data_get_callback_data(data));
            }

            cgdb_inode_instance_free(instance), instance = NULL;
            cg_storage_fs_cb_data_set_inode_instance_in_use(data, NULL);

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
        CGUTILS_ERROR("Error deleting instance inode %"PRIu64" of fs %s, state %s: %d",
                      inode_instance->inode_number,
                      fs->name,
                      cg_storage_filesystem_state_to_str(state),
                      result);

        if (state != cg_storage_filesystem_state_handling_error)
        {
            CGUTILS_DEBUG("Setting deleting to false for instance inode %"PRIu64" of fs %s",
                          inode_instance->inode_number,
                          fs->name);

            cg_storage_fs_cb_data_set_error(data, result);

            cg_storage_fs_cb_data_set_state(data,
                                            cg_storage_filesystem_state_handling_error);

            result = cg_storage_filesystem_db_set_inode_instance_deleting_failed(fs,
                                                                                 data);
        }

        if (result != 0)
        {
            cg_storage_filesystem_status_cb * cb = cg_storage_fs_cb_data_get_callback(data);
            cgdb_inode_instance * instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);

            if (cb != NULL)
            {
                (*cb)(result,
                      cg_storage_fs_cb_data_get_callback_data(data));
            }

            cgdb_inode_instance_free(instance), instance = NULL;
            cg_storage_fs_cb_data_set_inode_instance_in_use(data, NULL);

            cg_storage_fs_cb_data_free(data), data = NULL;
        }
    }
}

int cg_storage_filesystem_instance_delete_inode(cg_storage_filesystem * const this,
                                                cgdb_inode_instance * inode_instance,
                                                cg_storage_filesystem_status_cb * const cb,
                                                void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL &&
        inode_instance != NULL)
    {
        cg_storage_fs_cb_data * data = NULL;

        result = cg_storage_fs_cb_data_init(this,
                                            &data);

        if (result == 0)
        {
            cg_storage_fs_cb_data_set_inode_instance_in_use(data,
                                                            inode_instance);

            cg_storage_fs_cb_data_set_handler(data,
                                              &cg_storage_filesystem_instance_delete_handler);

            cg_storage_fs_cb_data_set_callback(data,
                                               cb,
                                               cb_data);

            if (inode_instance->upload_time > 0)
            {
                /* Inode has already been uploaded */

                cg_storage_fs_cb_data_set_state(data,
                                                cg_storage_filesystem_state_setting_delete_in_progress);


                result = cg_storage_filesystem_db_set_inode_instance_delete_in_progress(this,
                                                                                        data);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error setting inode instance's delete flag for %"PRIu64" on fs %s: %d",
                                  inode_instance->inode_number,
                                  this->name,
                                  result);
                }
            }
            else
            {
                /* Inode has never been uploaded */
                cg_storage_fs_cb_data_set_state(data,
                                                cg_storage_filesystem_state_deleting_inode_from_db);

                result = cg_storage_filesystem_db_remove_inode_instance(this,
                                                                        data);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error deleting inode %"PRIu64" from DB (%s) on fs %s: %d",
                                  inode_instance->inode_number,
                                  inode_instance->id_in_instance,
                                  this->name,
                                  result);
                }
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating cb data: %d", result);
        }
    }

    if (result != 0)
    {
        cgdb_inode_instance_free(inode_instance), inode_instance = NULL;
    }

    return result;
}
