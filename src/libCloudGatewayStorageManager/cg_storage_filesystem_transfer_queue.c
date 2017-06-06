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

#include <cgsm/cg_storage_filesystem_common.h>
#include <cgsm/cg_storage_filesystem_transfer_queue.h>
#include <cgsm/cg_storage_filesystem_utils.h>

static int cg_storage_filesystem_transfer_queue_compare_cb(void const * const a,
                                                           void const * const b)
{
    int result = 0;
    uint64_t const * const tmp_a = a;
    uint64_t const * const tmp_b = b;
    CGUTILS_ASSERT(tmp_a != NULL);
    CGUTILS_ASSERT(tmp_b != NULL);

    if (*tmp_a > *tmp_b)
    {
        result = 1;
    }
    else if (*tmp_a < *tmp_b)
    {
        result = -1;
    }

    return result;
}

static void cg_storage_filesystem_transfer_queue_key_del_cb(void * key)
{
    CGUTILS_ASSERT(key != NULL);

    CGUTILS_FREE(key);
}

static void cg_storage_filesystem_transfer_queue_value_del_cb(void * value)
{
    CGUTILS_ASSERT(value != NULL);

    (void) value;
}

bool cg_storage_filesystem_transfer_queue_is_pending(cg_storage_filesystem * const this,
                                                     cg_storage_object * const object)
{
    bool result = false;

    assert(this != NULL);
    assert(object != NULL);

    if (this->pending_transfers != NULL)
    {
        uint64_t const ino = cg_storage_object_get_inode_number(object);
        cgutils_rbtree_node * node = NULL;

        int res = cgutils_rbtree_get(this->pending_transfers,
                                     &ino,
                                     &node);

        if (res == 0)
        {
            result = true;
        }
    }

    return result;
}

int cg_storage_filesystem_transfer_queue_add(cg_storage_filesystem * const this,
                                             cg_storage_fs_cb_data * const request)
{
    int result = 0;
    cg_storage_object * object = cg_storage_fs_cb_data_get_object(request);
    assert(this != NULL);
    assert(request != NULL);
    assert(object != NULL);

    uint64_t const ino = cg_storage_object_get_inode_number(object);

    if (this->pending_transfers == NULL)
    {
        result = cgutils_rbtree_init(&cg_storage_filesystem_transfer_queue_compare_cb,
                                     &cg_storage_filesystem_transfer_queue_key_del_cb,
                                     &cg_storage_filesystem_transfer_queue_value_del_cb,
                                     &(this->pending_transfers));



        if (result != 0)
        {
            CGUTILS_ERROR("Error creating pending transfers table: %d", result);
        }
    }

    if (result == 0)
    {
        cgutils_rbtree_node * node = NULL;
        cgutils_llist * waiting_list_for_object = NULL;

        result = cgutils_rbtree_get(this->pending_transfers,
                                    &ino,
                                    &node);

        if (result == 0)
        {
            waiting_list_for_object = cgutils_rbtree_node_get_value(node);
            CGUTILS_ASSERT(waiting_list_for_object != NULL);
        }
        else if (result == ENOENT)
        {
            uint64_t * key = NULL;

            CGUTILS_MALLOC(key, 1, sizeof *key);

            if (COMPILER_LIKELY(key != NULL))
            {
                *key = ino;

                result = cgutils_llist_create(&waiting_list_for_object);

                if (result == 0)
                {
                    assert(waiting_list_for_object != NULL);

                    result = cgutils_rbtree_insert(this->pending_transfers,
                                                   key,
                                                   waiting_list_for_object);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error inserting pending requests list in table: %d", result);
                        cgutils_llist_free(&waiting_list_for_object, NULL);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error creating object waiting list: %d", result);
                }

                if (result != 0)
                {
                    CGUTILS_FREE(key);
                }
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for table key: %d",
                              result);
            }
        }
        else if (result != 0)
        {
            CGUTILS_ERROR("Error looking for object's waiting list in hash table: %d", result);
        }

        if (result == 0)
        {
            CGUTILS_ASSERT(waiting_list_for_object != NULL);

            result = cgutils_llist_insert(waiting_list_for_object,
                                          request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error inserting download request in waiting list: %d", result);
            }
        }
    }

    return result;
}

int cg_storage_filesystem_transfer_queue_done(cg_storage_filesystem * const this,
                                              cg_storage_fs_cb_data * const request,
                                              int const status)
{
    int result = 0;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(request != NULL);
    cg_storage_object * object = cg_storage_fs_cb_data_get_object(request);
    CGUTILS_ASSERT(object != NULL);
    uint64_t const inode_number = cg_storage_object_get_inode_number(object);

    char * path_in_cache = NULL;
    size_t path_in_cache_len = 0;

    if (status == 0)
    {
        result = cg_storage_cache_get_existing_path(this->cache,
                                                    inode_number,
                                                    false,
                                                    &path_in_cache,
                                                    &path_in_cache_len);

        if (result != 0)
        {
            CGUTILS_ERROR("Error getting path in cache for inode %"PRIu64": %d",
                          inode_number,
                          result);
        }
    }

    if (result == 0)
    {
        cgutils_rbtree_node * node = NULL;

        result = cgutils_rbtree_get(this->pending_transfers,
                                    &inode_number,
                                    &node);

        if (result == 0)
        {
            cgutils_llist * waiting_list_for_object = cgutils_rbtree_node_get_value(node);

            int res = cgutils_rbtree_remove(this->pending_transfers,
                                            node);

            if (res != 0)
            {
                CGUTILS_WARN("Error removing object from tree: %d",
                             res);
            }

            for (cgutils_llist_elt * it = cgutils_llist_get_first(waiting_list_for_object);
                 it != NULL;
                 it = cgutils_llist_elt_get_next(it))
            {
                cg_storage_fs_cb_data * data = cgutils_llist_elt_get_object(it);

                if (data != NULL)
                {
                    if (data != request)
                    {
                        CGUTILS_ASSERT(cg_storage_fs_cb_data_get_state(data) == cg_storage_filesystem_state_queued);

                        if (status == 0)
                        {
                            char * path_in_cache_dup = cgutils_strdup(path_in_cache);

                            if (path_in_cache_dup != NULL)
                            {
                                cg_storage_fs_cb_data_set_path_in_cache(data, path_in_cache_dup);
                            }
                            else
                            {
                                CGUTILS_ERROR("Error allocating memory for path in cache: %d",
                                              result);
                            }
                        }

                        cg_storage_filesystem_return_to_handler(status, data);
                    }
                }
            }

            /* now that we have handled queued requests,
               call the handler for the main one. */
            cg_storage_filesystem_return_to_handler(status, request);

            cgutils_llist_free(&waiting_list_for_object, NULL);
        }
        else if (result == ENOENT)
        {
            CGUTILS_WARN("Callback called for a non waiting object, should not happen.");
            result = 0;
        }
        else
        {
            CGUTILS_ERROR("Error getting the list of waiting objects: %d", result);
        }
    }

    CGUTILS_FREE(path_in_cache);

    return result;
}
