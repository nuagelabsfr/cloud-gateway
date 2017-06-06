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
#include <time.h>

#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>
#include <cgsm/cg_storage_filesystem.h>

#include <cgdb/cgdb.h>

#include <cloudutils/cloudutils_htable.h>
#include <cloudutils/cloudutils_llist.h>

#include "cgStorageManagerCleaner.h"
#include "cgStorageManagerCommon.h"

#define CG_STORAGE_MANAGER_CLEANER_DELAY_DEFAULT (60)

#define CG_STORAGE_MANAGER_CLEANER_DB_SLOTS_DEFAULT (10)
#define CG_STORAGE_MANAGER_CLEANER_MAX_ACCESS_OFFSET_DEFAULT (24 * 60 * 60)
#define CG_STORAGE_MANAGER_CLEANER_MAX_ACCESS_OFFSET_MINIMUM (60)

#define CG_STORAGE_MANAGER_CLEANER_MAX_DB_ENTRIES_PER_CALL (50)

typedef struct
{
    cg_storage_manager_data * data;
    cgutils_event * timer_event;
    /* hash table of cg_storage_filesystem * */
    cgutils_htable_iterator * filesystems_it;
    /* vector of cgdb_entry * */
    cgutils_vector * entries;

    size_t remaining_db_slots;

    cg_storage_filesystem * fs;
    uint64_t min_file_size;
    uint64_t max_access;

    size_t current_entry_idx;

    size_t offset;
    size_t got;
    size_t remaining;
    size_t pending;

    bool consuming;
    bool running;
    bool exiting;
} cg_storage_manager_cleaner_data;

typedef struct
{
    cg_storage_manager_cleaner_data * cleaner;
    cgdb_entry * entry;
} cg_storage_manager_cleaner_cb_data;


static void cg_storage_manager_cleaner_graceful_exit(int const sig,
                                                     void * const cb_data)
{
    cg_storage_manager_cleaner_data * cleaner_data = cb_data;

    assert(sig == CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG);
    assert(cb_data != NULL);

    (void) sig;

    if (cleaner_data->exiting == false)
    {
        if (cleaner_data->timer_event != NULL)
        {
            cgutils_event_disable(cleaner_data->timer_event);
        }

        cleaner_data->exiting = true;

        if (cleaner_data->running == false)
        {
            cgutils_event_data * event_data = cg_storage_manager_data_get_event(cleaner_data->data);
            assert(event_data != NULL);
            cgutils_event_exit_after_loop(event_data, NULL);
        }
    }
}

static void cg_storage_manager_cleaner_handling(cg_storage_manager_cleaner_data * cleaner);

static void cg_storage_manager_cleaner_cb_data_free(cg_storage_manager_cleaner_cb_data * this)
{
    this->entry = NULL;

    this->cleaner = NULL;

    CGUTILS_FREE(this);
}

static void cg_storage_manager_cleaner_clean_entries_list(cg_storage_manager_cleaner_data * const cleaner)
{
    assert(cleaner != NULL);

    cgutils_vector_deep_free(&(cleaner->entries), &cgdb_entry_delete);

    cleaner->current_entry_idx = 0;
}

static void cg_storage_manager_cleaner_reset(cg_storage_manager_cleaner_data * const cleaner)
{
    assert(cleaner != NULL);

    if (cleaner->filesystems_it != NULL)
    {
        cgutils_htable_iterator_free(cleaner->filesystems_it), cleaner->filesystems_it = NULL;
    }

    cg_storage_manager_cleaner_clean_entries_list(cleaner);

    cleaner->offset = 0;
    cleaner->got = 0;
    cleaner->remaining = 0;
    cleaner->pending = 0;
    cleaner->running = false;

    if (cleaner->exiting == true)
    {
        cgutils_event_data * event_data = cg_storage_manager_data_get_event(cleaner->data);
        assert(event_data != NULL);
        cgutils_event_exit_after_loop(event_data, NULL);
    }
}

static size_t cg_storage_manager_cleaner_compute_entries_per_call(cg_storage_manager_cleaner_data * const cleaner)
{
    size_t result = CG_STORAGE_MANAGER_CLEANER_MAX_DB_ENTRIES_PER_CALL;

    assert(cleaner != NULL);

    if (cleaner->remaining_db_slots < result)
    {
        result = cleaner->remaining_db_slots;
    }

    return result;
}

static int cg_storage_manager_cleaner_entry_cache_cleaned(int const status,
                                                          void * const cb_data)
{
    int result = status;
    cg_storage_manager_cleaner_data * cleaner = NULL;
    cg_storage_manager_cleaner_cb_data * cleaner_cb_data = cb_data;
    assert(cb_data != NULL);
    assert(cleaner_cb_data->cleaner != NULL);
    cleaner = cleaner_cb_data->cleaner;

    if (result == 0)
    {
        CGUTILS_DEBUG("Cleaned inode %zu",
                      cleaner_cb_data->entry->inode.inode_number);
    }
    else
    {
        CGUTILS_WARN("Error cleaning cache entry for inode %"PRIu64" on fs %s: %d",
                     cleaner_cb_data->entry->inode.inode_number,
                     cg_storage_filesystem_get_name(cleaner_cb_data->cleaner->fs),
                     result);
    }

    cleaner->remaining_db_slots++;
    cleaner->pending--;

    cg_storage_manager_cleaner_cb_data_free(cleaner_cb_data), cleaner_cb_data = NULL;

    if (cleaner->running == true)
    {
        cg_storage_manager_cleaner_handling(cleaner);
    }

    return result;
}

static void cg_storage_manager_cleaner_consume_entries(cg_storage_manager_cleaner_data * const cleaner)
{
    assert(cleaner != NULL);
    assert(cleaner->fs != NULL);
    assert(cleaner->got > 0);
    assert(cleaner->remaining > 0);
    assert(cleaner->entries != NULL);

    for (;
         cleaner->current_entry_idx < cgutils_vector_count(cleaner->entries) &&
             cleaner->remaining_db_slots > 0;
         cleaner->current_entry_idx++)
    {
        cgdb_entry * entry = NULL;

        cleaner->remaining--;

        int result = cgutils_vector_get(cleaner->entries,
                                        cleaner->current_entry_idx,
                                        (void **) &entry);

        if (result == 0)
        {
            assert(entry != NULL);

            if (entry->inode.dirty_writers == 0)
            {
                cg_storage_manager_cleaner_cb_data * cb_data = NULL;

                CGUTILS_ALLOCATE_STRUCT(cb_data);

                if (cb_data != NULL)
                {
                    cb_data->cleaner = cleaner;
                    cb_data->entry = entry;

                    CGUTILS_DEBUG("Trying to expunge entry to gain space, inode is %zu",
                                  entry->inode.inode_number);

                    result = cg_storage_filesystem_entry_expunge_inode_from_cache_if_all_instances_valid(cleaner->fs,
                                                                                                         &(entry->inode),
                                                                                                         &cg_storage_manager_cleaner_entry_cache_cleaned,
                                                                                                         cb_data);

                    if (result == 0)
                    {
                        cleaner->remaining_db_slots--;
                        cleaner->pending++;
                        cb_data = NULL;
                    }
                    else if (result == EWOULDBLOCK)
                    {
                        /* Failed to lock the file, it is probably in use, skip it. */
                    }
                    else
                    {
                        CGUTILS_WARN("Error in cg_storage_filesystem_entry_expunge_inode_from_cache_if_all_instances_valid: %d",
                                     result);
                    }

                    if (cb_data != NULL)
                    {
                        cg_storage_manager_cleaner_cb_data_free(cb_data), cb_data = NULL;
                    }
                }
                else
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error while allocating memory for callback data: %d", result);
                }
            }
        }
        else
        {
            CGUTILS_ERROR("Error while getting entry %zu: %d",
                          cleaner->current_entry_idx,
                          result);
        }
    }

    if (cleaner->running == true)
    {
        cg_storage_manager_cleaner_handling(cleaner);
    }
}

static int cg_storage_manager_cleaner_entries_cb(int const status,
                                                 size_t const entries_count,
                                                 /* vector * cgdb_entry * */
                                                 cgutils_vector * entries,
                                                 void * const cb_data)
{
    int result = status;
    cg_storage_manager_cleaner_data * cleaner = cb_data;
    assert(cleaner != NULL);
    assert(cleaner->entries == NULL);
    assert(cleaner->current_entry_idx == 0);

    cleaner->remaining_db_slots++;
    cleaner->pending--;

    if (result == 0)
    {
        CGUTILS_DEBUG("Got %zu entries for fs %s",
                      entries_count,
                      cg_storage_filesystem_get_name(cleaner->fs));

        cleaner->got = entries_count;
        cleaner->remaining = entries_count;
        cleaner->entries = entries;

        if (entries_count > 0)
        {
            cleaner->consuming = true;
            cleaner->current_entry_idx = 0;
            cg_storage_manager_cleaner_consume_entries(cleaner);
            cleaner->consuming = false;
        }
        else
        {
            cgutils_vector_deep_free(&entries, &cgdb_entry_delete);
            cleaner->entries = NULL;
            cleaner->current_entry_idx = 0;
        }
    }
    else
    {
        CGUTILS_ERROR("Error listing files: %d", result);
    }

    if (cleaner->running == true)
    {
        cg_storage_manager_cleaner_handling(cleaner);
    }

    return result;
}

static void cg_storage_manager_cleaner_get_entries(cg_storage_manager_cleaner_data * const cleaner)
{
    cgdb_data * db = NULL;
    assert(cleaner != NULL);
    assert(cleaner->data != NULL);
    assert(cleaner->fs != NULL);

    assert(cleaner->entries == NULL);
    assert(cleaner->current_entry_idx == 0);
    assert(cleaner->pending == 0);
    assert(cleaner->remaining == 0);

    assert(cleaner->remaining_db_slots > 0);

    db = cg_storage_manager_data_get_db(cleaner->data);

    if (db != NULL)
    {
        uint64_t const fs_id = cg_storage_filesystem_get_id(cleaner->fs);
        size_t const to_get = cg_storage_manager_cleaner_compute_entries_per_call(cleaner);
        assert(fs_id > 0);

        if (to_get > 0 &&
            to_get < UINT32_MAX &&
            cleaner->offset < UINT32_MAX)
        {
            int result = cgdb_get_not_dirty_entries_by_type_size_last_usage_cached(db,
                                                                                   fs_id,
                                                                                   CGDB_OBJECT_TYPE_FILE,
                                                                                   cleaner->min_file_size,
                                                                                   cleaner->max_access,
                                                                                   cg_storage_instance_status_dirty,
                                                                                   (uint32_t) to_get,
                                                                                   (uint32_t) cleaner->offset,
                                                                                   &cg_storage_manager_cleaner_entries_cb,
                                                                                   cleaner);

            if (result == 0)
            {
                CGUTILS_DEBUG("Looking for entries for fs %s",
                              cg_storage_filesystem_get_name(cleaner->fs));

                cleaner->remaining_db_slots--;
                cleaner->pending++;
                cleaner->offset += to_get;
            }
            else
            {
                CGUTILS_ERROR("Error in cgdb_get_entries_by_type_size_access: %d", result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Error getting database");
    }
}

static bool cg_storage_manager_cleaner_fs_is_above_threshold(cg_storage_filesystem const * const fs)
{
    bool result = false;
    int res = 0;

    assert(fs != NULL);

    res = cg_storage_filesystem_check_cache(fs,
                                            &result);
    if (res != 0)
    {
        if (res != ENOENT)
        {
            CGUTILS_ERROR("Error checking filesystem cache size: %d",
                          res);
        }
    }

    return result;
}

static void cg_storage_manager_cleaner_handle_fs(cg_storage_manager_cleaner_data * const cleaner)
{
    int result = 0;
    bool valid = true;

    assert(cleaner != NULL);
    assert(cleaner->filesystems_it != NULL);
    assert(cleaner->pending == 0);
    assert(cleaner->remaining == 0);
    assert(cleaner->current_entry_idx == 0);
    assert(cleaner->entries == NULL);

    while (cleaner->pending == 0 &&
           valid == true &&
           cleaner->filesystems_it != NULL)
    {
        cg_storage_filesystem * const fs = cgutils_htable_iterator_get_value(cleaner->filesystems_it);
        assert(fs != NULL);

        bool const full = cg_storage_manager_cleaner_fs_is_above_threshold(fs);

        if (full == true)
        {
            time_t const now = time(NULL);

            CGUTILS_DEBUG("Filesystem %s is over threshold",
                          cg_storage_filesystem_get_name(fs));

            if (now != -1)
            {
                uint64_t max_access_offset = cg_storage_filesystem_get_clean_max_access_offset(fs);

                cleaner->fs = fs;
                cleaner->min_file_size = cg_storage_filesystem_get_clean_min_file_size(fs);

                assert(now > 0 && (uint64_t) now <= UINT64_MAX);

                if (max_access_offset == 0)
                {
                    max_access_offset = CG_STORAGE_MANAGER_CLEANER_MAX_ACCESS_OFFSET_DEFAULT;
                }
                else if (max_access_offset < CG_STORAGE_MANAGER_CLEANER_MAX_ACCESS_OFFSET_MINIMUM)
                {
                    max_access_offset = CG_STORAGE_MANAGER_CLEANER_MAX_ACCESS_OFFSET_MINIMUM;
                }

                cleaner->max_access = ((uint64_t) now) - max_access_offset;

                cleaner->offset = 0;
                cleaner->got = 0;

                cg_storage_manager_cleaner_get_entries(cleaner);
            }
            else
            {
                result = errno;
                CGUTILS_ERROR("Error getting time: %d", result);
            }
        }

        valid = cgutils_htable_iterator_next(cleaner->filesystems_it);
    }

    if (cleaner->pending == 0)
    {
        /* No more filesystems and no request pending */
        cg_storage_manager_cleaner_reset(cleaner);
    }
    else if (valid == false)
    {
        /* No more data on this iterator */
        cgutils_htable_iterator_free(cleaner->filesystems_it), cleaner->filesystems_it = NULL;
    }
}

static void cg_storage_manager_cleaner_handling(cg_storage_manager_cleaner_data * const cleaner)
{
    assert(cleaner != NULL);

    if (cleaner->running == true)
    {
        if (cleaner->pending > 0)
        {
            /* Nothing to do. */
        }
        else if (cleaner->remaining_db_slots == 0)
        {
            /* Nothing pending, no slots available, something is wrong */
            cg_storage_manager_cleaner_reset(cleaner);
        }
        else if (cleaner->remaining > 0)
        {
            if (cleaner->consuming == false)
            {
                /* We have some data from the last DB lookup,
                   we were probably stuck by the maximum number
                   of DB connections. */
                cleaner->consuming = true;
                cg_storage_manager_cleaner_consume_entries(cleaner);
                cleaner->consuming = false;
            }
        }
        else if (cleaner->got > 0)
        {
            assert(cleaner->fs != NULL);

            bool const full = cg_storage_manager_cleaner_fs_is_above_threshold(cleaner->fs);

            if (full == true)
            {
                cg_storage_manager_cleaner_clean_entries_list(cleaner);
                /* Do a new DB lookup for the next data */
                cg_storage_manager_cleaner_get_entries(cleaner);
            }
            else
            {
                /* Nothing to clean, FS is ok */
                cg_storage_manager_cleaner_clean_entries_list(cleaner);

                if (cleaner->filesystems_it != NULL)
                {
                    /* No more entry for this FS, try the next one if any */
                    cg_storage_manager_cleaner_handle_fs(cleaner);
                }
                else
                {
                    /* No more entry for this FS and no more FS. */
                    cg_storage_manager_cleaner_reset(cleaner);
                }
            }
        }
        else
        {
            cg_storage_manager_cleaner_clean_entries_list(cleaner);

            if (cleaner->filesystems_it != NULL)
            {
                /* No more entry for this FS, try the next one if any */
                cg_storage_manager_cleaner_handle_fs(cleaner);
            }
            else
            {
                /* No more entry for this FS and no more FS. */
                cg_storage_manager_cleaner_reset(cleaner);
            }
        }
    }
}

static void cg_storage_manager_cleaner_timer_cb(void * cb_data)
{
    cg_storage_manager_cleaner_data * cleaner = cb_data;
    assert(cb_data != NULL);
    assert(cleaner->data != NULL);

    if (cleaner->running == false &&
        cleaner->remaining_db_slots > 0)
    {
        cg_storage_manager_data * data = cleaner->data;

        cg_storage_manager_cleaner_reset(cleaner);

        cleaner->running = true;
        assert(cleaner->filesystems_it == NULL);

        int result = cg_storage_manager_data_get_all_filesystems(data,
                                                                 &(cleaner->filesystems_it));

        if (result == 0)
        {
            assert(cleaner->filesystems_it != NULL);
            cg_storage_manager_cleaner_handle_fs(cleaner);
        }
        else
        {
            CGUTILS_ERROR("Error getting filesystem iterator: %d", result);
            cg_storage_manager_cleaner_reset(cleaner);
        }
    }
}

int cg_storage_manager_cleaner_run(cg_storage_manager_data * const data,
                                   bool const graceful)
{
    int result = 0;
    assert(data != NULL);

    cg_monitor_data * monitor_data = cg_storage_manager_data_get_monitor_data(data);

    if (monitor_data != NULL)
    {
        cg_monitor_data_free(monitor_data), monitor_data = NULL;
        cg_storage_manager_data_set_monitor_data(data, NULL);
    }

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    cg_storage_manager_cleaner_data * cleaner = NULL;

    (void) graceful;

    CGUTILS_ALLOCATE_STRUCT(cleaner);

    if (cleaner != NULL)
    {
        size_t cleaner_delay = cg_storage_manager_data_get_cleaner_delay(data);
        cleaner->data = data;
        cleaner->remaining_db_slots = cg_storage_manager_data_get_cleaner_db_slots(data);

        if (cleaner->remaining_db_slots == 0)
        {
            cleaner->remaining_db_slots = CG_STORAGE_MANAGER_CLEANER_DB_SLOTS_DEFAULT;
        }

        if (cleaner_delay == 0)
        {
            cleaner_delay = CG_STORAGE_MANAGER_CLEANER_DELAY_DEFAULT;
        }

        result = cgutils_event_create_timer_event(event_data,
                                                  CGUTILS_EVENT_PERSIST,
                                                  &cg_storage_manager_cleaner_timer_cb,
                                                  cleaner,
                                                  &(cleaner->timer_event));

        if (result == 0)
        {
            result = cg_storage_manager_common_register_signal(data,
                                                               CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG,
                                                               &cg_storage_manager_cleaner_graceful_exit,
                                                               cleaner);

            if (result == 0)
            {
                struct timeval tv =
                    {
                        .tv_sec = (time_t) cleaner_delay,
                        .tv_usec = 0
                    };

                result = cgutils_event_enable(cleaner->timer_event, &tv);

                if (result == 0)
                {
                    cg_storage_manager_loop(data);
                    cgutils_event_disable(cleaner->timer_event);
                }
                else
                {
                    CGUTILS_ERROR("Error enabling timer event: %d", result);
                }

                cgutils_event_free(cleaner->timer_event), cleaner->timer_event = NULL;
            }
            else
            {
                    CGUTILS_ERROR("Error registering signal event: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating timer event: %d", result);
        }

        CGUTILS_FREE(cleaner), cleaner = NULL;
    }
    else
    {
        result = ENOMEM;
        CGUTILS_ERROR("Error allocating memory for cleaner data: %d", result);
    }

    return result;
}
