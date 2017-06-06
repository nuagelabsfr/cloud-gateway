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
#include <string.h>
#include <time.h>

#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>
#include <cgsm/cg_storage_filesystem.h>

#include <cgdb/cgdb.h>

#include <cloudutils/cloudutils.h>

#include "cgStorageManagerSyncer.h"
#include "cgStorageManagerCommon.h"

#define CG_STORAGE_MANAGER_SYNCER_DELAY_DEFAULT (5)
#define CG_STORAGE_MANAGER_SYNCER_DIRTYNESS_DELAY_DEFAULT (10)
#define CG_STORAGE_MANAGER_SYNCER_DB_SLOTS_DEFAULT (20)

#define CG_STORAGE_MANAGER_SYNCER_MAX_DB_OBJECTS_PER_CALL_DEFAULT (50)

typedef enum
{
    cg_storage_manager_syncer_type_deleted,
    cg_storage_manager_syncer_type_dirty,
} cg_storage_manager_syncer_ctx_type;

typedef struct cg_storage_manager_syncer_data cg_storage_manager_syncer_data;

typedef struct
{
    cg_storage_manager_syncer_data * syncer_data;
    /* llist of cgdb_inode_instance * */
    cgutils_llist * file_instances;
    /* elt of type cgdb_inode_instance * */
    cgutils_llist_elt * current;
    /* DB offset for the next query (think nb of objects to skip) */
    size_t offset;
    /* The nb of objects returned by the last DB query */
    size_t got;
    /* Number of remaining objects not handled in the file_instances list,
       the current one pointed to by the current var */
    size_t remaining;
    /* Number of currently pending calls,
       can be DB or _instance_ calls */
    size_t pending;
    cg_storage_manager_syncer_ctx_type type;
    bool fetching_from_db;
    bool error;
    bool running;
    bool consuming;
} cg_storage_manager_syncer_ctx;

typedef struct
{
    cg_storage_manager_syncer_ctx * ctx;
    cg_storage_filesystem * fs;
    cgdb_inode * fake_inode;
    char * id_in_instance;
    uint64_t inode_number;
    uint64_t inode_mtime;
    uint64_t inode_last_modification;
    uint64_t inode_size;
    uint64_t instance_id;
    size_t inode_dirty_writers;
    time_t beginning_time;
} cg_storage_manager_syncer_task;

struct cg_storage_manager_syncer_data
{
    cg_storage_manager_syncer_ctx dirty_ctx;
    cg_storage_manager_syncer_ctx deleted_ctx;
    cg_storage_manager_data * data;
    cg_monitor_data_instance_status_tab * status_tab;
    cgutils_event * timer_event;
    /* llist of cg_storage_manager_syncer_task * */
    cgutils_llist * running_tasks;
    size_t remaining_db_slots;
    size_t max_db_objects_per_call;
    bool exiting;
    bool dump_http_states;
};

static void cg_storage_manager_syncer_task_free(cg_storage_manager_syncer_task * task)
{
    if (task != NULL)
    {
        if (task->fake_inode != NULL)
        {
            cgdb_inode_free(task->fake_inode), task->fake_inode = NULL;
        }

        CGUTILS_FREE(task->id_in_instance);

        task->ctx = NULL;
        task->fs = NULL;
        task->inode_number = 0;
        task->inode_mtime = 0;
        task->inode_last_modification = 0;
        task->inode_size = 0;
        task->inode_dirty_writers = 0;
        task->instance_id = 0;
        task->beginning_time = 0;

        CGUTILS_FREE(task);
    }
}

static void cg_storage_manager_syncer_task_delete(void * task)
{
    cg_storage_manager_syncer_task_free(task);
}

static int cg_storage_manager_syncer_add_task(cg_storage_manager_syncer_ctx * const ctx,
                                              cgdb_inode_instance * const instance,
                                              cg_storage_filesystem * const fs,
                                              cg_storage_manager_syncer_task ** out)
{
    int result = 0;
    cg_storage_manager_syncer_task * task = NULL;

    CGUTILS_ASSERT(ctx != NULL);
    CGUTILS_ASSERT(ctx->syncer_data != NULL);
    CGUTILS_ASSERT(ctx->syncer_data->running_tasks != NULL);
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(instance != NULL);
    CGUTILS_ASSERT(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(task);

    if (task != NULL)
    {
        task->id_in_instance = cgutils_strdup(instance->id_in_instance);

        if (task->id_in_instance != NULL)
        {
            task->ctx = ctx;
            task->fs = fs;
            task->instance_id = instance->instance_id;
            task->inode_number = instance->inode_number;
            task->inode_mtime = instance->inode_mtime;
            task->inode_last_modification = instance->inode_last_modification;
            task->inode_size = instance->inode_size;
            task->inode_dirty_writers = instance->inode_dirty_writers;

            task->beginning_time = time(NULL);

            result = cgutils_llist_insert(ctx->syncer_data->running_tasks,
                                          task);

            if (result == 0)
            {
                *out = task;
            }
        }
        else
        {
            result = ENOMEM;
        }

        if (result != 0)
        {
            cg_storage_manager_syncer_task_free(task), task = NULL;
        }
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static int cg_storage_manager_syncer_find_task(cg_storage_manager_syncer_ctx const * const ctx,
                                               cgdb_inode_instance const * const instance,
                                               cgutils_llist_elt ** const elt_out)
{
    CGUTILS_ASSERT(ctx != NULL);
    CGUTILS_ASSERT(ctx->syncer_data != NULL);
    CGUTILS_ASSERT(ctx->syncer_data->running_tasks != NULL);
    CGUTILS_ASSERT(instance != NULL);
    CGUTILS_ASSERT(elt_out != NULL);

    int result = 0;
    cgutils_llist_elt * elt = cgutils_llist_get_first(ctx->syncer_data->running_tasks);

    *elt_out = NULL;

    while (elt != NULL &&
           result == 0 &&
           *elt_out == NULL)
    {
        cg_storage_manager_syncer_task const * const task = cgutils_llist_elt_get_object(elt);
        CGUTILS_ASSERT(task != NULL);

        if (instance->inode_number == task->inode_number &&
            instance->fs_id == cg_storage_filesystem_get_id(task->fs) &&
            instance->instance_id == task->instance_id &&
            strcmp(instance->id_in_instance, task->id_in_instance) == 0)
        {
            *elt_out = elt;
        }
        else
        {
            elt = cgutils_llist_elt_get_next(elt);
        }
    }

    if (*elt_out == NULL)
    {
        result = ENOENT;
    }

    return result;
}

static void cg_storage_manager_syncer_remove_task(cg_storage_manager_syncer_task * task)
{
    CGUTILS_ASSERT(task != NULL);
    cg_storage_manager_syncer_ctx * ctx = task->ctx;
    CGUTILS_ASSERT(ctx != NULL);
    CGUTILS_ASSERT(ctx->syncer_data != NULL);
    CGUTILS_ASSERT(ctx->syncer_data->running_tasks != NULL);

    int result = cgutils_llist_remove_by_object(ctx->syncer_data->running_tasks,
                                                task);

    if (result != 0)
    {
        CGUTILS_ERROR("Error looking for task to remove from list: %d", result);
    }

    cg_storage_manager_syncer_task_free(task), task = NULL;
}

static bool cg_storage_manager_syncer_is_inode_instance_running(cg_storage_manager_syncer_ctx const * const ctx,
                                                                cgdb_inode_instance const * const instance)
{
    CGUTILS_ASSERT(ctx != NULL);
    CGUTILS_ASSERT(instance != NULL);

    bool result = false;
    cgutils_llist_elt * elt = NULL;

    int res = cg_storage_manager_syncer_find_task(ctx,
                                                  instance,
                                                  &elt);


    if (res == 0)
    {
        CGUTILS_ASSERT(elt != NULL);
        result = true;
    }
    else if (res == ENOENT)
    {
        result = false;
    }
    else
    {
        CGUTILS_ERROR("Error looking for task: %d", result);
    }

    return result;
}

static void cg_storage_manager_syncer_graceful_exit(int const sig,
                                                     void * const cb_data)
{
    cg_storage_manager_syncer_data * syncer_data = cb_data;
    assert(sig == CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG);
    assert(cb_data != NULL);

    (void) sig;

    if (syncer_data->exiting == false)
    {
        if (syncer_data->timer_event != NULL)
        {
            cgutils_event_disable(syncer_data->timer_event);
        }

        syncer_data->exiting = true;

        if (syncer_data->dirty_ctx.running == false &&
            syncer_data->deleted_ctx.running == false)
        {
            /* Nothing pending */
            cgutils_event_data * event_data = cg_storage_manager_data_get_event(syncer_data->data);
            assert(event_data != NULL);
            cgutils_event_exit_after_loop(event_data, NULL);
        }
    }
}

static bool cg_storage_manager_syncer_instance_is_up(cg_storage_manager_syncer_data const * const data,
                                                     cg_storage_instance const * const instance,
                                                     cg_storage_manager_syncer_ctx_type const op)
{
    bool result = false;
    assert(data != NULL);
    assert(data->status_tab != NULL);
    assert(instance != NULL);
    (void) op;

    if (data->status_tab->values_set > 0)
    {
        size_t instance_idx = cg_storage_instance_get_index(instance);
        assert(instance_idx < data->status_tab->instances_count);

        result = data->status_tab->instances_data[instance_idx].last_success;
    }
    else
    {
        /* No data, assuming it's ok */
        result = true;
    }

    return result;
}

static int cg_storage_manager_syncer_ctx_handle(cg_storage_manager_syncer_ctx * const ctx);

static void cg_storage_manager_syncer_ctx_reset(cg_storage_manager_syncer_ctx * const ctx)
{
    if (ctx != NULL)
    {
        assert(ctx->pending == 0);
        ctx->got = 0;
        ctx->offset = 0;
        ctx->remaining = 0;
        ctx->running = false;
        ctx->error = false;

        while(ctx->current != NULL)
        {
            cgdb_inode_instance * inst = cgutils_llist_elt_get_object(ctx->current);

            if (inst != NULL)
            {
                cgdb_inode_instance_free(inst), inst = NULL;
            }

            ctx->current = cgutils_llist_elt_get_next(ctx->current);
        }

        if (ctx->file_instances != NULL)
        {
            cgutils_llist_free(&(ctx->file_instances), NULL);
        }

        if (ctx->syncer_data->exiting == true &&
            ctx->syncer_data->dirty_ctx.running == false &&
            ctx->syncer_data->deleted_ctx.running == false)
        {
            /* Nothing pending */
            cgutils_event_data * event_data = cg_storage_manager_data_get_event(ctx->syncer_data->data);
            assert(event_data != NULL);
            cgutils_event_exit_after_loop(event_data, NULL);
        }
    }
}

static bool cg_storage_manager_syncer_ctx_has_error(cg_storage_manager_syncer_ctx const * const ctx)
{
    assert(ctx != NULL);

    return ctx->error;
}

static void cg_storage_manager_syncer_ctx_set_db_error(cg_storage_manager_syncer_ctx * const ctx)
{
    assert(ctx != NULL);

    if (ctx->pending == 0)
    {
        cg_storage_manager_syncer_ctx_reset(ctx);
    }
    else
    {
        ctx->error = true;
    }
}

static size_t cg_storage_manager_syncer_compute_objects_per_call(cg_storage_manager_syncer_ctx * const ctx)
{
    assert(ctx != NULL);
    assert(ctx->syncer_data != NULL);
    assert(ctx->syncer_data->data != NULL);

    size_t result = ctx->syncer_data->max_db_objects_per_call;

    if (ctx->syncer_data->remaining_db_slots < result)
    {
        result = ctx->syncer_data->remaining_db_slots;
    }

    return result;
}

static bool cg_storage_manager_syncer_has_auto_expunge(cg_storage_manager_syncer_task const * const task)
{
    bool result = false;
    CGUTILS_ASSERT(task != NULL);
    CGUTILS_ASSERT(task->fs != NULL);

    if (cg_storage_filesystem_has_auto_expunge(task->fs) == true)
    {
        result = true;
    }

    return result;
}

static int cg_storage_manager_syncer_auto_expunge_done(int const status,
                                                       void * cb_data)
{
    cg_storage_manager_syncer_task * task = cb_data;
    CGUTILS_ASSERT(task != NULL);
    cg_storage_manager_syncer_ctx * ctx = task->ctx;
    assert(task->ctx != NULL);
    assert(ctx->syncer_data != NULL);

    if (status != 0)
    {
        CGUTILS_ERROR("Error while handling auto expunge for inode number %"PRIu64" of FS %s on instance %"PRIu64" (ID in instance %s): %d",
                      task->inode_number,
                      cg_storage_filesystem_get_name(task->fs),
                      task->instance_id,
                      task->id_in_instance,
                      status);
    }

    ctx->pending--;
    ctx->syncer_data->remaining_db_slots++;

    cg_storage_manager_syncer_remove_task(task);

    cg_storage_manager_syncer_ctx_handle(ctx);

    return 0;
}

static int cg_storage_manager_syncer_handle_auto_expunge(cg_storage_manager_syncer_task * task)
{
    int result = 0;

    CGUTILS_ASSERT(task != NULL);
    CGUTILS_ASSERT(task->fs != NULL);

    CGUTILS_ALLOCATE_STRUCT(task->fake_inode);

    if (task->fake_inode != NULL)
    {
        task->fake_inode->st.st_size = (task->inode_size <= LONG_MAX) ? (long) task->inode_size : 0;
        task->fake_inode->st.st_mtime = (task->inode_mtime <= LONG_MAX) ? (long) task->inode_mtime : 0;
        task->fake_inode->inode_number = task->inode_number;

        result = cg_storage_filesystem_entry_expunge_inode_from_cache_if_all_instances_valid(task->fs,
                                                                                             task->fake_inode,
                                                                                             &cg_storage_manager_syncer_auto_expunge_done,
                                                                                             task);

        if (result == EWOULDBLOCK)
        {
            /* Failed to lock the file, it is probably in use, skip it. */
        }
        else if (result != 0)
        {
            CGUTILS_WARN("Error in cg_storage_filesystem_entry_expunge_inode_from_cache_if_all_instances_valid: %d",
                         result);
        }
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static int cg_storage_manager_syncer_action_done(int status,
                                                 void * cb_data)
{
    bool handled = false;

    cg_storage_manager_syncer_task * task = cb_data;
    CGUTILS_ASSERT(task != NULL);
    cg_storage_manager_syncer_ctx * ctx = task->ctx;
    assert(task->ctx != NULL);
    assert(ctx->syncer_data != NULL);

    if (status == 0)
    {
        if (ctx->offset > 0)
        {
            ctx->offset--;
        }

        if (task->inode_dirty_writers == 0 &&
            cg_storage_manager_syncer_has_auto_expunge(task) == true)
        {
            int result = cg_storage_manager_syncer_handle_auto_expunge(task);

            if (result == 0)
            {
                handled = true;
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Error while handling action of type %s (%d) for inode number %"PRIu64" of FS %s on instance %"PRIu64" (ID in instance %s): %d",
                      (ctx->type == cg_storage_manager_syncer_type_deleted ? "deletion" : "uploading"),
                      ctx->type,
                      task->inode_number,
                      cg_storage_filesystem_get_name(task->fs),
                      task->instance_id,
                      task->id_in_instance,
                      status);
    }

    if (handled == false)
    {
        ctx->pending--;
        ctx->syncer_data->remaining_db_slots++;

        cg_storage_manager_syncer_remove_task(task);
    }

    cg_storage_manager_syncer_ctx_handle(ctx);

    return 0;
}

static bool cg_storage_manager_syncer_ctx_is_element_usable(cg_storage_manager_syncer_ctx const * const ctx,
                                                            cgdb_inode_instance const * const instance)
{
    bool result = false;
    assert(ctx != NULL);
    assert(instance != NULL);

    if (cg_storage_manager_syncer_is_inode_instance_running(ctx,
                                                            instance) == false)
    {
        switch(ctx->type)
        {
        case cg_storage_manager_syncer_type_deleted:
            result = (instance->deleting == false &&
                      instance->uploading == false);
            break;
        case cg_storage_manager_syncer_type_dirty:
        {
            /* The given inode instance should not already being uploaded,
               and we need to make sure that we are not constantly re-uploading
               a file that has one or more writing fd open, but is not really
               modified.
               The FUSE client is going to notify us every <dirtyness delay> seconds
               if a file is modified (not have been, be careful). We keep uploading for
               2 * <dirtyness delay> seconds after the last notification,
               because we will not be notified if a write happens in <dirtyness delay> seconds
               after the last notification.
               See feature request #36.
            */

            size_t dirtyness_delay = cg_storage_manager_data_get_syncer_dirtyness_delay(ctx->syncer_data->data);

            if (dirtyness_delay == 0)
            {
                dirtyness_delay = CG_STORAGE_MANAGER_SYNCER_DIRTYNESS_DELAY_DEFAULT;
            }

            if (instance->uploading == false)
            {
                if (instance->inode_dirty_writers == 0)
                {
                    result = true;
                }
                else if (instance->upload_time <= (2 * dirtyness_delay) ||
                         instance->upload_time - (2 * dirtyness_delay) <= instance->inode_last_modification)
                {
                    result = true;
                }
            }

            break;
        }
        }
    }

    return result;
}

static int cg_storage_manager_syncer_ctx_handle_element(cg_storage_manager_syncer_ctx * const ctx,
                                                        cg_storage_filesystem * const fs,
                                                        cgdb_inode_instance * instance)
{
    int result = 0;
    bool free_instance = false;
    cg_storage_manager_syncer_task * task = NULL;
    assert(ctx != NULL);
    assert(fs != NULL);
    assert(instance != NULL);

    result = cg_storage_manager_syncer_add_task(ctx,
                                                instance,
                                                fs,
                                                &task);

    if (result == 0)
    {
        ctx->syncer_data->remaining_db_slots--;
        ctx->pending++;

        switch(ctx->type)
        {
        case cg_storage_manager_syncer_type_deleted:
            result = cg_storage_filesystem_instance_delete_inode(fs,
                                                                 instance,
                                                                 &cg_storage_manager_syncer_action_done,
                                                                 task);
            if (result != 0)
            {
                CGUTILS_ERROR("Error deleting file on instance: %d",
                              result);
            }
            break;
        case cg_storage_manager_syncer_type_dirty:
            result = cg_storage_filesystem_instance_put_inode(fs,
                                                              instance,
                                                              &cg_storage_manager_syncer_action_done,
                                                              task);
            if (result != 0)
            {
                CGUTILS_ERROR("Error fsyncing file on instance: %d",
                              result);
            }
            break;
        default:
            result = ENOSYS;
            free_instance = true;
        }

        if (result != 0)
        {
            ctx->syncer_data->remaining_db_slots++;
            ctx->pending--;
            cg_storage_manager_syncer_remove_task(task);
        }
    }
    else
    {
        CGUTILS_ERROR("Error adding task to list: %d", result);
    }

    if (free_instance == true)
    {
        cgdb_inode_instance_free(instance), instance = NULL;
    }

    return result;
}

static void cg_storage_manager_syncer_ctx_consume(cg_storage_manager_syncer_ctx * const ctx)
{
    int result = 0;
    assert(ctx != NULL);
    cg_storage_manager_syncer_data * const syncer_data = ctx->syncer_data;
    assert(ctx->current != NULL);
    assert(syncer_data != NULL);
    assert(syncer_data->data != NULL);

    cg_monitor_data * monitor_data = cg_storage_manager_data_get_monitor_data(syncer_data->data);
    CGUTILS_ASSERT(monitor_data != NULL);
    CGUTILS_ASSERT(syncer_data->status_tab != NULL);
    int res = cg_monitor_data_retrieve(monitor_data,
                                       syncer_data->status_tab);

    if (res != 0)
    {
        CGUTILS_WARN("Error retrieving monitor data: %d", res);
    }

    for (;
         ctx->current != NULL &&
             syncer_data->remaining_db_slots > 0;
         ctx->current = cgutils_llist_elt_get_next(ctx->current))
    {
        cg_storage_manager_data * const data = syncer_data->data;
        cgdb_inode_instance * file_instance = cgutils_llist_elt_get_object(ctx->current);
        assert(file_instance != NULL);

        ctx->remaining--;

        if (cg_storage_manager_syncer_ctx_is_element_usable(ctx, file_instance) == true)
        {
            cg_storage_filesystem * fs = NULL;

            result = cg_storage_manager_data_get_filesystem_by_id(data,
                                                                  file_instance->fs_id,
                                                                  &fs);

            if (result == 0)
            {
                cg_storage_instance * inst = NULL;

                result = cg_storage_manager_data_get_instance_by_id(data,
                                                                    file_instance->instance_id,
                                                                    &inst);

                if (result == 0)
                {
                    if (cg_storage_manager_syncer_instance_is_up(syncer_data,
                                                                 inst,
                                                                 ctx->type) == true)
                    {
                        result = cg_storage_manager_syncer_ctx_handle_element(ctx,
                                                                              fs,
                                                                              file_instance);

                        file_instance = NULL;

                        if (result != 0)
                        {
                            CGUTILS_ERROR("Error handling file on instance: %d",
                                          result);
                        }
                    }
                    else
                    {
                        /*CGUTILS_TRACE("Not using object %s because instance %s is down",
                                      file_instance->id_in_instance,
                                      cg_storage_instance_get_name(inst));*/
                    }
                }
                else
                {
                    CGUTILS_INFO("Error getting instance %"PRIu64" for inode %"PRIu64": %d",
                                 file_instance->instance_id,
                                 file_instance->inode_number,
                                 result);
                }
            }
            else
            {
                CGUTILS_INFO("Error getting filesystem %"PRIu64" for inode %"PRIu64": %d",
                             file_instance->fs_id,
                             file_instance->inode_number,
                             result);
            }
        }

        if (file_instance != NULL)
        {
            cgdb_inode_instance_free(file_instance), file_instance = NULL;
        }
    }

    cg_storage_manager_syncer_ctx_handle(ctx);

}

static int cg_storage_manager_syncer_ctx_db_list_cb(int status,
                                                    cgutils_llist * files_instances,
                                                    void * cb_data)
{
    int result = status;
    cg_storage_manager_syncer_ctx * ctx = cb_data;
    assert(ctx != NULL);
    cg_storage_manager_syncer_data * syncer_data = ctx->syncer_data;
    assert(syncer_data->data != NULL);

    syncer_data->remaining_db_slots++;
    ctx->pending--;
    ctx->fetching_from_db = false;

    if (result == 0)
    {
        assert(files_instances != NULL);
        assert(ctx->file_instances == NULL);
        size_t const count = cgutils_llist_get_count(files_instances);
        ctx->got = count;
        ctx->remaining = count;
        ctx->offset += count;
        ctx->file_instances = files_instances;
        ctx->current = cgutils_llist_get_iterator(files_instances);

/*        CGUTILS_TRACE("Got %zu objects of type %s",
                       count,
                       ctx->type == cg_storage_manager_syncer_type_deleted ? "deleted" : "dirty");*/

        if (count > 0)
        {
            ctx->consuming = true;
            cg_storage_manager_syncer_ctx_consume(ctx);
            ctx->consuming = false;
        }
        else
        {
            cg_storage_manager_syncer_ctx_handle(ctx);
        }
    }
    else
    {
        CGUTILS_ERROR("Got error listing files_instances: %d", result);

        cg_storage_manager_syncer_ctx_handle(ctx);
    }

    return result;
}

static int cg_storage_manager_syncer_ctx_get_object_from_db(cg_storage_manager_syncer_ctx * const ctx)
{
    int result = 0;
    assert(ctx != NULL);
    assert(ctx->file_instances == NULL);
    assert(ctx->remaining == 0);
    assert(ctx->got == 0);
    assert(ctx->running == true);
    assert(ctx->syncer_data != NULL);
    cg_storage_manager_syncer_data * syncer_data = ctx->syncer_data;

    if (syncer_data->remaining_db_slots > 0)
    {
        cg_storage_manager_data * data = syncer_data->data;
        cgdb_data * db = cg_storage_manager_data_get_db(data);
        size_t const to_get = cg_storage_manager_syncer_compute_objects_per_call(ctx);

        if (to_get > 0 &&
            to_get < UINT32_MAX &&
            ctx->offset < UINT32_MAX)
        {
            cg_storage_instance_status status;

            if (ctx->type == cg_storage_manager_syncer_type_deleted)
            {
                status = cg_storage_instance_status_deleting;
            }
            else
            {
                assert(ctx->type == cg_storage_manager_syncer_type_dirty);
                status = cg_storage_instance_status_dirty;
            }

            result = cgdb_get_inode_instances_by_status(db,
                                                        status,
                                                        (uint32_t) to_get,
                                                        (uint32_t) ctx->offset,
                                                        &cg_storage_manager_syncer_ctx_db_list_cb,
                                                        ctx);

/*            CGUTILS_TRACE("Asking %zu, offset %zu, type %s",
                           to_get,
                           ctx->offset,
                           ctx->type == cg_storage_manager_syncer_type_deleted ? "deleted" : "dirty");*/

            if (result == 0)
            {
                ctx->pending++;
                ctx->fetching_from_db = true;
                syncer_data->remaining_db_slots--;
            }
            else
            {
                CGUTILS_ERROR("Error getting files list: %d", result);
                cg_storage_manager_syncer_ctx_set_db_error(ctx);
            }
        }
        else
        {
            CGUTILS_ERROR("Invalid number of objects (%zu) to retrieve, or invalid offset (%zu)",
                          to_get,
                          ctx->offset);
            cg_storage_manager_syncer_ctx_set_db_error(ctx);
        }
    }

    cg_storage_manager_syncer_ctx_handle(ctx);

    return result;
}

static int cg_storage_manager_syncer_ctx_handle(cg_storage_manager_syncer_ctx * const ctx)
{
    int result = 0;
    assert(ctx != NULL);
    assert(ctx->syncer_data != NULL);
    assert(ctx->syncer_data->data != NULL);

    if (ctx->running == true)
    {
        cg_storage_manager_syncer_data * const syncer_data = ctx->syncer_data;

        if (syncer_data->exiting == true)
        {
            if (ctx->pending == 0)
            {
                cg_storage_manager_syncer_ctx_reset(ctx);
            }
        }
        else
        {
            if (cg_storage_manager_syncer_ctx_has_error(ctx) &&
                ctx->pending == 0)
            {
//            CGUTILS_TRACE("We have an error and nothing is pending, resetting");
                cg_storage_manager_syncer_ctx_reset(ctx);
            }

            if (ctx->remaining > 0)
            {
                if (syncer_data->remaining_db_slots > 0)
                {
/*                CGUTILS_TRACE("We have objects remaining (%zu), and DB slots (%zu), consuming",
                  ctx->remaining,
                  syncer_data->remaining_db_slots);*/
                    if (ctx->consuming == false)
                    {
                        ctx->consuming = true;
                        cg_storage_manager_syncer_ctx_consume(ctx);
                        ctx->consuming = false;
                    }
                }
                else if (ctx->pending == 0)
                {
/*                CGUTILS_TRACE("We have objects remaining (%zu), but no DB slot, and no call pending, resetting",
                  ctx->remaining);*/
                    cg_storage_manager_syncer_ctx_reset(ctx);
                }
                else
                {
/*                CGUTILS_TRACE("We have objects remaining (%zu), no DB slot, but some calls pending (%zu)",
                  ctx->remaining,
                  ctx->pending);*/
                }
            }
            else
            {
                if (ctx->got == 0)
                {
                    if (ctx->pending == 0)
                    {
//                    CGUTILS_TRACE("No objects remaining, last DB call returned nothing, nothing pending, sleeping");
                        /* last request returned no data, clean up and wait for the next timer event. */
                        cg_storage_manager_syncer_ctx_reset(ctx);
                    }
                    else
                    {
/*                    CGUTILS_TRACE("No objects remaining, last DB call returned nothing, some call pending (%zu), waiting",
                      ctx->pending);*/
                    }
                }
                else if (syncer_data->remaining_db_slots > 0 &&
                         ctx->fetching_from_db == false)
                {
/*                CGUTILS_TRACE("No objects remaining, last DB call returned some data (%zu) or had an offset (%zu), we have DB slots (%zu), getting from DB",
                  ctx->got,
                  ctx->offset,
                  syncer_data->remaining_db_slots);*/

                    /* fetch more object from db */

                    cgutils_llist_free(&(ctx->file_instances), NULL);
                    ctx->got = 0;
                    result = cg_storage_manager_syncer_ctx_get_object_from_db(ctx);
                }
                else if (ctx->pending == 0)
                {
/*                CGUTILS_TRACE("No objects remaining, last DB call returned some data (%zu) or had an offset (%zu), but no DB slots, nothing pending, resetting",
                  ctx->got,
                  ctx->offset);*/
                    cg_storage_manager_syncer_ctx_reset(ctx);
                }
                else
                {
/*                CGUTILS_TRACE("No object remaining, last DB call returned some data (%zu), but no DB slots, some calls are pending (%zu), waiting",
                  ctx->got,
                  ctx->pending);*/
                }
            }
        }
    }
    else
    {
        ctx->running = true;

        result = cg_storage_manager_syncer_ctx_get_object_from_db(ctx);
    }

    return result;
}

static void cg_storage_manager_syncer_timer_cb(void * cb_data)
{
    cg_storage_manager_syncer_data * const syncer_data = cb_data;
    assert(cb_data != NULL);
    assert(syncer_data->data != NULL);

    if (syncer_data->dump_http_states == true)
    {
        cgutils_http_data * http = cg_storage_manager_data_get_http(syncer_data->data);

        if (http != NULL)
        {
            cgutils_http_dump_state(http);
        }
    }

    if (syncer_data->exiting == false)
    {
        int result = 0;

        if (syncer_data->dirty_ctx.running == false)
        {
            result = cg_storage_manager_syncer_ctx_handle(&(syncer_data->dirty_ctx));

            if (result != 0)
            {
                CGUTILS_ERROR("Error handling dirty files: %d", result);
            }
        }

        if (syncer_data->deleted_ctx.running == false)
        {
            result = cg_storage_manager_syncer_ctx_handle(&(syncer_data->deleted_ctx));

            if (result != 0)
            {
                CGUTILS_ERROR("Error handling deleted files: %d", result);
            }
        }
    }
}


static int cg_storage_manager_syncer_dirty_writers_cleared(int const status,
                                                           void * const cb_data)
{
    cg_storage_manager_syncer_data * const syncer_data = cb_data;
    int result = status;
    assert(cb_data != NULL);
    assert(syncer_data->data != NULL);
    cg_storage_manager_data * data = syncer_data->data;

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    if (status == 0)
    {
        size_t syncer_delay = cg_storage_manager_data_get_syncer_delay(data);

        if (syncer_delay == 0)
        {
            syncer_delay = CG_STORAGE_MANAGER_SYNCER_DELAY_DEFAULT;
        }

        result = cg_storage_manager_common_register_signal(data,
                                                           CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG,
                                                           &cg_storage_manager_syncer_graceful_exit,
                                                           syncer_data);

        if (result == 0)
        {
            struct timeval tv =
                {
                    .tv_sec = (time_t) syncer_delay,
                    .tv_usec = 0
                };

            assert(syncer_data->timer_event != NULL);

            result = cgutils_event_enable(syncer_data->timer_event, &tv);

            if (result != 0)
            {
                CGUTILS_ERROR("Error enabling timer event: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error registering signal event: %d", result);
        }
    }

    if (result != 0)
    {
        cgutils_event_exit_loop(event_data);
    }

    return result;
}

static int cg_storage_manager_syncer_flags_cleared(int const status,
                                                   void * const cb_data)
{
    cg_storage_manager_syncer_data * const syncer_data = cb_data;
    int result = status;
    assert(cb_data != NULL);
    assert(syncer_data->data != NULL);
    cg_storage_manager_data * data = syncer_data->data;

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    if (status == 0)
    {
        cgdb_data * db = cg_storage_manager_data_get_db(data);
        assert(db != NULL);

        result = cgdb_clear_inodes_dirty_writers(db,
                                                 &cg_storage_manager_syncer_dirty_writers_cleared,
                                                 syncer_data);

        if (result != 0)
        {
            CGUTILS_INFO("Error dirty writers: %d", result);
        }
    }

    if (result != 0)
    {
        cgutils_event_exit_loop(event_data);
    }

    return result;
}

int cg_storage_manager_syncer_run(cg_storage_manager_data * const data,
                                  bool const graceful)
{
    int result = 0;
    cg_storage_manager_syncer_data * syncer_data = NULL;
    assert(data != NULL);

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    CGUTILS_ALLOCATE_STRUCT(syncer_data);

    if (syncer_data != NULL)
    {
        size_t const instances_count = cg_storage_manager_data_get_instances_count(data);

        syncer_data->data = data;
        syncer_data->deleted_ctx.syncer_data = syncer_data;
        syncer_data->deleted_ctx.type = cg_storage_manager_syncer_type_deleted;
        syncer_data->dirty_ctx.syncer_data = syncer_data;
        syncer_data->dirty_ctx.type = cg_storage_manager_syncer_type_dirty;

        CGUTILS_MALLOC(syncer_data->status_tab,
                       1,
                       sizeof *(syncer_data->status_tab) + (sizeof *(syncer_data->status_tab->instances_data) * instances_count));

        if (syncer_data->status_tab != NULL)
        {
            syncer_data->status_tab->instances_count = instances_count;

            syncer_data->remaining_db_slots = cg_storage_manager_data_get_syncer_db_slots(data);

            if (syncer_data->remaining_db_slots == 0)
            {
                syncer_data->remaining_db_slots = CG_STORAGE_MANAGER_SYNCER_DB_SLOTS_DEFAULT;
            }

            syncer_data->max_db_objects_per_call = cg_storage_manager_data_get_syncer_max_db_objects_per_call(data);

            if (syncer_data->max_db_objects_per_call == 0)
            {
                syncer_data->max_db_objects_per_call = CG_STORAGE_MANAGER_SYNCER_MAX_DB_OBJECTS_PER_CALL_DEFAULT;
            }

            syncer_data->dump_http_states = cg_storage_manager_data_get_syncer_dump_http_states(data);

            result = cgutils_event_create_timer_event(event_data,
                                                      CGUTILS_EVENT_PERSIST,
                                                      &cg_storage_manager_syncer_timer_cb,
                                                      syncer_data,
                                                      &(syncer_data->timer_event));
            if (result == 0)
            {
                result = cgutils_llist_create(&(syncer_data->running_tasks));

                if (result == 0)
                {
                    cgdb_data * db = cg_storage_manager_data_get_db(data);
                    assert(db != NULL);

                    if (graceful == false)
                    {
                        result = cgdb_clear_inodes_instances_flags(db,
                                                                   &cg_storage_manager_syncer_flags_cleared,
                                                                   syncer_data);
                    }
                    else
                    {
                        result = cg_storage_manager_syncer_dirty_writers_cleared(0,
                                                                                 syncer_data);
                    }

                    if (result == 0)
                    {
                        cg_storage_manager_loop(data);
                    }
                    else
                    {
                        CGUTILS_INFO("Error clearing flags: %d", result);
                    }

                    cgutils_event_disable(syncer_data->timer_event);

                    cgutils_event_free(syncer_data->timer_event), syncer_data->timer_event = NULL;

                    cgutils_llist_free(&(syncer_data->running_tasks), &cg_storage_manager_syncer_task_delete);
                }
                else
                {
                    CGUTILS_ERROR("Error creating tasks list: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error creating timer event: %d", result);
            }

            CGUTILS_FREE(syncer_data->status_tab);
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for monitor data: %d", result);
        }

        CGUTILS_FREE(syncer_data), syncer_data = NULL;
    }
    else
    {
        result = ENOMEM;
        CGUTILS_ERROR("Error allocating memory for syncer data: %d", result);
    }

    return result;
}
