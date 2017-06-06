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

static int cg_storage_filesystem_refresh_monitor_data(cg_storage_filesystem * const fs,
                                                      bool * const has_data)
{
    /* Would be nice to implement caching. */
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(has_data != NULL);
    CGUTILS_ASSERT(fs->data != NULL);
    CGUTILS_ASSERT(fs->instances != NULL);
    size_t const instances_count = cg_storage_manager_data_get_instances_count(fs->data);
    cg_monitor_data * monitor_data = cg_storage_manager_data_get_monitor_data(fs->data);
    CGUTILS_ASSERT(instances_count > 0);

    *has_data = false;

    if (monitor_data != NULL)
    {
        cg_monitor_data_instance_status_tab * status_tab = NULL;

        CGUTILS_MALLOC(status_tab, 1, sizeof *(status_tab) + (sizeof *(status_tab->instances_data) * instances_count));

        if (status_tab != NULL)
        {
            *status_tab = (cg_monitor_data_instance_status_tab) { 0 };
            status_tab->instances_count = instances_count;

            result = cg_monitor_data_retrieve(monitor_data, status_tab);

            if (result == 0)
            {
                if (instances_count > 0 && status_tab->values_set > 0)
                {
                    CGUTILS_ASSERT(fs->instances_count <= instances_count);
                    *has_data = true;

                    for (size_t fs_instance_idx = 0; fs_instance_idx < fs->instances_count; fs_instance_idx++)
                    {
                        bool found = false;
                        cg_storage_instance const * inst = fs->instances[fs_instance_idx].instance;
                        size_t const instance_idx = cg_storage_instance_get_index(inst);

                        for (size_t status_tab_idx = 0;
                             status_tab_idx < instances_count && found == false;
                             status_tab_idx++)
                        {
                            if (status_tab->instances_data[status_tab_idx].instance_index == instance_idx)
                            {
                                fs->instances[fs_instance_idx].status = status_tab->instances_data[status_tab_idx];
                                found = true;
                            }
                        }
                    }
                }
            }
            else
            {
                CGUTILS_ERROR("Error retrieving monitor data: %d", result);
            }

            CGUTILS_FREE(status_tab);
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

static int cg_storage_filesystem_get_fs_instance_by_db_obj(cg_storage_filesystem * const fs,
                                                           cgdb_inode_instance const * const obj_instance,
                                                           cg_storage_filesystem_instance ** const out)
{
    int result = ENOENT;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(fs->instances != NULL);
    CGUTILS_ASSERT(obj_instance != NULL);
    CGUTILS_ASSERT(out != NULL);

    uint64_t const obj_inst_id = obj_instance->instance_id;

    for (size_t idx = 0;
         result == ENOENT && idx < fs->instances_count;
         idx++)
    {
        CGUTILS_ASSERT(fs->instances[idx].instance != NULL);
        uint64_t const inst_id = cg_storage_instance_get_id(fs->instances[idx].instance);

        if (obj_inst_id == inst_id)
        {
            result = 0;
            *out = &(fs->instances[idx]);
        }
    }

    return result;
}

static int cg_storage_filesystem_get_instance_by_db_obj(cg_storage_filesystem * const fs,
                                                        cgdb_inode_instance const * const obj_instance,
                                                        cg_storage_instance ** const out)
{
    cg_storage_filesystem_instance * fs_inst = NULL;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(fs->instances != NULL);
    CGUTILS_ASSERT(obj_instance != NULL);
    CGUTILS_ASSERT(out != NULL);

    int result = cg_storage_filesystem_get_fs_instance_by_db_obj(fs, obj_instance, &fs_inst);

    if (result == 0)
    {
        CGUTILS_ASSERT(fs_inst != NULL);

        *out = fs_inst->instance;
    }

    return result;
}

static bool cg_storage_filesystem_fs_instance_is_up(cg_storage_filesystem * const fs,
                                                    cg_storage_filesystem_instance const * const inst)
{
    bool result = false;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(inst != NULL);

    (void) fs;

    if (inst->status.last_success == true)
    {
        result = true;
    }

    return result;
}

static size_t cg_storage_filesystem_fs_instance_get_get_weight(cg_storage_filesystem_instance const * const inst)
{
    size_t result = 0;

    CGUTILS_ASSERT(inst != NULL);

    result = inst->status.get_weight;

    return result;
}

static size_t cg_storage_filesystem_fs_instance_get_put_weight(cg_storage_filesystem_instance const * const inst)
{
    size_t result = 0;

    CGUTILS_ASSERT(inst != NULL);

    result = inst->status.put_weight;

    return result;
}

static bool cg_storage_filesystem_instance_object_is_usable(cg_storage_filesystem const * const fs,
                                                            cgdb_inode_instance const * const obj,
                                                            bool const use_dirty)
{
    bool result = false;

    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(obj != NULL);

    (void) fs;

    if ( obj->status == cg_storage_instance_status_ok ||
         (use_dirty == true && obj->status == cg_storage_instance_status_dirty))
    {
        result = true;
    }

    return result;
}

static int cg_storage_filesystem_instance_pick_first(cg_storage_filesystem * const fs,
                                                     /* list of usable instances (has object, has not failed),
                                                        llist of cgdb_inode_instance * */
                                                     cgutils_llist * const usable_instances,
                                                     cgdb_inode_instance ** const obj_inst,
                                                     cg_storage_instance ** const out)
{
    int result = 0;
    bool use_dirty = true;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(usable_instances != NULL);
    CGUTILS_ASSERT(obj_inst != NULL);
    CGUTILS_ASSERT(out != NULL);

    *out = NULL;

    for (cgutils_llist_elt * elt = cgutils_llist_get_first(usable_instances);
         use_dirty == true &&
             elt != NULL;
         elt = cgutils_llist_elt_get_next(elt))
    {
        cgdb_inode_instance * inst_obj = cgutils_llist_elt_get_object(elt);

        /* If at least one instance is up and not dirty */

        if (inst_obj->status == cg_storage_instance_status_ok)
        {
            use_dirty = false;
        }
    }

    for (cgutils_llist_elt * elt = cgutils_llist_get_first(usable_instances);
         result == 0 && elt != NULL && *out == NULL;
         elt = cgutils_llist_elt_get_next(elt))
    {
        cgdb_inode_instance * usable_inst_obj = cgutils_llist_elt_get_object(elt);
        CGUTILS_ASSERT(usable_inst_obj != NULL);

        if (cg_storage_filesystem_instance_object_is_usable(fs, usable_inst_obj, use_dirty))
        {
            result = cg_storage_filesystem_get_instance_by_db_obj(fs,
                                                                  usable_inst_obj,
                                                                  out);
            if (result == 0)
            {
                *obj_inst = usable_inst_obj;
            }
            else
            {
                CGUTILS_ERROR("Error getting instance from db object: %d", result);
            }
        }
    }

    if (*out == NULL)
    {
        result = ENOENT;
    }

    return result;
}

static int cg_storage_filesystem_monitor_get_instance_pos_in_tab(cg_storage_filesystem * const fs,
                                                                 uint64_t const instance_id,
                                                                 size_t * const pos)
{
    int result = ENOENT;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(pos != NULL);

    for(size_t idx = 0;
        result == ENOENT && idx < fs->instances_count;
        idx++)
    {
        CGUTILS_ASSERT(fs->instances[idx].instance != NULL);
        uint64_t const this_inst_id = cg_storage_instance_get_id(fs->instances[idx].instance);

        if (instance_id == this_inst_id)
        {
            result = 0;
            *pos = idx;
        }
    }

    return result;
}

static int cg_storage_filesystem_monitor_update_instances_tab_for_get(cg_storage_filesystem * const fs,
                                                                      /* list of usable instances (has object, has not failed),
                                                                         llist of cgdb_inode_instance * */
                                                                      cgutils_llist * const usable_instances,
                                                                      size_t * const weight,
                                                                      bool * const use_dirty)
{
    int result = 0;
    bool found = true;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(usable_instances != NULL);
    CGUTILS_ASSERT(weight != NULL);
    CGUTILS_ASSERT(use_dirty != NULL);

    *weight = 0;
    *use_dirty = true;

    for (size_t idx = 0;
         idx < fs->instances_count;
         idx++)
    {
        fs->instances[idx].object_instance = NULL;
        fs->instances[idx].usable = false;
    }

    for (cgutils_llist_elt * elt = cgutils_llist_get_first(usable_instances);
         *use_dirty == true &&
             elt != NULL;
         elt = cgutils_llist_elt_get_next(elt))
    {
        cgdb_inode_instance * inst_obj = cgutils_llist_elt_get_object(elt);
        size_t pos = 0;
        /* If at least one instance is up and not dirty */

        if (inst_obj->status == cg_storage_instance_status_ok)
        {
            result = cg_storage_filesystem_monitor_get_instance_pos_in_tab(fs,
                                                                           inst_obj->instance_id,
                                                                           &pos);
            if (result == 0)
            {
                if (cg_storage_filesystem_fs_instance_is_up(fs, &(fs->instances[pos])))
                {
                    *use_dirty = false;
                }
            }
        }
    }

    for (cgutils_llist_elt * elt = cgutils_llist_get_first(usable_instances);
         result == 0 && elt != NULL;
         elt = cgutils_llist_elt_get_next(elt))
    {
        cgdb_inode_instance * inst_obj = cgutils_llist_elt_get_object(elt);
        size_t pos = 0;

        if (cg_storage_filesystem_instance_object_is_usable(fs, inst_obj, *use_dirty))
        {
            result = cg_storage_filesystem_monitor_get_instance_pos_in_tab(fs,
                                                                           inst_obj->instance_id,
                                                                           &pos);

            if (result == 0)
            {
                if (cg_storage_filesystem_fs_instance_is_up(fs, &(fs->instances[pos])))
                {
                    fs->instances[pos].object_instance = inst_obj;
                    fs->instances[pos].usable = true;
                    *weight += fs->instances[pos].status.get_weight;
                    found = true;
                }
            }
            else
            {
                CGUTILS_WARN("Requested object seems to be present in an instance not existing in this filesystem.");
                result = 0;
            }
        }
    }

    if (found == false)
    {
        result = ENOENT;
        CGUTILS_INFO("No instance UP with an usable (ok or dirty) copy of the requested file: %d", result);
    }

    return result;
}

static int cg_storage_filesystem_monitor_update_instances_tab_for_put(cg_storage_filesystem * const fs,
                                                                      size_t * const weight)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(weight != NULL);
    *weight = 0;

    for (size_t idx = 0;
         idx < fs->instances_count;
         idx++)
    {
        fs->instances[idx].object_instance = NULL;

        if (cg_storage_filesystem_fs_instance_is_up(fs, &(fs->instances[idx])))
        {
            fs->instances[idx].usable = true;
            *weight += fs->instances[idx].status.put_weight;
        }
        else
        {
            fs->instances[idx].usable = false;
        }
    }

    return result;
}

static int cg_storage_filesystem_monitor_select_one_instance(cg_storage_filesystem * const fs,
                                                             bool const is_get,
                                                             /* Total weight of all valid instances */
                                                             size_t const total_weight,
                                                             cgdb_inode_instance ** const obj_inst,
                                                             cg_storage_instance ** const inst)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(total_weight <= UINT_MAX);
    CGUTILS_ASSERT(is_get == false || obj_inst != NULL);

    /* If everything did fine, we need to pick one
       of these according to their weight. */
    unsigned int got = cgutils_get_random_number_r(&(fs->seed),
                                                   (unsigned int) total_weight);
    bool found = false;
    size_t idx = 0;

    if (got > 0)
    {
        for (idx = 0;
             got > 0 && idx < fs->instances_count;
             idx++)
        {
            cg_storage_filesystem_instance const * const fs_inst = &(fs->instances[idx]);

            if (fs_inst->usable == true)
            {
                size_t inst_weight = 0;

                if (is_get)
                {
                    inst_weight = cg_storage_filesystem_fs_instance_get_get_weight(fs_inst);
                }
                else
                {
                    inst_weight = cg_storage_filesystem_fs_instance_get_put_weight(fs_inst);
                }

                if (got > (unsigned int) inst_weight)
                {
                    got -= (unsigned int) inst_weight;
                }
                else
                {
                    got = 0;
                    found = true;
                }
            }

        }

        idx--;
    }
    else
    {
        for (idx = 0;
             idx < fs->instances_count &&
                 found == false;
             idx++)
        {
            cg_storage_filesystem_instance const * const fs_inst = &(fs->instances[idx]);

            if (fs_inst->usable == true)
            {
                found = true;
            }
        }

        if (idx > 0)
        {
            idx--;
        }
    }

    CGUTILS_ASSERT(got == 0);

    if (found == true)
    {
        *inst = fs->instances[idx].instance;

        if (*inst != NULL)
        {
            if (obj_inst != NULL)
            {
                *obj_inst = fs->instances[idx].object_instance;
            }
        }
        else
        {
            result = ENOENT;
        }
    }
    else
    {
        result = ENOENT;
    }

    return result;
}

int cg_storage_filesystem_monitor_pick_instance_from(cg_storage_filesystem * const fs,
                                                     /* list of usable instances (has object, has not failed),
                                                        llist of cgdb_inode_instance * */
                                                     cgutils_llist * const usable_instances,
                                                     cgdb_inode_instance ** const obj_inst,
                                                     cg_storage_instance ** const out)
{
    int result = 0;

    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(usable_instances != NULL);
    CGUTILS_ASSERT(obj_inst != NULL);
    CGUTILS_ASSERT(out != NULL);

    size_t const usable_instances_count = cgutils_llist_get_count(usable_instances);

    if (usable_instances_count)
    {
        bool use_dirty = true;
        bool usable_data = false;

        cg_storage_filesystem_refresh_monitor_data(fs, &usable_data);

        if (usable_data == true)
        {
            /* First, we fill an array with all usable and UP instances,
               computing their cumulated weight. */

            size_t total_weight = 0;

            result = cg_storage_filesystem_monitor_update_instances_tab_for_get(fs,
                                                                                usable_instances,
                                                                                &total_weight,
                                                                                &use_dirty);

            if (result == 0)
            {
                /* If everything did fine, we need to pick one
                   of these according to their weight. */

                result = cg_storage_filesystem_monitor_select_one_instance(fs,
                                                                           true,
                                                                           total_weight,
                                                                           obj_inst,
                                                                           out);

                if (result == 0)
                {
                    CGUTILS_ASSERT(*obj_inst != NULL);
                    CGUTILS_ASSERT(*out != NULL);
                }
                else
                {
                    CGUTILS_ERROR("Error in cg_storage_filesystem_monitor_select_one_instance: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error while looking for a working instance with a valid copy: %d", result);
            }
        }
        else
        {
            CGUTILS_DEBUG("No monitoring data");
            /* No Monitoring data, well.. */
            result = cg_storage_filesystem_instance_pick_first(fs,
                                                               usable_instances,
                                                               obj_inst,
                                                               out);

            if (result == 0)
            {
                CGUTILS_ASSERT(*obj_inst != NULL);
                CGUTILS_ASSERT(*out != NULL);
            }
        }
    }
    else
    {
        result = ENOENT;
    }

    return result;
}

static int cg_storage_filesystem_monitor_pick_one_instance_to_put(cg_storage_filesystem * const fs,
                                                                  cg_storage_instance ** const out)
{
    int result = 0;

    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(out != NULL);

    bool usable_data = false;

    cg_storage_filesystem_refresh_monitor_data(fs, &usable_data);

    if (usable_data == true)
    {
        /* First, we fill an array with all usable and UP instances,
           computing their cumulated weight. */

        size_t total_weight = 0;

        result = cg_storage_filesystem_monitor_update_instances_tab_for_put(fs,
                                                                            &total_weight);

        if (result == 0)
        {
            /* If everything did fine, we need to pick one
               of these according to their weight. */

            result = cg_storage_filesystem_monitor_select_one_instance(fs,
                                                                       false,
                                                                       total_weight,
                                                                       NULL,
                                                                       out);

            if (result == 0)
            {
                CGUTILS_ASSERT(*out != NULL);
            }
            else
            {
                CGUTILS_ERROR("Error in cg_storage_filesystem_monitor_select_one_instance: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error updating tab: %d", result);
        }
    }
    else
    {
        *out = fs->instances[0].instance;
        result = 0;
    }

    return result;
}

int cg_storage_filesystem_monitor_pick_instances_to(cg_storage_filesystem * const fs,
                                                    /* llist of cg_storage_instance * */
                                                    cgutils_llist ** const out)
{
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(out != NULL);

    int result = cgutils_llist_create(out);

    if (result == 0)
    {
        size_t const instances_count = fs->instances_count;

        if (instances_count > 0)
        {
            bool found = false;

            if (fs->type == cg_storage_filesystem_type_mirroring ||
                fs->type == cg_storage_filesystem_type_single)
            {
                /* In mirroring mode, we have no need to select an instance,
                   each file should be uploaded to every instance anyway. */
                for (size_t idx = 0;
                     idx < instances_count && result == 0;
                     idx++)
                {
                    cg_storage_instance * inst = fs->instances[idx].instance;

                    if (inst != NULL)
                    {
                        result = cgutils_llist_insert(*out, inst);

                        if (result == 0)
                        {
                            found = true;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error inserting instance into list: %d", result);
                        }
                    }
                }
            }
            else
            {
                /* In striping mode, select a working instance,
                   using the upload weight. */
                cg_storage_instance * inst = NULL;

                result = cg_storage_filesystem_monitor_pick_one_instance_to_put(fs, &inst);

                if (result == 0)
                {
                    result = cgutils_llist_insert(*out, inst);

                    if (result == 0)
                    {
                        found = true;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error inserting instance into list: %d", result);
                    }
                }
            }

            if (result == 0 && found == false)
            {
                result = ENOENT;
            }
        }
        else
        {
            result = ENOENT;
        }

        if (result != 0)
        {
            cgutils_llist_free(out, NULL);
            CGUTILS_WARN("Looks like there is no instance available for filesystem %s, too bad.", fs->name);
        }
    }
    else
    {
        CGUTILS_ERROR("Unable to create list: %d", result);
    }

    return result;
}
