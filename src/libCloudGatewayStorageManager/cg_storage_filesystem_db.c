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

#include <cgsm/cg_storage_filesystem_db.h>
#include <cgsm/cg_storage_filesystem_utils.h>
#include <cgsm/cg_storage_object.h>

static int cg_storage_filesystem_db_status_cb(int const status,
                                              void * const void_data)
{
    int result = status;
    CGUTILS_ASSERT(void_data != NULL);
    cg_storage_fs_cb_data * data = void_data;

    cg_storage_filesystem_return_to_handler(result, data);

    return status;
}

static int cg_storage_filesystem_db_entries_cb(int const status,
                                               size_t const entries_count,
                                               cgutils_vector * const entries,
                                               void * const void_data)
{
    int result = status;
    CGUTILS_ASSERT(void_data != NULL);
    cg_storage_fs_cb_data * data = void_data;

    if (result == 0)
    {
        (void) entries_count;

        cg_storage_fs_cb_data_set_entries_vector(data, entries);
    }

    cg_storage_filesystem_return_to_handler(result, data);

    return status;
}

static int cg_storage_filesystem_db_instances_cb(int const status,
                                                 cgutils_llist * const instances,
                                                 void * const void_data)
{
    int result = status;
    CGUTILS_ASSERT(void_data != NULL);
    cg_storage_fs_cb_data * data = void_data;

    if (result == 0 &&
        instances != NULL)
    {
        cg_storage_fs_cb_data_set_available_instances(data, instances);
    }

    cg_storage_filesystem_return_to_handler(result, data);

    return status;
}

static int cg_storage_filesystem_db_returning_cb(int const status,
                                                 uint64_t const returning_id,
                                                 void * const void_data)
{
    int result = status;
    CGUTILS_ASSERT(void_data != NULL);

    cg_storage_fs_cb_data * data = void_data;

    if (result == 0)
    {
        cg_storage_fs_cb_data_set_returning_id(data, returning_id);
    }

    cg_storage_filesystem_return_to_handler(result, data);

    return status;
}

static int cg_storage_filesystem_db_count_cb(int const status,
                                             size_t const count,
                                             void * const void_data)
{
    int result = status;
    CGUTILS_ASSERT(void_data != NULL);
    cg_storage_fs_cb_data * data = void_data;

    if (result == 0)
    {
        cg_storage_fs_cb_data_set_entries_count(data, count);
    }

    cg_storage_filesystem_return_to_handler(result, data);

    return status;
}

static int cg_storage_filesystem_db_get_entry_info_cb(int const status,
                                                      cgdb_entry * entry,
                                                      void * const void_data)
{
    int result = status;
    cg_storage_fs_cb_data * data = void_data;
    cg_storage_filesystem * fs = cg_storage_fs_cb_data_get_fs(data);

    CGUTILS_ASSERT(void_data != NULL);
    CGUTILS_ASSERT(fs != NULL);

    if (result == 0)
    {
        cg_storage_object * object = NULL;

        result = cg_storage_object_init_from_entry(fs,
                                                   entry,
                                                   &object);

        if (result == 0)
        {
            cg_storage_fs_cb_data_set_object(data, object);
            object = NULL;
        }
        else
        {
                CGUTILS_ERROR("Error getting object from entry: %d", result);
        }

        cgdb_entry_free(entry), entry = NULL;
    }

    cg_storage_filesystem_return_to_handler(result, data);

    return status;
}

int cg_storage_filesystem_db_get_entry_info(cg_storage_filesystem * const fs,
                                            char const * const entry_path,
                                            cg_storage_fs_cb_data * const data)
{
    int result = 0;

    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    result = cgdb_get_entry_info_recursive(fs->db,
                                           fs->id,
                                           entry_path,
                                           &cg_storage_filesystem_db_get_entry_info_cb,
                                           data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error fetching inode information for path %s on fs %s: %d",
                      entry_path,
                      fs->name,
                      result);
    }

    return result;
}

static int cg_storage_filesystem_db_get_inode_info_cb(int const status,
                                                      cgdb_inode * inode,
                                                      void * const void_data)
{
    int result = status;
    cg_storage_fs_cb_data * data = void_data;
    cg_storage_filesystem * fs = cg_storage_fs_cb_data_get_fs(data);

    CGUTILS_ASSERT(void_data != NULL);
    CGUTILS_ASSERT(fs != NULL);

    if (result == 0)
    {
        CGUTILS_ASSERT(inode != NULL);
        cg_storage_object * object = NULL;
        cgdb_entry_type const type = cg_storage_object_mode_to_type(inode->st.st_mode);

        result = cg_storage_object_init_from_inode(fs,
                                                   inode,
                                                   NULL,
                                                   type,
                                                   &object);

        if (result == 0)
        {
            cg_storage_object * old_obj = cg_storage_fs_cb_data_get_object(data);

            if (old_obj != NULL)
            {
                cg_storage_object_free(old_obj), old_obj = NULL;
            }

            cg_storage_fs_cb_data_set_object(data, object);
            object = NULL;
        }
        else
        {
                CGUTILS_ERROR("Error getting object from inode: %d", result);
        }

        cgdb_inode_free(inode), inode = NULL;
    }

    cg_storage_filesystem_return_to_handler(result, data);

    return status;
}

int cg_storage_filesystem_db_get_inode_info(cg_storage_filesystem * const fs,
                                            uint64_t const inode_number,
                                            cg_storage_fs_cb_data * const data)
{
    int result = 0;

    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    result = cgdb_get_inode_info(fs->db,
                                 fs->id,
                                 inode_number,
                                 &cg_storage_filesystem_db_get_inode_info_cb,
                                 data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error fetching information for inode %"PRIu64" on fs %s: %d",
                      inode_number,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_get_child_inode_info(cg_storage_filesystem * const fs,
                                                  uint64_t const parent_inode_number,
                                                  char const * const child_name,
                                                  cg_storage_fs_cb_data * const data)
{
    int result = 0;

    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(child_name != NULL);
    CGUTILS_ASSERT(data != NULL);

    result = cgdb_get_child_inode_info(fs->db,
                                       fs->id,
                                       parent_inode_number,
                                       child_name,
                                       &cg_storage_filesystem_db_get_inode_info_cb,
                                       data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error fetching information for child named %s of inode %"PRIu64" on fs %s: %d",
                      child_name,
                      parent_inode_number,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_get_or_create_root_inode(cg_storage_filesystem * const fs,
                                                      cg_storage_fs_cb_data * const data)
{
    int result = 0;

    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    cg_storage_object * const object = cg_storage_fs_cb_data_get_object(data);
    CGUTILS_ASSERT(object != NULL);
    cgdb_inode const * inode = NULL;

    result = cg_storage_object_get_inode(object,
                                         &inode);

    if (result == 0)
    {
        /* inode is still linked to the cg_storage_object,
           do not free it.
        */
        result = cgdb_get_or_create_root_inode(fs->db,
                                               fs->id,
                                               inode,
                                               &cg_storage_filesystem_db_get_inode_info_cb,
                                               data);

        if (result != 0)
        {
            CGUTILS_ERROR("Error getting root inode for on fs %s: %d",
                          fs->name,
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error getting inode from root object on fs %s: %d",
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_create_file_entry(cg_storage_filesystem * const fs,
                                               uid_t const uid,
                                               gid_t const gid,
                                               mode_t const mode,
                                               int const flags,
                                               cg_storage_fs_cb_data * const data)
{
    int result = 0;
    time_t const now = time(NULL);
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);
    cg_storage_object * object = NULL;

    result = cg_storage_object_new(fs,
                                   cg_storage_fs_cb_data_get_path(data),
                                   CGDB_OBJECT_TYPE_FILE,
                                   mode,
                                   now,
                                   now,
                                   now,
                                   now,
                                   now,
                                   uid,
                                   gid,
                                   NULL,
                                   &object);

    if (COMPILER_LIKELY(result == 0))
    {
        cgdb_entry * entry = NULL;

        cg_storage_object_set_in_cache(object, true);

        if (flags & O_WRONLY ||
            flags & O_RDWR)
        {
            cg_storage_object_inc_dirty_writers_count(object);
        }

        cg_storage_fs_cb_data_set_object(data, object);


        result = cg_storage_object_get_entry(object,
                                             &entry);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgdb_add_new_entry_and_inode(fs->db,
                                                  cg_storage_fs_cb_data_get_parent_inode_number(data),
                                                  entry,
                                                  &cg_storage_filesystem_db_returning_cb,
                                                  data);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error adding entry %"PRIu64"->%s, on fs %s: %d",
                              cg_storage_fs_cb_data_get_parent_inode_number(data),
                              cg_storage_fs_cb_data_get_path(data),
                              fs->name,
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error getting entry from object: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error creating object: %d",
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_create_symlink_entry(cg_storage_filesystem * const fs,
                                                  uid_t const uid,
                                                  gid_t const gid,
                                                  mode_t const mode,
                                                  cg_storage_fs_cb_data * const data)
{
    int result = 0;
    time_t const now = time(NULL);
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);
    cg_storage_object * object = NULL;

    result = cg_storage_object_new(fs,
                                   cg_storage_fs_cb_data_get_path(data),
                                   CGDB_OBJECT_TYPE_SYMLINK,
                                   mode,
                                   now,
                                   now,
                                   now,
                                   now,
                                   now,
                                   uid,
                                   gid,
                                   cg_storage_fs_cb_data_get_symlink_to(data),
                                   &object);

    if (COMPILER_LIKELY(result == 0))
    {
        cgdb_entry * entry = NULL;

        cg_storage_object_set_in_cache(object, false);

        cg_storage_fs_cb_data_set_object(data, object);

        result = cg_storage_object_get_entry(object,
                                             &entry);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgdb_add_new_entry_and_inode(fs->db,
                                                  cg_storage_fs_cb_data_get_parent_inode_number(data),
                                                  entry,
                                                  &cg_storage_filesystem_db_returning_cb,
                                                  data);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error adding symlink %"PRIu64"->%s to %s, on fs %s: %d",
                              cg_storage_fs_cb_data_get_parent_inode_number(data),
                              cg_storage_fs_cb_data_get_path(data),
                              cg_storage_fs_cb_data_get_symlink_to(data),
                              fs->name,
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error getting entry from object: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error creating object: %d",
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_create_dir_entry(cg_storage_filesystem * const fs,
                                              uid_t const uid,
                                              gid_t const gid,
                                              mode_t const mode,
                                              cg_storage_fs_cb_data * const data)
{
    int result = 0;
    time_t const now = time(NULL);
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);
    cg_storage_object * object = NULL;

    result = cg_storage_object_new(fs,
                                   cg_storage_fs_cb_data_get_path(data),
                                   CGDB_OBJECT_TYPE_DIRECTORY,
                                   mode,
                                   now,
                                   now,
                                   now,
                                   now,
                                   now,
                                   uid,
                                   gid,
                                   NULL,
                                   &object);

    if (COMPILER_LIKELY(result == 0))
    {
        cgdb_entry * entry = NULL;

        cg_storage_fs_cb_data_set_object(data, object);

        result = cg_storage_object_get_entry(object,
                                             &entry);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgdb_add_new_entry_and_inode(fs->db,
                                                  cg_storage_fs_cb_data_get_parent_inode_number(data),
                                                  entry,
                                                  &cg_storage_filesystem_db_returning_cb,
                                                  data);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error adding dir entry %"PRIu64"->%s, on fs %s: %d",
                              cg_storage_fs_cb_data_get_parent_inode_number(data),
                              cg_storage_fs_cb_data_get_path(data),
                              fs->name,
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error getting entry from object: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error creating object: %d",
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_add_delayed_expunge_entry(cg_storage_filesystem * const fs,
                                                       uint64_t const inode_number,
                                                       char const * const path,
                                                       time_t const delete_after,
                                                       time_t const deletion_time,
                                                       cg_storage_fs_cb_data * const data)
{
    int result = 0;

    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(path != NULL);
    CGUTILS_ASSERT(data != NULL);

    /* entry is still linked to the cg_storage_object,
       do not free it.
    */
    result = cgdb_add_delayed_expunge_entry(fs->db,
                                            fs->id,
                                            inode_number,
                                            path,
                                            (uint64_t) delete_after,
                                            (uint64_t) deletion_time,
                                            &cg_storage_filesystem_db_status_cb,
                                            data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error adding delayed_entry for path %s on fs %s: %d",
                      path,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_set_inode_instance_uploading_in_progress(cg_storage_filesystem * const fs,
                                                                      cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    cgdb_inode_instance const * const inode_instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);
    CGUTILS_ASSERT(inode_instance != NULL);

    result = cgdb_update_inode_instance_set_uploading(fs->db,
                                                      fs->id,
                                                      inode_instance->instance_id,
                                                      inode_instance->inode_number,
                                                      inode_instance->id_in_instance,
                                                      &cg_storage_filesystem_db_status_cb,
                                                      data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error setting inode instance status to uploading for %s, inode %"PRIu64" on instance %"PRIu64", fs %s: %d",
                      inode_instance->id_in_instance,
                      inode_instance->inode_number,
                      inode_instance->instance_id,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_clear_inode_instance_dirty_status(cg_storage_filesystem * const fs,
                                                               bool const compressed,
                                                               bool const encrypted,
                                                               cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    cgdb_inode_instance const * const inode_instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);
    CGUTILS_ASSERT(inode_instance != NULL);

    result = cgdb_update_inode_instance_clear_dirty_status(fs->db,
                                                           fs->id,
                                                           inode_instance->instance_id,
                                                           inode_instance->inode_number,
                                                           inode_instance->id_in_instance,
                                                           cg_storage_instance_status_dirty,
                                                           cg_storage_instance_status_ok,
                                                           compressed,
                                                           encrypted,
                                                           &cg_storage_filesystem_db_status_cb,
                                                           data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error clearing inode instance dirty status for %s, inode %"PRIu64" on instance %"PRIu64", fs %s: %d",
                      inode_instance->id_in_instance,
                      inode_instance->inode_number,
                      inode_instance->instance_id,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_set_inode_instance_uploading_done(cg_storage_filesystem * const fs,
                                                               bool const error_occured,
                                                               cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    cgdb_inode_instance const * const inode_instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);
    CGUTILS_ASSERT(inode_instance != NULL);

    result = cgdb_update_inode_instance_set_uploading_done(fs->db,
                                                           fs->id,
                                                           inode_instance->instance_id,
                                                           inode_instance->inode_number,
                                                           inode_instance->id_in_instance,
                                                           error_occured,
                                                           &cg_storage_filesystem_db_status_cb,
                                                           data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error setting inode instance status to done for %s, inode %"PRIu64" on instance %"PRIu64", fs %s: %d",
                      inode_instance->id_in_instance,
                      inode_instance->inode_number,
                      inode_instance->instance_id,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_remove_inode_instance(cg_storage_filesystem * const fs,
                                                   cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    cgdb_inode_instance const * const inode_instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);
    CGUTILS_ASSERT(inode_instance != NULL);

    result = cgdb_remove_inode_instance(fs->db,
                                        fs->id,
                                        inode_instance->instance_id,
                                        inode_instance->inode_number,
                                        inode_instance->id_in_instance,
                                        cg_storage_instance_status_deleting,
                                        &cg_storage_filesystem_db_status_cb,
                                        data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error removing inode instance %s, inode %"PRIu64" on instance %"PRIu64", fs %s: %d",
                      inode_instance->id_in_instance,
                      inode_instance->inode_number,
                      inode_instance->instance_id,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_add_inode_instance(cg_storage_filesystem * const fs,
                                                 uint64_t const instance_id,
                                                 uint64_t const inode_number,
                                                 char const * const id_in_instance,
                                                 cg_storage_instance_status const status,
                                                 cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    result = cgdb_add_inode_instance(fs->db,
                                     fs->id,
                                     instance_id,
                                     inode_number,
                                     id_in_instance,
                                     status,
                                     &cg_storage_filesystem_db_status_cb,
                                     data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error adding inode instance for inode %"PRIu64" on instance %"PRIu64", fs %s: %d",
                      inode_number,
                      instance_id,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_set_inode_instance_delete_in_progress(cg_storage_filesystem * const fs,
                                                                   cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    cgdb_inode_instance const * const inode_instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);
    CGUTILS_ASSERT(inode_instance != NULL);

    result = cgdb_update_inode_instance_set_delete_in_progress(fs->db,
                                                               fs->id,
                                                               inode_instance->instance_id,
                                                               inode_instance->inode_number,
                                                               inode_instance->id_in_instance,
                                                               &cg_storage_filesystem_db_status_cb,
                                                               data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error setting inode instance delete flag for %s, inode %"PRIu64" on instance %"PRIu64", fs %s: %d",
                      inode_instance->id_in_instance,
                      inode_instance->inode_number,
                      inode_instance->instance_id,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_set_inode_instance_deleting_failed(cg_storage_filesystem * const fs,
                                                                cg_storage_fs_cb_data * const data)
{
        int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    cgdb_inode_instance const * const inode_instance = cg_storage_fs_cb_data_get_inode_instance_in_use(data);
    CGUTILS_ASSERT(inode_instance != NULL);

    result = cgdb_update_inode_instance_set_deleting_failed(fs->db,
                                                            fs->id,
                                                            inode_instance->instance_id,
                                                            inode_instance->inode_number,
                                                            inode_instance->id_in_instance,
                                                            &cg_storage_filesystem_db_status_cb,
                                                            data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error setting inode instance status to done for %s, inode %"PRIu64" on instance %"PRIu64", fs %s: %d",
                      inode_instance->id_in_instance,
                      inode_instance->inode_number,
                      inode_instance->instance_id,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_get_inode_dirty_instances_count(cg_storage_filesystem * const fs,
                                                             cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    uint64_t const inode_number = cg_storage_fs_cb_data_get_inode_number(data);
    CGUTILS_ASSERT(inode_number > 0);

    result = cgdb_count_inode_instances_by_status(fs->db,
                                                  fs->id,
                                                  inode_number,
                                                  cg_storage_instance_status_dirty,
                                                  &cg_storage_filesystem_db_count_cb,
                                                  data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error counting dirty instances for inode %"PRIu64", fs %s: %d",
                      inode_number,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_get_dir_entries_by_inode(cg_storage_filesystem * const fs,
                                                      uint64_t const inode,
                                                      cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(inode >= 1);
    CGUTILS_ASSERT(data != NULL);

    result = cgdb_get_inode_entries(fs->db,
                                    fs->id,
                                    inode,
                                    &cg_storage_filesystem_db_entries_cb,
                                    data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error listing entries from directory %"PRIu64", fs %s: %d",
                      inode,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_update_cache_status(cg_storage_filesystem * const fs,
                                                 uint64_t const inode_number,
                                                 bool const in_cache,
                                                 cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    result = cgdb_update_inode_cache_status(fs->db,
                                            fs->id,
                                            inode_number,
                                            in_cache,
                                            &cg_storage_filesystem_db_status_cb,
                                            data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error updating cache status for inode %"PRIu64" on fs %s: %d",
                      inode_number,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_set_inode_digest(cg_storage_filesystem * const fs,
                                              uint64_t const inode_number,
                                              cgutils_crypto_digest_algorithm const digest_algo,
                                              char const * const digest,
                                              size_t const digest_size,
                                              uint64_t const max_mtime,
                                              cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    result = cgdb_update_inode_digest(fs->db,
                                      fs->id,
                                      inode_number,
                                      digest_algo,
                                      digest,
                                      digest_size,
                                      max_mtime,
                                      &cg_storage_filesystem_db_status_cb,
                                      data);

    if (result != 0)
    {
        CGUTILS_ERROR("Error updating digest for inode %"PRIu64" on fs %s: %d",
                      inode_number,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_get_valid_inode_instances(cg_storage_filesystem * const fs,
                                                       cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    cg_storage_object * const object = cg_storage_fs_cb_data_get_object(data);
    CGUTILS_ASSERT(object != NULL);
    uint64_t const inode_number = cg_storage_object_get_inode_number(object);

    result = cgdb_get_inode_valid_instances(fs->db,
                                            fs->id,
                                            inode_number,
                                            /* We don't want deleting inode instances,
                                             everything else is fine */
                                            cg_storage_instance_status_deleting,
                                            &cg_storage_filesystem_db_instances_cb,
                                            data);
    if (result != 0)
    {
        CGUTILS_ERROR("Error getting valid instances for inode %"PRIu64" on fs %s: %d",
                      inode_number,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_update_inode_counter(cg_storage_filesystem * const fs,
                                                  uint64_t const inode_number,
                                                  bool const increment,
                                                  cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    result = cgdb_update_inode_counter(fs->db,
                                       fs->id,
                                       inode_number,
                                       1,
                                       increment,
                                       &cg_storage_filesystem_db_status_cb,
                                       data);
    if (result != 0)
    {
        CGUTILS_ERROR("Error updating dirty writers counter for inode %"PRIu64" on fs %s: %d",
                      inode_number,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_release_inode(cg_storage_filesystem * const fs,
                                           bool const altered,
                                           time_t const min_mtime,
                                           time_t const last_modification,
                                           cg_storage_fs_cb_data * const data)
{
    int result = 0;

    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    if (altered == true)
    {
        time_t const now = time(NULL);

        result = cgdb_release_inode(fs->db,
                                    fs->id,
                                    cg_storage_fs_cb_data_get_inode_number(data),
                                    (uint64_t) min_mtime,
                                    (uint64_t) now, /* ctime */
                                    (uint64_t) last_modification,
                                    cg_storage_fs_cb_data_get_file_size(data),
                                    /* We don't want deleting inode instances,
                                       everything else is fine */
                                    cg_storage_instance_status_ok,
                                    cg_storage_instance_status_dirty,
                                    &cg_storage_filesystem_db_status_cb,
                                    data);
    }
    else
    {
        result = cgdb_update_inode_counter(fs->db,
                                           fs->id,
                                           cg_storage_fs_cb_data_get_inode_number(data),
                                           1,
                                           false,
                                           &cg_storage_filesystem_db_status_cb,
                                           data);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error releasing inode %"PRIu64" on fs %s: %d",
                      cg_storage_fs_cb_data_get_inode_number(data),
                      fs->name,
                      result);
    }


    return result;
}


int cg_storage_filesystem_db_set_inode_dirty(cg_storage_filesystem * const fs,
                                             uint64_t const inode_number,
                                             time_t const mtime,
                                             time_t const ctime_local,
                                             time_t const last_modification,
                                             cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(inode_number > 0);
    CGUTILS_ASSERT(data != NULL);

    result = cgdb_set_inode_and_all_inodes_instances_dirty(fs->db,
                                                           fs->id,
                                                           inode_number,
                                                           mtime,
                                                           ctime_local,
                                                           last_modification,
                                                           /* We don't want deleting inode instances,
                                                              everything else is fine */
                                                           cg_storage_instance_status_ok,
                                                           cg_storage_instance_status_dirty,
                                                           &cg_storage_filesystem_db_status_cb,
                                                           data);
    if (result != 0)
    {
        CGUTILS_ERROR("Error settting status dirty for inode %"PRIu64" of fs %s: %d",
                      inode_number,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_update_cache_and_dirty_writers_status(cg_storage_filesystem * const fs,
                                                                   uint64_t const inode_number,
                                                                   bool const in_cache,
                                                                   bool const increase_dirty_writers,
                                                                   cg_storage_fs_cb_data * const data)
{
    int result = 0;

    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(inode_number > 0);
    CGUTILS_ASSERT(data != NULL);

    if (increase_dirty_writers == true)
    {
        result = cgdb_update_inode_cache_status_and_increase_dirty_writers(fs->db,
                                                                           fs->id,
                                                                           inode_number,
                                                                           in_cache,
                                                                           &cg_storage_filesystem_db_status_cb,
                                                                           data);
    }
    else
    {
        result = cgdb_update_inode_cache_status(fs->db,
                                                fs->id,
                                                inode_number,
                                                in_cache,
                                                &cg_storage_filesystem_db_status_cb,
                                                data);
    }

    if (result != 0)
    {
        CGUTILS_ERROR("Error updating inode cache status (to %d, dirty writers %d) for inode %"PRIu64" of fs %s: %d",
                      in_cache,
                      increase_dirty_writers,
                      inode_number,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_get_inode_cache_status_updating_writers(cg_storage_filesystem * const fs,
                                                                     uint64_t const inode_number,
                                                                     bool const increase_dirty_writers,
                                                                     cg_storage_fs_cb_data * const data)
{
    int result = 0;

    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(inode_number > 0);
    CGUTILS_ASSERT(data != NULL);

    time_t const now = time(NULL);

    result = cgdb_get_inode_info_updating_times_and_writers(fs->db,
                                                            fs->id,
                                                            inode_number,
                                                            (uint64_t) now,
                                                            (uint64_t) now,
                                                            (uint64_t) now,
                                                            increase_dirty_writers,
                                                            &cg_storage_filesystem_db_get_inode_info_cb,
                                                            data);
    if (result != 0)
    {
        CGUTILS_ERROR("Error getting inode info, updating attributes for inode %"PRIu64" of fs %s: %d",
                      inode_number,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_decrease_dirty_writers_count(cg_storage_filesystem * const fs,
                                                          uint64_t const inode_number,
                                                          cg_storage_fs_cb_data * const data)
{
    int result = 0;

    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(inode_number > 0);
    CGUTILS_ASSERT(data != NULL);

    result = cgdb_update_inode_counter(fs->db,
                                       fs->id,
                                       inode_number,
                                       1,
                                       true,
                                       &cg_storage_filesystem_db_status_cb,
                                       data);
    if (result != 0)
    {
        CGUTILS_ERROR("Error decreasing inode %"PRIu64" dirty writers count, on fs %s: %d",
                      inode_number,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_update_inode_attributes(cg_storage_filesystem * const fs,
                                                     uint64_t const inode_number,
                                                     mode_t const mode,
                                                     uid_t const uid,
                                                     gid_t const gid,
                                                     time_t const atime,
                                                     time_t const mtime,
                                                     size_t const size,
                                                     cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);

    result = cgdb_update_inode_attributes(fs->db,
                                          fs->id,
                                          inode_number,
                                          mode,
                                          uid,
                                          gid,
                                          (uint64_t) atime,
                                          (uint64_t) mtime,
                                          size,
                                          &cg_storage_filesystem_db_status_cb,
                                          data);
    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error updating attributes of inode %"PRIu64", on fs %s: %d",
                      inode_number,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_remove_dir_entry(cg_storage_filesystem * const fs,
                                              uint64_t const parent_inode_number,
                                              char const * const entry_name,
                                              cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(entry_name != NULL);

    result = cgdb_remove_dir_entry(fs->db,
                                   fs->id,
                                   parent_inode_number,
                                   entry_name,
                                   &cg_storage_filesystem_db_returning_cb,
                                   data);
    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error removing dir entry named %s from inode %"PRIu64", on fs %s: %d",
                      entry_name,
                      parent_inode_number,
                      fs->name,
                      result);
    }

    return result;
}

static int cg_storage_filesystem_db_returning_inode_number_and_deleted_status_cb(int const status,
                                                                                 uint64_t const returning_id,
                                                                                 bool const deleted,
                                                                                 void * const void_data)
{
    int result = status;
    CGUTILS_ASSERT(void_data != NULL);

    cg_storage_fs_cb_data * data = void_data;

    if (result == 0)
    {
        cg_storage_fs_cb_data_set_returning_id(data, returning_id);
        cg_storage_fs_cb_data_set_object_been_deleted(data, deleted);
    }

    cg_storage_filesystem_return_to_handler(result, data);

    return status;
}

int cg_storage_filesystem_db_remove_inode_entry(cg_storage_filesystem * const fs,
                                                uint64_t const parent_inode_number,
                                                char const * const entry_name,
                                                cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(entry_name != NULL);

    result = cgdb_remove_inode_entry(fs->db,
                                     fs->id,
                                     parent_inode_number,
                                     entry_name,
                                     &cg_storage_filesystem_db_returning_inode_number_and_deleted_status_cb,
                                     data);

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error removing entry named %s from inode %"PRIu64", on fs %s: %d",
                      entry_name,
                      parent_inode_number,
                      fs->name,
                      result);
    }

    return result;
}

static int cg_storage_filesystem_db_rename_inode_cb(int const status,
                                                    uint64_t const renamed_ino,
                                                    uint64_t const deleted_ino,
                                                    bool const deleted,
                                                    void * const void_data)
{
    int result = status;
    CGUTILS_ASSERT(void_data != NULL);

    cg_storage_fs_cb_data * data = void_data;

    if (result == 0)
    {
        cg_storage_fs_cb_data_set_returning_id(data, renamed_ino);
        cg_storage_fs_cb_data_set_parent_inode_number(data, deleted_ino);
        cg_storage_fs_cb_data_set_object_been_deleted(data, deleted);
    }

    cg_storage_filesystem_return_to_handler(result, data);

    return 0;
}

int cg_storage_filesystem_db_rename_inode_entry(cg_storage_filesystem * const fs,
                                                uint64_t const old_parent_ino,
                                                char const * const old_entry_name,
                                                uint64_t const new_parent_ino,
                                                char const * const new_entry_name,
                                                cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(old_parent_ino > 0);
    CGUTILS_ASSERT(old_entry_name != NULL);
    CGUTILS_ASSERT(new_parent_ino > 0);
    CGUTILS_ASSERT(new_entry_name != NULL);

    result = cgdb_rename_inode(fs->db,
                               fs->id,
                               old_parent_ino,
                               old_entry_name,
                               new_parent_ino,
                               new_entry_name,
                               &cg_storage_filesystem_db_rename_inode_cb,
                               data);

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error renaming entry from %"PRIu64"->%s to %"PRIu64"->%s, on fs %s: %d",
                      old_parent_ino,
                      old_entry_name,
                      new_parent_ino,
                      new_entry_name,
                      fs->name,
                      result);
    }

    return result;
}

int cg_storage_filesystem_db_add_inode_hardlink(cg_storage_filesystem * const fs,
                                                uint64_t const existing_ino,
                                                uint64_t const new_parent_ino,
                                                char const * const new_entry_name,
                                                cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(existing_ino > 0);
    CGUTILS_ASSERT(new_parent_ino > 0);
    CGUTILS_ASSERT(new_entry_name != NULL);

    result = cgdb_add_hardlink(fs->db,
                               fs->id,
                               existing_ino,
                               new_parent_ino,
                               new_entry_name,
                               CGDB_OBJECT_TYPE_FILE,
                               &cg_storage_filesystem_db_get_inode_info_cb,
                               data);

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error hardlinking existing inode %"PRIu64" to %"PRIu64"->%s, on fs %s: %d",
                      existing_ino,
                      new_parent_ino,
                      new_entry_name,
                      fs->name,
                      result);
    }

    return result;
}

static int cg_storage_filesystemd_readlink_cb(int const status,
                                              char * link_to,
                                              void * cb_data)
{
    int result = status;
    CGUTILS_ASSERT(cb_data != NULL);
    cg_storage_fs_cb_data * data = cb_data;

    if (result == 0)
    {
        CGUTILS_ASSERT(link_to != NULL);

        cg_storage_fs_cb_data_set_symlink_to(data,
                                             link_to);
        link_to = NULL;
    }

    CGUTILS_FREE(link_to);
    cg_storage_filesystem_return_to_handler(result, data);

    return status;
}

int cg_storage_filesystem_db_readlink(cg_storage_filesystem * const fs,
                                      uint64_t const inode_number,
                                      cg_storage_fs_cb_data * const data)
{
    int result = 0;
    CGUTILS_ASSERT(fs != NULL);
    CGUTILS_ASSERT(inode_number > 0);
    CGUTILS_ASSERT(data != NULL);

    result = cgdb_readlink(fs->db,
                           fs->id,
                           inode_number,
                           CGDB_OBJECT_TYPE_SYMLINK,
                           &cg_storage_filesystemd_readlink_cb,
                           data);

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error reading symlink %"PRIu64" on fs %s: %d",
                      inode_number,
                      fs->name,
                      result);
    }


    return result;
}
