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
#include <limits.h>
#include <string.h>
#include <time.h>

#include <cgdb/cgdb.h>
#include <cgdb/cgdb_backend.h>
#include <cgdb/cgdb_utils.h>
#include "cgdb_utils_internal.h"

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_event.h>
#include <cloudutils/cloudutils_vector.h>

struct cgdb_data
{
    char * type;
    cgdb_backend * backend;
};

typedef struct
{
    cgdb_data * data;
    cgdb_entry * entry;
    cgdb_inode const * inode;
    uint64_t inode_number;
    uint64_t entry_id;
    uint64_t fs_id;
    void * cb;
    void * cb_data;
} cgdb_request_data;

static void cgdb_request_data_free(cgdb_request_data * this)
{
    if (this != NULL)
    {
        this->data = NULL;
        this->cb = NULL;
        this->cb_data = NULL;
        CGUTILS_FREE(this);
    }
}

static int cgdb_request_data_init(cgdb_data * const data,
                                  void * const cb,
                                  void * const cb_data,
                                  cgdb_request_data ** const out)
{
    int result = ENOMEM;

    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(*out);

    if (*out != NULL)
    {
        cgdb_request_data * request = *out;
        request->data = data;
        request->cb = cb;
        request->cb_data = cb_data;
        result = 0;
    }

    return result;
}

int cgdb_data_init(char const * const backends_path,
                   cgutils_configuration * const config,
                   cgutils_event_data * const event_data,
                   cgdb_data ** const data)
{
    int result = EINVAL;

    if (config != NULL && backends_path != NULL && event_data != NULL && data != NULL)
    {
        CGUTILS_ALLOCATE_STRUCT(*data);

        if (*data != NULL)
        {
            cgdb_data * ldata = *data;

            result = cgutils_configuration_get_string(config, "Type", &(ldata->type));

            if (result == 0)
            {
                cgutils_configuration * specifics = NULL;

                result = cgutils_configuration_from_path(config, "Specifics", &specifics);

                if (result == 0)
                {
                    result = cgdb_backend_init(ldata->type, backends_path, event_data, specifics, &(ldata->backend));

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error initializing backend of type %s: %d", ldata->type, result);
                    }

                    cgutils_configuration_free(specifics), specifics = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error getting database specific configuration: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Unable to get database type: %d", result);
            }

            if (result != 0)
            {
                cgdb_data_free(*data), *data = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

void cgdb_data_free(cgdb_data * data)
{
    if (data != NULL)
    {
        if (data->backend != NULL)
        {
            cgdb_backend_free(data->backend);
        }

        if (data->type != NULL)
        {
            CGUTILS_FREE(data->type), data->type = NULL;
        }

        CGUTILS_FREE(data);
    }
}

static void cgdb_generic_status_cb(void * const data,
                                   int const status,
                                   void * cb_data)
{
    int result = status;
    cgdb_request_data * request = cb_data;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(cb_data != NULL);

    (void) data;

    if (request->cb != NULL)
    {
        result = (*((cgdb_status_cb * )request->cb))(result,
                                                     request->cb_data);

        if (result != 0 &&
            result != status)
        {
            CGUTILS_WARN("Callback returned: %d", result);
        }
    }

    cgdb_request_data_free(request);
}

static void cgdb_generic_status_returning_cb(void * const data,
                                             int const status,
                                             uint64_t const id,
                                             void * const cb_data)
{
    int result = status;
    cgdb_request_data * request = cb_data;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(cb_data != NULL);

    (void) data;

    CGUTILS_ASSERT(request->cb != NULL);
    result = (*((cgdb_status_returning_cb * )request->cb))(result,
                                                           id,
                                                           request->cb_data);

    if (result != 0 &&
        result != status)
    {
        CGUTILS_WARN("Callback returned: %d", result);
    }

    cgdb_request_data_free(request);
}

static int cgdb_generic_cursor_discard_cb(cgdb_backend_cursor * cursor,
                                          int status,
                                          bool has_error,
                                          char const * error_str,
                                          size_t rows_count,
                                          cgutils_vector * rows,
                                          void * cb_data)
{
    int result = status;

    CGUTILS_ASSERT(cb_data != NULL);
    cgdb_request_data * request = cb_data;
    CGUTILS_ASSERT(request->cb != NULL);

    if (status == 0 &&
        has_error == false)
    {
        CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

        if (rows_count == 1)
        {
        }
        else
        {
            result = ENOENT;

            if (rows_count > 0)
            {
                result = EIO;
                CGUTILS_WARN("More than one row returned [%zu], this is bad: %d",
                             rows_count,
                             result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Backend returned an error: %d (%s)",
                      status,
                      error_str != NULL ? error_str : "");
    }

    if (rows != NULL)
    {
        cgutils_vector_deep_free(&rows, &cgdb_row_delete);
    }

    result = (*((cgdb_status_cb * )request->cb))(result,
                                                 request->cb_data);

    cgdb_backend_cursor_destroy(request->data->backend, cursor);

    cgdb_request_data_free(request);

    return result;
}

static int cgdb_get_inode_cb(cgdb_backend_cursor * cursor,
                             int status,
                             bool has_error,
                             char const * error_str,
                             size_t rows_count,
                             cgutils_vector * rows,
                             void * cb_data)
{
    int result = status;

    cgdb_inode * inode = NULL;

    CGUTILS_ASSERT(cb_data != NULL);
    cgdb_request_data * request = cb_data;
    CGUTILS_ASSERT(request->cb != NULL);

    if (status == 0 &&
        has_error == false)
    {
        CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

        if (rows_count == 1)
        {
            void * tmp_row = NULL;

            result = cgutils_vector_get(rows,
                                        0,
                                        &tmp_row);

            if (result == 0)
            {
                cgdb_row const * const row = tmp_row;

                CGUTILS_ASSERT(row != NULL);

                result = cgdb_get_inode_from_row(row,
                                                 &inode);

                if (result == 0)
                {
                    CGUTILS_ASSERT(inode != NULL);
                }
                else
                {
                    CGUTILS_ERROR("Unable to convert database response to inode: %d",
                                  result);
                }

                if (result != 0)
                {
                    cgdb_inode_free(inode), inode = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting row: %d", result);
            }
        }
        else
        {
            result = ENOENT;

            if (rows_count > 0)
            {
                result = EIO;
                CGUTILS_WARN("More than one row returned [%zu], this is bad: %d", rows_count, result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Backend returned an error: %d (%s)", status, error_str != NULL ? error_str : "");
    }

    if (rows != NULL)
    {
        cgutils_vector_deep_free(&rows, &cgdb_row_delete);
    }

    result = (*((cgdb_inode_getter_cb * )request->cb))(result,
                                                       inode,
                                                       request->cb_data);

    cgdb_backend_cursor_destroy(request->data->backend, cursor);

    cgdb_request_data_free(request);

    return result;
}

static int cgdb_get_status_and_inode_cb(cgdb_backend_cursor * cursor,
                                        int status,
                                        bool has_error,
                                        char const * error_str,
                                        size_t rows_count,
                                        cgutils_vector * rows,
                                        void * cb_data)
{
    int result = status;

    cgdb_inode * inode = NULL;

    CGUTILS_ASSERT(cb_data != NULL);
    cgdb_request_data * request = cb_data;
    CGUTILS_ASSERT(request->cb != NULL);

    if (status == 0 &&
        has_error == false)
    {
        CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

        if (rows_count == 1)
        {
            void * tmp_row = NULL;

            result = cgutils_vector_get(rows,
                                        0,
                                        &tmp_row);

            if (result == 0)
            {
                cgdb_row const * const row = tmp_row;
                uint16_t return_value = 0;

                CGUTILS_ASSERT(row != NULL);


                result = cgdb_row_get_field_value_as_uint16(row,
                                                            "return_code",
                                                            &return_value);

                if (result == 0)
                {
                    if (return_value == 0)
                    {
                        result = cgdb_get_inode_from_row(row,
                                                         &inode);

                        if (result == 0)
                        {
                            CGUTILS_ASSERT(inode != NULL);
                        }
                        else
                        {
                            CGUTILS_ERROR("Unable to convert database response to inode: %d",
                                          result);
                        }

                        if (result != 0)
                        {
                            cgdb_inode_free(inode), inode = NULL;
                        }
                    }
                    else
                    {
                        CGUTILS_ASSERT(request->cb != NULL);

                        result = (*((cgdb_inode_getter_cb * )request->cb))((int) return_value,
                                                                           NULL,
                                                                           request->cb_data);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error getting the return value: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting row: %d", result);
            }
        }
        else
        {
            result = ENOENT;

            if (rows_count > 0)
            {
                result = EIO;
                CGUTILS_WARN("More than one row returned [%zu], this is bad: %d", rows_count, result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Backend returned an error: %d (%s)", status, error_str != NULL ? error_str : "");
    }

    if (rows != NULL)
    {
        cgutils_vector_deep_free(&rows, &cgdb_row_delete);
    }

    result = (*((cgdb_inode_getter_cb * )request->cb))(result,
                                                       inode,
                                                       request->cb_data);

    cgdb_backend_cursor_destroy(request->data->backend, cursor);

    cgdb_request_data_free(request);

    return result;
}

static int cgdb_get_entry_cb(cgdb_backend_cursor * cursor,
                             int status,
                             bool has_error,
                             char const * error_str,
                             size_t rows_count,
                             cgutils_vector * rows,
                             void * cb_data)
{
    int result = status;

    cgdb_entry * entry = NULL;

    CGUTILS_ASSERT(cb_data != NULL);
    cgdb_request_data * request = cb_data;
    CGUTILS_ASSERT(request->cb != NULL);

    if (status == 0 && has_error == false)
    {
        CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

        if (rows_count == 1)
        {
            void * tmp_row = NULL;

            result = cgutils_vector_get(rows,
                                        0,
                                        &tmp_row);

            if (result == 0)
            {
                cgdb_row const * const row = tmp_row;

                CGUTILS_ASSERT(row != NULL);

                result = cgdb_get_entry_from_row(row, &entry);

                if (result == 0)
                {
                    CGUTILS_ASSERT(entry != NULL);
                }
                else
                {
                    CGUTILS_ERROR("Unable to convert database response to entry: %d",
                                  result);
                }

                if (result != 0)
                {
                    cgdb_entry_free(entry), entry = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting row: %d", result);
            }
        }
        else
        {
            result = ENOENT;

            if (rows_count > 0)
            {
                result = EIO;
                CGUTILS_WARN("More than one row returned [%zu], this is bad: %d", rows_count, result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Backend returned an error: %d (%s)", status, error_str != NULL ? error_str : "");
    }

    if (rows != NULL)
    {
        cgutils_vector_deep_free(&rows, &cgdb_row_delete);
    }

    result = (*((cgdb_entry_getter_cb *) request->cb))(result,
                                                       entry,
                                                       request->cb_data);

    cgdb_backend_cursor_destroy(request->data->backend, cursor);

    cgdb_request_data_free(request);

    return result;
}

static int cgdb_generic_count_cb(cgdb_backend_cursor * cursor,
                                 int status,
                                 bool has_error,
                                 char const * error_str,
                                 size_t rows_count,
                                 cgutils_vector * rows,
                                 void * cb_data)
{
    int result = status;
    size_t count = 0;

    CGUTILS_ASSERT(cb_data != NULL);
    cgdb_request_data * request = cb_data;
    CGUTILS_ASSERT(request->cb != NULL);

    if (status == 0 && has_error == false)
    {
        CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

        if (rows_count == 1)
        {
            cgdb_row const * row = NULL;

            result = cgutils_vector_get(rows,
                                        0,
                                        (void*) &row);

            if (result == 0)
            {
                uint64_t count_tmp = 0;
                CGUTILS_ASSERT(row != NULL);

                result = cgdb_row_get_field_value_as_uint64(row,
                                                            "count",
                                                            &count_tmp);

                if (result == 0)
                {
                    if (count_tmp < SIZE_MAX)
                    {
                        count = (size_t) count_tmp;
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error getting count field from row: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting row 0 on %zu: %d",
                              rows_count,
                              result);
            }
        }
        else
        {
            result = EIO;

            if (rows_count > 0)
            {
                result = EIO;
                CGUTILS_WARN("More than one row returned [%zu], this is bad: %d", rows_count, result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Backend returned an error: %d (%s)", status, error_str != NULL ? error_str : "");
    }

    if (rows != NULL)
    {
        cgutils_vector_deep_free(&rows, &cgdb_row_delete);
    }

    result = (*((cgdb_count_cb * )request->cb))(result,
                                                count,
                                                request->cb_data);

    cgdb_backend_cursor_destroy(request->data->backend, cursor);

    cgdb_request_data_free(request);

    return result;
}

static int cgdb_get_inode_instances_cb(cgdb_backend_cursor * cursor,
                                       int status,
                                       bool has_error,
                                       char const * error_str,
                                       size_t rows_count,
                                       cgutils_vector * rows,
                                       void * cb_data)
{
    int result = status;

    cgutils_llist * instances = NULL;

    CGUTILS_ASSERT(cb_data != NULL);
    cgdb_request_data * request = cb_data;
    CGUTILS_ASSERT(request->cb != NULL);

    if (status == 0 && has_error == false)
    {
        result = cgutils_llist_create(&instances);

        if (result == 0)
        {
            CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

            if (rows_count > 0)
            {
                for (size_t idx = 0;
                     result == 0 &&
                         idx < rows_count;
                     idx++)
                {
                    cgdb_row const * row = NULL;

                    result = cgutils_vector_get(rows,
                                                idx,
                                                (void *) &row);

                    if (result == 0)
                    {
                        cgdb_inode_instance * instance = NULL;

                        result = cgdb_get_inode_instance_from_row(row, &instance);

                        if (result == 0)
                        {
                            result = cgutils_llist_insert(instances, instance);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error inserting instance into list: %d", result);
                                cgdb_inode_instance_free(instance), instance = NULL;
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Unable to get instance from database row: %d", result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error getting row %zu on %zu: %d",
                                      idx,
                                      rows_count,
                                      result);
                    }
                }

                if (result != 0)
                {
                    cgutils_llist_free(&instances, &cgdb_inode_instance_delete);
                }
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating instances list: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Backend returned an error: %d (%s)", status,
                      error_str != NULL ? error_str : "");
    }

    if (rows != NULL)
    {
        cgutils_vector_deep_free(&rows, &cgdb_row_delete);
    }

    result = (*((cgdb_multiple_inode_instances_getter_cb *)request->cb))(result,
                                                                         instances,
                                                                         request->cb_data);

    cgdb_backend_cursor_destroy(request->data->backend, cursor);

    cgdb_request_data_free(request);

    return result;
}

int cgdb_get_entry_info_recursive(cgdb_data * const db,
                                  uint64_t const fs_id,
                                  char const * const name,
                                  cgdb_entry_getter_cb *cb,
                                  void * cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        name != NULL &&
        cb != NULL)
    {
        cgdb_request_data * request = NULL;
        cgdb_param entry_params[cgdb_backend_statement_params_count[cgdb_backend_statement_get_entry_info_recursive]];
        size_t const entry_params_size = sizeof entry_params / sizeof *entry_params;
        size_t param_idx = 0;

        cgdb_param_array_init(entry_params, entry_params_size);

        cgdb_param_set_uint64(entry_params, &param_idx, &fs_id);
        cgdb_param_set_immutable_string(entry_params, &param_idx, name);

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_find(db->backend,
                                       cgdb_backend_statement_get_entry_info_recursive,
                                       entry_params,
                                       entry_params_size,
                                       CGDB_LIMIT_NONE,
                                       CGDB_SKIP_NONE,
                                       &cgdb_get_entry_cb,
                                       request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in find operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }

        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_get_inode_info(cgdb_data * const db,
                        uint64_t const fs_id,
                        uint64_t const ino,
                        cgdb_inode_getter_cb * const cb,
                        void * const cb_data)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(db != NULL &&
                        fs_id > 0 &&
                        ino >= 1 &&
                        cb != NULL))
    {
        cgdb_request_data * request = NULL;
        cgdb_param entry_params[cgdb_backend_statement_params_count[cgdb_backend_statement_get_inode_info]];
        size_t const entry_params_size = sizeof entry_params / sizeof *entry_params;
        size_t param_idx = 0;

        cgdb_param_array_init(entry_params, entry_params_size);
        cgdb_param_set_uint64(entry_params, &param_idx, &ino);
        cgdb_param_set_uint64(entry_params, &param_idx, &fs_id);

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_find(db->backend,
                                       cgdb_backend_statement_get_inode_info,
                                       entry_params,
                                       /* -1 for limit */
                                       entry_params_size - 1,
                                       1,
                                       CGDB_SKIP_NONE,
                                       &cgdb_get_inode_cb,
                                       request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in find operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }

        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_get_inode_info_updating_times_and_writers(cgdb_data * const db,
                                                   uint64_t const fs_id,
                                                   uint64_t const ino,
                                                   uint64_t const atime_min,
                                                   uint64_t const ctime_min,
                                                   uint64_t const last_usage,
                                                   bool const increase_writers,
                                                   cgdb_inode_getter_cb * const cb,
                                                   void * const cb_data)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(db != NULL &&
                        fs_id > 0 &&
                        ino >= 1 &&
                        cb != NULL))
    {
        cgdb_request_data * request = NULL;
        cgdb_param entry_params[cgdb_backend_statement_params_count[cgdb_backend_statement_get_inode_info_updating_times_and_writers]];
        size_t const entry_params_size = sizeof entry_params / sizeof *entry_params;
        size_t param_idx = 0;

        cgdb_param_array_init(entry_params, entry_params_size);
        cgdb_param_set_uint64(entry_params, &param_idx, &fs_id);
        cgdb_param_set_uint64(entry_params, &param_idx, &ino);
        cgdb_param_set_uint64(entry_params, &param_idx, &atime_min);
        cgdb_param_set_uint64(entry_params, &param_idx, &ctime_min);
        cgdb_param_set_uint64(entry_params, &param_idx, &last_usage);
        cgdb_param_set_boolean(entry_params, &param_idx, &increase_writers);

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_exec_rows_stmt(db->backend,
                                                 cgdb_backend_statement_get_inode_info_updating_times_and_writers,
                                                 entry_params,
                                                 entry_params_size,
                                                 &cgdb_get_inode_cb,
                                                 request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in rows statement operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }

        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_get_child_inode_info(cgdb_data * const db,
                              uint64_t const fs_id,
                              uint64_t const parent_ino,
                              char const * const child_name,
                              cgdb_inode_getter_cb * const cb,
                              void * const cb_data)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(db != NULL &&
                        fs_id > 0 &&
                        parent_ino >= 1 &&
                        child_name != NULL &&
                        cb != NULL))
    {
        cgdb_request_data * request = NULL;
        cgdb_param entry_params[cgdb_backend_statement_params_count[cgdb_backend_statement_get_child_inode_info]];
        size_t const entry_params_size = sizeof entry_params / sizeof *entry_params;
        size_t param_idx = 0;

        cgdb_param_array_init(entry_params, entry_params_size);
        cgdb_param_set_uint64(entry_params, &param_idx, &fs_id);
        cgdb_param_set_uint64(entry_params, &param_idx, &parent_ino);
        cgdb_param_set_immutable_string(entry_params, &param_idx, child_name);

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_find(db->backend,
                                       cgdb_backend_statement_get_child_inode_info,
                                       entry_params,
                                       /* -1 for limit */
                                       entry_params_size - 1,
                                       1,
                                       CGDB_SKIP_NONE,
                                       &cgdb_get_inode_cb,
                                       request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in find operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_get_or_create_root_inode(cgdb_data * const db,
                                  uint64_t const fs_id,
                                  cgdb_inode const * const inode,
                                  cgdb_inode_getter_cb * const cb,
                                  void * const cb_data)
{
    int result  = 0;
    cgdb_request_data * request = NULL;
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(inode != NULL);
    CGUTILS_ASSERT(cb != NULL);

    result = cgdb_request_data_init(db,
                                    cb,
                                    cb_data,
                                    &request);

    if (COMPILER_LIKELY(result == 0))
    {
        request->inode = inode;

        static cgdb_backend_statement const statement = cgdb_backend_statement_get_or_create_root_inode;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        uint64_t const uid = (uint64_t) inode->st.st_uid;
        uint64_t const gid = (uint64_t) inode->st.st_gid;
        uint64_t const mode = (uint64_t) inode->st.st_mode;
        uint64_t const size = (uint64_t) inode->st.st_size;
        uint64_t const atime = (uint64_t) inode->st.st_atime;
        uint64_t const ctime_temp = (uint64_t) inode->st.st_ctime;
        uint64_t const mtime = (uint64_t) inode->st.st_mtime;
        uint64_t const last_usage = (uint64_t) inode->last_usage;
        uint64_t const last_modification = (uint64_t) inode->last_modification;
        uint64_t const nlink = (uint64_t) inode->st.st_nlink;
        uint16_t const digest_type = (uint16_t) inode->digest_type;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &uid);
        cgdb_param_set_uint64(params, &param_idx, &gid);
        cgdb_param_set_uint64(params, &param_idx, &mode);
        cgdb_param_set_uint64(params, &param_idx, &size);
        cgdb_param_set_uint64(params, &param_idx, &atime);
        cgdb_param_set_uint64(params, &param_idx, &ctime_temp);
        cgdb_param_set_uint64(params, &param_idx, &mtime);
        cgdb_param_set_uint64(params, &param_idx, &last_usage);
        cgdb_param_set_uint64(params, &param_idx, &last_modification);
        cgdb_param_set_uint64(params, &param_idx, &nlink);
        cgdb_param_set_uint64(params, &param_idx, &(inode->dirty_writers));
        cgdb_param_set_boolean(params, &param_idx, &(inode->in_cache));
        cgdb_param_set_uint16(params, &param_idx, &digest_type);
        cgdb_param_set_immutable_string(params, &param_idx, inode->digest != NULL ? inode->digest : "");

        result = cgdb_backend_exec_rows_stmt(db->backend,
                                             statement,
                                             params,
                                             params_size,
                                             &cgdb_get_inode_cb,
                                             request);

        if (result != 0)
        {
            CGUTILS_ERROR("Error in stmt operation: %d", result);
            cgdb_request_data_free(request), request = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Unable to allocate request data: %d", result);
    }

    return result;
}

static int cgdb_return_code_and_inode_number_cb(cgdb_backend_cursor * cursor,
                                                int status,
                                                bool has_error,
                                                char const * error_str,
                                                size_t rows_count,
                                                cgutils_vector * rows,
                                                void * cb_data)
{
    int result = status;
    cgdb_request_data * request = cb_data;
    CGUTILS_ASSERT(cb_data != NULL);

    if (result == 0 &&
        has_error == false)
    {
        CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

        if (rows_count == 1)
        {
            void * tmp_row = NULL;

            result = cgutils_vector_get(rows,
                                        0,
                                        &tmp_row);

            if (result == 0)
            {
                cgdb_row const * const row = tmp_row;
                uint16_t return_value = 0;

                CGUTILS_ASSERT(row != NULL);

                result = cgdb_row_get_field_value_as_uint16(row,
                                                            "return_code",
                                                            &return_value);

                if (result == 0)
                {
                    if (return_value == 0)
                    {
                        uint64_t new_inode_number = 0;

                        result = cgdb_row_get_field_value_as_uint64(row,
                                                                    "inode_number",
                                                                    &(new_inode_number));

                        if (result == 0)
                        {
                            CGUTILS_ASSERT(request->cb != NULL);

                            int res  = (*((cgdb_status_returning_cb * )request->cb))(0,
                                                                                     new_inode_number,
                                                                                     request->cb_data);

                            if (res != 0)
                            {
                                CGUTILS_WARN("Callback returned: %d", res);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error getting inode number: %d", result);
                        }
                    }
                    else
                    {
                        CGUTILS_ASSERT(request->cb != NULL);

                        int res  = (*((cgdb_status_returning_cb *) request->cb))((int) return_value,
                                                                                 0,
                                                                                 request->cb_data);

                        if (res != 0 &&
                            res != (int) return_value)
                        {
                            CGUTILS_WARN("Callback returned: %d", res);
                        }
                    }

                }
                else
                {
                    CGUTILS_ERROR("Error getting the return value: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting row: %d", result);
            }
        }
        else
        {
            result = ENOENT;

            if (rows_count > 0)
            {
                result = EIO;
                CGUTILS_WARN("More than one row returned [%zu], this is bad: %d", rows_count, result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Backend returned an error: %d (%s)", status, error_str != NULL ? error_str : "");
    }

    if (rows != NULL)
    {
        cgutils_vector_deep_free(&rows, &cgdb_row_delete);
    }

    if (result != 0)
    {
        CGUTILS_ASSERT(request->cb != NULL);
        result = (*((cgdb_status_returning_cb * )request->cb))(result,
                                                               0,
                                                               request->cb_data);

        if (result != 0 &&
            result != status)
        {
            CGUTILS_WARN("Callback returned: %d", result);
        }
    }

    cgdb_backend_cursor_destroy(request->data->backend,
                                cursor);

    cgdb_request_data_free(request);

    return result;
}

static int cgdb_return_code_inode_number_and_deletion_status_cb(cgdb_backend_cursor * cursor,
                                                                int status,
                                                                bool has_error,
                                                                char const * error_str,
                                                                size_t rows_count,
                                                                cgutils_vector * rows,
                                                                void * cb_data)
{
    int result = status;
    cgdb_request_data * request = cb_data;
    CGUTILS_ASSERT(cb_data != NULL);

    if (result == 0 &&
        has_error == false)
    {
        CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

        if (rows_count == 1)
        {
            void * tmp_row = NULL;

            result = cgutils_vector_get(rows,
                                        0,
                                        &tmp_row);

            if (result == 0)
            {
                cgdb_row const * const row = tmp_row;
                uint16_t return_value = 0;

                CGUTILS_ASSERT(row != NULL);

                result = cgdb_row_get_field_value_as_uint16(row,
                                                            "return_code",
                                                            &return_value);

                if (result == 0)
                {
                    if (return_value == 0)
                    {
                        uint64_t new_inode_number = 0;

                        result = cgdb_row_get_field_value_as_uint64(row,
                                                                    "inode_number",
                                                                    &(new_inode_number));

                        if (result == 0)
                        {
                            bool deleted = false;

                            result = cgdb_row_get_field_value_as_boolean(row,
                                                                         "deleted",
                                                                         &deleted);

                            if (result == 0)
                            {
                                CGUTILS_ASSERT(request->cb != NULL);

                                int res  = (*((cgdb_status_returning_id_and_deletion_status_cb * )request->cb))(0,
                                                                                                                new_inode_number,
                                                                                                                deleted,
                                                                                                                request->cb_data);

                                if (res != 0)
                                {
                                    CGUTILS_WARN("Callback returned: %d",
                                                 res);
                                }
                            }
                            else
                            {
                                CGUTILS_ERROR("Error getting deletion status: %d",
                                              result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error getting inode number: %d",
                                          result);
                        }
                    }
                    else
                    {
                        CGUTILS_ASSERT(request->cb != NULL);

                        int res  = (*((cgdb_status_returning_id_and_deletion_status_cb * )request->cb))((int) return_value,
                                                                                                        0,
                                                                                                        false,
                                                                                                        request->cb_data);

                        if (res != 0)
                        {
                            CGUTILS_WARN("Callback returned: %d",
                                         res);
                        }
                    }

                }
                else
                {
                    CGUTILS_ERROR("Error getting the return value: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting row: %d", result);
            }
        }
        else
        {
            result = ENOENT;

            if (rows_count > 0)
            {
                result = EIO;
                CGUTILS_WARN("More than one row returned [%zu], this is bad: %d", rows_count, result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Backend returned an error: %d (%s)", status, error_str != NULL ? error_str : "");
    }

    if (rows != NULL)
    {
        cgutils_vector_deep_free(&rows, &cgdb_row_delete);
    }

    if (result != 0)
    {
        CGUTILS_ASSERT(request->cb != NULL);
        result = (*((cgdb_status_returning_id_and_deletion_status_cb *)request->cb))(result,
                                                                                     0,
                                                                                     false,
                                                                                     request->cb_data);

        if (result != 0 &&
            result != status)
        {
            CGUTILS_WARN("Callback returned: %d", result);
        }
    }

    cgdb_backend_cursor_destroy(request->data->backend,
                                cursor);

    cgdb_request_data_free(request);

    return result;
}

/* If the entry has a entry number, refuse to add it.
   If there is an inode number, refuse to add it.
   Otherwise, add the inode and entry */
int cgdb_add_new_entry_and_inode(cgdb_data * const db,
                                 uint64_t const parent_ino,
                                 cgdb_entry const * const entry,
                                 cgdb_status_returning_cb * const cb,
                                 void * const cb_data)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(db != NULL &&
                        entry != NULL &&
                        entry->entry_id == 0 &&
                        entry->inode.inode_number == 0))
    {
        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (COMPILER_LIKELY(result == 0))
        {
            request->entry = (cgdb_entry * ) entry;

            static cgdb_backend_statement const statement = cgdb_backend_statement_add_low_inode_and_entry;
            cgdb_param params[cgdb_backend_statement_params_count[statement]];
            size_t const params_size = sizeof params / sizeof *params;
            size_t param_idx = 0;

            cgdb_inode const * const inode = &(entry->inode);

            uint64_t const uid = (uint64_t) inode->st.st_uid;
            uint64_t const gid = (uint64_t) inode->st.st_gid;
            uint64_t const mode = (uint64_t) inode->st.st_mode;
            uint64_t const size = (uint64_t) inode->st.st_size;
            uint64_t const atime = (uint64_t) inode->st.st_atime;
            uint64_t const ctime_temp = (uint64_t) inode->st.st_ctime;
            uint64_t const mtime = (uint64_t) inode->st.st_mtime;
            uint64_t const last_usage = (uint64_t) inode->last_usage;
            uint64_t const last_modification = (uint64_t) inode->last_modification;
            uint64_t const nlink = (uint64_t) inode->st.st_nlink;
            uint16_t const digest_type = (uint16_t) inode->digest_type;
            uint16_t const type = entry->type;

            cgdb_param_array_init(params, params_size);

            cgdb_param_set_uint64(params, &param_idx, &(entry->fs_id));
            cgdb_param_set_uint64(params, &param_idx, &(parent_ino));
            cgdb_param_set_immutable_string(params, &param_idx, entry->name);
            cgdb_param_set_uint16(params, &param_idx, &type);
            cgdb_param_set_immutable_string(params, &param_idx, entry->link_to != NULL ? entry->link_to : "");
            cgdb_param_set_uint64(params, &param_idx, &uid);
            cgdb_param_set_uint64(params, &param_idx, &gid);
            cgdb_param_set_uint64(params, &param_idx, &mode);
            cgdb_param_set_uint64(params, &param_idx, &size);
            cgdb_param_set_uint64(params, &param_idx, &atime);
            cgdb_param_set_uint64(params, &param_idx, &ctime_temp);
            cgdb_param_set_uint64(params, &param_idx, &mtime);
            cgdb_param_set_uint64(params, &param_idx, &last_usage);
            cgdb_param_set_uint64(params, &param_idx, &last_modification);
            cgdb_param_set_uint64(params, &param_idx, &nlink);
            cgdb_param_set_uint64(params, &param_idx, &(inode->dirty_writers));
            cgdb_param_set_boolean(params, &param_idx, &(inode->in_cache));
            cgdb_param_set_uint16(params, &param_idx, &digest_type);
            cgdb_param_set_immutable_string(params, &param_idx, inode->digest != NULL ? inode->digest : "");

            result = cgdb_backend_exec_rows_stmt(db->backend,
                                                 statement,
                                                 params,
                                                 params_size,
                                                 &cgdb_return_code_and_inode_number_cb,
                                                 request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in insert operation: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_release_inode(cgdb_data * const db,
                       uint64_t const fs_id,
                       uint64_t const ino,
                       uint64_t const min_mtime,
                       uint64_t const ctime_local,
                       uint64_t const last_modification,
                       size_t const size,
                       uint8_t const old_status,
                       uint8_t const new_status,
                       cgdb_status_cb * const cb,
                       void * const cb_data)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(db != NULL))
    {
        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db,
                                        cb,
                                        cb_data,
                                        &request);

        if (COMPILER_LIKELY(result == 0))
        {
            static cgdb_backend_statement const statement = cgdb_backend_statement_release_low_inode;
            cgdb_param params[cgdb_backend_statement_params_count[statement]];
            size_t const params_size = sizeof params / sizeof *params;
            size_t param_idx = 0;

            uint64_t const size_temp = (uint64_t) size;
            uint16_t const old_status_temp = (uint16_t) old_status;
            uint16_t const new_status_temp = (uint16_t) new_status;

            cgdb_param_array_init(params, params_size);

            cgdb_param_set_uint64(params, &param_idx, &(fs_id));
            cgdb_param_set_uint64(params, &param_idx, &(ino));
            cgdb_param_set_uint64(params, &param_idx, &min_mtime);
            cgdb_param_set_uint64(params, &param_idx, &ctime_local);
            cgdb_param_set_uint64(params, &param_idx, &last_modification);
            cgdb_param_set_uint64(params, &param_idx, &size_temp);
            cgdb_param_set_uint16(params, &param_idx, &old_status_temp);
            cgdb_param_set_uint16(params, &param_idx, &new_status_temp);

            result = cgdb_backend_exec_stmt(db->backend,
                                            statement,
                                            params,
                                            params_size,
                                            &cgdb_generic_status_cb,
                                            request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in update operation: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_update_inode_counter(cgdb_data * const db,
                              uint64_t const fs_id,
                              uint64_t const inode_number,
                              uint32_t const value,
                              bool const increment,
                              cgdb_status_cb * const cb,
                              void * const cb_data)
{
    int result  = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        inode_number > 0)
    {
        static cgdb_backend_statement const inc_statement = cgdb_backend_statement_update_inode_counter_inc;
        static cgdb_backend_statement const dec_statement = cgdb_backend_statement_update_inode_counter_dec;
        cgdb_param inc_params[cgdb_backend_statement_params_count[inc_statement]];
        cgdb_param dec_params[cgdb_backend_statement_params_count[dec_statement]];
        size_t const inc_params_size = sizeof inc_params / sizeof *inc_params;
        size_t const dec_params_size = sizeof dec_params / sizeof *dec_params;
        size_t param_idx = 0;
        int64_t inc_value;

        if (increment == true)
        {
            inc_value = (int32_t) value;

            cgdb_param_array_init(inc_params, inc_params_size);

            cgdb_param_set_int64(inc_params, &param_idx, &inc_value);
            cgdb_param_set_uint64(inc_params, &param_idx, &fs_id);
            cgdb_param_set_uint64(inc_params, &param_idx, &inode_number);
        }
        else
        {
            inc_value = -(int32_t) value;

            cgdb_param_array_init(dec_params, dec_params_size);

            cgdb_param_set_int64(dec_params, &param_idx, &inc_value);
            cgdb_param_set_uint64(dec_params, &param_idx, &fs_id);
            cgdb_param_set_uint64(dec_params, &param_idx, &inode_number);
        }

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_increment(db->backend,
                                            (increment == true) ?
                                            inc_statement :
                                            dec_statement,
                                            (increment == true) ?
                                            inc_params :
                                            dec_params,
                                            (increment == true) ?
                                            inc_params_size :
                                            dec_params_size,
                                            &cgdb_generic_status_cb,
                                            request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in increment operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_update_inode_cache_status(cgdb_data * const db,
                                   uint64_t const fs_id,
                                   uint64_t const inode_number,
                                   bool const in_cache,
                                   cgdb_status_cb * const cb,
                                   void * const cb_data)
{
    int result  = EINVAL;

    if (db != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_update_inode_cache_status;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_boolean(params, &param_idx, &in_cache);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);
        cgdb_param_set_uint64(params, &param_idx, &fs_id);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_update(db->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in update operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }

        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_update_inode_cache_status_and_increase_dirty_writers(cgdb_data * const db,
                                                              uint64_t const fs_id,
                                                              uint64_t const inode_number,
                                                              bool const in_cache,
                                                              cgdb_status_cb * const cb,
                                                              void * const cb_data)
{
    int result  = EINVAL;

    if (db != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_update_inode_cache_status_and_increase_writers;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_boolean(params, &param_idx, &in_cache);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);
        cgdb_param_set_uint64(params, &param_idx, &fs_id);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_update(db->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in update operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }

        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_update_inode_digest(cgdb_data * const db,
                             uint64_t const fs_id,
                             uint64_t const inode_number,
                             uint8_t const digest_type,
                             char const * const digest,
                             size_t const digest_size,
                             uint64_t const mtime_max,
                             cgdb_status_cb * const cb,
                             void * const cb_data)
{
    int result  = EINVAL;

    (void) digest_size;

    if (db != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_update_inode_digest;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        uint16_t const temp = digest_type;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint16(params, &param_idx, &temp);
        cgdb_param_set_immutable_string(params, &param_idx, digest);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);
        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &mtime_max);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_update(db->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in update operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_add_inode_instance(cgdb_data * const db,
                            uint64_t const fs_id,
                            uint64_t const instance_id,
                            uint64_t const inode_number,
                            char const * const id_in_instance,
                            uint8_t const status,
                            cgdb_status_cb * const cb,
                            void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        instance_id > 0 &&
        inode_number > 0 &&
        id_in_instance != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_add_inode_instance;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        uint16_t const status_temp = status;
        uint64_t const upload_time = (uint64_t) 0;
        bool const state = false;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &instance_id);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);
        /* NOT immutable, see cg_storage_filesystem_file_create_handler() */
        cgdb_param_set_string(params, &param_idx, id_in_instance);
        cgdb_param_set_uint16(params, &param_idx, &status_temp);
        cgdb_param_set_uint64(params, &param_idx, &upload_time);
        /* uploading */
        cgdb_param_set_boolean(params, &param_idx, &state);
        /* deleting */
        cgdb_param_set_boolean(params, &param_idx, &state);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_insert(db->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in insert operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_remove_inode_instance(cgdb_data * const db,
                               uint64_t const fs_id,
                               uint64_t const instance_id,
                               uint64_t const inode_number,
                               char const * const id_in_instance,
                               uint8_t const status,
                               cgdb_status_cb * const cb,
                               void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        instance_id > 0 &&
        inode_number > 0 &&
        id_in_instance != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_remove_inode_instance;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        uint16_t const status_temp = status;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &instance_id);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);
        cgdb_param_set_immutable_string(params, &param_idx, id_in_instance);
        cgdb_param_set_uint16(params, &param_idx, &status_temp);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_remove(db->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in remove operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_update_inode_instance_set_uploading(cgdb_data * const db,
                                             uint64_t const fs_id,
                                             uint64_t const instance_id,
                                             uint64_t const inode_number,
                                             char const * const id_in_instance,
                                             cgdb_status_cb * const cb,
                                             void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        instance_id > 0 &&
        inode_number > 0 &&
        id_in_instance != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_update_inode_instance_set_uploading;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;
        uint64_t const upload_time = (uint64_t) time(NULL);
        bool const uploading = true;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_boolean(params, &param_idx, &uploading);
        cgdb_param_set_uint64(params, &param_idx, &upload_time);
        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &instance_id);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);
        cgdb_param_set_immutable_string(params, &param_idx, id_in_instance);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_update(db->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in update operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_update_inode_instance_set_uploading_done(cgdb_data * const db,
                                                  uint64_t const fs_id,
                                                  uint64_t const instance_id,
                                                  uint64_t const inode_number,
                                                  char const * const id_in_instance,
                                                  bool const error,
                                                  cgdb_status_cb * const cb,
                                                  void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        instance_id > 0 &&
        inode_number > 0 &&
        id_in_instance != NULL)
    {
        static cgdb_backend_statement const done_statement = cgdb_backend_statement_update_inode_instance_set_uploading_done;
        static cgdb_backend_statement const failed_statement = cgdb_backend_statement_update_inode_instance_set_uploading_failed;
        cgdb_param done_params[cgdb_backend_statement_params_count[done_statement]];
        size_t const done_params_size = sizeof done_params / sizeof *done_params;
        cgdb_param failed_params[cgdb_backend_statement_params_count[failed_statement]];
        size_t const failed_params_size = sizeof failed_params / sizeof *failed_params;
        size_t param_idx = 0;

        bool const state_true = true;
        bool const state_false = false;

        if (error == false)
        {
            cgdb_param_array_init(done_params, done_params_size);

            /* set uploading to false */
            cgdb_param_set_boolean(done_params, &param_idx, &state_false);
            cgdb_param_set_uint64(done_params, &param_idx, &fs_id);
            cgdb_param_set_uint64(done_params, &param_idx, &instance_id);
            cgdb_param_set_uint64(done_params, &param_idx, &inode_number);
            cgdb_param_set_immutable_string(done_params, &param_idx, id_in_instance);
            /* uploading was true */
            cgdb_param_set_boolean(done_params, &param_idx, &state_true);
        }
        else
        {
            cgdb_param_array_init(failed_params, failed_params_size);

            /* set uploading to false */
            cgdb_param_set_boolean(failed_params, &param_idx, &state_false);
            cgdb_param_set_uint64(failed_params, &param_idx, &fs_id);
            cgdb_param_set_uint64(failed_params, &param_idx, &instance_id);
            cgdb_param_set_uint64(failed_params, &param_idx, &inode_number);
            cgdb_param_set_string(failed_params, &param_idx, id_in_instance);
            /* uploading was true */
            cgdb_param_set_boolean(failed_params, &param_idx, &state_true);
        }

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_update(db->backend,
                                         error == false ?
                                         done_statement :
                                         failed_statement,
                                         error == false ?
                                         done_params :
                                         failed_params,
                                         error == false ?
                                         done_params_size :
                                         failed_params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in update operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_update_inode_instance_clear_dirty_status(cgdb_data * const db,
                                                  uint64_t const fs_id,
                                                  uint64_t const instance_id,
                                                  uint64_t const inode_number,
                                                  char const * const id_in_instance,
                                                  uint8_t const old_status,
                                                  uint8_t const new_status,
                                                  bool const compressed,
                                                  bool const encrypted,
                                                  cgdb_status_cb * const cb,
                                                  void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        instance_id > 0 &&
        inode_number > 0 &&
        id_in_instance != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_update_inode_instance_clear_dirty_status;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        uint16_t const old_status_temp = (uint16_t) old_status;
        uint64_t const dirty_writers = 0;
        uint16_t const status_temp = (uint16_t) new_status;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint16(params, &param_idx, &status_temp);
        cgdb_param_set_boolean(params,&param_idx, &compressed);
        cgdb_param_set_boolean(params, &param_idx, &encrypted);
        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &instance_id);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);
        cgdb_param_set_immutable_string(params, &param_idx, id_in_instance);
        cgdb_param_set_uint16(params, &param_idx, &old_status_temp);
        cgdb_param_set_uint64(params, &param_idx, &dirty_writers);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_update(db->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in update operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_update_inode_instance_set_delete_in_progress(cgdb_data * const db,
                                                      uint64_t const fs_id,
                                                      uint64_t const instance_id,
                                                      uint64_t const inode_number,
                                                      char const * const id_in_instance,
                                                      cgdb_status_cb * const cb,
                                                      void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        instance_id > 0 &&
        inode_number > 0 &&
        id_in_instance != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_update_inode_instance_set_delete_in_progress;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        bool const deleting = true;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_boolean(params, &param_idx, &deleting);
        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &instance_id);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);
        cgdb_param_set_immutable_string(params,&param_idx, id_in_instance);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_update(db->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in update operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
   }

    return result;
}

int cgdb_update_inode_instance_set_deleting_failed(cgdb_data * const db,
                                                   uint64_t const fs_id,
                                                   uint64_t const instance_id,
                                                   uint64_t const inode_number,
                                                   char const * const id_in_instance,
                                                   cgdb_status_cb * const cb,
                                                   void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        instance_id > 0 &&
        inode_number > 0 &&
        id_in_instance != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_update_inode_instance_set_deleting_failed;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;
        bool const deleting_before = true;
        bool const deleting_after = false;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_boolean(params, &param_idx, &deleting_after);
        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &instance_id);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);
        cgdb_param_set_immutable_string(params,&param_idx, id_in_instance);
        cgdb_param_set_boolean(params, &param_idx, &deleting_before);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_update(db->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in update operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_set_inode_and_all_inodes_instances_dirty(cgdb_data * const db,
                                                  uint64_t const fs_id,
                                                  uint64_t const inode_number,
                                                  time_t const min_mtime,
                                                  time_t const min_ctime,
                                                  time_t const last_modification,
                                                  uint8_t const old_status,
                                                  uint8_t const new_status,
                                                  cgdb_status_cb * const cb,
                                                  void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        inode_number > 0)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_update_set_inode_and_all_inodes_instances_dirty;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        uint16_t const status_temp = new_status;
        uint16_t const old_status_temp = old_status;
        uint64_t const min_mtime_temp = (uint64_t) min_mtime;
        uint64_t const min_ctime_temp = (uint64_t) min_ctime;
        uint64_t const last_modification_temp = (uint64_t) last_modification;

        cgdb_param_array_init(params, params_size);
        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);
        cgdb_param_set_uint64(params, &param_idx, &min_mtime_temp);
        cgdb_param_set_uint64(params, &param_idx, &min_ctime_temp);
        cgdb_param_set_uint64(params, &param_idx, &last_modification_temp);
        cgdb_param_set_uint16(params, &param_idx, &old_status_temp);
        cgdb_param_set_uint16(params, &param_idx, &status_temp);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_update(db->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in update operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_get_inode_valid_instances(cgdb_data * const db,
                                   uint64_t const fs_id,
                                   uint64_t const inode_number,
                                   uint8_t const old_status_not_equal_to,
                                   cgdb_multiple_inode_instances_getter_cb * cb,
                                   void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        inode_number > 0 &&
        cb != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_get_valid_inode_instances;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        uint16_t const old_status_temp = old_status_not_equal_to;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);
        cgdb_param_set_uint16(params, &param_idx, &old_status_temp);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_find(db->backend,
                                       statement,
                                       params,
                                       params_size,
                                       CGDB_LIMIT_NONE,
                                       CGDB_SKIP_NONE,
                                       &cgdb_get_inode_instances_cb,
                                       request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in find operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_get_inode_instances(cgdb_data * const db,
                             uint64_t const fs_id,
                             uint64_t const inode_number,
                             cgdb_multiple_inode_instances_getter_cb * cb,
                             void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        inode_number > 0 &&
        cb != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_get_inode_instances;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_find(db->backend,
                                       statement,
                                       params,
                                       params_size,
                                       CGDB_LIMIT_NONE,
                                       CGDB_SKIP_NONE,
                                       &cgdb_get_inode_instances_cb,
                                       request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in find operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

static int cgdb_get_directory_entries_cb(cgdb_backend_cursor * cursor,
                                         int status,
                                         bool has_error,
                                         char const * error_str,
                                         size_t rows_count,
                                         cgutils_vector * rows,
                                         void * cb_data)
{
    int result = status;
    (void) rows_count;

    CGUTILS_ASSERT(cb_data != NULL);
    cgdb_request_data * request = cb_data;

    cgutils_vector * entries = NULL;

    if (result == 0 &&
        has_error == false)
    {
        CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

        if (rows_count > 0)
        {
            result = cgutils_vector_init(rows_count,
                                         &entries);

            if (result == 0)
            {
                for (size_t idx = 0;
                     result == 0 &&
                         idx < rows_count;
                     idx++)
                {
                    cgdb_row * row = NULL;

                    result = cgutils_vector_get(rows,
                                                idx,
                                                (void *) &row);

                    if (result == 0)
                    {
                        CGUTILS_ASSERT(row != NULL);

                        cgdb_entry * entry = NULL;

                        result = cgdb_get_entry_from_row(row, &entry);

                        if (result == 0)
                        {
                            result = cgutils_vector_add(entries,
                                                        entry);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error inserting entry in vector: %d", result);
                                cgdb_entry_free(entry), entry = NULL;
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error getting entry from row: %d", result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error getting row %zu on %zu: %d",
                                      idx,
                                      rows_count,
                                      result);
                    }
                }
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error creating vector: %d", result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Backend returned an error: %d (%s)",
                      status,
                      error_str != NULL ? error_str : "");
    }

    if (rows != NULL)
    {
        cgutils_vector_deep_free(&rows, &cgdb_row_delete);
    }

    if (result != 0 &&
        entries != NULL)
    {
        cgutils_vector_deep_free(&entries, &cgdb_entry_delete);
    }

    result = (*((cgdb_multiple_entries_getter_cb * )(request->cb)))(result,
                                                                    entries != NULL ? cgutils_vector_count(entries) : 0,
                                                                    entries,
                                                                    request->cb_data);

    cgdb_backend_cursor_destroy(request->data->backend,
                                cursor);

    cgdb_request_data_free(request);

    return result;
}

int cgdb_get_inode_entries(cgdb_data * const db,
                           uint64_t const fs_id,
                           uint64_t const directory_inode_id,
                           cgdb_multiple_entries_getter_cb * const cb,
                           void * const cb_data)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(db != NULL &&
                        fs_id > 0 &&
                        directory_inode_id > 0 &&
                        cb != NULL))
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_get_inode_entries;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &directory_inode_id);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            request->entry_id = directory_inode_id;

            result = cgdb_backend_find(db->backend,
                                       statement,
                                       params,
                                       params_size,
                                       CGDB_LIMIT_NONE,
                                       CGDB_SKIP_NONE,
                                       &cgdb_get_directory_entries_cb,
                                       request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in find operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_get_inode_instances_by_status(cgdb_data * const db,
                                       uint8_t const status,
                                       cgdb_limit_type const limit,
                                       cgdb_skip_type const skip,
                                       cgdb_multiple_inode_instances_getter_cb * const cb,
                                       void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL && cb != NULL && limit > 0)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_get_inode_instances_by_status;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        uint16_t const status_temp = status;
        static char const order_by_str[] = "upload_failures ASC, inode_mtime";

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint16(params, &param_idx, &status_temp);
        cgdb_param_set_immutable_string(params, &param_idx, order_by_str);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_find(db->backend,
                                       statement,
                                       params,
                                       /* limit and skip are omitted */
                                       params_size - 2,
                                       limit,
                                       skip,
                                       &cgdb_get_inode_instances_cb,
                                       request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in find operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_clear_inodes_instances_flags(cgdb_data * const db,
                                      cgdb_status_cb * const cb,
                                      void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_update_clear_inodes_instances_flags;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        bool const state = false;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_boolean(params, &param_idx, &state);
        cgdb_param_set_boolean(params, &param_idx, &state);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_update(db->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in update operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_clear_inodes_dirty_writers(cgdb_data * const db,
                                    cgdb_status_cb * const cb,
                                    void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_update_clear_inodes_dirty_writers;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        uint64_t const dirty_writers = 0;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &dirty_writers);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_update(db->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in update operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

static int cgdb_get_entries_cb(cgdb_backend_cursor * cursor,
                               int status,
                               bool has_error,
                               char const * error_str,
                               size_t rows_count,
                               cgutils_vector * rows,
                               void * cb_data)
{
    int result = status;

    cgutils_vector * entries = NULL;

    CGUTILS_ASSERT(cb_data != NULL);
    cgdb_request_data * request = cb_data;
    CGUTILS_ASSERT(request->cb != NULL);

    if (status == 0 &&
        has_error == false)
    {
        CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

        if (rows_count > 0)
        {
            result = cgutils_vector_init(rows_count,
                                         &entries);

            if (result == 0)
            {
                for (size_t idx = 0;
                     result == 0 &&
                         idx < rows_count;
                     idx++)
                {
                    cgdb_row const * row = NULL;

                    result = cgutils_vector_get(rows,
                                                idx,
                                                (void *) &row);

                    if (result == 0)
                    {
                        cgdb_entry * entry = NULL;

                        result = cgdb_get_entry_from_row(row, &entry);

                        if (result == 0)
                        {
                            result = cgutils_vector_add(entries,
                                                        entry);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error inserting entry into vector: %d", result);
                                cgdb_entry_free(entry), entry = NULL;
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Unable to get entry from database row: %d", result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error getting rows %zu on %zu: %d",
                                      idx,
                                      rows_count,
                                      result);
                    }
                }

                if (result != 0)
                {
                    cgutils_vector_deep_free(&entries,
                                             &cgdb_entry_delete);
                }
            }
            else
            {
                CGUTILS_ERROR("Error creating entries vector: %d", result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Backend returned an error: %d (%s)", status, error_str != NULL ? error_str : "");
    }

    if (rows != NULL)
    {
        cgutils_vector_deep_free(&rows, &cgdb_row_delete);
    }

    result = (*((cgdb_multiple_entries_getter_cb *)request->cb))(result,
                                                                 entries != NULL ? cgutils_vector_count(entries) : 0,
                                                                 entries,
                                                                 request->cb_data);

    cgdb_backend_cursor_destroy(request->data->backend, cursor);

    cgdb_request_data_free(request);

    return result;
}

int cgdb_get_not_dirty_entries_by_type_size_last_usage_cached(cgdb_data * const db,
                                                              uint64_t const fs_id,
                                                              cgdb_entry_type const type,
                                                              size_t const min_size,
                                                              uint64_t const max_usage,
                                                              uint16_t const dirty_status,
                                                              cgdb_limit_type const limit,
                                                              cgdb_skip_type const skip,
                                                              cgdb_multiple_entries_getter_cb * const cb,
                                                              void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL && cb != NULL
#if (SIZE_MAX >= UINT64_MAX)
        && min_size <= UINT64_MAX
#endif /* (SIZE_MAX >= UINT64_MAX) */
        )
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_get_not_dirty_entries_by_type_size_last_usage;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        uint64_t const min_size_temp = (uint64_t) min_size;
        uint16_t const type_temp = (uint16_t) type;
        uint16_t const status_temp = dirty_status;
        bool const in_cache = true;
        static char const order_by_str[] = "mtime";

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint16(params, &param_idx, &type_temp);
        cgdb_param_set_uint64(params, &param_idx, &min_size_temp);
        cgdb_param_set_uint64(params, &param_idx, &max_usage);
        cgdb_param_set_boolean(params, &param_idx, &in_cache);
        cgdb_param_set_uint16(params, &param_idx, &status_temp);
        cgdb_param_set_immutable_string(params, &param_idx, order_by_str);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db,
                                        cb,
                                        cb_data,
                                        &request);

        if (result == 0)
        {
            result = cgdb_backend_find(db->backend,
                                       statement,
                                       params,
                                       /* limit and skip are omitted */
                                       params_size - 2,
                                       limit,
                                       skip,
                                       &cgdb_get_entries_cb,
                                       request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in find operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

void cgdb_inode_clean(cgdb_inode * this)
{
    if (COMPILER_LIKELY(this != NULL))
    {
        this->st = (struct stat) { 0 };

        CGUTILS_FREE(this->digest);

        this->inode_number = 0;
        this->dirty_writers = 0;
        this->in_cache = false;
    }
}

void cgdb_inode_free(cgdb_inode * this)
{
    if (this != NULL)
    {
        cgdb_inode_clean(this);

        CGUTILS_FREE(this);
    }
}

void cgdb_inode_instance_free(cgdb_inode_instance * this)
{
    if (this != NULL)
    {
        CGUTILS_FREE(this->id_in_instance);

        this->uploading = false;
        this->deleting = false;
        this->compressed = false;
        this->encrypted = false;

        this->fs_id = 0;
        this->instance_id = 0;
        this->inode_number = 0;
        this->upload_time = 0;
        this->inode_mtime = 0;
        this->inode_dirty_writers = 0;
        this->inode_size = 0;
        this->status = 0;

        CGUTILS_FREE(this);
    }
}

void cgdb_entry_clean(cgdb_entry * this)
{
    if (COMPILER_LIKELY(this != NULL))
    {
        cgdb_inode_clean(&this->inode);

        CGUTILS_FREE(this->name);
        CGUTILS_FREE(this->link_to);

        this->fs_id = 0;
        this->entry_id = 0;
    }
}

void cgdb_entry_free(cgdb_entry * this)
{
    if (this != NULL)
    {
        cgdb_entry_clean(this);

        CGUTILS_FREE(this);
    }
}

void cgdb_delayed_expunge_entry_free(cgdb_delayed_expunge_entry * this)
{
    if (this != NULL)
    {
        cgdb_entry_clean(&(this->entry));

        CGUTILS_FREE(this->full_path);

        this->deletion_time = 0;
        this->delete_after = 0;
        CGUTILS_FREE(this);
    }
}

int cgdb_sync_get_filesystem_id(cgdb_data * const db,
                                char const * const name,
                                uint64_t * const id)
{
    int result = EINVAL;

    if (db != NULL &&
        name != NULL &&
        id != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_get_filesystem_id;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_immutable_string(params, &param_idx, name);

        cgdb_backend_cursor * cursor = NULL;
        size_t rows_count = 0;
        cgutils_vector * rows = NULL;

        result = cgdb_backend_exec_rows_stmt_sync(db->backend,
                                                  statement,
                                                  params,
                                                  params_size,
                                                  CGDB_LIMIT_NONE,
                                                  CGDB_SKIP_NONE,
                                                  &cursor,
                                                  &rows_count,
                                                  &rows);

        if (result == 0)
        {
            CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

            if (rows_count == 1)
            {
                /* we have to extract the resulting id */
                cgdb_row const * row = NULL;

                result = cgutils_vector_get(rows,
                                            0,
                                            (void *) &row);

                if (result == 0)
                {
                    CGUTILS_ASSERT(row != NULL);

                    result = cgdb_row_get_field_value_as_uint64(row,
                                                                "fs_id",
                                                                id);
                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error getting resulting ID: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error getting row 0 on %zu: %d",
                                  rows_count,
                                  result);
                }
            }
            else if (rows_count == 0)
            {
                result = EIO;
                CGUTILS_ERROR("Error, statement returned no row: %d", result);
            }
            else
            {
                result = EIO;
                CGUTILS_ERROR("Error, statement returned %zu rows, expecting one: %d",
                              rows_count,
                              result);
            }

            if (rows != NULL)
            {
                cgutils_vector_deep_free(&rows, &cgdb_row_delete);
            }

            cgdb_backend_cursor_destroy(db->backend, cursor), cursor = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error in sync find operation: %d", result);
        }
    }

    return result;
}

int cgdb_sync_get_instance_id(cgdb_data * const db,
                              char const * const name,
                              uint64_t * const id)
{
    int result = EINVAL;

    if (db != NULL &&
        name != NULL &&
        id != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_get_instance_id;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_immutable_string(params, &param_idx, name);

        cgdb_backend_cursor * cursor = NULL;
        size_t rows_count = 0;
        cgutils_vector * rows = NULL;

        result = cgdb_backend_exec_rows_stmt_sync(db->backend,
                                                  statement,
                                                  params,
                                                  params_size,
                                                  CGDB_LIMIT_NONE,
                                                  CGDB_SKIP_NONE,
                                                  &cursor,
                                                  &rows_count,
                                                  &rows);

        if (result == 0)
        {
            CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

            if (rows_count == 1)
            {
                /* we have to extract the resulting id */
                cgdb_row const * row = NULL;

                result = cgutils_vector_get(rows,
                                            0,
                                            (void *) &row);

                if (result == 0)
                {
                    CGUTILS_ASSERT(row != NULL);

                    result = cgdb_row_get_field_value_as_uint64(row,
                                                                "instance_id",
                                                                id);
                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error getting resulting ID: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error getting row 0 on %zu: %d",
                                  rows_count,
                                  result);
                }
            }
            else if (rows_count == 0)
            {
                result = EIO;
                CGUTILS_ERROR("Error, statement returned no row: %d", result);
            }
            else
            {
                result = EIO;
                CGUTILS_ERROR("Error, statement returned %zu rows, expecting one: %d",
                              rows_count,
                              result);
            }

            if (rows != NULL)
            {
                cgutils_vector_deep_free(&rows, &cgdb_row_delete);
            }

            cgdb_backend_cursor_destroy(db->backend, cursor), cursor = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error in sync find operation: %d", result);
        }
    }

    return result;
}

int cgdb_remove_delayed_expunge_entry(cgdb_data * const db,
                                      uint64_t const fs_id,
                                      uint64_t const inode_number,
                                      cgdb_status_cb * const cb,
                                      void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        inode_number > 0)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_remove_delayed_expunge_entry;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db,
                                        cb,
                                        cb_data,
                                        &request);

        if (result == 0)
        {
            result = cgdb_backend_remove(request->data->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in delete operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_count_inode_instances_by_status(cgdb_data * const db,
                                         uint64_t const fs_id,
                                         uint64_t const inode_number,
                                         uint8_t const status,
                                         cgdb_count_cb * const cb,
                                         void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        inode_number > 0)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_get_inode_instances_count_by_status;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        uint16_t const status_temp = status;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);
        cgdb_param_set_uint16(params, &param_idx, &status_temp);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db,
                                        cb,
                                        cb_data,
                                        &request);

        if (result == 0)
        {
            result = cgdb_backend_find(db->backend,
                                       statement,
                                       params,
                                       params_size,
                                       CGDB_LIMIT_NONE,
                                       CGDB_SKIP_NONE,
                                       &cgdb_generic_count_cb,
                                       request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in find operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_add_delayed_expunge_entry(cgdb_data * const db,
                                   uint64_t const fs_id,
                                   uint64_t const inode_number,
                                   char const * const path,
                                   uint64_t const delete_after,
                                   uint64_t const deletion_time,
                                   cgdb_status_cb * const cb,
                                   void * const cb_data)
{
    int result  = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        inode_number > 0 &&
        path != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_add_delayed_expunge_entry;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &inode_number);
        cgdb_param_set_immutable_string(params, &param_idx, path);
        cgdb_param_set_uint64(params, &param_idx, &delete_after);
        cgdb_param_set_uint64(params, &param_idx, &deletion_time);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_insert(db->backend,
                                         statement,
                                         params,
                                         params_size,
                                         &cgdb_generic_status_cb,
                                         request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

static int cgdb_get_delayed_expunge_entries_cb(cgdb_backend_cursor * cursor,
                                               int status,
                                               bool has_error,
                                               char const * error_str,
                                               size_t rows_count,
                                               cgutils_vector * rows,
                                               void * cb_data)
{
    int result = status;
    (void) rows_count;

    CGUTILS_ASSERT(cb_data != NULL);
    cgdb_request_data * request = cb_data;

    /* llist of cgdb_delayed_expunge_entry * */
    cgutils_llist * entries = NULL;

    if (result == 0 &&
        has_error == false)
    {
        result = cgutils_llist_create(&entries);

        if (result == 0)
        {
            CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

            for (size_t idx = 0;
                 result == 0 &&
                     idx < rows_count;
                 idx++)
            {
                cgdb_row const * row = NULL;

                result = cgutils_vector_get(rows,
                                            idx,
                                            (void *) &row);

                if (result == 0)
                {
                    CGUTILS_ASSERT(row != NULL);

                    cgdb_delayed_expunge_entry * entry = NULL;

                    result = cgdb_get_delayed_expunge_entry_from_row(row,
                                                                     &entry);

                    if (result == 0)
                    {
                        result = cgutils_llist_insert(entries,
                                                      entry);

                        if (result != 0)
                        {
                            CGUTILS_ERROR("Error inserting entry in list: %d", result);
                            cgdb_delayed_expunge_entry_free(entry), entry = NULL;
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error getting entry from row: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error getting row %zu on %zu: %d",
                                  idx,
                                  rows_count,
                                  result);
                }
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error creating llist: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Backend returned an error: %d (%s)",
                      status,
                      error_str != NULL ? error_str : "");
    }

    if (rows != NULL)
    {
        cgutils_vector_deep_free(&rows, &cgdb_row_delete);
    }

    if (result != 0 &&
        entries != NULL)
    {
        cgutils_llist_free(&entries, &cgdb_delayed_expunge_entry_delete);
    }

    result = (*((cgdb_multiple_delayed_expunge_entries_getter_cb * )(request->cb)))(result,
                                                                                    entries,
                                                                                    request->cb_data);

    cgdb_backend_cursor_destroy(request->data->backend,
                                cursor);

    cgdb_request_data_free(request);

    return result;
}

int cgdb_get_delayed_expunge_entries(cgdb_data * const db,
                                     uint64_t const fs_id,
                                     char const * const path,
                                     uint64_t const deleted_after,
                                     cgdb_multiple_delayed_expunge_entries_getter_cb * const cb,
                                     void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        path != NULL &&
        cb != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_get_delayed_expunge_entries;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        static char const order_by_str[] = "full_path, deletion_time";

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_immutable_string(params, &param_idx, path);
        cgdb_param_set_uint64(params, &param_idx, &deleted_after);
        cgdb_param_set_immutable_string(params, &param_idx, order_by_str);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_find(db->backend,
                                       statement,
                                       params,
                                       params_size,
                                       CGDB_LIMIT_NONE,
                                       CGDB_SKIP_NONE,
                                       &cgdb_get_delayed_expunge_entries_cb,
                                       request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in find operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_get_expired_delayed_expunge_entries(cgdb_data * const db,
                                             uint64_t const fs_id,
                                             cgdb_multiple_delayed_expunge_entries_getter_cb * const cb,
                                             void * const cb_data)
{
    int result = EINVAL;

    if (db != NULL &&
        fs_id > 0 &&
        cb != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_get_expired_delayed_expunge_entries;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        uint64_t const delete_after = (uint64_t) time(NULL);

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &fs_id);
        cgdb_param_set_uint64(params, &param_idx, &delete_after);

        cgdb_request_data * request = NULL;

        result = cgdb_request_data_init(db, cb, cb_data, &request);

        if (result == 0)
        {
            result = cgdb_backend_find(db->backend,
                                       statement,
                                       params,
                                       params_size,
                                       CGDB_LIMIT_NONE,
                                       CGDB_SKIP_NONE,
                                       &cgdb_get_delayed_expunge_entries_cb,
                                       request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error in find operation: %d", result);
                cgdb_request_data_free(request), request = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to allocate request data: %d", result);
        }
    }

    return result;
}

int cgdb_sync_get_version(cgdb_data * const db,
                          char ** version)
{
    int result = EINVAL;

    if (db != NULL &&
        version != NULL)
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_get_version;

        cgdb_backend_cursor * cursor = NULL;
        size_t rows_count = 0;
        cgutils_vector * rows = NULL;

        result = cgdb_backend_exec_rows_stmt_sync(db->backend,
                                                  statement,
                                                  NULL,
                                                  0,
                                                  CGDB_LIMIT_NONE,
                                                  CGDB_SKIP_NONE,
                                                  &cursor,
                                                  &rows_count,
                                                  &rows);

        if (result == 0)
        {
            CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

            if (rows_count == 1)
            {
                /* we have to extract the resulting id */
                cgdb_row const * row = NULL;

                result = cgutils_vector_get(rows,
                                            0,
                                            (void *) &row);

                if (result == 0)
                {
                    CGUTILS_ASSERT(row != NULL);

                    result = cgdb_row_get_field_value_as_string(row,
                                                                "version",
                                                                version);
                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error getting resulting version: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error getting row 0 on %zu: %d",
                                  rows_count,
                                  result);
                }
            }
            else if (rows_count == 0)
            {
                result = EIO;
                CGUTILS_ERROR("Error, statement returned no row: %d", result);
            }
            else
            {
                result = EIO;
                CGUTILS_ERROR("Error, statement returned %zu rows, expecting one: %d",
                              rows_count,
                              result);
            }

            if (rows != NULL)
            {
                cgutils_vector_deep_free(&rows, &cgdb_row_delete);
            }

            cgdb_backend_cursor_destroy(db->backend, cursor), cursor = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error in sync find operation: %d", result);
        }
    }

    return result;
}

int cgdb_sync_test_credentials(cgdb_data * const db,
                               char ** const error_str_out)
{
    int result = EINVAL;

    if (db != NULL)
    {
        result = cgdb_backend_sync_test_credentials(db->backend,
                                                    error_str_out);
    }

    return result;
}

int cgdb_add_person(cgdb_data * const db,
                    uint64_t const id,
                    char const * const name,
                    uint64_t const age,
                    cgdb_status_returning_cb * const cb,
                    void * const cb_data)
{
    int result = 0;
    cgdb_request_data * request = NULL;
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(name != NULL);
    CGUTILS_ASSERT(cb != NULL);

    result = cgdb_request_data_init(db,
                                    cb,
                                    cb_data,
                                    &request);

    if (COMPILER_LIKELY(result == 0))
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_add_person;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &id);
        cgdb_param_set_immutable_string(params, &param_idx, name);
        cgdb_param_set_uint64(params, &param_idx, &age);

        result = cgdb_backend_insert_returning(db->backend,
                                               statement,
                                               params,
                                               params_size,
                                               &cgdb_generic_status_returning_cb,
                                               request);

        if (result != 0)
        {
            CGUTILS_ERROR("Error in insert operation: %d", result);
            cgdb_request_data_free(request), request = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Unable to allocate request data: %d", result);
    }

    return result;
}

int cgdb_get_person(cgdb_data * const db,
                    uint64_t const id,
                    cgdb_status_cb * const cb,
                    void * const cb_data)
{
    int result = 0;
    cgdb_request_data * request = NULL;
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(cb != NULL);

    result = cgdb_request_data_init(db,
                                    cb,
                                    cb_data,
                                    &request);

    if (COMPILER_LIKELY(result == 0))
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_get_person;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &id);

        result = cgdb_backend_find(db->backend,
                                   statement,
                                   params,
                                   params_size,
                                   CGDB_LIMIT_NONE,
                                   CGDB_SKIP_NONE,
                                   &cgdb_generic_cursor_discard_cb,
                                   request);

        if (result != 0)
        {
            CGUTILS_ERROR("Error in find operation: %d", result);
            cgdb_request_data_free(request), request = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Unable to allocate request data: %d", result);
    }

    return result;
}

int cgdb_remove_person(cgdb_data * const db,
                       uint64_t const id,
                       cgdb_status_cb * const cb,
                       void * const cb_data)
{
    int result = 0;
    cgdb_request_data * request = NULL;
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(cb != NULL);

    result = cgdb_request_data_init(db,
                                    cb,
                                    cb_data,
                                    &request);

    if (COMPILER_LIKELY(result == 0))
    {
        static cgdb_backend_statement const statement = cgdb_backend_statement_remove_person;
        cgdb_param params[cgdb_backend_statement_params_count[statement]];
        size_t const params_size = sizeof params / sizeof *params;
        size_t param_idx = 0;

        cgdb_param_array_init(params, params_size);

        cgdb_param_set_uint64(params, &param_idx, &id);

        result = cgdb_backend_remove(db->backend,
                                     statement,
                                     params,
                                     params_size,
                                     &cgdb_generic_status_cb,
                                     request);

        if (result != 0)
        {
            CGUTILS_ERROR("Error in remove operation: %d", result);
            cgdb_request_data_free(request), request = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Unable to allocate request data: %d", result);
    }

    return result;
}

int cgdb_update_inode_attributes(cgdb_data * const db,
                                 uint64_t const fs_id,
                                 uint64_t const inode_number,
                                 mode_t const mode,
                                 uid_t const uid,
                                 gid_t const gid,
                                 uint64_t const atime,
                                 uint64_t const mtime,
                                 size_t const file_size,
                                 cgdb_status_cb * const cb,
                                 void * const cb_data)
{
    int result = 0;

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(inode_number > 0);
    static cgdb_backend_statement const statement = cgdb_backend_statement_update_inode_attributes;
    cgdb_param params[cgdb_backend_statement_params_count[statement]];
    size_t const params_size = sizeof params / sizeof *params;
    size_t param_idx = 0;
    uint64_t const mode_temp = mode;
    uint64_t const uid_temp = uid;
    uint64_t const gid_temp = gid;
    uint64_t const ctime_temp = (uint64_t) time(NULL);
    COMPILER_STATIC_ASSERT(sizeof(uint64_t) >= sizeof (size_t),
                           "uint64_t is smaller then size_t, we might overflow");

    uint64_t const file_size_temp = (uint64_t) file_size;

    cgdb_param_array_init(params, params_size);

    cgdb_param_set_uint64(params, &param_idx, &mode_temp);
    cgdb_param_set_uint64(params, &param_idx, &uid_temp);
    cgdb_param_set_uint64(params, &param_idx, &gid_temp);
    cgdb_param_set_uint64(params, &param_idx, &atime);
    cgdb_param_set_uint64(params, &param_idx, &mtime);
    cgdb_param_set_uint64(params, &param_idx, &ctime_temp);
    cgdb_param_set_uint64(params, &param_idx, &file_size_temp);
    cgdb_param_set_uint64(params, &param_idx, &fs_id);
    cgdb_param_set_uint64(params, &param_idx, &inode_number);

    cgdb_request_data * request = NULL;

    result = cgdb_request_data_init(db, cb, cb_data, &request);

    if (result == 0)
    {
        result = cgdb_backend_update(db->backend,
                                     statement,
                                     params,
                                     params_size,
                                     &cgdb_generic_status_cb,
                                     request);

        if (result != 0)
        {
            CGUTILS_ERROR("Error in update operation: %d", result);
            cgdb_request_data_free(request), request = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Unable to allocate request data: %d", result);
    }

    return result;
}

int cgdb_remove_dir_entry(cgdb_data * const db,
                          uint64_t const fs_id,
                          uint64_t const parent_inode_number,
                          char const * const entry_name,
                          cgdb_status_returning_cb * const cb,
                          void * const cb_data)
{
    int result = 0;

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(parent_inode_number > 0);
    static cgdb_backend_statement const statement = cgdb_backend_statement_remove_dir_entry;
    cgdb_param params[cgdb_backend_statement_params_count[statement]];
    size_t const params_size = sizeof params / sizeof *params;
    size_t param_idx = 0;

    uint64_t const ctime_temp = (uint64_t) time(NULL);

    cgdb_param_array_init(params, params_size);

    cgdb_param_set_uint64(params, &param_idx, &fs_id);
    cgdb_param_set_uint64(params, &param_idx, &parent_inode_number);
    cgdb_param_set_immutable_string(params, &param_idx, entry_name);
    cgdb_param_set_uint64(params, &param_idx, &ctime_temp);

    cgdb_request_data * request = NULL;

    result = cgdb_request_data_init(db, cb, cb_data, &request);

    if (result == 0)
    {
        result = cgdb_backend_exec_rows_stmt(db->backend,
                                             statement,
                                             params,
                                             params_size,
                                             &cgdb_return_code_and_inode_number_cb,
                                             request);

        if (result != 0)
        {
            CGUTILS_ERROR("Error in exec stmt operation: %d", result);
            cgdb_request_data_free(request), request = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Unable to allocate request data: %d", result);
    }

    return result;
}

int cgdb_remove_inode_entry(cgdb_data * const db,
                            uint64_t const fs_id,
                            uint64_t const parent_inode_number,
                            char const * const entry_name,
                            cgdb_status_returning_id_and_deletion_status_cb * const cb,
                            void * const cb_data)
{
    int result = 0;

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(parent_inode_number > 0);
    static cgdb_backend_statement const statement = cgdb_backend_statement_remove_inode_entry;
    cgdb_param params[cgdb_backend_statement_params_count[statement]];
    size_t const params_size = sizeof params / sizeof *params;
    size_t param_idx = 0;

    uint64_t const ctime_temp = (uint64_t) time(NULL);

    cgdb_param_array_init(params, params_size);

    cgdb_param_set_uint64(params, &param_idx, &fs_id);
    cgdb_param_set_uint64(params, &param_idx, &parent_inode_number);
    cgdb_param_set_immutable_string(params, &param_idx, entry_name);
    cgdb_param_set_uint64(params, &param_idx, &ctime_temp);

    cgdb_request_data * request = NULL;

    result = cgdb_request_data_init(db, cb, cb_data, &request);

    if (result == 0)
    {
        result = cgdb_backend_exec_rows_stmt(db->backend,
                                             statement,
                                             params,
                                             params_size,
                                             &cgdb_return_code_inode_number_and_deletion_status_cb,
                                             request);

        if (result != 0)
        {
            CGUTILS_ERROR("Error in exec stmt operation: %d", result);
            cgdb_request_data_free(request), request = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Unable to allocate request data: %d", result);
    }

    return result;
}

static int cgdb_rename_inode_entry_status_cb(cgdb_backend_cursor * cursor,
                                             int status,
                                             bool has_error,
                                             char const * error_str,
                                             size_t rows_count,
                                             cgutils_vector * rows,
                                             void * cb_data)
{
    int result = status;
    cgdb_request_data * request = cb_data;
    CGUTILS_ASSERT(cb_data != NULL);

    if (result == 0 &&
        has_error == false)
    {
        CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

        if (rows_count == 1)
        {
            void * tmp_row = NULL;

            result = cgutils_vector_get(rows,
                                        0,
                                        &tmp_row);

            if (result == 0)
            {
                cgdb_row const * const row = tmp_row;
                uint16_t return_value = 0;

                CGUTILS_ASSERT(row != NULL);

                result = cgdb_row_get_field_value_as_uint16(row,
                                                            "return_code",
                                                            &return_value);

                if (result == 0)
                {
                    if (return_value == 0)
                    {
                        uint64_t renamed_inode_number = 0;

                        result = cgdb_row_get_field_value_as_uint64(row,
                                                                    "renamed_inode_number",
                                                                    &(renamed_inode_number));

                        if (result == 0)
                        {
                            uint64_t deleted_inode_number = 0;

                            result = cgdb_row_get_field_value_as_uint64(row,
                                                                        "deleted_inode_number",
                                                                        &(deleted_inode_number));

                            if (result == 0)
                            {
                                bool deleted = false;

                                result = cgdb_row_get_field_value_as_boolean(row,
                                                                             "deleted",
                                                                             &deleted);

                                if (result == 0)
                                {
                                    CGUTILS_ASSERT(request->cb != NULL);

                                    int res  = (*((cgdb_inode_rename_status_cb *)request->cb))(0,
                                                                                               renamed_inode_number,
                                                                                               deleted_inode_number,
                                                                                               deleted,
                                                                                               request->cb_data);

                                    if (res != 0)
                                    {
                                        CGUTILS_WARN("Callback returned: %d",
                                                     res);
                                    }
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error getting deletion status: %d",
                                                  result);
                                }
                            }
                            else
                            {
                                CGUTILS_ERROR("Error getting deleted inode number: %d",
                                              result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error getting renamed inode number: %d",
                                          result);
                        }
                    }
                    else
                    {
                        CGUTILS_ASSERT(request->cb != NULL);

                        int res  = (*((cgdb_inode_rename_status_cb * )request->cb))((int) return_value,
                                                                                    0,
                                                                                    0,
                                                                                    false,
                                                                                    request->cb_data);

                        if (res != 0)
                        {
                            CGUTILS_WARN("Callback returned: %d",
                                         res);
                        }
                    }

                }
                else
                {
                    CGUTILS_ERROR("Error getting the return value: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting row: %d", result);
            }
        }
        else
        {
            result = ENOENT;

            if (rows_count > 0)
            {
                result = EIO;
                CGUTILS_WARN("More than one row returned [%zu], this is bad: %d", rows_count, result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Backend returned an error: %d (%s)", status, error_str != NULL ? error_str : "");
    }

    if (rows != NULL)
    {
        cgutils_vector_deep_free(&rows, &cgdb_row_delete);
    }

    if (result != 0)
    {
        CGUTILS_ASSERT(request->cb != NULL);
        result = (*((cgdb_inode_rename_status_cb *)request->cb))(result,
                                                                 0,
                                                                 0,
                                                                 false,
                                                                 request->cb_data);

        if (result != 0 &&
            result != status)
        {
            CGUTILS_WARN("Callback returned: %d", result);
        }
    }

    cgdb_backend_cursor_destroy(request->data->backend,
                                cursor);

    cgdb_request_data_free(request);

    return result;
}

int cgdb_rename_inode(cgdb_data * const db,
                      uint64_t const fs_id,
                      uint64_t const old_parent_inode_number,
                      char const * const old_name,
                      uint64_t const new_parent_inode_number,
                      char const * const new_name,
                      cgdb_inode_rename_status_cb * const cb,
                      void * const cb_data)
{
    int result = 0;

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(old_parent_inode_number > 0);
    CGUTILS_ASSERT(new_parent_inode_number > 0);
    CGUTILS_ASSERT(old_name != NULL);
    CGUTILS_ASSERT(new_name != NULL);
    CGUTILS_ASSERT(cb != NULL);
    static cgdb_backend_statement const statement = cgdb_backend_statement_rename_inode_entry;
    cgdb_param params[cgdb_backend_statement_params_count[statement]];
    size_t const params_size = sizeof params / sizeof *params;
    size_t param_idx = 0;

    uint64_t const ctime_temp = (uint64_t) time(NULL);

    cgdb_param_array_init(params, params_size);

    cgdb_param_set_uint64(params, &param_idx, &fs_id);
    cgdb_param_set_uint64(params, &param_idx, &old_parent_inode_number);
    cgdb_param_set_immutable_string(params, &param_idx, old_name);
    cgdb_param_set_uint64(params, &param_idx, &new_parent_inode_number);
    cgdb_param_set_immutable_string(params, &param_idx, new_name);
    cgdb_param_set_uint64(params, &param_idx, &ctime_temp);

    cgdb_request_data * request = NULL;

    result = cgdb_request_data_init(db, cb, cb_data, &request);

    if (result == 0)
    {
        result = cgdb_backend_exec_rows_stmt(db->backend,
                                             statement,
                                             params,
                                             params_size,
                                             &cgdb_rename_inode_entry_status_cb,
                                             request);

        if (result != 0)
        {
            CGUTILS_ERROR("Error in exec stmt operation: %d", result);
            cgdb_request_data_free(request), request = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Unable to allocate request data: %d", result);
    }

    return result;
}

int cgdb_add_hardlink(cgdb_data * const db,
                      uint64_t const fs_id,
                      uint64_t const existing_ino,
                      uint64_t const new_parent_ino,
                      char const * const new_name,
                      uint8_t const type,
                      cgdb_inode_getter_cb * const cb,
                      void * const cb_data)
{
    int result = 0;

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(existing_ino > 0);
    CGUTILS_ASSERT(new_parent_ino > 0);
    CGUTILS_ASSERT(new_name != NULL);
    CGUTILS_ASSERT(cb != NULL);

    static cgdb_backend_statement const statement = cgdb_backend_statement_add_hardlink;
    cgdb_param params[cgdb_backend_statement_params_count[statement]];
    size_t const params_size = sizeof params / sizeof *params;
    size_t param_idx = 0;

    uint64_t const ctime_temp = (uint64_t) time(NULL);
    uint16_t const type_temp = type;

    cgdb_param_array_init(params, params_size);

    cgdb_param_set_uint64(params, &param_idx, &fs_id);
    cgdb_param_set_uint64(params, &param_idx, &existing_ino);
    cgdb_param_set_uint64(params, &param_idx, &new_parent_ino);
    cgdb_param_set_immutable_string(params, &param_idx, new_name);
    cgdb_param_set_uint16(params, &param_idx, &type_temp);
    cgdb_param_set_uint64(params, &param_idx, &ctime_temp);

    cgdb_request_data * request = NULL;

    result = cgdb_request_data_init(db, cb, cb_data, &request);

    if (result == 0)
    {
        result = cgdb_backend_exec_rows_stmt(db->backend,
                                             statement,
                                             params,
                                             params_size,
                                             &cgdb_get_status_and_inode_cb,
                                             request);

        if (result != 0)
        {
            CGUTILS_ERROR("Error in exec stmt operation: %d", result);
            cgdb_request_data_free(request), request = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Unable to allocate request data: %d", result);
    }

    return result;
}

static int cgdb_readlink_response_cb(cgdb_backend_cursor * cursor,
                                     int const status,
                                     bool const has_error,
                                     char const * const error_str,
                                     size_t const rows_count,
                                     cgutils_vector * rows,
                                     void * const cb_data)
{
    int result = status;
    cgdb_request_data * request = cb_data;
    CGUTILS_ASSERT(cb_data != NULL);

    if (result == 0 &&
        has_error == false)
    {
        CGUTILS_ASSERT(rows_count == cgutils_vector_count(rows));

        if (rows_count == 1)
        {
            void * tmp_row = NULL;

            result = cgutils_vector_get(rows,
                                        0,
                                        &tmp_row);

            if (result == 0)
            {
                cgdb_row const * const row = tmp_row;
                char * link_to = NULL;

                result = cgdb_row_get_field_value_as_string(row,
                                                            "link_to",
                                                            &link_to);

                if (result == 0)
                {
                    CGUTILS_ASSERT(request->cb != NULL);

                    int res  = (*((cgdb_readlink_cb *)request->cb))(0,
                                                                    link_to,
                                                                    request->cb_data);
                    link_to = NULL;

                    if (res != 0)
                    {
                        CGUTILS_WARN("Callback returned: %d",
                                     res);
                    }

                    CGUTILS_FREE(link_to);
                }
                else
                {
                    CGUTILS_ERROR("Error getting link_to value: %d",
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting row: %d", result);
            }
        }
        else
        {
            result = ENOENT;

            if (rows_count > 0)
            {
                result = EIO;
                CGUTILS_WARN("More than one row returned [%zu], this is bad: %d", rows_count, result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Backend returned an error: %d (%s)", status, error_str != NULL ? error_str : "");
    }

    if (rows != NULL)
    {
        cgutils_vector_deep_free(&rows, &cgdb_row_delete);
    }

    if (result != 0)
    {
        CGUTILS_ASSERT(request->cb != NULL);
        result = (*((cgdb_readlink_cb *)request->cb))(result,
                                                      NULL,
                                                      request->cb_data);

        if (result != 0 &&
            result != status)
        {
            CGUTILS_WARN("Callback returned: %d", result);
        }
    }

    cgdb_backend_cursor_destroy(request->data->backend,
                                cursor);

    cgdb_request_data_free(request);

    return result;
}

int cgdb_readlink(cgdb_data * const db,
                  uint64_t const fs_id,
                  uint64_t const inode_number,
                  cgdb_entry_type const type,
                  cgdb_readlink_cb * const cb,
                  void * const cb_data)
{
    int result = 0;

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(inode_number > 0);
    CGUTILS_ASSERT(cb != NULL);

    cgdb_request_data * request = NULL;
    static cgdb_backend_statement const statement = cgdb_backend_statement_readlink;
    cgdb_param params[cgdb_backend_statement_params_count[statement]];
    size_t const params_size = sizeof params / sizeof *params;
    size_t param_idx = 0;
    uint16_t const type_temp = type;

    cgdb_param_array_init(params, params_size);
    cgdb_param_set_uint64(params, &param_idx, &fs_id);
    cgdb_param_set_uint64(params, &param_idx, &inode_number);
    cgdb_param_set_uint16(params, &param_idx, &type_temp);

    result = cgdb_request_data_init(db, cb, cb_data, &request);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cgdb_backend_find(db->backend,
                                   statement,
                                   params,
                                   params_size,
                                   CGDB_LIMIT_NONE,
                                   CGDB_SKIP_NONE,
                                   &cgdb_readlink_response_cb,
                                   request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in find operation: %d", result);
            cgdb_request_data_free(request), request = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Unable to allocate request data: %d", result);
    }

    return result;
}
