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
#include <dlfcn.h>
#include <errno.h>
#include <string.h>

#include "cloudutils/cloudutils.h"
#include "cloudutils/cloudutils_file.h"

#include <cgdb/cgdb_backend.h>
#include <cgdb/cgdb_utils.h>

struct cgdb_backend
{
    cgdb_backend_ops ops;
    void * handle;
    void * backend_data;
};

static int cgdb_backend_load(cgdb_backend * const this,
                             cgutils_event_data * const event_data,
                             cgutils_configuration * const config)
{
    assert(this != NULL);
    assert(event_data != NULL);
    assert(config != NULL);

    int result = (this->ops.init)(event_data, config, &(this->backend_data));

    if (result != 0)
    {
        CGUTILS_ERROR("Error while initializing database backend: %d", result);
    }

    return result;
}

static int cgdb_backend_get_ops(char const * const backend,
                                char const * const backends_path,
                                void ** const handle,
                                cgdb_backend_ops const ** const ops)
{
    assert(backend != NULL);
    assert(backends_path != NULL);
    assert(ops != NULL);
    assert(handle != NULL);

    char * name_lower = NULL;
    int result = cgutils_str_tolower(backend, &name_lower);

    if (result == 0)
    {
        char * file = NULL;

        result = cgutils_asprintf(&file,
                                  "%s/cgdb_%s.so",
                                  backends_path,
                                  name_lower);

        if (result == 0)
        {
            if (cgutils_file_exists(file) == true)
            {
                char * funcs_name = NULL;

                result = cgutils_asprintf(&funcs_name,
                                          "cgdb_backend_%s_ops",
                                          name_lower);

                if (result == 0)
                {
                    dlerror();

                    *handle = dlopen(file, RTLD_NOW);

                    if (*handle != NULL)
                    {
                        *ops = dlsym(*handle,
                                    funcs_name);

                        if (*ops == NULL)
                        {
                            CGUTILS_ERROR("Error looking for symbol %s in DB Backend %s (%s): %s",
                                          funcs_name,
                                          backend,
                                          file,
                                          dlerror());
                            result = EINVAL;
                        }

                        if (result != 0 &&
                            *handle != NULL)
                        {
                            dlclose(*handle), *handle = NULL;
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error while loading DB Backend named %s (%s): %s",
                                      backend,
                                      file,
                                      dlerror());
                        result = EINVAL;
                    }

                    CGUTILS_FREE(funcs_name);
                }
            }
            else
            {
                CGUTILS_ERROR("DB Backend not found %s (%s)",
                              backend,
                              file);
                result = ENOENT;
            }

            CGUTILS_FREE(file);
        }

        CGUTILS_FREE(name_lower);
    }

    return result;
}

int cgdb_backend_init(char const * const name,
                      char const * const backends_path,
                      cgutils_event_data * const event_data,
                      cgutils_configuration * const specifics,
                      cgdb_backend ** const backend)
{
    int result = EINVAL;

    if (name != NULL && backends_path != NULL && event_data != NULL && specifics != NULL && backend != NULL)
    {
        void * handle = NULL;
        cgdb_backend_ops const * ops = NULL;

        result = cgdb_backend_get_ops(name, backends_path, &handle, &ops);

        if (result == 0)
        {
            CGUTILS_ASSERT(ops != NULL);

            CGUTILS_ALLOCATE_STRUCT(*backend);

            if (*backend != NULL)
            {
                (*backend)->ops = *ops;
                (*backend)->handle = handle;
                handle = NULL;

                result = cgdb_backend_load(*backend, event_data, specifics);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error loading backend: %d", result);
                    cgdb_backend_free(*backend), *backend = NULL;
                }
            }
            else
            {
                result = ENOMEM;
            }

            if (result != 0 && handle != NULL)
            {
                dlclose(handle), handle = NULL;
            }
        }
    }

    return result;
}

int cgdb_backend_insert(cgdb_backend * const backend,
                        cgdb_backend_statement const statement,
                        cgdb_param const * const params,
                        size_t const params_count,
                        cgdb_backend_status_cb * const cb,
                        void * const cb_data)
{
    int result = EINVAL;

    assert(backend != NULL && params != NULL);

    if (backend->ops.insert != NULL)
    {
        result = (*(backend->ops.insert))(backend->backend_data,
                                          statement,
                                          params,
                                          params_count,
                                          cb,
                                          cb_data);
    }
    else
    {
        result = ENOSYS;
    }

    return result;
}

int cgdb_backend_insert_returning(cgdb_backend * const backend,
                                  cgdb_backend_statement const statement,
                                  cgdb_param const * const params,
                                  size_t const params_count,
                                  cgdb_backend_status_returning_cb * const cb,
                                  void * const cb_data)
{
    int result = EINVAL;

    assert(backend != NULL && params != NULL);

    if (backend->ops.insert_returning != NULL)
    {
        result = (*(backend->ops.insert_returning))(backend->backend_data,
                                                    statement,
                                                    params,
                                                    params_count,
                                                    cb,
                                                    cb_data);
    }
    else
    {
        result = ENOSYS;
    }

    return result;
}

int cgdb_backend_find(cgdb_backend * const backend,
                      cgdb_backend_statement const stmt,
                      cgdb_param const * const params,
                      size_t const params_count,
                      cgdb_limit_type const limit,
                      cgdb_skip_type const skip,
                      cgdb_backend_cursor_cb * const cb,
                      void * const cb_data)
{
    int result = EINVAL;

    assert(backend != NULL && params != NULL);

    if (backend->ops.find != NULL)
    {
        result = (*(backend->ops.find))(backend->backend_data,
                                        stmt,
                                        params,
                                        params_count,
                                        limit,
                                        skip,
                                        cb,
                                        cb_data);
    }
    else
    {
        result = ENOSYS;
    }

    return result;
}

int cgdb_backend_update(cgdb_backend * const backend,
                        cgdb_backend_statement const statement,
                        cgdb_param const * const params,
                        size_t const params_count,
                        cgdb_backend_status_cb * const cb,
                        void * const cb_data)
{
    int result = EINVAL;

    assert(backend != NULL && params != NULL);

    if (backend->ops.update != NULL)
    {
        result = (*(backend->ops.update))(backend->backend_data,
                                          statement,
                                          params,
                                          params_count,
                                          cb,
                                          cb_data);
    }
    else
    {
        result = ENOSYS;
    }

    return result;
}

int cgdb_backend_remove(cgdb_backend * const backend,
                        cgdb_backend_statement const statement,
                        cgdb_param const * const params,
                        size_t const params_count,
                        cgdb_backend_status_cb * const cb,
                        void * const cb_data)
{
    int result = EINVAL;

    assert(backend != NULL && params != NULL);

    if (backend->ops.remove != NULL)
    {
        result = (*(backend->ops.remove))(backend->backend_data,
                                          statement,
                                          params,
                                          params_count,
                                          cb,
                                          cb_data);
    }
    else
    {
        result = ENOSYS;
    }

    return result;
}

int cgdb_backend_increment(cgdb_backend * const backend,
                           cgdb_backend_statement const statement,
                           cgdb_param const * const params,
                           size_t const params_count,
                           cgdb_backend_status_cb * const cb,
                           void * const cb_data)
{
    int result = EINVAL;

    assert(backend != NULL && params != NULL);

    if (backend->ops.increment != NULL)
    {
        result = (*(backend->ops.increment))(backend->backend_data,
                                             statement,
                                             params,
                                             params_count,
                                             cb,
                                             cb_data);
    }
    else
    {
        result = ENOSYS;
    }

    return result;
}

void cgdb_backend_free(cgdb_backend * this)
{
    if (this != NULL)
    {
        if (this->backend_data != NULL && this->ops.free != NULL)
        {
            (*(this->ops.free))(this->backend_data);
        }

        this->backend_data = NULL;

        if (this->handle != NULL)
        {
            dlclose(this->handle), this->handle = NULL;
        }

        CGUTILS_FREE(this);
    }
}

void cgdb_backend_cursor_destroy(cgdb_backend * const backend,
                                 cgdb_backend_cursor * const cursor)
{
    if (backend != NULL && cursor != NULL)
    {
        if (backend->ops.destroy_cursor != NULL)
        {
            (*(backend->ops.destroy_cursor))(backend->backend_data, cursor);
        }
    }
}

int cgdb_backend_exec_rows_stmt_sync(cgdb_backend * const backend,
                                     cgdb_backend_statement const stmt,
                                     cgdb_param const * const params,
                                     size_t const params_count,
                                     cgdb_limit_type const limit,
                                     cgdb_skip_type const skip,
                                     cgdb_backend_cursor ** const cursor_out,
                                     size_t * const rows_count,
                                     cgutils_vector ** const rows)
{
    int result = ENOSYS;

    assert(backend != NULL);
    assert(params != NULL || params_count == 0);

    if (backend->ops.exec_rows_stmt_sync != NULL)
    {
        result = (*(backend->ops.exec_rows_stmt_sync))(backend->backend_data,
                                                       stmt,
                                                       params,
                                                       params_count,
                                                       limit,
                                                       skip,
                                                       cursor_out,
                                                       rows_count,
                                                       rows);
    }

    return result;
}

int cgdb_backend_exec_stmt(cgdb_backend * const backend,
                           cgdb_backend_statement const statement,
                           cgdb_param const * const params,
                           size_t const params_count,
                           cgdb_backend_status_cb * const cb,
                           void * const cb_data)
{
    int result = ENOSYS;

    assert(backend != NULL && params != NULL);

    if (backend->ops.exec_stmt != NULL)
    {
        result = (*(backend->ops.exec_stmt))(backend->backend_data,
                                             statement,
                                             params,
                                             params_count,
                                             cb,
                                             cb_data);
    }

    return result;
}

int cgdb_backend_exec_rows_stmt(cgdb_backend * const backend,
                                cgdb_backend_statement const statement,
                                cgdb_param const * const params,
                                size_t const params_count,
                                cgdb_backend_cursor_cb * const cb,
                                void * const cb_data)
{
    int result = ENOSYS;

    assert(backend != NULL && params != NULL);

    if (backend->ops.exec_rows_stmt != NULL)
    {
        result = (*(backend->ops.exec_rows_stmt))(backend->backend_data,
                                                  statement,
                                                  params,
                                                  params_count,
                                                  cb,
                                                  cb_data);
    }

    return result;
}

int cgdb_backend_sync_test_credentials(cgdb_backend * const backend,
                                       char ** const error_str_out)
{
    int result = ENOSYS;
    assert(backend != NULL);

    if (backend->ops.sync_test_credentials != NULL)
    {
        result = (*(backend->ops.sync_test_credentials))(backend->backend_data,
                                                         error_str_out);
    }

    return result;
}
