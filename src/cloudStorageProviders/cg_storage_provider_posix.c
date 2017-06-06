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
#include <cgsm/cg_storage_provider_utils.h>

/* Data of the POSIX provider,
   not linked to a specific instance. */
typedef struct
{
    cg_storage_manager_data * data;
    cg_storage_provider * provider;
} cg_stp_posix_data;

typedef struct cg_stp_posix_specifics cg_stp_posix_specifics;

/* Data for a specific instance of
   this provider. */
struct cg_stp_posix_specifics
{
#define STRING_PARAM(name, path, required) char * name;
#define UINT64_PARAM(name, path, required) uint64_t name;
#define BOOLEAN_PARAM(name, path, required) bool name;
#include "cg_storage_provider_posix_parameters.itm"
#undef STRING_PARAM
#undef UINT64_PARAM
#undef BOOLEAN_PARAM
    size_t base_dir_len;
    bool init;
};

typedef struct
{
    char * final_path;
    char * temporary_path;
    int fd;
} cg_stp_posix_request_ctx_data;

#define CG_STP_POSIX_PATH_MAY_NOT_EXIST (false)
#define CG_STP_POSIX_PATH_ALREADY_EXISTS (true)

#define CG_STP_POSIX_DEFAULT_DEPTH (3)

static void cg_stp_posix_request_ctx_data_free(cg_stp_posix_request_ctx_data * ctx)
{
    if (ctx != NULL)
    {
        if (ctx->fd != -1)
        {
            cgutils_file_close(ctx->fd), ctx->fd = -1;
        }
        CGUTILS_FREE(ctx->final_path);
        CGUTILS_FREE(ctx->temporary_path);
        CGUTILS_FREE(ctx);
    }
}

static int cg_stp_posix_init(cg_storage_manager_data * const global_data,
                             void ** const data)
{
    int result = EINVAL;

    if (global_data != NULL &&
        data != NULL)
    {
        cg_stp_posix_data * pvd = NULL;
        CGUTILS_ALLOCATE_STRUCT(pvd);

        if (pvd != NULL)
        {
            pvd->data = global_data;
            result = 0;
            *data = pvd;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

static void cg_stp_posix_destroy(void * data)
{
    if (data != NULL)
    {
        CGUTILS_FREE(data);
    }
}

static void cg_stp_posix_clear_specifics(void * data)
{
    if (data != NULL)
    {
        cg_stp_posix_specifics * specifics = data;

#define STRING_PARAM(name, path, required) CGUTILS_FREE(specifics->name);
#define UINT64_PARAM(name, path, required) specifics->name = 0;
#define BOOLEAN_PARAM(name, path, required)
#include "cg_storage_provider_posix_parameters.itm"
#undef BOOLEAN_PARAM
#undef UINT64_PARAM
#undef STRING_PARAM

        CGUTILS_FREE(specifics);
    }
}

static int cg_stp_posix_parse_specifics(void * const provider_data,
                                        cgutils_configuration * const config,
                                        void ** data)
{
    int result = 0;

    (void) provider_data;

    if (config != NULL &&
        data != NULL)
    {
        cg_stp_posix_specifics * specifics = NULL;

        CGUTILS_ALLOCATE_STRUCT(specifics);

        if (specifics != NULL)
        {
            specifics->verbose = false;
            specifics->tree_depth = CG_STP_POSIX_DEFAULT_DEPTH;
            result = 0;
            specifics->init = true;

#define STRING_PARAM(name, path, required) CG_STP_UTILS_RETRIEVE_STRING(config, specifics, result, name, path, required)
#define UINT64_PARAM(name, path, required) CG_STP_UTILS_RETRIEVE_UINT64(config, specifics, result, name, path, required)
#define BOOLEAN_PARAM(name, path, required) CG_STP_UTILS_RETRIEVE_BOOLEAN(config, specifics, result, name, path, required)
#include "cg_storage_provider_posix_parameters.itm"
#undef STRING_PARAM
#undef UINT64_PARAM
#undef BOOLEAN_PARAM

            if (result == 0)
            {
                specifics->base_dir_len = strlen(specifics->base_dir);
            }

            if (result != 0)
            {
                cg_stp_posix_clear_specifics(specifics), specifics = NULL;
            }

            *data = specifics;
        }
        else
        {
            result = ENOMEM;
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

static int cg_stp_posix_setup(cg_storage_provider * const provider,
                              void * const provider_data,
                              void * const specifics_gen)
{
    int result = 0;

    if (provider != NULL &&
        provider_data != NULL &&
        specifics_gen != NULL)
    {
        cg_stp_posix_data * const pvd = provider_data;

        pvd->provider = provider;
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

static int cg_stp_posix_construct_path(cg_stp_posix_specifics const * const specifics,
                                       char const * const key,
                                       bool const dirs_exist,
                                       char ** const path)
{
    int result = 0;
    size_t path_len = 0;
    CGUTILS_ASSERT(specifics != NULL);
    CGUTILS_ASSERT(key != NULL);
    CGUTILS_ASSERT(path != NULL);

    result = cgutils_file_compute_hashed_path(specifics->base_dir,
                                              specifics->base_dir_len,
                                              key,
                                              strlen(key),
                                              specifics->tree_depth,
                                              path,
                                              &path_len);

    if (result == 0)
    {
        if (dirs_exist == false)
        {
            for (size_t idx = 0;
                 result == 0 &&
                     idx < path_len;
                 idx++)
            {
                if (COMPILER_UNLIKELY(idx > 0 &&
                                      (*path)[idx] == '/'))
                {
                    (*path)[idx] = '\0';
                    result = cgutils_file_mkdir(*path,
                                                S_IRUSR | S_IWUSR | S_IXUSR);

                    if (result != 0)
                    {
                        if (result == EEXIST)
                        {
                            result = 0;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error creating directory %s: %d",
                                          *path,
                                          result);
                        }
                    }

                    (*path)[idx] = '/';
                }
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Error computing hashed path: %d",
                      result);
    }

    return result;
}

static int cg_stp_posix_io_completed(int const status,
                                     void * const cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    CGUTILS_ASSERT(pv_request != NULL);
    CGUTILS_ASSERT(pv_request->ctx != NULL);
    CGUTILS_ASSERT(pv_request->ctx->provider_request_ctx_data != NULL);
    cg_stp_posix_request_ctx_data * ctx = pv_request->ctx->provider_request_ctx_data;

    if (status != 0)
    {
        CGUTILS_ERROR("Error in copying data: %d", status);
    }

    cg_stp_posix_request_ctx_data_free(ctx), ctx = NULL;
    pv_request->ctx->provider_request_ctx_data = NULL;

    cg_storage_provider_handle_status_response(pv_request, result);

    return result;
}

static int cg_stp_posix_put_io_completed(int const status,
                                         void * const cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    CGUTILS_ASSERT(pv_request != NULL);
    CGUTILS_ASSERT(pv_request->ctx != NULL);
    CGUTILS_ASSERT(pv_request->ctx->provider_request_ctx_data != NULL);
    cg_stp_posix_request_ctx_data * ctx = pv_request->ctx->provider_request_ctx_data;

    if (status == 0)
    {
        CGUTILS_ASSERT(ctx->final_path != NULL);
        CGUTILS_ASSERT(ctx->temporary_path != NULL);

        result = cgutils_file_rename(ctx->temporary_path,
                                     ctx->final_path);

        if (result != 0)
        {
            CGUTILS_ERROR("Error moving temporary file to final destination (%s -> %s): %d",
                          ctx->temporary_path,
                          ctx->final_path,
                          result);

            cgutils_file_unlink(ctx->temporary_path);
        }
    }
    else
    {
        CGUTILS_ERROR("Error in copying data: %d", status);
        cgutils_file_unlink(ctx->temporary_path);
    }

    cg_stp_posix_request_ctx_data_free(ctx), ctx = NULL;
    pv_request->ctx->provider_request_ctx_data = NULL;
    cg_storage_provider_handle_status_response(pv_request, result);

    return result;
}

static int cg_stp_posix_get_temporary_file_for_upload(char const * const final_path,
                                                      char ** const out,
                                                      int * const fd)
{
    static char const template_end[] = "XXXXXX";
    static size_t const template_end_len = sizeof template_end -1;

    int result = 0;
    CGUTILS_ASSERT(final_path != NULL);
    CGUTILS_ASSERT(out != NULL);
    CGUTILS_ASSERT(fd != NULL);
    size_t const final_path_len = strlen(final_path);
    size_t temporary_path_len = final_path_len + template_end_len;
    char * temporary_path = NULL;

    CGUTILS_MALLOC(temporary_path, temporary_path_len + 1, 1);

    if (temporary_path != NULL)
    {
        memcpy(temporary_path, final_path, final_path_len);
        memcpy(temporary_path + final_path_len, template_end, template_end_len);
        temporary_path[temporary_path_len] = '\0';

        result = cgutils_file_mkstemp(temporary_path,
                                      fd);

        if (result == 0)
        {
            *out = temporary_path;
            temporary_path = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error opening temporary file %s for writing: %d",
                          temporary_path,
                          result);
        }

        CGUTILS_FREE(temporary_path);
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static int cg_stp_posix_put_file(cg_storage_provider_request * pv_request)
{
    int result = 0;

    if (pv_request != NULL)
    {
        CGUTILS_ASSERT(pv_request->ctx != NULL);
        CGUTILS_ASSERT(pv_request->ctx->key != NULL);
        cg_stp_posix_data * pvd = pv_request->ctx->provider_data;
        cg_stp_posix_specifics * specifics = pv_request->ctx->instance_specifics;
        cg_stp_posix_request_ctx_data * ctx = NULL;

        CGUTILS_ALLOCATE_STRUCT(ctx);

        if (ctx != NULL)
        {
            pv_request->ctx->provider_request_ctx_data = ctx;

            result = cg_stp_posix_construct_path(specifics,
                                                 pv_request->ctx->key,
                                                 CG_STP_POSIX_PATH_MAY_NOT_EXIST,
                                                 &(ctx->final_path));

            if (result == 0)
            {
                result = cg_stp_posix_get_temporary_file_for_upload(ctx->final_path,
                                                                    &(ctx->temporary_path),
                                                                    &(ctx->fd));

                if (result == 0)
                {
                    CGUTILS_ASSERT(pv_request->ctx->dest_io == NULL);

                    result = cg_storage_io_destination_init_from_fd(cg_storage_manager_data_get_aio(pvd->data),
                                                                    ctx->fd,
                                                                    &(pv_request->ctx->dest_io));

                    if (result == 0)
                    {
                        CGUTILS_ASSERT(pv_request->dest_io == NULL);

                        result = cg_storage_io_ctx_destination_init(pv_request->ctx->dest_io,
                                                                    &(pv_request->dest_io));

                        if (result == 0)
                        {
                            pv_request->raw_request_cb = &cg_stp_posix_put_io_completed;
                            pv_request->request_cb_data = pv_request;

                            result = cg_storage_provider_utils_io_copy(pv_request);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error in IO copy: %d",
                                              result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error creating IO destination context: %d",
                                          result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating IO destination from fd: %d",
                                      result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error getting temporary destination file for %s: %d",
                                  ctx->final_path,
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error constructing destination path: %d",
                              result);
            }

            if (result != 0)
            {
                cg_stp_posix_request_ctx_data_free(ctx), ctx = NULL;
                pv_request->ctx->provider_request_ctx_data = NULL;
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating ctx request data: %d",
                          result);
        }
    }

    return result;
}

static int cg_stp_posix_get_file(cg_storage_provider_request * pv_request)
{
    int result = 0;

    if (pv_request != NULL)
    {
        CGUTILS_ASSERT(pv_request->ctx != NULL);
        CGUTILS_ASSERT(pv_request->ctx->key != NULL);
        cg_stp_posix_data * pvd = pv_request->ctx->provider_data;
        cg_stp_posix_specifics * specifics = pv_request->ctx->instance_specifics;
        cg_stp_posix_request_ctx_data * ctx = NULL;

        CGUTILS_ALLOCATE_STRUCT(ctx);

        if (ctx != NULL)
        {
            pv_request->ctx->provider_request_ctx_data = ctx;

            result = cg_stp_posix_construct_path(specifics,
                                                 pv_request->ctx->key,
                                                 CG_STP_POSIX_PATH_ALREADY_EXISTS,
                                                 &(ctx->final_path));

            if (result == 0)
            {
                result = cgutils_file_open(ctx->final_path,
                                           O_RDONLY,
                                           0,
                                           &(ctx->fd));

                if (result == 0)
                {
                    struct stat st = (struct stat) { 0 };

                    result = cgutils_file_fstat(ctx->fd,
                                                &st);

                    if (result == 0 &&
                        st.st_size >= 0)
                    {
                        CGUTILS_ASSERT(pv_request->ctx->source_io == NULL);

                        result = cg_storage_io_source_init_from_fd(cg_storage_manager_data_get_aio(pvd->data),
                                                                   ctx->fd,
                                                                   (size_t) st.st_size,
                                                                   &(pv_request->ctx->source_io));

                        if (result == 0)
                        {
                            CGUTILS_ASSERT(pv_request->source_io == NULL);

                            result = cg_storage_io_ctx_source_init(pv_request->ctx->source_io,
                                                                   0,
                                                                   (size_t) st.st_size,
                                                                   &(pv_request->source_io));

                            if (result == 0)
                            {
                                pv_request->raw_request_cb = &cg_stp_posix_io_completed;
                                pv_request->request_cb_data = pv_request;

                                result = cg_storage_provider_utils_io_copy(pv_request);

                                if (result != 0)
                                {
                                    CGUTILS_ERROR("Error in IO copy: %d",
                                                  result);
                                }
                            }
                            else
                            {
                                CGUTILS_ERROR("Error creating IO destination context: %d",
                                              result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error creating IO destination from fd: %d",
                                      result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error getting file size from fd: %d",
                                      result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error opening destination file %s: %d",
                                  ctx->final_path,
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error constructing destination path: %d",
                              result);
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating ctx request data: %d",
                          result);
        }
    }

    return result;
}

static int cg_stp_posix_delete_file(cg_storage_provider_request * pv_request)
{
    int result = 0;

    if (pv_request != NULL)
    {
        CGUTILS_ASSERT(pv_request->ctx != NULL);
        CGUTILS_ASSERT(pv_request->ctx->key != NULL);
        cg_stp_posix_specifics * specifics = pv_request->ctx->instance_specifics;
        char * path = NULL;

        result = cg_stp_posix_construct_path(specifics,
                                             pv_request->ctx->key,
                                             CG_STP_POSIX_PATH_ALREADY_EXISTS,
                                             &path);

        if (result == 0)
        {
            result = cgutils_file_unlink(path);

            if (result == 0)
            {
                cg_storage_provider_handle_status_response(pv_request, result);
            }

            CGUTILS_FREE(path);
        }
        else
        {
            CGUTILS_ERROR("Error constructing destination path: %d",
                          result);
        }
    }

    return result;
}

static size_t cg_stp_posix_get_single_upload_size(void const * const data)
{
    (void) data;
    return SIZE_MAX;
}

COMPILER_BLOCK_VISIBILITY_DEFAULT

extern cg_stp_vtable const cg_storage_provider_posix_vtable;

cg_stp_vtable const cg_storage_provider_posix_vtable =
{
    .capabilities =
    {
        .chunked_upload = true,
        .object_hashing = false,
    },
    .init = &cg_stp_posix_init,
    .destroy = &cg_stp_posix_destroy,
    .parse_specifics = &cg_stp_posix_parse_specifics,
    .clear_specifics = &cg_stp_posix_clear_specifics,
    .setup = &cg_stp_posix_setup,
    .get_file = &cg_stp_posix_get_file,
    .put_file = &cg_stp_posix_put_file,
    .delete_file = &cg_stp_posix_delete_file,
    .get_single_upload_size = &cg_stp_posix_get_single_upload_size,
};

COMPILER_BLOCK_VISIBILITY_END
