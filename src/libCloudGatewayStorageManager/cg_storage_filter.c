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

#include <cgsm/cg_storage_filter.h>

#include <cloudutils/cloudutils_file.h>

struct cg_storage_filter
{
    char * name;
    cg_storage_filter_ops ops;
    void * handle;
    void * filter_data;
};

struct cg_storage_filter_ctx
{
    cg_storage_filter * filter;
    void * filter_ctx;
};

static int cg_storage_filter_load_from_configuration(cg_storage_filter * const this,
                                                     cgutils_configuration * const config)
{
    assert(this != NULL);
    assert(config != NULL);

    int result = (this->ops.init)(config, &(this->filter_data));

    if (result != 0)
    {
        CGUTILS_ERROR("Error while initializing storage filter: %d", result);
    }

    return result;
}

static int cg_storage_filter_get_ops(char const * const filter_name,
                                     char const * const filters_path,
                                     void ** const handle,
                                     cg_storage_filter_ops const ** const ops)
{
    assert(filter_name != NULL);
    assert(filters_path != NULL);
    assert(ops != NULL);
    assert(handle != NULL);

    char * name_lower = NULL;

    int result = cgutils_str_tolower(filter_name, &name_lower);

    if (result == 0)
    {
        char * file = NULL;

        result = cgutils_asprintf(&file,
                                  "%s/cg_storage_filter_%s.so",
                                  filters_path,
                                  name_lower);

        if (result == 0)
        {
            if (cgutils_file_exists(file) == true)
            {
                char * funcs_name = NULL;

                result = cgutils_asprintf(&funcs_name,
                                          "cg_storage_filter_%s_ops",
                                          name_lower);

                if (result == 0)
                {
                    dlerror();

                    *handle = dlopen(file, RTLD_NOW);

                    if (*handle != NULL)
                    {
                        *ops = dlsym(*handle,
                                    funcs_name);

                        if (*ops != NULL)
                        {
                        }
                        else
                        {
                            CGUTILS_ERROR("Error looking for symbol %s in storage filter %s (%s): %s",
                                          funcs_name,
                                          filter_name,
                                          file,
                                          dlerror());
                            result = EINVAL;
                        }

                        if (result != 0 && *handle != NULL)
                        {
                            dlclose(*handle), *handle = NULL;
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error while loading storage filter named %s (%s): %s",
                                      filter_name,
                                      file,
                                      dlerror());
                        result = EINVAL;
                    }

                    CGUTILS_FREE(funcs_name);
                }
            }
            else
            {
                CGUTILS_ERROR("Storage filter not found %s (%s)",
                              filter_name,
                              file);
                result = ENOENT;
            }

            CGUTILS_FREE(file);
        }

        CGUTILS_FREE(name_lower);
    }

    return result;
}

int cg_storage_filter_init(char const * const name,
                           char const * const filters_path,
                           cgutils_configuration * const specifics,
                           cg_storage_filter ** const out)
{
    int result = EINVAL;

    if (filters_path != NULL && specifics != NULL && out != NULL)
    {
        void * handle = NULL;
        cg_storage_filter_ops const * ops = NULL;

        result = cg_storage_filter_get_ops(name, filters_path, &handle, &ops);

        if (result == 0)
        {
            assert(ops != NULL);

            CGUTILS_ALLOCATE_STRUCT(*out);

            if (*out != NULL)
            {
                (*out)->ops = *ops;
                (*out)->handle = handle;
                handle = NULL;

                result = cg_storage_filter_load_from_configuration(*out, specifics);

                if (result == 0)
                {
                    (*out)->name = cgutils_strdup(name);

                    if ((*out)->name == NULL)
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Error allocating memory for filter name: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error loading filter: %d", result);
                    cg_storage_filter_free(*out), *out = NULL;
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

void cg_storage_filter_free(cg_storage_filter * this)
{
    if (this != NULL)
    {
        if (this->filter_data != NULL && this->ops.free != NULL)
        {
            (*(this->ops.free))(this->filter_data);
        }

        if (this->name != NULL)
        {
            CGUTILS_FREE(this->name);
        }

        this->filter_data = NULL;

        if (this->handle != NULL)
        {
            dlclose(this->handle), this->handle = NULL;
        }

        CGUTILS_FREE(this);
    }
}

bool cg_storage_filter_support_predictable_output_size(cg_storage_filter const * const filter)
{
    bool result = false;

    if (filter != NULL)
    {
        result = filter->ops.predictable_output_size;
    }

    return result;
}

bool cg_storage_filter_ctx_support_predictable_output_size(cg_storage_filter_ctx const * const ctx)
{
    bool result = false;

    if (ctx != NULL && ctx->filter != NULL)
    {
        result = ctx->filter->ops.predictable_output_size;
    }

    return result;
}

int cg_storage_filter_ctx_init(cg_storage_filter * const filter,
                               cg_storage_filter_mode const mode,
                               cg_storage_filter_ctx ** const ctx)
{
    int result = EINVAL;

    if (filter != NULL && ctx != NULL)
    {
        void * filter_ctx = NULL;

        result = 0;

        if (filter->ops.init_context != NULL)
        {
            result = (*(filter->ops.init_context))(filter->filter_data,
                                                   mode,
                                                   &filter_ctx);
        }

        if (result == 0)
        {
            CGUTILS_ALLOCATE_STRUCT(*ctx);

            if (*ctx != NULL)
            {
                (*ctx)->filter = filter;
                (*ctx)->filter_ctx = filter_ctx;
                filter_ctx = NULL;

                if (result != 0)
                {
                    cg_storage_filter_ctx_free(*ctx), *ctx = NULL;
                }
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for filter context: %d", result);
            }

            if (result != 0 && filter_ctx != NULL && filter->ops.free_context != NULL)
            {
                (*(filter->ops.free_context))(filter_ctx), filter_ctx = NULL;
            }
        }
    }

    return result;
}


int cg_storage_filter_do(cg_storage_filter_ctx * const filter_ctx,
                         char const * const in,
                         size_t const in_size,
                         char ** const out,
                         size_t * const out_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(filter_ctx != NULL && in != NULL && out != NULL && out_size != NULL))
    {
        cg_storage_filter * filter = filter_ctx->filter;
        assert(filter != NULL);

        if (COMPILER_LIKELY(filter->ops.do_filter != NULL))
        {
            result = (*(filter->ops.do_filter))(filter_ctx->filter_ctx, in, in_size, out, out_size);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error applying filter: %d", result);
            }
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}

void cg_storage_filter_ctx_free(cg_storage_filter_ctx * ctx)
{
    if (ctx != NULL)
    {
        assert(ctx->filter != NULL);

        if (ctx->filter_ctx != NULL)
        {
            if (ctx->filter->ops.free_context != NULL)
            {
                (*(ctx->filter->ops.free_context))(ctx->filter_ctx);
            }

            ctx->filter_ctx = NULL;
        }

        ctx->filter = NULL;
        CGUTILS_FREE(ctx);
    }
}

size_t cg_storage_filter_max_input_for_buffer(cg_storage_filter_ctx * const ctx,
                                              size_t const buffer_size)
{
    size_t result = buffer_size;

    if (ctx != NULL)
    {
        cg_storage_filter * filter = ctx->filter;
        assert(filter != NULL);

        if (filter->ops.max_input_for_buffer != NULL)
        {
            result = (*(filter->ops.max_input_for_buffer))(ctx->filter_ctx,
                                                           buffer_size);
        }
    }

    return result;
}

int cg_storage_filter_finish(cg_storage_filter_ctx * const filter_ctx,
                             char ** const out,
                             size_t * const out_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(filter_ctx != NULL && out != NULL && out_size != NULL))
    {
        cg_storage_filter * filter = filter_ctx->filter;
        assert(filter != NULL);

        if (filter->ops.finish != NULL)
        {
            result = (*(filter->ops.finish))(filter_ctx->filter_ctx, out, out_size);
        }
        else
        {
            result = 0;
        }
    }

    return result;
}

int cg_storage_filter_get_max_final_size(cg_storage_filter_ctx const * const filter_ctx,
                                         size_t const in_size,
                                         size_t * const out_size)
{
    int result = EINVAL;

    if (filter_ctx != NULL && out_size != NULL)
    {
        cg_storage_filter * filter = filter_ctx->filter;
        assert(filter != NULL);

        if (filter->ops.get_max_final_size != NULL)
        {
            result = (*(filter->ops.get_max_final_size))(filter_ctx->filter_ctx, in_size, out_size);
        }
        else
        {
            result = ENOSYS;
        }

    }

    return result;
}

char const * cg_storage_filter_get_name(cg_storage_filter const * const this)
{
    char const * result = NULL;

    if (this != NULL)
    {
        result = this->name;
    }

    return result;
}

cg_storage_filter_type cg_storage_filter_get_type(cg_storage_filter const * const this)
{
    cg_storage_filter_type result = cg_storage_filter_type_none;

    if (this != NULL)
    {
        if (this->ops.get_type != NULL)
        {
            result = (*(this->ops.get_type))(this->filter_data);
        }
    }

    return result;
}
