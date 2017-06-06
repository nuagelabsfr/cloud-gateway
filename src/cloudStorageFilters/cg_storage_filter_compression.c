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
#include <string.h>

#include <cgsm/cg_storage_filter_backend.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_buffer.h>

#include <zlib.h>

typedef struct
{
    uint8_t level;
} cg_storage_filter_compression_data;

typedef struct
{
    cgutils_buffer buffer;
    z_stream stream;
    cg_storage_filter_compression_data * data;
    cg_storage_filter_mode mode;
} cg_storage_filter_compression_ctx;

#define CG_STORAGE_FILTER_COMPRESSION_MINIMUM_BUFFER_SIZE (16 * 1024)

static void cg_storage_filter_compression_free(void * data)
{
    if (data != NULL)
    {
        cg_storage_filter_compression_data * this = data;

        this->level = 0;

        CGUTILS_FREE(this);
    }
}

static int cg_storage_filter_compression_init(cgutils_configuration const * const specifics,
                                              void ** const data)
{
    int result = EINVAL;

    if (specifics != NULL && data != NULL)
    {
        uint64_t level = 0;

        result = 0;

#define UNSIGNED_INTEGER_PARAMETER(storage, path, required)             \
        if (result == 0)                                                \
        {                                                               \
            result = cgutils_configuration_get_unsigned_integer(specifics, \
                                                                path,   \
                                                                &(storage)); \
            if (result == ENOENT && required == false)                  \
            {                                                           \
                result = 0;                                             \
            }                                                           \
            else if (result != 0)                                       \
            {                                                           \
                CGUTILS_ERROR("Required parameter [%s] not found.",     \
                              path);                                    \
            }                                                           \
        }
#include "cg_storage_filter_compression_parameters.itm"
#undef UNSIGNED_INTEGER_PARAMETER

        if (result == 0)
        {
            if (level >= 1 && level <= 9)
            {
                cg_storage_filter_compression_data * this = NULL;

                CGUTILS_ALLOCATE_STRUCT(this);

                if (this != NULL)
                {
                    this->level = (uint8_t) level;

                    *data = this;
                }
                else
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error allocating memory for compression filter data: %d",
                                  result);
                }
            }
            else
            {
                result = EINVAL;
                CGUTILS_ERROR("Error, the compression level parameter should be between 0 and 9, inclusive.");
            }
        }
    }

    return result;
}

static void cg_storage_filter_compression_context_free(void * ctx)
{
    if (ctx != NULL)
    {
        cg_storage_filter_compression_ctx * this = ctx;

        cgutils_buffer_clear(&(this->buffer));

        if (this->mode == cg_storage_filter_enc)
        {
            deflateEnd(&(this->stream));
        }
        else
        {
            inflateEnd(&(this->stream));
        }

        this->data = NULL;

        CGUTILS_FREE(this);
    }
}

static int cg_storage_filter_compression_context_init(void * const data,
                                                      cg_storage_filter_mode const mode,
                                                      void ** const ctx_out)
{
    int result = EINVAL;

    if (data != NULL && ctx_out != NULL)
    {
        cg_storage_filter_compression_data * const this = data;

        result = 0;

        if (result == 0)
        {
            cg_storage_filter_compression_ctx * ctx = NULL;

            CGUTILS_ALLOCATE_STRUCT(ctx);

            if (ctx != NULL)
            {
                char const * operation_str = NULL;
                ctx->data = this;
                ctx->mode = mode;

                ctx->stream.zalloc = Z_NULL;
                ctx->stream.zfree = Z_NULL;
                ctx->stream.opaque = Z_NULL;

                if (mode == cg_storage_filter_enc)
                {
                    operation_str = "deflate";
                    result = deflateInit(&(ctx->stream),
                                         this->level);
                }
                else
                {
                    operation_str = "inflate";
                    result = inflateInit(&(ctx->stream));
                }

                if (result == Z_OK)
                {
                    result = 0;
                }
                else if (result == Z_MEM_ERROR)
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error while allocating memory for %s operations: %d",
                                  operation_str,
                                  result);
                }
                else if (result == Z_STREAM_ERROR)
                {
                    result = EINVAL;
                    CGUTILS_ERROR("Invalid compression level %d: %d",
                                  this->level,
                                  result);
                }
                else if (result == Z_VERSION_ERROR)
                {
                    result = ENOSYS;
                    CGUTILS_ERROR("Invalid compression library version: %d",
                                  result);

                }
                else
                {
                    CGUTILS_ERROR("Unexpected result %d while initializing the compression context",
                                  result);
                    result = ENOMEM;
                }

                if (result == 0)
                {
                    *ctx_out = ctx;
                }
                else
                {
                    cg_storage_filter_compression_context_free(ctx), ctx = NULL;
                }
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for storage filter compression ctx: %d",
                              result);
            }
        }
    }

    return result;
}

static int cg_storage_filter_compression_context_do_internal(cg_storage_filter_compression_ctx * const this,
                                                             char const * const in,
                                                             size_t const in_size,
                                                             char ** const out,
                                                             size_t * const out_size,
                                                             bool const finish)
{
    int result = 0;
    int res = 0;
    int const flush = (finish == true) ? Z_FINISH : Z_NO_FLUSH;
    assert(this != NULL);
    assert(out != NULL);
    assert(out_size != NULL);
    assert(in != NULL || in_size == 0);
    assert(in_size > 0 || finish == true);

    /* We don't care about previous data if any */
    cgutils_buffer_discard(&(this->buffer));

    this->stream.next_in = (unsigned char const *) in;

    this->stream.avail_in = (typeof (this->stream.avail_in)) in_size;

    do
    {
        /* Make sure we have at least CG_STORAGE_FILTER_COMPRESSION_MINIMUM_BUFFER_SIZE bytes
           of storage */

        result = cgutils_buffer_make_space_for(&(this->buffer),
                                               CG_STORAGE_FILTER_COMPRESSION_MINIMUM_BUFFER_SIZE);

        if (COMPILER_LIKELY(result == 0))
        {
            char * buffer = NULL;
            size_t buffer_size = 0;

            cgutils_buffer_get_writable_buf(&(this->buffer),
                                            &buffer,
                                            &buffer_size);

            this->stream.next_out = (unsigned char *) buffer;
            this->stream.avail_out = (typeof (this->stream.avail_in)) buffer_size;

            if (this->mode == cg_storage_filter_enc)
            {
                res = deflate(&(this->stream),
                              flush);
            }
            else
            {
                res = inflate(&(this->stream),
                              flush);
            }

            if (COMPILER_LIKELY(res == Z_OK ||
                                res == Z_STREAM_END))
            {
                size_t got = buffer_size - this->stream.avail_out;
                cgutils_buffer_add_readable(&(this->buffer), got);
            }

            if (COMPILER_UNLIKELY(res == Z_STREAM_ERROR))
            {
                /* Z_STREAM_ERROR if the stream state was inconsistent (for example
                   if next_in or next_out was Z_NULL) */
                CGUTILS_ERROR("Stream error while %s %scompression.",
                              finish == true ? "finishing" : "doing",
                              this->mode == cg_storage_filter_enc ? "" : "de");
                result = EIO;
            }
            else if (COMPILER_UNLIKELY(res == Z_BUF_ERROR))
            {
                /* Z_BUF_ERROR if no progress is possible
                   (for example avail_in or avail_out was zero) */
                CGUTILS_ERROR("Buffer error while %s %scompressing.",
                              finish == true ? "finishing" : "doing",
                              this->mode == cg_storage_filter_enc ? "" : "de");
                result = EIO;
            }
        }
        else
        {
            CGUTILS_ERROR("Error while increasing buffer: %d", result);
        }

        /* Z_OK means that more data is available but output buffer is full */
    }
    while(result == 0 &&
          res == Z_OK &&
          (flush == Z_FINISH || this->stream.avail_in > 0));

    if (result == 0)
    {
        *out_size = this->buffer.len;

        if (*out_size > 0)
        {
            *out = this->buffer.data;
            cgutils_buffer_reset(&(this->buffer));
        }
        else
        {
            *out = NULL;
            cgutils_buffer_discard(&(this->buffer));
        }
    }
    else
    {
        *out_size = 0;
        *out = NULL;
        cgutils_buffer_clear(&(this->buffer));
    }

    return result;
}


static int cg_storage_filter_compression_context_finish(void * const ctx,
                                                        char ** const out,
                                                        size_t * const out_size)
{
    int result = EINVAL;

    if (ctx != NULL && out != NULL && out_size != NULL)
    {
        cg_storage_filter_compression_ctx * this = ctx;

        result = cg_storage_filter_compression_context_do_internal(this,
                                                                   NULL,
                                                                   0,
                                                                   out,
                                                                   out_size,
                                                                   true);

    }
    else
    {
        CGUTILS_ERROR("Called with %p, %p, %p", ctx, out, out_size);

        if (out_size != NULL)
        {
            *out_size = 0;
        }

        if (out != NULL)
        {
            *out = NULL;
        }
    }

    return result;
}

static int cg_storage_filter_compression_context_do(void * const ctx,
                                                    char const * in,
                                                    size_t in_size,
                                                    char ** const out,
                                                    size_t * const out_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(ctx != NULL && in != NULL && out != NULL && out_size != NULL))
    {
        cg_storage_filter_compression_ctx * this = ctx;

        result = cg_storage_filter_compression_context_do_internal(this,
                                                                   in,
                                                                   in_size,
                                                                   out,
                                                                   out_size,
                                                                   false);

    }
    else
    {
        if (out_size != NULL)
        {
            *out_size = 0;
        }

        if (out != NULL)
        {
            *out = NULL;
        }
    }

    return result;
}

static int cg_storage_filter_compression_get_max_final_size(void * const ctx,
                                                            size_t const in_size,
                                                            size_t * const out_size)
{
    int result = EINVAL;

    if (ctx != NULL)
    {
        cg_storage_filter_compression_ctx * this = ctx;

        if (this->mode == cg_storage_filter_enc)
        {
            result = 0;
            *out_size = deflateBound(&(this->stream),
                                     in_size);
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}

static cg_storage_filter_type cg_storage_filter_compression_get_type(void const * const data)
{
    (void) data;

    return cg_storage_filter_type_compression;
}

COMPILER_BLOCK_VISIBILITY_DEFAULT

extern cg_storage_filter_ops const cg_storage_filter_compression_ops;

cg_storage_filter_ops const cg_storage_filter_compression_ops =
{
    .init = &cg_storage_filter_compression_init,
    .get_type = &cg_storage_filter_compression_get_type,
    .init_context = &cg_storage_filter_compression_context_init,
    .do_filter = &cg_storage_filter_compression_context_do,
    .max_input_for_buffer = NULL,
    .get_max_final_size = &cg_storage_filter_compression_get_max_final_size,
    .finish = &cg_storage_filter_compression_context_finish,
    .free_context = &cg_storage_filter_compression_context_free,
    .free = &cg_storage_filter_compression_free,
    .predictable_output_size = false,
};

COMPILER_BLOCK_VISIBILITY_END
