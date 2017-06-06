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

#ifndef CLOUD_UTILS_BUFFER_H_
#define CLOUD_UTILS_BUFFER_H_

#include <stddef.h>
#include <string.h>

typedef struct
{
    char * data;
    /* size of data (allocated) */
    size_t size;
    /* len of remaining data in buffer */
    size_t len;
    /* start of remaining data in buffer */
    size_t pos;
    /* at every moment,
       size >= pos + len;
    */
} cgutils_buffer;

#include <cloudutils/cloudutils.h>

static inline void cgutils_buffer_reset(cgutils_buffer * const buf)
{
    assert(buf != NULL);

    buf->data = NULL;
    buf->size = 0;
    buf->len = 0;
    buf->pos = 0;
}

static inline void cgutils_buffer_clear(cgutils_buffer * const buf)
{
    assert(buf != NULL);

    if (buf->data != NULL)
    {
        CGUTILS_FREE(buf->data);
    }

    cgutils_buffer_reset(buf);
}

static inline void cgutils_buffer_discard(cgutils_buffer * const buf)
{
    assert(buf != NULL);

    buf->len = 0;
    buf->pos = 0;
}

static inline COMPILER_PURE_FUNCTION size_t cgutils_buffer_get_available_data(cgutils_buffer const * const buf)
{
    assert(buf != NULL);

    /* returns readable data */

    return buf->len;
}

static inline COMPILER_PURE_FUNCTION size_t cgutils_buffer_get_usable_size(cgutils_buffer const * const buf)
{
    assert(buf != NULL);

    /* returns usable size at the end of the buffer */

    return buf->size - (buf->len + buf->pos);
}

static inline int cgutils_buffer_make_space_for(cgutils_buffer * const buf,
                                                size_t const needed_size)
{
    int result = 0;

    assert(buf != NULL);
    assert(SIZE_MAX - buf->len > needed_size);

    if (cgutils_buffer_get_usable_size(buf) < needed_size)
    {
        if (needed_size > (buf->size - buf->len))
        {
            /* buffer is too small */
            size_t new_size = buf->len + needed_size;
            char * new_ptr = NULL;

            if (buf->pos == 0)
            {
                CGUTILS_REALLOC(new_ptr, buf->data, new_size, 1);

                if (new_ptr != NULL)
                {
                    buf->size = new_size;
                    buf->data = new_ptr;
                }
                else
                {
                    result = ENOMEM;
                }
            }
            else
            {
                CGUTILS_MALLOC(new_ptr, new_size, 1);

                if (new_ptr != NULL)
                {
                    buf->size = new_size;
                    memcpy(new_ptr, buf->data + buf->pos, buf->len);
                    CGUTILS_FREE(buf->data);
                    buf->data = new_ptr;
                    buf->pos = 0;
                }
                else
                {
                    result = ENOMEM;
                }
            }

        }
        else
        {
            assert(buf->pos > 0);

            /* We have enough space, but fragmented */
            memmove(buf->data, buf->data + buf->pos, buf->len);
            buf->pos = 0;
        }
    }

    return result;
}

static inline int cgutils_buffer_add(cgutils_buffer * const buf,
                                     char const * const data,
                                     size_t const data_size)
{
    int result = 0;
    assert(buf != NULL);
    assert(data != NULL);
    assert((SIZE_MAX - buf->len) > data_size);

    result = cgutils_buffer_make_space_for(buf, data_size);

    if (result == 0)
    {
        memcpy(buf->data + buf->pos, data, data_size);
        buf->len += data_size;
    }

    return result;
}

static inline void cgutils_buffer_set_buffer(cgutils_buffer * const buf,
                                             char * const new_buf,
                                             size_t const new_buf_len)
{
    assert(new_buf != NULL);

    if (new_buf != NULL && new_buf_len > 0)
    {
        if (buf->data != NULL)
        {
            CGUTILS_FREE(buf->data);
        }

        buf->data = new_buf;
        buf->size = new_buf_len;
    }

    buf->pos = 0;
    buf->len = new_buf_len;
}

static inline void cgutils_buffer_get_readable_data(cgutils_buffer * const buf,
                                                    char const ** const ptr,
                                                    size_t * const ptr_len)
{
    assert(buf != NULL);
    assert(ptr != NULL);
    assert(ptr_len != NULL);

    if (buf->data != NULL && buf->len > 0)
    {
        *ptr = (buf->data + buf->pos);
        *ptr_len = buf->len;
    }
    else
    {
        *ptr = NULL;
        *ptr_len = 0;
    }
}

static inline void cgutils_buffer_get_writable_buf(cgutils_buffer * const buf,
                                                   char ** const ptr,
                                                   size_t * const ptr_size)
{
    assert(buf != NULL);
    assert(ptr != NULL);
    assert(ptr_size != NULL);

    if (buf->data != NULL)
    {
        *ptr = (buf->data + buf->pos + buf->len);
        *ptr_size = buf->size - (buf->pos + buf->len);
    }
    else
    {
        *ptr = NULL;
        *ptr_size = 0;
    }
}

static inline void cgutils_buffer_consume(cgutils_buffer * const buf,
                                          size_t const size)
{
    assert(buf != NULL);
    assert(buf->size >= size);
    assert(SIZE_MAX - buf->pos > buf->len);
    assert(SIZE_MAX - (buf->pos + buf->len) > size);
    assert(buf->len >= size);
    assert(buf->pos + size <= buf->size);

    buf->len -= size;
    buf->pos += size;
}

static inline void cgutils_buffer_add_readable(cgutils_buffer * const buf,
                                               size_t const size)
{
    assert(buf != NULL);
    assert(buf->data != NULL);
    assert(buf->size >= size);
    assert(cgutils_buffer_get_usable_size(buf) >= size);
    assert(SIZE_MAX - buf->len > size);

    buf->len += size;
}

#endif /* CLOUD_UTILS_BUFFER_H_ */
