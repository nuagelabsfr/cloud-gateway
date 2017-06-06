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

#include "cloudutils/cloudutils_advanced_file_ops.h"
#include "cloudutils/cloudutils_crypto.h"
#include "cloudutils/cloudutils_file.h"

#define CGUTILS_FILE_READ_BUFFER_SIZE (16384)
#define CGUTILS_FILE_WRITE_BUFFER_SIZE (16384)

typedef struct
{
    cgutils_crypto_hash_context * hash_context;
    cgutils_aio * aio;
    cgutils_file_hash_cb * cb;
    void * cb_data;

    char * buffer;
    size_t buffer_size;
    size_t file_size;
    size_t got;

    int fd;

} cgutils_file_hash_data;

static void cgutils_file_hash_data_free(cgutils_file_hash_data * data)
{
    if (data != NULL)
    {
        if (data->hash_context != NULL)
        {
            cgutils_crypto_hash_context_free(data->hash_context);
        }

        if (data->fd >= 0)
        {
            cgutils_file_close(data->fd), data->fd = -1;
        }

        data->aio = NULL;
        data->buffer = NULL;
        data->buffer_size = 0;
        data->file_size = 0;
        data->got = 0;

        CGUTILS_FREE(data);
    }
}

static int cgutils_file_hash_read_done(int const status,
                                       size_t const completion,
                                       void * const cb_data)
{
    assert(cb_data != NULL);

    int result = status;
    void * hash = NULL;
    size_t hash_size = 0;
    cgutils_file_hash_data * data = cb_data;

    if (result == 0)
    {
        if (completion > 0)
        {
            result = cgutils_crypto_hash_context_update(data->hash_context,
                                                        data->buffer,
                                                        completion);

            if (result == 0)
            {
                assert(SIZE_MAX - data->got >= completion);

                data->got += completion;

                if (data->got == data->file_size)
                {
                    result = cgutils_crypto_hash_context_finish(data->hash_context,
                                                                &hash,
                                                                &hash_size);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error finishing context: %d", result);
                    }
                }
            }
            else
            {
                CGUTILS_ERROR("Error updating context: %d", result);
            }
        }

        if (result == 0 && data->got < data->file_size)
        {
            result = cgutils_aio_read(data->aio,
                                      data->fd,
                                      data->buffer,
                                      data->buffer_size,
                                      (off_t) data->got,
                                      &cgutils_file_hash_read_done,
                                      data);
        }

    }
    else
    {
        CGUTILS_WARN("Got result of %d", result);

        if (result == EAGAIN || result == EWOULDBLOCK ||
            result == EINTR)
        {
            result = 0;
        }
    }

    if (result != 0 || data->got == data->file_size)
    {
        (*(data->cb))(result,
                      hash,
                      hash_size,
                      data->cb_data);

        cgutils_file_hash_data_free(data), data = NULL;
    }

    return result;
}

int cgutils_file_hash(cgutils_aio * const aio,
                      char const * const path,
                      cgutils_crypto_digest_algorithm const algorithm,
                      cgutils_file_hash_cb * const cb,
                      void * const cb_data)
{
    int result = EINVAL;

    if (aio != NULL && path != NULL && cb != NULL && cb_data != NULL)
    {
        if (cgutils_file_exists(path) == true)
        {
            size_t const buffer_size = CGUTILS_FILE_READ_BUFFER_SIZE;

            cgutils_file_hash_data * data = NULL;

            CGUTILS_MALLOC(data, 1, sizeof *data + buffer_size);

            if (data != NULL)
            {
                *data = (cgutils_file_hash_data) { 0 };

                data->aio = aio;

                data->buffer = (void*) (data + 1);
                data->buffer_size = buffer_size;

                data->cb = cb;
                data->cb_data = cb_data;

                result = cgutils_file_open(path,
                                           O_RDONLY | O_NONBLOCK,
                                           0,
                                           &(data->fd));

                if (result == 0)
                {
                    result = cgutils_file_get_size(data->fd,
                                                   &(data->file_size));

                    if (result == 0)
                    {
                        result = cgutils_crypto_hash_context_init(algorithm,
                                                                  &(data->hash_context));

                        if (result == 0)
                        {
                            result = cgutils_aio_read(data->aio,
                                                      data->fd,
                                                      data->buffer,
                                                      data->buffer_size,
                                                      (off_t) data->got,
                                                      &cgutils_file_hash_read_done,
                                                      data);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error adding aio read: %d", result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error in context init: %d", result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error getting size: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error opening file: %d", result);
                }

                if (result != 0)
                {
                    cgutils_file_hash_data_free(data), data = NULL;
                }
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for file %s: %d", path, result);
            }
        }
        else
        {
            result = ENOENT;
            CGUTILS_ERROR("Error looking for file %s: %d", path, result);
        }
    }

    return result;
}

int cgutils_file_descriptor_hash_sync(int const fd,
                                      cgutils_crypto_digest_algorithm const algorithm,
                                      void ** const hash,
                                      size_t * const hash_size)
{
    int result = EINVAL;

    if (fd >= 0 && hash != NULL && hash_size != NULL)
    {
        size_t const buffer_size = CGUTILS_FILE_READ_BUFFER_SIZE;
        char * buffer = NULL;

        CGUTILS_MALLOC(buffer, buffer_size, sizeof *buffer);

        if (buffer != NULL)
        {
            cgutils_crypto_hash_context * ctx = NULL;

            result = cgutils_crypto_hash_context_init(algorithm,
                                                      &ctx);

            if (result == 0)
            {
                off_t before = (off_t) -1;

                result = cgutils_file_tell(fd, &before);

                if (result == 0)
                {
                    result = cgutils_file_lseek(fd, SEEK_SET, 0);

                    if (result == 0)
                    {
                        size_t got = 0;

                        do
                        {
                            result = cgutils_file_read(fd,
                                                       buffer,
                                                       buffer_size,
                                                       &got);

                            if (COMPILER_LIKELY(result == 0))
                            {
                                if (COMPILER_LIKELY(got > 0))
                                {
                                    result = cgutils_crypto_hash_context_update(ctx,
                                                                                buffer,
                                                                                got);
                                    if (COMPILER_UNLIKELY(result != 0))
                                    {
                                        CGUTILS_ERROR("Error updating hash context: %d", result);
                                    }
                                }
                            }
                            else
                            {
                                CGUTILS_ERROR("Error while reading file: %d",
                                              result);
                            }
                        }
                        while (result == 0 &&
                               got > 0);

                        int res = cgutils_file_lseek(fd, SEEK_SET, before);

                        if (res != 0)
                        {
                            CGUTILS_ERROR("Error while setting file pos back: %d", res);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error while setting file pos to 0: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error while getting file position: %d", result);
                }

                if (result == 0)
                {
                    result = cgutils_crypto_hash_context_finish(ctx, hash, hash_size);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error finishing hash: %d", result);
                    }
                }

                cgutils_crypto_hash_context_free(ctx), ctx = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error in context init: %d", result);
            }

            CGUTILS_FREE(buffer), buffer = NULL;
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for file: %d", result);
        }
    }

    return result;
}

int cgutils_file_hash_sync(char const * const path,
                           cgutils_crypto_digest_algorithm const algorithm,
                           void ** const hash,
                           size_t * const hash_size)
{
    int result = EINVAL;

    if (path != NULL && hash != NULL && hash_size != NULL)
    {
        if (cgutils_file_exists(path) == true)
        {
            size_t const buffer_size = CGUTILS_FILE_READ_BUFFER_SIZE;
            char * buffer = NULL;

            CGUTILS_MALLOC(buffer, buffer_size, sizeof *buffer);

            if (buffer != NULL)
            {
                int fd = -1;

                result = cgutils_file_open(path,
                                           O_RDONLY,
                                           0,
                                           &fd);

                if (result == 0)
                {
                    result = cgutils_file_descriptor_hash_sync(fd, algorithm, hash, hash_size);

                    cgutils_file_close(fd), fd = -1;
                }
                else
                {
                    CGUTILS_ERROR("Error opening file %s: %d", path, result);
                }

                CGUTILS_FREE(buffer), buffer = NULL;
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for file %s: %d", path, result);
            }
        }
        else
        {
            result = ENOENT;
            CGUTILS_ERROR("Error looking for file %s: %d", path, result);
        }
    }

    return result;
}

int cgutils_file_fill_with_pseudo_random_data(int const fd,
                                              size_t const file_size)
{
    int result = EINVAL;

    if (fd >= 0 && file_size > 0)
    {
        size_t const buffer_size = file_size > CGUTILS_FILE_WRITE_BUFFER_SIZE ?
            CGUTILS_FILE_WRITE_BUFFER_SIZE : file_size;
        char * buffer = NULL;

        CGUTILS_MALLOC(buffer, buffer_size, sizeof *buffer);

        if (buffer != NULL)
        {
            result = cgutils_file_lseek(fd, SEEK_SET, 0);

            if (result == 0)
            {
                size_t remaining = file_size;

                do
                {
                    size_t const to_write = remaining > buffer_size ? buffer_size : remaining;
                    result = cgutils_crypto_get_pseudo_random_bytes(buffer,
                                                                    to_write);

                    if (COMPILER_LIKELY(result == 0))
                    {
                        size_t res = 0;

                        result = cgutils_file_write(fd,
                                                    buffer,
                                                    to_write,
                                                    &res);

                        if (COMPILER_LIKELY(result == 0))
                        {
                            if (COMPILER_LIKELY(res > 0))
                            {
                                remaining -= (size_t) res;
                            }
                        }
                        else
                        {
                            if (result != EINTR)
                            {
                                CGUTILS_ERROR("Error writing pseudo random bytes to file: %d", result);
                            }
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error getting pseudo random bytes: %d", result);
                    }
                }
                while (remaining > 0 &&
                       (result == 0 ||
                        result == EINTR));
            }
            else
            {
                CGUTILS_ERROR("Error setting file position to start of file: %d", result);
            }

            int res = cgutils_file_lseek(fd, SEEK_SET, 0);

            if (res != 0)
            {
                CGUTILS_ERROR("Error while setting file pos back: %d", res);
            }

            CGUTILS_FREE(buffer);
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_file_fill_with_urandom_data(int const fd,
                                        size_t const file_size)
{
    int result = EINVAL;

    if (fd >= 0 && file_size > 0)
    {
        int urandom_fd = -1;

        result = cgutils_file_open("/dev/urandom",
                                   O_RDONLY,
                                   0,
                                   &urandom_fd);

        if (result == 0)
        {
            size_t const buffer_size = file_size > CGUTILS_FILE_WRITE_BUFFER_SIZE ?
                CGUTILS_FILE_WRITE_BUFFER_SIZE : file_size;
            char * buffer = NULL;

            CGUTILS_MALLOC(buffer, buffer_size, sizeof *buffer);

            if (buffer != NULL)
            {
                result = cgutils_file_lseek(fd, SEEK_SET, 0);

                if (result == 0)
                {
                    size_t remaining = file_size;
                    size_t to_write = 0;
                    size_t pos = 0;

                    do
                    {
                        size_t const to_get = remaining > buffer_size ? buffer_size : remaining;

                        to_write = 0;

                        result = cgutils_file_read(urandom_fd,
                                                   buffer,
                                                   to_get,
                                                   &to_write);

                        if (COMPILER_LIKELY(result == 0))
                        {
                            if (COMPILER_LIKELY(to_write > 0))
                            {
                                pos = 0;
                            }
                            else if (to_write == 0)
                            {
                                result = EIO;
                                CGUTILS_ERROR("Error, got EOF while reading data from /dev/urandom");
                            }
                        }
                        else
                        {
                            if (result == EINTR)
                            {
                                result = 0;
                            }
                            else
                            {
                                CGUTILS_ERROR("Error getting data from /dev/urandom: %d", result);
                            }
                        }

                        if (COMPILER_LIKELY(result == 0 &&
                                            to_write > 0))
                        {
                            size_t res = 0;

                            result = cgutils_file_write(fd,
                                                        buffer + pos,
                                                        to_write,
                                                        &res);

                            if (COMPILER_LIKELY(result == 0))
                            {
                                if (COMPILER_LIKELY(res > 0))
                                {
                                    remaining -= (size_t) res;
                                    pos += (size_t) res;
                                }
                            }
                            else
                            {
                                if (result == EINTR)
                                {
                                    result = 0;
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error writing pseudo random bytes to file: %d", result);
                                }
                            }
                        }
                    }
                    while (remaining > 0 &&
                           result == 0);
                }
                else
                {
                    CGUTILS_ERROR("Error setting file position to start of file: %d", result);
                }

                int res = cgutils_file_lseek(fd, SEEK_SET, 0);

                if (res != 0)
                {
                    CGUTILS_ERROR("Error while setting file pos back: %d", res);
                }

                CGUTILS_FREE(buffer);
            }
            else
            {
                result = ENOMEM;
            }

            cgutils_file_close(urandom_fd), urandom_fd = -1;
        }
        else
        {
            CGUTILS_ERROR("Error opening /dev/urandom: %d", result);
        }
    }

    return result;
}
