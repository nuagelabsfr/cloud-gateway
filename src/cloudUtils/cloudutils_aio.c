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

#include <evaio.h>

#include "cloudutils/cloudutils_aio.h"
#include "cloudutils/cloudutils_file.h"
#include "cloudutils_event_internal.h"

struct cgutils_aio
{
    evaio * aio;
};

typedef struct
{
    evaio_config config;
    cgutils_aio_cb * cb;
    void * cb_data;
    char * data;
    bool allocated;
} cgutils_aio_config;

static void cgutils_aio_config_free(cgutils_aio_config * this)
{
    if (COMPILER_LIKELY(this != NULL))
    {
        if (this->allocated == true)
        {
            CGUTILS_FREE(this->data);
        }

        CGUTILS_FREE(this);
    }
}

static void cgutils_aio_completion_handler(evaio * const aio,
                                           errno_t const status,
                                           size_t const transfered,
                                           void * const cb_data)
{
    assert(aio != NULL);
    assert(cb_data != NULL);

    cgutils_aio_config * this = cb_data;
    (void) aio;

    (this->cb)(status,
               transfered,
               this->cb_data);

    cgutils_aio_config_free(this);
}

static int cgutils_aio_config_init(evaio * const aio,
                                   void const * data,
                                   size_t const data_size,
                                   cgutils_aio_cb * const cb,
                                   void * cb_data,
                                   off_t const offset,
                                   int const fd,
                                   bool const allocate,
                                   cgutils_aio_config ** const config)
{
    assert(aio != NULL);
    assert(data != NULL || data_size == 0);
    assert(cb != NULL);
    assert(config != NULL);
    assert(fd >= 0);

    int result = 0;

    CGUTILS_ALLOCATE_STRUCT(*config);

    if (COMPILER_LIKELY(*config != NULL))
    {
        cgutils_aio_config * this = *config;

        this->cb = cb;
        this->cb_data = cb_data;

        if (allocate == true &&
            data_size > 0)
        {
            CGUTILS_MALLOC(this->data, data_size, sizeof *(this->data));

            if (COMPILER_LIKELY(this->data != NULL))
            {
                this->allocated = true;
                this->config.data = this->data;
                memcpy(this->data, data, data_size);
            }
            else
            {
                result = ENOMEM;
            }
        }
        else
        {
            this->config.data = data;
        }

        if (COMPILER_LIKELY(result == 0))
        {
            this->config.aio = aio;
            this->config.data_size = data_size;
            this->config.cb = &cgutils_aio_completion_handler;
            this->config.user_data = this;
            this->config.offset = offset;
            this->config.fd = fd;
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            cgutils_aio_config_free(*config), *config = NULL;
        }
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}


int cgutils_aio_read(cgutils_aio * const aio,
                     int const fd,
                     char * const buffer,
                     size_t const buffer_size,
                     off_t const offset,
                     cgutils_aio_cb * const cb,
                     void * const cb_data)
{
    int result = 0;

    if (COMPILER_LIKELY(aio != NULL &&
                        fd >= 0 &&
                        buffer != NULL &&
                        buffer_size > 0 &&
                        cb != NULL))
    {
        cgutils_aio_config * config = NULL;

        result = cgutils_aio_config_init(aio->aio,
                                         buffer,
                                         buffer_size,
                                         cb,
                                         cb_data,
                                         offset,
                                         fd,
                                         false,
                                         &config);

        if (COMPILER_LIKELY(result == 0))
        {
            result = evaio_read(&(config->config));

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error while trying to read: %d", result);
                cgutils_aio_config_free(config);
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating config: %d", result);
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgutils_aio_write(cgutils_aio * const aio,
                      int const fd,
                      char const * const buffer,
                      size_t const buffer_size,
                      off_t const offset,
                      cgutils_aio_cb * const cb,
                      void * const cb_data)
{
    int result = 0;

    if (COMPILER_LIKELY(aio != NULL &&
                        fd >= 0 &&
                        buffer != NULL &&
                        buffer_size > 0 &&
                        cb != NULL))
    {
        cgutils_aio_config * config = NULL;

        result = cgutils_aio_config_init(aio->aio,
                                         buffer,
                                         buffer_size,
                                         cb,
                                         cb_data,
                                         offset,
                                         fd,
                                         true,
                                         &config);

        if (COMPILER_LIKELY(result == 0))
        {
            result = evaio_write(&(config->config));

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error while trying to write: %d", result);
                cgutils_aio_config_free(config);
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating config: %d", result);
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgutils_aio_append(cgutils_aio * const aio,
                       int const fd,
                       char const * const buffer,
                       size_t const buffer_size,
                       cgutils_aio_cb * const cb,
                       void * const cb_data)
{
    int result = 0;

    if (COMPILER_LIKELY(aio != NULL &&
                        fd >= 0 &&
                        buffer != NULL &&
                        buffer_size > 0 &&
                        cb != NULL))
    {
        size_t offset = 0;

        result = cgutils_file_get_size(fd, &offset);

        if (COMPILER_LIKELY(result == 0))
        {
            cgutils_aio_config * config = NULL;

            result = cgutils_aio_config_init(aio->aio,
                                             buffer,
                                             buffer_size,
                                             cb,
                                             cb_data,
                                             (off_t) offset,
                                             fd,
                                             true,
                                             &config);

            if (COMPILER_LIKELY(result == 0))
            {
                result = evaio_write(&(config->config));

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error while trying to write: %d", result);
                    cgutils_aio_config_free(config);
                }
            }
            else
            {
                CGUTILS_ERROR("Error allocating config: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error getting file size: %d", result);
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgutils_aio_fsync(cgutils_aio * const aio,
                      int const fd,
                      int const op,
                      cgutils_aio_cb * const cb,
                      void * const cb_data)
{
    int result = 0;

    if (COMPILER_LIKELY(aio != NULL &&
                        fd != -1 &&
                        cb != NULL &&
                        (op == O_SYNC || op == O_DSYNC)))
    {
        cgutils_aio_config * config = NULL;

        result = cgutils_aio_config_init(aio->aio,
                                         NULL,
                                         0,
                                         cb,
                                         cb_data,
                                         0,
                                         fd,
                                         false,
                                         &config);

        if (COMPILER_LIKELY(result == 0))
        {
            result = evaio_fsync(&(config->config),
                                 op);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error while trying to read: %d", result);
                cgutils_aio_config_free(config);
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating config: %d", result);
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

void cgutils_aio_free(cgutils_aio * this)
{
    if (COMPILER_LIKELY(this != NULL))
    {
        if (this->aio != NULL)
        {
            evaio_del(this->aio), this->aio = NULL;
        }

        CGUTILS_FREE(this);
    }
}

int cgutils_aio_init(cgutils_event_data * const event_data,
                     cgutils_aio ** const aio)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(event_data != NULL && aio != NULL))
    {
        struct event_base * event_base = cgutils_event_get_base(event_data);

        assert(event_base != NULL);

        CGUTILS_ALLOCATE_STRUCT(*aio);

        if (COMPILER_LIKELY(*aio != NULL))
        {
            cgutils_aio * this = *aio;
            this->aio = evaio_new(event_base);

            if (COMPILER_LIKELY(this->aio != NULL))
            {
                result = 0;
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error creating evaio context: %d", result);
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                cgutils_aio_free(*aio), *aio = NULL;
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error creating evaio data: %d", result);
        }
    }

    return result;
}
