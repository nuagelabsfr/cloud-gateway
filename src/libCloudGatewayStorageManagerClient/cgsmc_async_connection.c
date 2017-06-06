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

#include <errno.h>

#include <cgsmclient/cgsmc_async_connection.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_network.h>

struct cgsmc_async_connection
{
    size_t requests;
    time_t creation_time;
    time_t last_used;
    int sock;
};

int cgsmc_async_connection_init(struct addrinfo * const binding,
                                cgsmc_async_connection ** const out)
{
    int result = 0;
    int sock = -1;
    CGUTILS_ASSERT(binding != NULL);
    CGUTILS_ASSERT(out != NULL);

    result = cgutils_network_connect_to_socket(binding,
                                               true,
                                               &sock);

    if (COMPILER_LIKELY(result == 0))
    {
        cgsmc_async_connection * this = NULL;
        CGUTILS_ALLOCATE_STRUCT(this);

        if (COMPILER_LIKELY(this != NULL))
        {
            this->sock = sock;
            this->creation_time = time(NULL);

            *out = this;
        }
        else
        {
            result = ENOMEM;
        }
    }
    else
    {
        CGUTILS_ERROR("Error connecting to the storage manager: %d",
                      result);
    }

    return result;
}

int cgsmc_async_connection_get_fd(cgsmc_async_connection const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->sock;
}

bool cgsmc_async_connection_is_valid(cgsmc_async_connection * const this)
{
    bool result = false;
    CGUTILS_ASSERT(this != NULL);

    int res = cgutils_network_check_socket_usability(this->sock,
                                                     &result);

    if (COMPILER_UNLIKELY(res != 0))
    {
        CGUTILS_ERROR("Error while checking socket usability: %d",
                      result);
    }

    return result;
}

void cgsmc_async_connection_increase_request_count(cgsmc_async_connection * const this)
{
    CGUTILS_ASSERT(this != NULL);
    this->requests++;
}

void cgsmc_async_connection_set_idle(cgsmc_async_connection * const this)
{
    CGUTILS_ASSERT(this != NULL);
    this->last_used = time(NULL);
}

size_t cgsmc_async_connection_get_request_count(cgsmc_async_connection const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->requests;
}

time_t cgsmc_async_connection_get_last_use(cgsmc_async_connection const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->last_used;
}

time_t cgsmc_async_connection_get_creation_time(cgsmc_async_connection const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->creation_time;
}

void cgsmc_async_connection_free(cgsmc_async_connection * this)
{
    if (this != NULL)
    {
        if (this->sock != -1)
        {
            /* FIXME / TODO handle shutdown gracefully (we need to shutdown(SHUT_WR), read until EOF, then only close the FD) */
            shutdown(this->sock, SHUT_RDWR);
            cgutils_file_close(this->sock);
            this->sock = -1;
        }

        CGUTILS_FREE(this);
    }
}
