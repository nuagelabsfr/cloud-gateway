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

#ifndef CGSMC_ASYNC_CONNECTION_H_
#define CGSMC_ASYNC_CONNECTION_H_

#include <netdb.h>
#include <stdbool.h>
#include <time.h>

typedef struct cgsmc_async_connection cgsmc_async_connection;

int cgsmc_async_connection_init(struct addrinfo * binding,
                                cgsmc_async_connection ** out);

int cgsmc_async_connection_get_fd(cgsmc_async_connection const * this);

bool cgsmc_async_connection_is_valid(cgsmc_async_connection * this);

void cgsmc_async_connection_increase_request_count(cgsmc_async_connection * this);

void cgsmc_async_connection_set_idle(cgsmc_async_connection * this);

size_t cgsmc_async_connection_get_request_count(cgsmc_async_connection const * this);

time_t cgsmc_async_connection_get_last_use(cgsmc_async_connection const * this);

time_t cgsmc_async_connection_get_creation_time(cgsmc_async_connection const * this);

void cgsmc_async_connection_free(cgsmc_async_connection * this);

static inline void cgsmc_async_connection_delete(void * this)
{
    cgsmc_async_connection_free(this);
}

#endif /* CGSMC_ASYNC_CONNECTION_H_ */
