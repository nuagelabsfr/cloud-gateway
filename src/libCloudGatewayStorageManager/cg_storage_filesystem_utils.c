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
#include <time.h>

#include <cgsm/cg_storage_filesystem_utils.h>

void cg_storage_filesystem_return_to_handler(int const status,
                                             cg_storage_fs_cb_data * const data)
{
    CGUTILS_ASSERT(data != NULL);
    cg_storage_filesystem_handler * handler = cg_storage_fs_cb_data_get_handler(data);
    CGUTILS_ASSERT(handler != NULL);

    (*handler)(status, data);
}

void cg_storage_filesystem_timespec_to_uint64(struct timespec const * const ts,
                                              uint64_t * const out)
{
    time_t const now = time(NULL);
    CGUTILS_ASSERT(ts != NULL);
    CGUTILS_ASSERT(out != NULL);

    if (ts->tv_nsec != UTIME_OMIT)
    {
        if (ts->tv_nsec != UTIME_NOW &&
            ts->tv_sec > 0)
        {
            *out = (uint64_t) ts->tv_sec;
        }
        else
        {
            *out = (uint64_t) (now - 1);
        }
    }
    else
    {
        *out = 0;
    }
}

void cg_storage_filesystem_uint64_to_timespec(uint64_t const timestamp,
                                              struct timespec * const out)
{
    CGUTILS_ASSERT(out != NULL);

    out->tv_sec = (time_t) timestamp;
    out->tv_nsec = 0;
}

void cg_storage_filesystem_time_to_timespec(time_t const timestamp,
                                            struct timespec * const out)
{
    CGUTILS_ASSERT(out != NULL);

    out->tv_sec = timestamp;
    out->tv_nsec = 0;
}
