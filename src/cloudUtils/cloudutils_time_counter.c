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

#include "cloudutils/cloudutils_time_counter.h"

static int cgutils_time_counter_subtract(struct timeval const * const x,
                                         struct timeval const * const y,
                                         struct timeval * const diff)
{
    assert(x != NULL);
    assert(y != NULL);
    assert(diff != NULL);

    int result = 0;
    struct timeval temp = *y;

    if (x->tv_usec < temp.tv_usec)
    {
        long int nsec = (temp.tv_usec - x->tv_usec) / 1000000 + 1;
        temp.tv_usec -= 1000000 * nsec;
        temp.tv_sec += nsec;
    }

    if (x->tv_usec - temp.tv_usec > 1000000)
    {
        long int nsec = (x->tv_usec - temp.tv_usec) / 1000000;
        temp.tv_usec += 1000000 * nsec;
        temp.tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
       tv_usec is certainly positive. */
    diff->tv_sec = x->tv_sec - temp.tv_sec;
    diff->tv_usec = x->tv_usec - temp.tv_usec;

    return result;
}

void cgutils_time_counter_init(cgutils_time_counter * const this)
{
    assert(this != NULL);
    *this = (cgutils_time_counter) { 0 };
}

void cgutils_time_counter_start(cgutils_time_counter * const this)
{
    assert(this != NULL && this->running == false);
    gettimeofday(&(this->start), NULL);
    this->running = true;
}

void cgutils_time_counter_stop(cgutils_time_counter * const this)
{
    int result = 0;
    struct timeval stop = { 0 };
    struct timeval diff = { 0 };
    assert(this != NULL && this->running == true);

    gettimeofday(&stop, NULL);

    result = cgutils_time_counter_subtract(&stop, &(this->start), &diff);

    if (COMPILER_LIKELY(result == 0))
    {
        this->sec_elapsed = (uint64_t) diff.tv_sec;
        this->usec_elapsed = (uint64_t) diff.tv_usec;
    }

    this->running = false;
}

inline void cgutils_time_counter_to_milliseconds(cgutils_time_counter const * const this,
                                                 uint64_t * const dest)
{
    assert(this != NULL && dest != NULL);
    *dest = (this->sec_elapsed * 1000) + (this->usec_elapsed / 1000);
}

void cgutils_time_counter_print(cgutils_time_counter const * const this)
{
    assert(this != NULL && this->running == false);

    (void) this;

    CGUTILS_DEBUG("Seconds elapsed: %"PRIu64, this->sec_elapsed);
    CGUTILS_DEBUG("Microseconds elapsed: %"PRIu64, this->usec_elapsed);
}
