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

#ifndef CLOUD_UTILS_TIME_COUNTER_H_
#define CLOUD_UTILS_TIME_COUNTER_H_

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>

struct cgutils_time_counter
{
    struct timeval start;
    uint64_t sec_elapsed;
    uint64_t usec_elapsed;
    bool running;
};

typedef struct cgutils_time_counter cgutils_time_counter;

#include <cloudutils/cloudutils.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

void cgutils_time_counter_init(cgutils_time_counter * this);
void cgutils_time_counter_start(cgutils_time_counter * this);
void cgutils_time_counter_stop(cgutils_time_counter * this);
void cgutils_time_counter_to_milliseconds(cgutils_time_counter const * this,
                                          uint64_t * dest);
void cgutils_time_counter_print(cgutils_time_counter const * this);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_TIME_COUNTER_H_ */
