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

#ifndef CLOUD_UTILS_POOL_H_
#define CLOUD_UTILS_POOL_H_

#include <stdbool.h>

typedef struct cgutils_pool cgutils_pool;

typedef void (cgutils_pool_releaser)(void * object);

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_pool_init(size_t pool_size,
                      cgutils_pool_releaser * releaser,
                      bool warn_on_full,
                      bool warn_on_empty,
                      cgutils_pool ** out);

int cgutils_pool_get(cgutils_pool * this,
                     void ** object);

int cgutils_pool_add(cgutils_pool * this,
                     void * object);

void cgutils_pool_free(cgutils_pool * this);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_POOL_H_ */
