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

#ifndef CLOUDUTILS_VECTOR_H_
#define CLOUDUTILS_VECTOR_H_

typedef struct cgutils_vector cgutils_vector;

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_vector_init(size_t initial_size,
                        cgutils_vector ** vector);

int cgutils_vector_add(cgutils_vector * vector,
                       void * element);

int cgutils_vector_get(cgutils_vector const * vector,
                       size_t position,
                       void ** element);

int cgutils_vector_set(cgutils_vector * vector,
                       size_t position,
                       void * value);

size_t cgutils_vector_count(cgutils_vector const * vector);

void cgutils_vector_free(cgutils_vector * vector);

void cgutils_vector_deep_free(cgutils_vector ** vector,
                              void (*freer)(void *));

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUDUTILS_VECTOR_H_ */
