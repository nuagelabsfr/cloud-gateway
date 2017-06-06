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

#ifndef CLOUD_UTILS_HTABLE_H_
#define CLOUD_UTILS_HTABLE_H_

#include <stdbool.h>

typedef struct cgutils_htable cgutils_htable;
typedef struct cgutils_htable_iterator cgutils_htable_iterator;

#include <cloudutils/cloudutils.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_htable_create(cgutils_htable ** table,
                          size_t table_size);

int cgutils_htable_easy_create(cgutils_htable **);

/* The key needs to exist for as long as the entry stays in the table */
int cgutils_htable_insert(cgutils_htable *,
                          char const * key,
                          void * value);
bool cgutils_htable_lookup(cgutils_htable const *,
                           char const * key) COMPILER_PURE_FUNCTION;

int cgutils_htable_get(cgutils_htable const *,
                       char const * key,
                       void ** value);

size_t cgutils_htable_get_count(cgutils_htable const * table) COMPILER_PURE_FUNCTION;

int cgutils_htable_remove(cgutils_htable *,
                          char const * key);

void cgutils_htable_free(cgutils_htable **,
                         cgutils_object_cleaner);


int cgutils_htable_get_iterator(cgutils_htable * htable,
                                cgutils_htable_iterator ** out);

size_t cgutils_htable_iterator_get_table_count(cgutils_htable_iterator const * it) COMPILER_PURE_FUNCTION;

bool cgutils_htable_iterator_next(cgutils_htable_iterator * const iterator);

void * cgutils_htable_iterator_get_value(cgutils_htable_iterator const * iterator) COMPILER_PURE_FUNCTION;

char const * cgutils_htable_iterator_get_key(cgutils_htable_iterator const * iterator) COMPILER_PURE_FUNCTION;

void cgutils_htable_iterator_free(cgutils_htable_iterator * iterator);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_HTABLE_H_ */
