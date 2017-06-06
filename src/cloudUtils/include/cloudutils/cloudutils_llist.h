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

#ifndef CLOUD_UTILS_LLIST_H_
#define CLOUD_UTILS_LLIST_H_

#include <stdlib.h>

typedef struct cgutils_llist cgutils_llist;
typedef struct cgutils_llist_elt cgutils_llist_elt;

#include <cloudutils/cloudutils.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

size_t cgutils_llist_get_count(cgutils_llist const *) COMPILER_PURE_FUNCTION;

int cgutils_llist_create(cgutils_llist **);
void cgutils_llist_free(cgutils_llist **,
                        cgutils_object_cleaner);
int cgutils_llist_insert(cgutils_llist *,
                         void * object);
int cgutils_llist_remove(cgutils_llist * list,
                         cgutils_llist_elt * elt);

int cgutils_llist_remove_by_object(cgutils_llist * list,
                                   void const * object);

cgutils_llist_elt * cgutils_llist_get_first(cgutils_llist * list) COMPILER_PURE_FUNCTION;
cgutils_llist_elt * cgutils_llist_get_last(cgutils_llist * list) COMPILER_PURE_FUNCTION;
cgutils_llist_elt * cgutils_llist_elt_get_next(cgutils_llist_elt * elt) COMPILER_PURE_FUNCTION;
cgutils_llist_elt * cgutils_llist_elt_get_previous(cgutils_llist_elt * elt) COMPILER_PURE_FUNCTION;

int cgutils_llist_elt_get_by_object(cgutils_llist * list,
                                    void const * object,
                                    cgutils_llist_elt ** out);

void * cgutils_llist_elt_get_object(cgutils_llist_elt * elt) COMPILER_PURE_FUNCTION;

static inline cgutils_llist_elt * cgutils_llist_get_iterator(cgutils_llist * const list)
{
    return cgutils_llist_get_first(list);
}

/* Add elements of llist list_to_add
   at the end of list_in.
   list_to_add does not have any more element
   after the merge but is _NOT_ freed. */
int cgutils_llist_merge(cgutils_llist * list_in,
                        cgutils_llist * list_to_add);


COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_LLIST_H_ */
