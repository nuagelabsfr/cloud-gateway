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

#ifndef CLOUDUTILS_RBTREE_H_
#define CLOUDUTILS_RBTREE_H_

typedef struct cgutils_rbtree cgutils_rbtree;
typedef struct cgutils_rbtree_node cgutils_rbtree_node;

/* Return:
   1 if a > b,
   -1 if a < b,
   0 otherwise.
*/
typedef int (cgutils_rbtree_compare)(void const * a,
                                     void const * b);

typedef void (cgutils_rbtree_key_delete)(void * key);
typedef void (cgutils_rbtree_value_delete)(void * value);

#include <cloudutils/cloudutils_compiler_specifics.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_rbtree_init(cgutils_rbtree_compare * compare,
                        cgutils_rbtree_key_delete * key_del,
                        cgutils_rbtree_value_delete * value_del,
                        cgutils_rbtree ** out);

void cgutils_rbtree_destroy(cgutils_rbtree * this);

int cgutils_rbtree_insert(cgutils_rbtree * this,
                          void * key,
                          void * value);

int cgutils_rbtree_remove(cgutils_rbtree * this,
                          cgutils_rbtree_node * node);

int cgutils_rbtree_get(cgutils_rbtree const * this,
                       void const * key,
                       cgutils_rbtree_node ** node);

void * cgutils_rbtree_node_get_value(cgutils_rbtree_node const * node);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUDUTILS_RBTREE_H_ */
