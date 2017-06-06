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

#include <cloudutils/cloudutils_rbtree.h>

#include "cgfs_cache.h"

struct cgfs_cache
{
    cgutils_rbtree * tree;
    size_t count;
};

static int cgfs_cache_btree_compare_key(void const * const a,
                                        void const * const b)
{
    int result = 0;
    uint64_t const * const tmp_a = a;
    uint64_t const * const tmp_b = b;
    CGUTILS_ASSERT(tmp_a != NULL);
    CGUTILS_ASSERT(tmp_b != NULL);

    if (*tmp_a > *tmp_b)
    {
        result = 1;
    }
    else if (*tmp_a < *tmp_b)
    {
        result = -1;
    }

    return result;
}

static void cgfs_cache_btree_release_key(void * key)
{
    CGUTILS_ASSERT(key != NULL);
    /* key will be released when the "value" eg the inode is
       released. */

    (void) key;
}

static void cgfs_cache_btree_release_value(void * value)
{
    cgfs_inode * inode = value;
    CGUTILS_ASSERT(inode != NULL);

    cgfs_inode_release(inode);
}

int cgfs_cache_lookup_child(cgfs_cache * const this,
                            uint64_t const parent_ino,
                            char const * const name,
                            cgfs_inode ** const out)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(parent_ino > 0);
    CGUTILS_ASSERT(name != NULL);
    CGUTILS_ASSERT(out != NULL);

    /* Not implemented for now */
    (void) this;
    (void) parent_ino;
    (void) name;
    (void) out;

    return ENOENT;
}

int cgfs_cache_lookup(cgfs_cache * const this,
                      uint64_t const ino,
                      cgfs_inode ** const out)
{
    cgutils_rbtree_node * node = NULL;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->tree != NULL);
    CGUTILS_ASSERT(out != NULL);

    int result = cgutils_rbtree_get(this->tree,
                                    &ino,
                                    &node);

    if (COMPILER_LIKELY(result == 0))
    {
        cgfs_inode * const inode = cgutils_rbtree_node_get_value(node);
        cgfs_inode_inc_ref_count(inode);
        *out = inode;
    }
    else if (result != ENOENT)
    {
        CGUTILS_ERROR("Error looking up inode %"PRIu64" from the cache tree: %d",
                      ino,
                      result);
    }

    return result;
}

int cgfs_cache_remove(cgfs_cache * const this,
                      uint64_t const ino)
{
    cgutils_rbtree_node * node = NULL;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->tree != NULL);

    int result = cgutils_rbtree_get(this->tree,
                                    &ino,
                                    &node);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cgutils_rbtree_remove(this->tree,
                                       node);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error removing inode %"PRIu64" from the cache tree: %d",
                          ino,
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error looking up inode %"PRIu64" for removal from the cache tree: %d",
                      ino,
                      result);
    }

    return result;
}

int cgfs_cache_add(cgfs_cache * const this,
                   cgfs_inode * const inode)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->tree != NULL);
    CGUTILS_ASSERT(inode != NULL);

    int result = cgutils_rbtree_insert(this->tree,
                                       &(inode->attr.st_ino),
                                       inode);

    if (COMPILER_LIKELY(result == 0))
    {
        /* do not forget to increment the inode refcount */
        cgfs_inode_inc_ref_count(inode);
    }

    return result;
}

int cgfs_cache_init(cgfs_cache ** const out)
{
    int result = 0;
    cgfs_cache * this = NULL;
    CGUTILS_ASSERT(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(this);

    if (this != NULL)
    {
        result = cgutils_rbtree_init(&cgfs_cache_btree_compare_key,
                                     &cgfs_cache_btree_release_key,
                                     &cgfs_cache_btree_release_value,
                                     &(this->tree));

        if (result == 0)
        {
            this->count = 0;

            *out = this;
        }
        else
        {
            CGUTILS_ERROR("Error creating the cache tree: %d",
                          result);
            cgfs_cache_free(this), this = NULL;
        }
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

void cgfs_cache_free(cgfs_cache * this)
{
    if (this != NULL)
    {
        if (this->tree != NULL)
        {
            cgutils_rbtree_destroy(this->tree), this->tree = NULL;
        }

        this->count = 0;

        CGUTILS_FREE(this);
    }
}
