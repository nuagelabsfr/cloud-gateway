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

#ifndef CGFS_INODE_H_
#define CGFS_INODE_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>

typedef struct cgfs_inode cgfs_inode;

#include <cgfs_file_handler.h>

struct cgfs_inode
{
    struct stat attr;
//    cgfs_inode * lru_prev;
//    cgfs_inode * lru_next;
    /* contains a pointer to a dir FH
       for this inode, used to speed up lookup during readdir */
    cgfs_file_handler * dir_fh;

    /* number of kernel references
       to this inode number. */
    uint64_t lookup_count;
    /* number of references to this struct
       in memory */
    uint64_t ref_count;
    time_t last_dirtyness_notification;
};

#include <cloudutils/cloudutils.h>

int cgfs_inode_init(struct stat const * st,
                    cgfs_inode ** out);

bool cgfs_inode_is_dir(cgfs_inode const * this);

void cgfs_inode_update_attributes(cgfs_inode * this,
                                  struct stat const * attr,
                                  int cgfs_to_set);

void cgfs_inode_release(cgfs_inode * inode);

static inline uint64_t cgfs_inode_get_number(cgfs_inode const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->attr.st_ino;
}

#if 0
#define cgfs_inode_inc_ref_count(inode) \
    CGUTILS_ASSERT(inode != NULL);      \
    inode->ref_count++;                 \
    CGUTILS_DEBUG("Incrementing inode %"PRIu64" refcount to %zu", cgfs_inode_get_number(inode), inode->ref_count);
#else /* NDEBUG */
static inline void cgfs_inode_inc_ref_count(cgfs_inode * const this)
{
    CGUTILS_ASSERT(this != NULL);
    this->ref_count++;
}
#endif /* NDEBUG */

static inline void cgfs_inode_inc_lookup_count(cgfs_inode * const this)
{
    CGUTILS_ASSERT(this != NULL);
    this->lookup_count++;
}

static inline void cgfs_inode_dec_lookup_count(cgfs_inode * const this,
                                               size_t const lookup_count)
{
    CGUTILS_ASSERT(this != NULL);

    if (COMPILER_LIKELY(this->lookup_count >= lookup_count))
    {
        this->lookup_count -= lookup_count;
    }
    else
    {
        CGUTILS_WARN("Warning, decrementing lookup count of inode %"PRIu64" of more than the existing count (%zu / %zu)",
                     cgfs_inode_get_number(this),
                     lookup_count,
                     this->lookup_count);
        this->lookup_count = 0;
    }
}

static inline size_t cgfs_inode_get_lookup_count(cgfs_inode const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->lookup_count;
}

static inline size_t cgfs_inode_get_ref_count(cgfs_inode const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->ref_count;
}

static inline void cgfs_inode_update_ctime(cgfs_inode * const this)
{
    CGUTILS_ASSERT(this != NULL);
    this->attr.st_ctime = time(NULL);
}

static inline void cgfs_inode_update_atime(cgfs_inode * const this,
                                           time_t const atime)
{
    CGUTILS_ASSERT(this != NULL);
    this->attr.st_atime = atime;
    cgfs_inode_update_ctime(this);
}

static inline void cgfs_inode_update_mtime(cgfs_inode * const this,
                                           time_t const mtime)
{
    CGUTILS_ASSERT(this != NULL);
    this->attr.st_mtime = mtime;
    cgfs_inode_update_ctime(this);
}

static inline void cgfs_inode_decrement_link_count(cgfs_inode * const this)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->attr.st_nlink > 0);
    this->attr.st_nlink--;
    cgfs_inode_update_ctime(this);
}

static inline void cgfs_inode_increment_link_count(cgfs_inode * const this)
{
    CGUTILS_ASSERT(this != NULL);
    this->attr.st_nlink++;
    cgfs_inode_update_ctime(this);
}

static inline bool cgfs_inode_has_been_deleted(cgfs_inode const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->attr.st_nlink == 0;
}

static inline void cgfs_inode_update_dirty_notification(cgfs_inode * const this)
{
    CGUTILS_ASSERT(this != NULL);
    this->last_dirtyness_notification = time(NULL);
}

static inline cgfs_file_handler * cgfs_inode_get_dir_file_handler(cgfs_inode const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->dir_fh;
}

#endif /* CGFS_INODE_H_ */
