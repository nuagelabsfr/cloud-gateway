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

#include <cgfs.h>
#include <cgfs_inode.h>

int cgfs_inode_init(struct stat const * const st,
                    cgfs_inode ** const out)
{
    int result = 0;
    cgfs_inode * this = NULL;

    CGUTILS_ASSERT(st != NULL);
    CGUTILS_ASSERT(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(this);

    if (this != NULL)
    {
        this->ref_count = 1;
        this->attr = *st;
        *out = this;
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static void cgfs_inode_free(cgfs_inode * this)
{
    if (this != NULL)
    {
        CGUTILS_ASSERT(this->ref_count == 0);
/*        CGUTILS_ASSERT(this->lru_next == NULL);
        CGUTILS_ASSERT(this->lru_prev == NULL);
        this->lru_next = NULL;
        this->lru_prev = NULL;*/
        this->lookup_count = 0;
        CGUTILS_FREE(this);
    }
}

void cgfs_inode_release(cgfs_inode * const this)
{
    if (this != NULL)
    {
        CGUTILS_ASSERT(this->ref_count > 0);
        this->ref_count--;

        if (this->ref_count == 0)
        {
            cgfs_inode_free(this);
        }
    }
}

bool cgfs_inode_is_dir(cgfs_inode const * const this)
{
    CGUTILS_ASSERT(this != NULL);

    return S_ISDIR(this->attr.st_mode);
}

void cgfs_inode_update_attributes(cgfs_inode * const this,
                                  struct stat const * const attr,
                                  int const cgfs_to_set)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(attr != NULL);

    if (cgfs_to_set & CGFS_SET_ATTR_MODE)
    {
        this->attr.st_mode = attr->st_mode;
    }

    if (cgfs_to_set & CGFS_SET_ATTR_UID)
    {
        this->attr.st_uid = attr->st_uid;
    }

    if (cgfs_to_set & CGFS_SET_ATTR_GID)
    {
        this->attr.st_gid = attr->st_gid;
    }

    if (cgfs_to_set & CGFS_SET_ATTR_SIZE)
    {
        this->attr.st_size = attr->st_size;
        cgfs_inode_update_mtime(this,
                                time(NULL));
    }

    if (cgfs_to_set & CGFS_SET_ATTR_ATIME)
    {
        this->attr.st_atime = attr->st_atime;
        cgfs_inode_update_ctime(this);
    }

    if (cgfs_to_set & CGFS_SET_ATTR_MTIME)
    {
        this->attr.st_mtime = attr->st_mtime;
        cgfs_inode_update_ctime(this);
    }

    if (cgfs_to_set & CGFS_SET_ATTR_ATIME_NOW)
    {
        time_t const now = time(NULL);
        this->attr.st_atime = now;
        cgfs_inode_update_ctime(this);
    }

    if (cgfs_to_set & CGFS_SET_ATTR_MTIME_NOW)
    {
        time_t const now = time(NULL);
        this->attr.st_mtime = now;
        cgfs_inode_update_ctime(this);
    }
}
