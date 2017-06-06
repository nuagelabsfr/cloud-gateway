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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#include "cgsm/cg_storage_filesystem.h"
#include "cgsm/cg_storage_object.h"
#include "cgsm/cg_storage_manager_proto.h"

#include <cloudutils/cloudutils.h>

#include <cgdb/cgdb.h>

struct cg_storage_object
{
    cgdb_entry entry;
    cg_storage_filesystem * fs;
    bool exists_in_db;
};

void cg_storage_object_free(cg_storage_object * obj)
{
    if (obj != NULL)
    {
        cgdb_entry_clean(&(obj->entry));

        obj->fs = NULL;
        obj->exists_in_db = false;

        CGUTILS_FREE(obj);
    }
}

int cg_storage_object_new(cg_storage_filesystem * const fs,
                          char const * const name,
                          cgdb_entry_type const type,
                          mode_t const mode,
                          time_t const atime,
                          time_t const ctime,
                          time_t const mtime,
                          time_t const last_usage,
                          time_t const last_modification,
                          uid_t const owner,
                          gid_t const group,
                          char const * const link_to,
                          cg_storage_object ** const obj)
{
    int result = EINVAL;

    if (fs != NULL &&
        name != NULL &&
        obj != NULL &&
        (link_to != NULL ||
         type != CGDB_OBJECT_TYPE_SYMLINK ))
    {
        CGUTILS_ALLOCATE_STRUCT(*obj);

        if (*obj != NULL)
        {
            cgdb_entry * entry = &((*obj)->entry);
            cgdb_inode * inode = &(entry->inode);

            (*obj)->fs = fs;
            (*obj)->exists_in_db = false;
            *entry = (cgdb_entry) { 0 };
            inode->st.st_nlink = 1;

            entry->name = cgutils_strdup(name);

            if (entry->name != NULL)
            {
                result = 0;

                if (type == CGDB_OBJECT_TYPE_SYMLINK &&
                    link_to != NULL)
                {
                    entry->link_to = cgutils_strdup(link_to);

                    if (entry->link_to == NULL)
                    {
                        result = ENOMEM;
                    }
                }

                if (result == 0)
                {
                    entry->type = type;
                    entry->fs_id = cg_storage_filesystem_get_id(fs);
                    inode->last_usage = (uint64_t) last_usage;
                    inode->last_modification = (uint64_t) last_modification;
                    inode->digest = NULL;
                    inode->dirty_writers = 0;
                    inode->inode_number = 0;
                    inode->in_cache = false;
                    inode->st.st_nlink = 1;
                    inode->st.st_uid = owner;
                    inode->st.st_gid = group;
                    inode->st.st_atime = atime;
                    inode->st.st_ctime = ctime;
                    inode->st.st_mtime = mtime;
                    inode->st.st_blksize = cg_storage_filesystem_get_io_block_size(fs);

                    if (type == CGDB_OBJECT_TYPE_SYMLINK &&
                        link_to != NULL)
                    {
                        size_t const to_len = strlen(link_to);

                        if (to_len <= LONG_MAX)
                        {
                            inode->st.st_size = (long) to_len;
                        }

                        /* Symlink permissions are irrelevant,
                           only user and group are used for link
                           removal or renaming in a sticky directory */
                        inode->st.st_mode = S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO;
                    }
                    else
                    {
                        inode->st.st_mode = mode;

                        if (entry->type == CGDB_OBJECT_TYPE_FILE
                            && inode->st.st_size > 0 )
                        {
                            inode->st.st_blocks = (inode->st.st_size +
                                                   (CG_STORAGE_MANAGER_BLOCK_SIZE - 1)) /
                                CG_STORAGE_MANAGER_BLOCK_SIZE;
                        }
                    }
                }
            }
            else
            {
                result = ENOMEM;
            }

            if (result != 0)
            {
                cg_storage_object_free(*obj), *obj = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cg_storage_object_fix_entry_block(cg_storage_filesystem const * const fs,
                                      cgdb_entry * const entry)
{
    int result = EINVAL;

    if (fs != NULL &&
        entry != NULL)
    {
        entry->inode.st.st_blksize = cg_storage_filesystem_get_io_block_size(fs);

        if (entry->type == CGDB_OBJECT_TYPE_FILE
            && entry->inode.st.st_size > 0 )
        {
            entry->inode.st.st_blocks = (entry->inode.st.st_size +
                                         (CG_STORAGE_MANAGER_BLOCK_SIZE - 1)) /
              CG_STORAGE_MANAGER_BLOCK_SIZE;
        }
    }

    return result;
}

int cg_storage_object_fix_block(cg_storage_object * const this)
{
    int result = EINVAL;

    if (this != NULL)
    {
        result = cg_storage_object_fix_entry_block(this->fs,
                                                   &this->entry);
    }

    return result;
}

int cg_storage_object_init_from_entry(cg_storage_filesystem * const fs,
                                      cgdb_entry const * const entry,
                                      cg_storage_object ** const obj)
{
    int result = EINVAL;

    if (fs != NULL &&
        entry != NULL &&
        obj != NULL)
    {
        CGUTILS_ALLOCATE_STRUCT(*obj);

        if (*obj != NULL)
        {
            cgdb_entry * obj_entry = &((*obj)->entry);
            cgdb_inode * obj_inode = &(obj_entry->inode);

            (*obj)->fs = fs;
            (*obj)->exists_in_db = false;

            *obj_entry = *entry;

            result = 0;

            if (entry->name != NULL)
            {
                obj_entry->name = cgutils_strdup(entry->name);

                if (obj_entry->name == NULL)
                {
                    result = ENOMEM;
                }
            }

            if (result == 0)
            {
                if (entry->link_to != NULL)
                {
                    obj_entry->link_to = cgutils_strdup(entry->link_to);

                    if (obj_entry->link_to == NULL)
                    {
                        result = ENOMEM;
                    }
                }

                if (result == 0)
                {
                    assert(((ino_t) entry->inode.inode_number) == entry->inode.st.st_ino);

                    *obj_inode = entry->inode;

                    if (entry->inode.digest != NULL)
                    {
                        obj_inode->digest = cgutils_strdup(entry->inode.digest);

                        if (obj_inode->digest == NULL)
                        {
                            result = ENOMEM;
                        }
                    }

                    cg_storage_object_fix_block(*obj);
                }
            }

            if (result != 0)
            {
                cg_storage_object_free(*obj), *obj = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cg_storage_object_init_from_inode(cg_storage_filesystem * const fs,
                                      cgdb_inode const * const inode,
                                      char const * const name,
                                      cgdb_entry_type const type,
                                      cg_storage_object ** const obj)
{
    int result = EINVAL;

    if (fs != NULL &&
        inode != NULL &&
        obj != NULL)
    {
        CGUTILS_ALLOCATE_STRUCT(*obj);

        if (*obj != NULL)
        {
            cgdb_entry * obj_entry = &((*obj)->entry);
            cgdb_inode * obj_inode = &(obj_entry->inode);

            (*obj)->fs = fs;
            (*obj)->exists_in_db = false;

            *obj_entry = (cgdb_entry) { 0 };

            result = 0;

            if (name != NULL)
            {
                obj_entry->name = cgutils_strdup(name);

                if (obj_entry->name == NULL)
                {
                    result = ENOMEM;
                }
            }

            if (result == 0)
            {
                obj_entry->type = type;
                obj_entry->fs_id = cg_storage_filesystem_get_id(fs);

                *obj_inode = *inode;

                if (inode->digest != NULL)
                {
                    obj_inode->digest = cgutils_strdup(inode->digest);

                    if (obj_inode->digest == NULL)
                    {
                        result = ENOMEM;
                    }
                }

                cg_storage_object_fix_block(*obj);
            }

            if (result != 0)
            {
                cg_storage_object_free(*obj), *obj = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

cgdb_entry_type cg_storage_object_mode_to_type(mode_t const mode)
{
    cgdb_entry_type result = CGDB_OBJECT_TYPE_INVALID;

    if (S_ISLNK(mode))
    {
        result = CGDB_OBJECT_TYPE_SYMLINK;
    }
    else if (S_ISDIR(mode))
    {
        result = CGDB_OBJECT_TYPE_DIRECTORY;
    }
    else if (S_ISREG(mode))
    {
        result = CGDB_OBJECT_TYPE_FILE;
    }

    return result;
}

char const * cg_storage_object_get_link_to(cg_storage_object const * const this)
{
    char const * result = NULL;

    if (this != NULL &&
        this->entry.type == CGDB_OBJECT_TYPE_SYMLINK)
    {
        result = this->entry.link_to;
    }

    return result;
}

int cg_storage_object_get_stat(cg_storage_object const * const this,
                               struct stat * const st_out)
{
    int result = EINVAL;

    if (this != NULL && st_out != NULL)
    {
        result = 0;
        *st_out = this->entry.inode.st;
    }

    return result;
}

bool cg_storage_object_is_symlink(cg_storage_object const * const this)
{
    bool result = false;

    if (this != NULL &&
        this->entry.type == CGDB_OBJECT_TYPE_SYMLINK)
    {
        result = true;
    }

    return result;
}

bool cg_storage_object_is_file(cg_storage_object const * const this)
{
    bool result = false;

    if (this != NULL &&
        this->entry.type == CGDB_OBJECT_TYPE_FILE)
    {
        result = true;
    }

    return result;
}

bool cg_storage_object_is_directory(cg_storage_object const * const this)
{
    bool result = false;

    if (this != NULL &&
        this->entry.type == CGDB_OBJECT_TYPE_DIRECTORY)
    {
        result = true;
    }

    return result;
}

bool cg_storage_object_is_inode_marked_as_in_cache(cg_storage_object const * const this)
{
    bool result = false;

    if (this != NULL)
    {
        result = this->entry.inode.in_cache;
    }

    return result;
}

uint64_t cg_storage_object_get_inode_number(cg_storage_object const * const this)
{
    uint64_t result = 0;

    if (this != NULL)
    {
        result = this->entry.inode.inode_number;
    }

    return result;
}

uint64_t cg_storage_object_get_entry_id(cg_storage_object const * const this)
{
    uint64_t result = 0;

    if (this != NULL)
    {
        result = this->entry.entry_id;
    }

    return result;
}

char const * cg_storage_object_get_entry_name(cg_storage_object const * const this)
{
    char const * result = NULL;

    if (this != NULL)
    {
        result = this->entry.name;
    }

    return result;
}

int cg_storage_object_get_entry(cg_storage_object * const this,
                                cgdb_entry ** const entry)
{
    int result = EINVAL;

    if (this != NULL &&
        entry != NULL)
    {
        result = 0;
        *entry = &(this->entry);
    }

    return result;
}

int cg_storage_object_get_inode(cg_storage_object * const this,
                                cgdb_inode const ** const inode)
{
    int result = EINVAL;

    if (this != NULL &&
        inode != NULL)
    {
        result = 0;
        *inode = &(this->entry.inode);
    }

    return result;
}

size_t cg_storage_object_get_size(cg_storage_object const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        if (this->entry.inode.st.st_size > 0)
        {
            COMPILER_STATIC_ASSERT(sizeof (off_t) <= sizeof (size_t),
                "off_t type is bigger than size_t");

            result = (size_t) this->entry.inode.st.st_size;
        }
    }

    return result;
}

size_t cg_storage_object_get_nlink(cg_storage_object const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        result = this->entry.inode.st.st_nlink;
    }

    return result;
}

time_t cg_storage_object_get_atime(cg_storage_object const * const this)
{
    time_t result = 0;

    if (this != NULL)
    {
        result = this->entry.inode.st.st_atime;
    }

    return result;
}

time_t cg_storage_object_get_mtime(cg_storage_object const * const this)
{
    time_t result = 0;

    if (this != NULL)
    {
        result = this->entry.inode.st.st_mtime;
    }

    return result;
}

int cg_storage_object_get_inode_digest(cg_storage_object const * const this,
                                       cgutils_crypto_digest_algorithm * const algo,
                                       void const ** const digest,
                                       size_t * const digest_size)
{
    int result = EINVAL;

    if (this != NULL &&
        algo != NULL &&
        digest != NULL &&
        digest_size != NULL)
    {
        *algo = this->entry.inode.digest_type;
        *digest = this->entry.inode.digest;
        *digest_size = this->entry.inode.digest_size;
        result = 0;
    }

    return result;
}

int cg_storage_object_refresh_from_cache_if_needed(cg_storage_object * const this,
                                                   char const * const path_in_cache)
{
    int result = EINVAL;

    if (this != NULL &&
        path_in_cache != NULL)
    {
        struct stat cache_st;

        result = cgutils_file_stat(path_in_cache, &cache_st);

        if (result == 0)
        {
            if (this->entry.inode.st.st_mtime <= cache_st.st_mtime)
            {
                this->entry.inode.st.st_size = cache_st.st_size;
                this->entry.inode.st.st_atime = cache_st.st_atime;
                this->entry.inode.st.st_mtime = cache_st.st_mtime;
            }
        }
        else
        {
            if (result == ENOENT)
            {
                result = 0;
            }
        }
    }

    return result;
}

size_t cg_storage_object_get_dirty_writers_count(cg_storage_object const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        result = this->entry.inode.dirty_writers;
    }

    return result;
}

cg_storage_filesystem * cg_storage_object_get_filesystem(cg_storage_object const * const this)
{
    cg_storage_filesystem * result = NULL;

    if (this != NULL)
    {
        result = this->fs;
    }

    return result;
}

void cg_storage_object_set_in_cache(cg_storage_object * const this,
                                    bool const in_cache)
{
    if (this != NULL)
    {
        this->entry.inode.in_cache = in_cache;
    }
}

void cg_storage_object_inc_dirty_writers_count(cg_storage_object * const this)
{
    if (this != NULL)
    {
        this->entry.inode.dirty_writers++;
    }
}

void cg_storage_object_set_inode_number(cg_storage_object * const this,
                                        uint64_t const inode_number)
{
    if (this != NULL)
    {
        this->entry.inode.inode_number = inode_number;
        this->entry.inode.st.st_ino = inode_number;
    }
}
