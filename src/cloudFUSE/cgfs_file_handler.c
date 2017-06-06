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
#include <string.h>

#include <cgfs_file_handler.h>
#include <cgfs_utils.h>

#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_htable.h>

struct cgfs_file_handler
{
    cgfs_inode * inode;
    union
    {
        struct
        {
            cgutils_htable * index;
            cgsmc_async_entry * entries;
            size_t entries_count;
        } dir;
        struct
        {
            int fd;
            int flags;
            bool dirty;
        } file;
    };
    cgfs_file_handler_type type;
};

static int cgfs_file_handler_create(cgfs_file_handler_type const type,
                                    cgfs_file_handler ** out)
{
    int result = 0;
    CGUTILS_ASSERT(out != NULL);
    CGUTILS_ASSERT(type > cgfs_file_handler_type_none);
    CGUTILS_ASSERT(type < cgfs_file_handler_type_count);

    CGUTILS_ALLOCATE_STRUCT(*out);

    if (COMPILER_LIKELY(*out != NULL))
    {
        (*out)->type = type;

        if (type == cgfs_file_handler_type_file)
        {
            (*out)->file.fd = -1;
        }
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

int  cgfs_file_handler_create_fd(int const fd,
                                 int const flags,
                                 cgfs_inode * const inode,
                                 cgfs_file_handler ** const out)
{
    CGUTILS_ASSERT(out != NULL);

    int result = cgfs_file_handler_create(cgfs_file_handler_type_file,
                                          out);

    if (COMPILER_LIKELY(result == 0))
    {
        (*out)->file.fd = fd;
        (*out)->file.flags = flags;
        (*out)->inode = inode;
        cgfs_inode_inc_ref_count(inode);
    }

    return result;
}

void cgfs_file_handler_free(cgfs_file_handler * this)
{
    if (this != NULL)
    {
        if (this->inode != NULL)
        {
            if (this->inode->dir_fh == this)
            {
                this->inode->dir_fh = NULL;
            }

            cgfs_inode_release(this->inode), this->inode = NULL;
        }

        if (this->type == cgfs_file_handler_type_file)
        {
            if (this->file.fd != -1)
            {
                cgutils_file_close(this->file.fd), this->file.fd = -1;
            }

            this->file.flags = 0;
        }
        else if (this->type == cgfs_file_handler_type_dir)
        {
            if (this->dir.index != NULL)
            {
                cgutils_htable_free(&(this->dir.index), NULL);
            }

            if (this->dir.entries != NULL)
            {
                for (size_t idx = 0;
                     idx < this->dir.entries_count;
                     idx++)
                {
                    cgfs_inode * inode = this->dir.entries[idx].data;

                    if (inode != NULL)
                    {
                        cgfs_inode_release(inode), inode = NULL;
                    }

                    cgsmc_async_entry_clean(&(this->dir.entries[idx]));
                }
            }

            CGUTILS_FREE(this->dir.entries);
            this->dir.entries_count = 0;
        }

        this->type = cgfs_file_handler_type_none;
        CGUTILS_FREE(this);
    }
}

cgfs_file_handler_type cgfs_file_handler_get_type(cgfs_file_handler const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->type;
}

uint64_t cgfs_file_handler_get_inode_number(cgfs_file_handler const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->inode != NULL);
    return cgfs_inode_get_number(this->inode);
}

void cgfs_file_handler_update_mtime(cgfs_file_handler * const this)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->inode != NULL);

    cgfs_utils_update_inode_mtime(this->inode);
}

cgfs_inode * cgfs_file_handler_get_inode(cgfs_file_handler const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    return this->inode;
}

/* FILE */

int cgfs_file_handler_file_set_mode(cgfs_file_handler * const this,
                                    mode_t const mode)
{
    int result = 0;

    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->type == cgfs_file_handler_type_file);

    if (COMPILER_LIKELY(this->file.fd != -1))
    {
        result = cgutils_file_fchmod(this->file.fd,
                                     mode);
    }
    else
    {
        result = EBADF;
    }

    return result;
}

int cgfs_file_handler_file_set_atime(cgfs_file_handler * const this,
                                     time_t const new_time)
{
    int result = 0;

    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->type == cgfs_file_handler_type_file);

    if (COMPILER_LIKELY(this->file.fd != -1))
    {
        struct timespec const ts[2] =
            {
                { .tv_sec = new_time, .tv_nsec = 0 },
                { .tv_sec = 0, .tv_nsec = UTIME_OMIT },

            };

        result = cgutils_file_futimens(this->file.fd,
                                       ts);
    }
    else
    {
        result = EBADF;
    }

    return result;
}

int cgfs_file_handler_file_set_mtime(cgfs_file_handler * const this,
                                     time_t const new_time)
{
    int result = 0;

    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->type == cgfs_file_handler_type_file);

    if (COMPILER_LIKELY(this->file.fd != -1))
    {
        struct timespec const ts[2] =
            {
                { .tv_sec = 0, .tv_nsec = UTIME_OMIT },
                { .tv_sec = new_time, .tv_nsec = 0 },
            };

        result = cgutils_file_futimens(this->file.fd,
                                       ts);
    }
    else
    {
        result = EBADF;
    }

    return result;
}

int cgfs_file_handler_file_truncate(cgfs_file_handler * const this,
                                    off_t const size)
{
    int result = 0;

    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->type == cgfs_file_handler_type_file);

    if (COMPILER_LIKELY(this->file.fd != -1))
    {
        result = cgutils_file_ftruncate(this->file.fd,
                                        size);
    }
    else
    {
        result = EBADF;
    }

    return result;
}


int cgfs_file_handler_file_get_fd_for_writing(cgfs_file_handler * const this,
                                              int * const fd_out)
{
    int result = 0;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(fd_out != NULL);

    if (COMPILER_LIKELY(this->type == cgfs_file_handler_type_file &&
                        cgfs_utils_writable_flags(this->file.flags) == true))
    {
        *fd_out = this->file.fd;
    }
    else
    {
        result = EBADF;
    }

    return result;
}

int cgfs_file_handler_file_get_fd_for_reading(cgfs_file_handler * const this,
                                              int * const fd_out)
{
    int result = 0;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(fd_out != NULL);

    if (COMPILER_LIKELY(this->type == cgfs_file_handler_type_file))
    {
        *fd_out = this->file.fd;
    }
    else
    {
        result = EBADF;
    }

    return result;
}

bool cgfs_file_handler_file_need_to_notify_write(cgfs_data * const data,
                                                 cgfs_file_handler const * const this)
{
    bool result = false;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->inode != NULL);
    CGUTILS_ASSERT(this->type == cgfs_file_handler_type_file);
    CGUTILS_ASSERT(cgfs_utils_writable_flags(this->file.flags) == true);

    if (cgfs_inode_has_been_deleted(this->inode) == false)
    {
        time_t const now = time(NULL);
        double const elapsed = difftime(now, this->inode->last_dirtyness_notification);

        if (COMPILER_LIKELY(elapsed >= 0))
        {
            result = cgsmc_async_need_to_notify_write(data->cgsmc_data,
                                                      (size_t) elapsed);
        }
        else
        {
            /* Last notification is in the future, this is not good.
               Notify right away to be back in a stable state.
            */
            result = true;
        }
    }

    return result;
}

int cgfs_file_handler_file_refresh_inode_attributes_from_fd(cgfs_file_handler * const this)
{
    int result = 0;

    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->type == cgfs_file_handler_type_file);
    CGUTILS_ASSERT(this->inode != NULL);

    if (COMPILER_LIKELY(this->file.fd != -1))
    {
        struct stat st = (struct stat) { 0 };

        result = cgutils_file_fstat(this->file.fd,
                                    &st);

        if (COMPILER_LIKELY(result == 0))
        {
            struct stat * inode_st = &(this->inode->attr);
            inode_st->st_atime = st.st_atime;
            inode_st->st_mtime = st.st_mtime;
            inode_st->st_ctime = st.st_ctime;
            inode_st->st_size = st.st_size;
        }
        else
        {
            CGUTILS_ERROR("Error getting stat from fd %d of inode number %"PRIu64": %d",
                          this->file.fd,
                          cgfs_inode_get_number(this->inode),
                          result);
        }
    }
    else
    {
        result = EBADF;
    }

    return result;

}

bool cgfs_file_handler_file_need_to_notify_release(cgfs_file_handler const * const this)
{
    bool result = false;

    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->inode != NULL);

    /* We need to notify that the file has been released
       even if we know it has not been written to.
       This information should be passed on to the Storage Manager however.
    */

    if (this->type == cgfs_file_handler_type_file &&
        cgfs_utils_writable_flags(this->file.flags) == true)
    {
        CGUTILS_ASSERT(this->inode != NULL);

        if (cgfs_inode_has_been_deleted(this->inode) == false)
        {
            result = true;
        }
    }

    return result;
}

void cgfs_file_handler_file_set_dirty(cgfs_file_handler * const this)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->type == cgfs_file_handler_type_file);

    this->file.dirty = true;
}

bool cgfs_file_handler_file_is_dirty(cgfs_file_handler const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->type == cgfs_file_handler_type_file);

    return this->file.dirty;
}


/* DIR */

int  cgfs_file_handler_create_dir(cgsmc_async_entry * const entries,
                                  size_t const entries_count,
                                  bool const use_dir_index,
                                  cgfs_inode * const inode,
                                  cgfs_file_handler ** const out)
{
    CGUTILS_ASSERT(entries != NULL ||
                   entries_count == 0);
    CGUTILS_ASSERT(out != NULL);

    int result = cgfs_file_handler_create(cgfs_file_handler_type_dir,
                                          out);

    if (COMPILER_LIKELY(result == 0))
    {
        (*out)->dir.entries = entries;
        (*out)->dir.entries_count = entries_count;
        (*out)->inode = inode;
        cgfs_inode_inc_ref_count(inode);

        if (use_dir_index == true)
        {
            CGUTILS_DEBUG("Using index (%zu)",
                          entries_count);

            result = cgutils_htable_create(&((*out)->dir.index),
                                           entries_count);

            if (COMPILER_LIKELY(result == 0))
            {
                cgutils_htable * table = (*out)->dir.index;

                for (size_t idx = 0;
                     result == 0 &&
                         idx < entries_count;
                     idx++)
                {
                    result = cgutils_htable_insert(table,
                                                   entries[idx].name,
                                                   &(entries[idx]));

                    if (COMPILER_UNLIKELY(result != 0))
                    {
                        CGUTILS_ERROR("Error inserting entry %s: %d",
                                      entries[idx].name,
                                      result);
                    }
                }
            }
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            cgfs_file_handler_free(*out), *out = NULL;
        }
    }

    return result;
}

size_t cgfs_file_handler_dir_get_entries_count(cgfs_file_handler const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->type == cgfs_file_handler_type_dir);
    return this->dir.entries_count;
}

cgsmc_async_entry * cgfs_file_handler_dir_get_entries(cgfs_file_handler const * const this)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->type == cgfs_file_handler_type_dir);
    return this->dir.entries;
}

int cgfs_file_handler_dir_get_child_ino(cgfs_file_handler const * const this,
                                        char const * const name,
                                        uint64_t * const out)
{
    int result = ENOENT;
    cgsmc_async_entry const * entry = NULL;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->type == cgfs_file_handler_type_dir);
    CGUTILS_ASSERT(name != NULL);
    CGUTILS_ASSERT(out != NULL);

    if (this->dir.index != NULL)
    {
        void * ptr = NULL;

        result = cgutils_htable_get(this->dir.index,
                                    name,
                                    &ptr);

        if (COMPILER_LIKELY(result == 0))
        {
            entry = ptr;
        }
    }
    else
    {
        size_t const name_len = strlen(name);

        for (size_t idx = 0;
             result == ENOENT &&
                 idx < this->dir.entries_count;
             idx++)
        {
            entry = &(this->dir.entries[idx]);

            if (COMPILER_UNLIKELY(entry->name_len == name_len &&
                                  strcmp(entry->name, name) == 0))
            {
                result = 0;
            }
        }
    }

    if (COMPILER_LIKELY(result == 0))
    {
        *out = entry->st.st_ino;
    }

    return result;
}
