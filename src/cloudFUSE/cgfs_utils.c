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
#include <time.h>

#include <cloudutils/cloudutils_file.h>

#include <cgfs_file_handler.h>
#include <cgfs_utils.h>

int cgfs_utils_open_file(cgfs_inode * const inode,
                         char const * const path,
                         int * const flags,
                         cgfs_file_handler ** const out)
{
    int result = 0;

    CGUTILS_ASSERT(inode != NULL);
    CGUTILS_ASSERT(flags != NULL);
    CGUTILS_ASSERT(path != NULL);
    CGUTILS_ASSERT(out != NULL);

    /* Creation has been taken care of,
       now we open the file (the Storage Manager already knows we are going to).
    */

    *flags &= ~(O_CREAT|O_EXCL);

    int fd = open(path,
                  *flags | O_NONBLOCK);

    if (COMPILER_LIKELY(fd != -1))
    {
        result = cgutils_file_flock(fd,
                                    LOCK_SH | LOCK_NB);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgfs_file_handler_create_fd(fd,
                                                 *flags,
                                                 inode,
                                                 out);

            if (COMPILER_LIKELY(result != 0))
            {
                CGUTILS_ERROR("Error allocating memory for file handler: %d",
                              result);
            }
        }
        else if (result == EWOULDBLOCK)
        {
            /* Looks like the file has been modified
               under our feet, probably by the cache cleaner.
            */
        }
        else
        {
            CGUTILS_ERROR("Error trying to lock the file: %d",
                          result);
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            cgutils_file_close(fd), fd = -1;
        }
    }
    else
    {
        result = errno;
        CGUTILS_ERROR("Error opening file: %d",
                      result);
    }

    return result;
}

bool cgfs_utils_writable_flags(int const flags)
{
    return cgutils_file_are_writable_flags(flags);
}

void cgfs_utils_update_inode_mtime(cgfs_inode * const inode)
{
    CGUTILS_ASSERT(inode != NULL);

    time_t const now = time(NULL);

    if (difftime(now, inode->attr.st_mtime) > 0)
    {
        inode->attr.st_mtime = now;
    }

    inode->attr.st_ctime = now;
}

bool cgfs_utils_check_flags_validity(int const flags)
{
    bool result = true;

    if (flags & O_RDWR)
    {
        result = !(flags & O_RDONLY) && !(flags & O_WRONLY);
    }
    else if (flags & O_RDONLY)
    {
        result = !(flags & O_WRONLY) && !(flags & O_RDWR);
    }
    else if (flags & O_WRONLY)
    {
        result = !(flags & O_RDONLY) && !(flags & O_RDWR);
    }

    return result;
}
