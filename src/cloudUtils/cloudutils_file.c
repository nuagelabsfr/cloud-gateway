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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "cloudutils/cloudutils.h"
#include "cloudutils/cloudutils_file.h"

#define CGUTILS_FILE_READ_BUFFER_SIZE (16384)

int cgutils_file_stat(char const * const file,
                      struct stat * const out)
{
    int result = EINVAL;

    if (file != NULL && out != NULL)
    {
        result = stat(file, out);

        if (result == -1)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_lstat(char const * const file,
                       struct stat * const out)
{
    int result = EINVAL;

    if (file != NULL && out != NULL)
    {
        result = lstat(file, out);

        if (result == -1)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_fstat(int const fd,
                       struct stat * const out)
{
    int result = EINVAL;

    if (fd != -1 &&
        out != NULL)
    {
        result = fstat(fd,
                       out);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

bool cgutils_file_exists(char const * const file)
{
    bool result = false;

    if (file != NULL)
    {
        struct stat filestat = { 0 };
        int res = stat(file, &filestat);

        if (res == 0)
        {
            result = true;
        }
    }

    return result;
}

int cgutils_file_mkdir(char const * const dir,
                       mode_t const mode)
{
    int result = EINVAL;

    if (dir != NULL)
    {
        result = mkdir(dir, mode);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_rmdir(char const * const dir)
{
    int result = EINVAL;

    if (dir != NULL)
    {
        result = rmdir(dir);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_touch(char const * const path,
                       mode_t const mode)
{
    int result = EINVAL;

    if (path != NULL)
    {
        int fd = open(path, O_WRONLY | O_CREAT, mode);

        if (fd != -1)
        {
            result = 0;
            cgutils_file_close(fd), fd = -1;
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_lock(int const fd,
                      short const type)
{
    int result = EINVAL;

    if (fd != -1 && (type == F_RDLCK || type == F_WRLCK))
    {
        struct flock lock = (struct flock) { 0 };
        lock.l_type = type;
        lock.l_whence = SEEK_SET;
        lock.l_start = 0;
        lock.l_len = 0;

        result = fcntl(fd, F_SETLK, &lock);

        if (result == -1)
        {
            result = errno;

            if (result == EAGAIN || result == EACCES)
            {
                int res = fcntl(fd, F_GETLK, &lock);

                if (res == 0)
                {
                    fprintf(stderr, "File already locked by process %ld, type %hi\n", (long) lock.l_pid, lock.l_type);
                }
                else
                {
                    res = errno;
                    fprintf(stderr, "error while trying to locate the process holding the lock: %d\n", res);
                }
            }
        }
        else
        {
            result = 0;
        }
    }

    return result;
}

int cgutils_file_unlock(int const fd)
{
    int result = EINVAL;

    if (fd != -1)
    {
        struct flock lock = (struct flock) { 0 };
        lock.l_type = F_UNLCK;
        lock.l_whence = SEEK_SET;
        lock.l_start = 0;
        lock.l_len = 0;

        result = fcntl(fd, F_SETLK, &lock);

        if (result == -1)
        {
            result = errno;
        }
        else
        {
            result = 0;
        }
    }

    return result;
}

int cgutils_file_unlink(char const * const file)
{
    int result = EINVAL;

    if (file != NULL)
    {
        result = unlink(file);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_rename(char const * const from,
                        char const * const to)
{
    int result = EINVAL;

    if (from != NULL && to != NULL)
    {
        result = rename(from, to);

        if (result == -1)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_set_closeonexec(int const fd)
{
    int result = 0;

    int const flags = fcntl(fd, F_GETFD, NULL);

    if (flags >= 0)
    {
        result = fcntl(fd, F_SETFD, flags | FD_CLOEXEC);

        if (result == -1)
        {
            result = errno;
        }
        else
        {
            result = 0;
        }
    }
    else
    {
        result = errno;
    }

    return result;
}

int cgutils_file_set_non_block(int const fd)
{
    int result = 0;

    int const flags = fcntl(fd, F_GETFL, NULL);

    if (flags >= 0)
    {
        result = fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        if (result == -1)
        {
            result = errno;
        }
        else
        {
            result = 0;
        }
    }
    else
    {
        result = errno;
    }

    return result;
}

int cgutils_file_set_block(int const fd)
{
    int result = 0;

    int const flags = fcntl(fd, F_GETFL, NULL);

    if (flags >= 0)
    {
        result = fcntl(fd, F_SETFL, flags & !O_NONBLOCK);

        if (result == -1)
        {
            result = errno;
        }
        else
        {
            result = 0;
        }
    }
    else
    {
        result = errno;
    }

    return result;
}

void cgutils_file_close(int fd)
{
    if (fd >= 0)
    {
        close(fd);
    }
}

int cgutils_file_read(int fd,
                      char * const buffer,
                      size_t const buffer_size,
                      size_t * const got)
{
    int result = 0;

    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(buffer != NULL);
    CGUTILS_ASSERT(buffer_size > 0);
    CGUTILS_ASSERT(got != NULL);

    ssize_t res = read(fd,
                       buffer,
                       buffer_size);

    if (COMPILER_LIKELY(res >= 0))
    {
        *got = (size_t) res;
    }
    else
    {
        result = errno;
    }

    return result;
}

int cgutils_file_write(int const fd,
                       char const * const buffer,
                       size_t const buffer_size,
                       size_t * const written)
{
    int result = 0;

    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(buffer != NULL);
    CGUTILS_ASSERT(buffer_size > 0);
    CGUTILS_ASSERT(written != NULL);

    ssize_t got = write(fd,
                        buffer,
                        buffer_size);

    if (COMPILER_LIKELY(got >= 0))
    {
        *written = (size_t) got;
    }
    else
    {
        result = errno;
    }

    return result;
}

int cgutils_file_open(char const * const path,
                      int const flags,
                      mode_t const mode,
                      int * const fd)
{
    int result = EINVAL;

    if (path != NULL && fd != NULL)
    {
        if ((flags & O_CREAT) == 0)
        {
            *fd = open(path, flags);
        }
        else
        {
            *fd = open(path, flags, mode);
        }

        if (*fd < 0)
        {
            result = errno;
        }
        else
        {
            result = 0;
        }
    }

    return result;
}

int cgutils_file_fopen(char const * const path,
                       char const * const mode,
                       FILE ** const fp)
{
    int result = EINVAL;

    if (path != NULL && mode != NULL && fp != NULL)
    {
        *fp = fopen(path, mode);

        if (*fp == NULL)
        {
            result = errno;
        }
        else
        {
            result = 0;
        }
    }

    return result;
}

int cgutils_file_fclose(FILE * fp)
{
    int result = EINVAL;

    if (fp != NULL)
    {
        result = fclose(fp);
    }

    return result;
}

int cgutils_file_ftruncate(int const fd,
                           off_t const len)
{
    int result = EINVAL;

    if (fd >= 0)
    {
        result = ftruncate(fd, len);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_get_size(int const fd,
                          size_t * const size)
{
    int result = EINVAL;

    if (fd >= 0 && size != NULL)
    {
        struct stat st = { 0 };
        result = fstat(fd, &st);

        if (result == 0)
        {
            if (st.st_size >= 0)
            {
                *size = (size_t) st.st_size;
            }
            else
            {
                result = EIO;
                CGUTILS_WARN("Negative size found, probably a flags issue during build: %d", result);
            }
        }
    }

    return result;
}

int cgutils_file_dirname(char const * const path,
                         char ** const out)
{
    int result = EINVAL;

    if (path != NULL && out != NULL)
    {
        size_t idx = strlen(path);

        for (; idx > 0 && path[idx -1] != '/'; idx--);

        if (idx > 0)
        {
            size_t const out_len = idx;
            *out = NULL;
            CGUTILS_MALLOC(*out, out_len + 1, 1);

            if (*out != NULL)
            {
                memcpy(*out, path, out_len);
                (*out)[out_len] = '\0';
                result = 0;
            }
            else
            {
                result = ENOMEM;
            }
        }
    }

    return result;
}

int cgutils_file_basename(char const * const path,
                          char ** const out)
{
    int result = EINVAL;

    if (path != NULL && out != NULL)
    {
        size_t const path_len = strlen(path);
        size_t idx = path_len;

        for (; idx > 0 && path[idx - 1] != '/'; idx--);

        if (idx > 0)
        {
            size_t const out_len = path_len - idx;
            *out = NULL;
            CGUTILS_MALLOC(*out, out_len + 1, 1);

            if (*out != NULL)
            {
                memcpy(*out, path + idx, out_len);
                (*out)[out_len] = '\0';
                result = 0;
            }
            else
            {
                result = ENOMEM;
            }
        }
    }

    return result;
}

int cgutils_file_chmod(char const * const file,
                       mode_t const mode)
{
    int result = EINVAL;

    if (file != NULL)
    {
        result = chmod(file, mode);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_chown(char const * const file,
                       uid_t const uid,
                       gid_t const gid)
{
    int result = EINVAL;

    if (file != NULL)
    {
        result = chown(file, uid, gid);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_symlink(char const * const point_to,
                         char const * const name)
{
    int result = EINVAL;

    if (point_to != NULL && name != NULL)
    {
        result = symlink(point_to, name);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_truncate(char const * const path,
                          off_t const offset)
{
    int result = EINVAL;

    if (path != NULL)
    {
        result = truncate(path, offset);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

COMPILER_STATIC_ASSERT(sizeof(fsblkcnt_t) <= sizeof(uint64_t),
                       "sizeof(fsblkcnt_t) should be <= sizeof(uint64_t)");

int cgutils_file_get_fs_usage(char const * const path,
                              uint64_t * const total,
                              uint64_t * const fsfree,
                              /* Space available for non privileged users */
                              uint64_t * const non_priv_free)
{
    int result = EINVAL;

    if (path != NULL && total != NULL && fsfree != NULL && non_priv_free != NULL)
    {
        struct statvfs stats = { 0 };

        result = statvfs(path, &stats);

        if (result == 0)
        {
            unsigned long const blocksize = stats.f_frsize > 0 ? stats.f_frsize : stats.f_bsize;

            if (UINT64_MAX / blocksize >= stats.f_blocks)
            {
                *total = stats.f_blocks * blocksize;
            }

            if (UINT64_MAX / blocksize >= stats.f_bfree)
            {
                *fsfree = stats.f_bfree * blocksize;
            }

            if (UINT64_MAX / blocksize >= stats.f_bavail)
            {
                *non_priv_free = stats.f_bavail * blocksize;
            }
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_mkstemp(char * const template,
                         int * const fd)
{
    int result = EINVAL;

    if (template != NULL && fd != NULL)
    {
        *fd = mkstemp(template);

        if (*fd < 0)
        {
            *fd = -1;
            result = errno;
        }
        else
        {
            result = 0;
        }
    }

    return result;
}

int cgutils_file_tell(int const fd,
                      off_t * const pos)
{
    int result = EINVAL;

    if (fd >= 0 && pos != NULL)
    {
        *pos = lseek(fd, 0, SEEK_CUR);

        if (*pos != (off_t) - 1)
        {
            result = 0;
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_lseek(int const fd,
                       int const whence,
                       off_t const pos)
{
    int result = EINVAL;

    if (fd >= 0)
    {
        off_t res = lseek(fd, pos, whence);

        if (res != (off_t) - 1)
        {
            result = 0;
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_get_size_by_seek(int const fd,
                                  size_t * const size)
{
    int result = EINVAL;

    if (fd >= 0 && size != NULL)
    {
        off_t previous = 0;

        result = cgutils_file_tell(fd, &previous);

        if (result == 0)
        {
            off_t end = lseek(fd, 0, SEEK_END);

            if (end >= 0)
            {
                *size = (size_t) end;
                lseek(fd, previous, SEEK_SET);
            }
            else
            {
                result = errno;
                CGUTILS_ERROR("Error in lseek %d", result);
            }
        }
    }

    return result;
}

int cgutils_file_flock(int const fd,
                       int const flags)
{
    int result = EINVAL;

    if (fd != -1)
    {
        result = flock(fd, flags);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_utimens(char const * const path,
                         struct timespec const ts[2])
{
    int result = EINVAL;

    if (path != NULL)
    {
        result = utimensat(AT_FDCWD,
                           path,
                           ts,
                           AT_SYMLINK_NOFOLLOW);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_futimens(int const fd,
                          struct timespec const ts[2])
{
    int result = 0;

    if (COMPILER_LIKELY(fd != -1))
    {
        result = futimens(fd,
                          ts);

        if (COMPILER_UNLIKELY(result != 0))
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_pipe(int pipefd[2],
                      bool const non_blocking)
{
    int result = EINVAL;

    if (pipefd != NULL)
    {
        int flags = O_CLOEXEC;

        if (non_blocking == true)
        {
            flags |= O_NONBLOCK;
        }

        result = pipe2(pipefd,
                       flags);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_fdopen(int const fd,
                        char const * const mode,
                        FILE ** const out)
{
    int result = EINVAL;

    if (fd != -1 &&
        mode != NULL &&
        out != NULL)
    {
        *out = fdopen(fd,
                      mode);

        if (*out != NULL)
        {
            result = 0;
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_fchmod(int const fd,
                        mode_t const mode)
{
    int result = EINVAL;

    if (fd != -1)
    {
        result = fchmod(fd, mode);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_fflush(FILE * const fp)
{
    int result = EINVAL;

    if (fp != NULL)
    {
        result = fflush(fp);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_fchown(int const fd,
                        uid_t const uid,
                        gid_t const gid)
{
    int result = EINVAL;

    if (fd != -1)
    {
        result = fchown(fd,
                        uid,
                        gid);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_fsync(int const fd)
{
    int result = EINVAL;

    if (fd != -1)
    {
        result = fsync(fd);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_readlink(char const * const path,
                          char * const buffer,
                          size_t const buffer_size,
                          size_t * const got)
{
    int result = EINVAL;

    if (path != NULL &&
        buffer != NULL &&
        got != NULL)
    {
        ssize_t const written = readlink(path,
                                         buffer,
                                         buffer_size);

        if (written >= 0)
        {
            result = 0;

            if ((size_t) written < buffer_size)
            {
                buffer[(size_t) written] = '\0';
                *got = (size_t) written;
            }
            else
            {
                buffer[buffer_size - 1] = '\0';
                *got = buffer_size;
            }
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_hardlink(char const * const existing,
                          char const * const new_path)
{
    int result = EINVAL;

    if (existing != NULL &&
        new_path != NULL)
    {
        result = link(existing,
                      new_path);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_statfs(char const * const path,
                        struct statvfs * const stats)
{
    int result = EINVAL;

    if (path != NULL &&
        stats != NULL)
    {
        result = statvfs(path,
                         stats);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_file_opendir(char const * const path,
                         DIR ** const out)
{
    int result = EINVAL;

    if (path != NULL &&
        out != NULL)
    {
        *out = opendir(path);

        if (*out != NULL)
        {
            result = 0;
        }
        else
        {
            result = errno;
        }
    }

    return result;
}


int cgutils_file_readdir_r(DIR * const dirp,
                           struct dirent * const dirent,
                           struct dirent ** const out)
{
    int result = EINVAL;

    if (dirp != NULL &&
        dirent != NULL &&
        out != NULL)
    {
        result = readdir_r(dirp,
                           dirent,
                           out);
    }

    return result;
}

void cgutils_file_closedir(DIR * dirp)
{
    if (dirp != NULL)
    {
        closedir(dirp);
    }
}

int cgutils_file_copy_fds(int const from_fd,
                          int const to_fd)
{
    int result = EINVAL;

    if (from_fd != -1 &&
        to_fd != -1)
    {
        static size_t const buffer_size = 4096;
        char buffer[buffer_size];

        bool error = false;
        bool finished = false;

        do
        {
            size_t got = 0;

            result = cgutils_file_read(from_fd,
                                       buffer,
                                       buffer_size,
                                       &got);

            if (COMPILER_LIKELY(result == 0))
            {
                if (COMPILER_LIKELY(got > 0))
                {
                    do
                    {
                        size_t written = 0;

                        result = cgutils_file_write(to_fd,
                                                    buffer,
                                                    got,
                                                    &written);

                        if (COMPILER_LIKELY(result == 0))
                        {
                            if (COMPILER_LIKELY(written > 0))
                            {
                                got -= written;
                            }
                        }
                        else if (result != EINTR)
                        {
                            error = true;
                        }
                        else
                        {
                            result = 0;
                        }
                    }
                    while (error == false &&
                           got > 0);

                }
                else if (got == 0 )
                {
                    finished = true;
                }
            }
            else if (result != EINTR)
            {
                error = true;
            }
            else
            {
                result = 0;
            }
        }
        while(finished == false &&
              error == false);

        if (error == false)
        {
            result = 0;
        }

    }

    return result;
}

int cgutils_file_copy(char const * const from,
                      char const * const to,
                      bool const destination_exists)
{
    int result = EINVAL;

    if (from != NULL &&
        to != NULL)
    {
        int from_fd = -1;

        result = cgutils_file_open(from,
                                   O_RDONLY,
                                   0,
                                   &from_fd);

        if (result == 0)
        {
            int to_fd = -1;

            result = cgutils_file_open(to,
                                       destination_exists == true ?
                                       O_WRONLY | O_CREAT :
                                       O_WRONLY | O_CREAT | O_EXCL,
                                       S_IRUSR | S_IWUSR,
                                       &to_fd);

            if (result == 0)
            {
                result = cgutils_file_copy_fds(from_fd,
                                               to_fd);

                cgutils_file_close(to_fd), to_fd = -1;
            }

            cgutils_file_close(from_fd), from_fd = -1;
        }
    }

    return result;
}

int cgutils_file_get_content_sync(char const * const filename,
                                  char ** const content,
                                  size_t * const content_size)
{
    int result = EINVAL;

    if (filename != NULL && content != NULL && content_size != NULL)
    {
        struct stat st = (struct stat) { 0 };

        result = cgutils_file_stat(filename, &st);

        if (result == 0)
        {
            int fd = -1;
            result = cgutils_file_open(filename, O_RDONLY, 0, &fd);

            if (result == 0)
            {
                size_t file_size = (size_t) st.st_size;
                assert(st.st_size >= 0);

                if (file_size > 0)
                {
                    size_t to_read = file_size;

                    CGUTILS_MALLOC(*content, to_read + 1, 1);

                    if (*content != NULL)
                    {
                        size_t pos = 0;
                        bool finished = false;

                        do
                        {
                            size_t got = 0;

                            result = cgutils_file_read(fd,
                                                       *content + pos,
                                                       to_read,
                                                       &got);

                            if (COMPILER_LIKELY(result == 0))
                            {
                                if (COMPILER_LIKELY(got > 0))
                                {
                                    to_read -= (size_t) got;
                                    pos += (size_t) got;
                                }
                                else if (got == 0)
                                {
                                    /* Unexpected EOF */
                                    finished = true;
                                }
                            }
                            else if (result == EINTR)
                            {
                                result = 0;
                            }
                            else
                            {
                                CGUTILS_ERROR("Error while reading from %s: %d", filename, result);
                                finished = true;
                            }
                        }
                        while (result == 0 && finished == false);

                        if (result == 0)
                        {
                            *content_size = pos;
                            (*content)[pos] = '\0';
                        }

                        if (result != 0)
                        {
                            CGUTILS_FREE(*content);
                        }
                    }
                    else
                    {
                        result = ENOMEM;
                        *content_size = 0;
                    }
                }
                else
                {
                    result = 0;
                    *content_size = 0;
                    *content = NULL;
                }

                cgutils_file_close(fd), fd = -1;
            }
            else
            {
                CGUTILS_ERROR("Error opening file %s: %d", filename, result);
            }
        }
    }

    return result;
}

int cgutils_file_get_proc_content_sync(char const * const filename,
                                       char ** const content,
                                       size_t * const content_size)
{
    int result = EINVAL;

    if (filename != NULL && content != NULL && content_size != NULL)
    {
        int fd = -1;
        result = cgutils_file_open(filename, O_RDONLY, 0, &fd);

        if (result == 0)
        {
            char * buffer = NULL;
            size_t buffer_size = 0;
            size_t remaining = 0;
            size_t pos = 0;
            bool finished = false;

            do
            {
                if (remaining == 0)
                {
                    char * new_buffer = NULL;

                    buffer_size += CGUTILS_FILE_READ_BUFFER_SIZE;
                    CGUTILS_REALLOC(new_buffer, buffer, buffer_size + 1, 1);

                    if (new_buffer != NULL)
                    {
                        buffer = new_buffer;
                        remaining += CGUTILS_FILE_READ_BUFFER_SIZE;
                    }
                    else
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Error allocating memory: %d", result);
                    }
                }

                if (COMPILER_LIKELY(result == 0))
                {
                    size_t got = 0;

                    result = cgutils_file_read(fd,
                                               buffer + pos,
                                               remaining,
                                               &got);

                    if (COMPILER_LIKELY(result == 0))
                    {
                        if (COMPILER_LIKELY(got > 0))
                        {
                            remaining -= (size_t) got;
                            pos += (size_t) got;
                        }
                        else if (got == 0)
                        {
                            finished = true;
                        }
                    }
                    else if (result == EINTR)
                    {
                        result = 0;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error while reading from %s: %d", filename, result);
                        finished = true;
                    }
                }
            }
            while (result == 0 && finished == false);

            if (result == 0)
            {
                buffer[pos] = '\0';
                *content_size = pos;
                *content = buffer;
            }
            else
            {
                CGUTILS_FREE(buffer);
            }

            cgutils_file_close(fd), fd = -1;
        }
        else
        {
            CGUTILS_ERROR("Error opening file %s: %d", filename, result);
        }
    }

    return result;
}

int cgutils_file_write_content_sync_fd(int const fd,
                                       char const * const buffer,
                                       size_t const buffer_size)
{
    int result = EINVAL;

    if (fd != -1 &&
        buffer != NULL &&
        buffer_size > 0)
    {
        size_t to_write = buffer_size;
        size_t pos = 0;
        bool finished = false;

        do
        {
            size_t written = 0;

            result = cgutils_file_write(fd,
                                        buffer + pos,
                                        to_write,
                                        &written);

            if (COMPILER_LIKELY(result == 0))
            {
                if (COMPILER_LIKELY(written > 0))
                {
                    to_write -= (size_t) written;
                    pos += (size_t) written;
                }
                else if (written == 0)
                {
                }
            }
            else if (result == EINTR)
            {
                result = 0;
            }
            else
            {
                finished = true;
            }
        }
        while (result == 0 &&
               to_write > 0 &&
               finished == false);

    }

    return result;
}

int cgutils_file_write_content_sync(char const * const filename,
                                    char const * const buffer,
                                    size_t const buffer_size)
{
    int result = EINVAL;

    if (filename != NULL &&
        buffer != NULL &&
        buffer_size > 0)
    {
        int fd = -1;
        result = cgutils_file_open(filename,
                                   O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                                   S_IRUSR | S_IWUSR,
                                   &fd);

        if (result == 0)
        {
            result = cgutils_file_write_content_sync_fd(fd,
                                                        buffer,
                                                        buffer_size);

            cgutils_file_close(fd), fd = -1;
        }
        else
        {
            CGUTILS_ERROR("Error opening file %s: %d", filename, result);
        }
    }

    return result;
}

bool cgutils_file_are_writable_flags(int const flags)
{
    return (flags & O_WRONLY || flags & O_RDWR);
}

int cgutils_file_pread(int const fd,
                       void * const buf,
                       size_t const count,
                       off_t const off,
                       size_t * const got)
{
    int result = 0;
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(buf != NULL);
    CGUTILS_ASSERT(count > 0);
    CGUTILS_ASSERT(got != NULL);

    ssize_t res = pread(fd,
                        buf,
                        count,
                        off);

    if (COMPILER_LIKELY(res >= 0))
    {
        *got = (size_t) res;
    }
    else
    {
        result = errno;
    }

    return result;
}

int cgutils_file_compute_hashed_path(char const * const base_dir,
                                     size_t const base_dir_len,
                                     char const * const base_name,
                                     size_t const base_name_len,
                                     size_t const depth,
                                     char ** const out,
                                     size_t * const out_len)
{
    int result = 0;

    if (COMPILER_LIKELY(base_dir != NULL &&
                        base_dir_len > 0 &&
                        base_name != NULL &&
                        base_name_len > 0 &&
                        out != NULL &&
                        out_len != NULL))
    {
        size_t const final_len = base_dir_len +
            ( 2 * depth ) +
            1 + base_name_len;
        char * final = NULL;

        CGUTILS_ASSERT(depth <= base_name_len);

        CGUTILS_MALLOC(final, final_len + 1, 1);

        if (COMPILER_LIKELY(final != NULL))
        {
            size_t final_pos = 0;

            memcpy(final + final_pos, base_dir, base_dir_len);
            final_pos += base_dir_len;

            final[final_pos] = '/';
            final_pos++;

            for (size_t idx = 0;
                 idx < depth;
                 idx++)
            {
                if (COMPILER_LIKELY(base_name[idx] != '/'))
                {
                    final[final_pos] = base_name[idx];
                }
                else
                {
                    final[final_pos] = '-';
                }

                final_pos++;
                final[final_pos] = '/';
                final_pos++;
            }

            for (size_t idx = 0;
                 idx < base_name_len;
                 idx++)
            {
                if (COMPILER_LIKELY(base_name[idx] != '/'))
                {
                    final[final_pos] = base_name[idx];
                }
                else
                {
                    final[final_pos] = '-';
                }
                final_pos++;
            }

            final[final_pos] = '\0';
            final_pos++;

            *out = final, final = NULL;
            *out_len = final_pos - 1;
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for cache path: %d",
                          result);
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}
