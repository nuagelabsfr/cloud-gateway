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

#include <common.h>

int cg_tools_handle_subprocess_exit(char const * const process,
                                    int const exec_result,
                                    int const exit_code)
{
    CGUTILS_ASSERT(process != NULL);

    int result = exec_result;

    if (result == 0)
    {
        result = exit_code;

        if (result != 0)
        {
            fprintf(stderr,
                    "The sub-process (%s) failed with: %d\n",
                    process,
                    result);
        }
    }
    else
    {
        fprintf(stderr,
                "Failed to launch sub-process (%s): %s\n",
                process,
                strerror(result));
    }

    return result;
}

int cg_tools_handle_subprocess_reap(char const * const process,
                                    pid_t const pid,
                                    int const exec_result,
                                    int const exit_code)

{
    int result = cg_tools_handle_subprocess_exit(process,
                                                 exec_result,
                                                 exit_code);

    if (result == 0)
    {
        int status = 0;
        bool exited = false;
        bool signaled = false;

        result = cgutils_process_waitpid(pid,
                                         &status,
                                         &exited,
                                         &signaled);

        if (result == 0)
        {
            result = status;

            if (result != 0)
            {
                fprintf(stderr,
                        "Process (%s) exited with return code %d\n",
                        process,
                        result);
            }
        }
        else
        {
            fprintf(stderr,
                    "Error while reaping child (%s): %s\n",
                    process,
                    strerror(result));
        }
    }

    return result;
}

int cg_tools_validate_mac_address(char const * const mac_address)
{
    int result = EINVAL;
    static char const mac_ex[] = "00:00:00:00:00:00";
    static size_t const expected_len = sizeof mac_ex - 1;
    assert(mac_address != NULL);

    size_t mac_address_len = strlen(mac_address);

    if (mac_address_len == expected_len)
    {
        if (mac_address[2] == ':' &&
            mac_address[5] == ':' &&
            mac_address[8] == ':' &&
            mac_address[11] == ':' &&
            mac_address[14] == ':')
        {
            result = 0;
        }
    }

    return result;
}

/*
   Check that:
   - the file exists and ;
   - it is not a symlink and ;
   - it is owned by the current user (uid, not euid) and group (guid, not egid) .
   This last condition can be overriden by passing allow_root_owned_file at true
   in order to allow files belonging to root:root to be opened.

   Additional checks are done to ensure that no race
   condition occured between the time of check (TOC)
   and the time of use (TOU), by using fstat() on the
   obtained file descriptor.
*/

int cg_tools_check_and_open_source_file(char const * const path,
                                        int * const fd,
                                        bool const allow_root_owned_file)
{
    int result = EINVAL;
    CGUTILS_ASSERT(path != NULL);
    CGUTILS_ASSERT(fd != NULL);

    struct stat st = (struct stat) { 0 };

    result = cgutils_file_stat(path,
                               &st);

    if (result == 0)
    {
        if (!S_ISLNK(st.st_mode) &&
            (
                (st.st_uid == getuid() &&
                 st.st_gid == getgid()) ||
                (allow_root_owned_file == true &&
                 st.st_uid == 0 &&
                 st.st_gid == 0)))
        {
            result = cgutils_file_open(path,
                                       O_RDONLY,
                                       0,
                                       fd);

            if (result == 0)
            {
                struct stat st_f = (struct stat) { 0 };

                result = cgutils_file_fstat(*fd,
                                            &st_f);

                if (result == 0)
                {
                    if (!S_ISLNK(st_f.st_mode) &&
                        st_f.st_mode == st.st_mode &&
                        st_f.st_uid == st.st_uid &&
                        st_f.st_gid == st.st_gid &&
                        st_f.st_ino == st.st_ino &&
                        st_f.st_dev == st.st_dev)
                    {
                        result = 0;
                    }
                    else
                    {
                        fprintf(stderr, "Error checking the opened source file: %s\n",
                                strerror(result));

                    }
                }
                else
                {
                    fprintf(stderr, "Error stating the opened source file: %s\n",
                        strerror(result));
                }

                if (result != 0)
                {
                    cgutils_file_close(*fd), *fd = -1;
                }
            }
            else
            {
                fprintf(stderr, "Error opening the source file: %s\n",
                        strerror(result));
            }
        }
        else
        {
            result = EINVAL;
            fprintf(stderr,
                    "The source file must not be a symlink and be owned by the user executing this command.\n");
            fprintf(stderr,
                    "Link (%d), UID %zu / %zu, GID %zu / %zu\n",
                    S_ISLNK(st.st_mode),
                    (size_t) st.st_uid,
                    (size_t) getuid(),
                    (size_t) st.st_gid,
                    (size_t) getgid());
        }
    }
    else
    {
        fprintf(stderr, "Error stating the source file: %s\n",
                strerror(result));
    }

    return result;
}

/*
   Check that either:
   - the file does not exists yet or ;
   - it is not a symlink and is owned by root:root.

   If the file does not exist yet, is it created
   as rw-rw---- owned by root:root (rw-rw-r-- if strict_perms if false).

   If the file exists and strict_perms is on, it should
   be accessible only by its owner and group.

   Additional checks are done to ensure that no race
   condition occured between the time of check (TOC)
   and the time of use (TOU), by using fstat() on the
   obtained file descriptor.
*/
int cg_tools_check_and_open_destination_file(char const * const path,
                                             int * const fd,
                                             bool const strict_perms)
{
    int result = EINVAL;
    bool new_file = false;
    struct stat st = (struct stat) { 0 };

    CGUTILS_ASSERT(path != NULL);
    CGUTILS_ASSERT(fd != NULL);

    result = cgutils_file_lstat(path,
                                &st);

    if (result == ENOENT)
    {
        new_file = true;
        result = 0;
    }
    else if (result == 0)
    {
        if (S_ISLNK(st.st_mode) ||
            st.st_uid != 0 ||
            st.st_gid != 0)
        {
            result = EINVAL;
            fprintf(stderr, "Lnk %d, uid %zu, gid %zu\n",
                    S_ISLNK(st.st_mode),
                    (size_t) st.st_uid,
                    (size_t) st.st_gid);
        }
        else if ((strict_perms == true) &&
                 ((st.st_mode & S_IROTH) ||
                  (st.st_mode & S_IWOTH) ||
                  (st.st_mode & S_IXOTH)))
        {
            result = EINVAL;
            fprintf(stderr, "Permissions on destination are too open\n");
        }
    }

    if (result == 0)
    {
        static mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP;

        if (strict_perms == false)
        {
            mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        }

        result = cgutils_file_open(path,
                                   O_WRONLY|O_CREAT,
                                   mode,
                                   fd);
        if (result == 0)
        {
            struct stat fst = (struct stat) { 0 };

            result = cgutils_file_fstat(*fd,
                                        &fst);

            if (result == 0)
            {
                if (!S_ISLNK(fst.st_mode))
                {
                    if (new_file == false)
                    {
                        if (fst.st_uid != 0 ||
                            fst.st_gid != 0 ||
                            st.st_dev != fst.st_dev ||
                            st.st_ino != fst.st_ino)
                        {
                            result = EINVAL;
                            fprintf(stderr,
                                    "Destination file changed: %s\n",
                                    strerror(result));
                        }
                    }
                    else if (fst.st_size > 0)
                    {
                        result = EINVAL;
                        fprintf(stderr,
                                "Just created destination file is not empty: %s\n",
                                strerror(result));
                    }
                    else
                    {
                        /* New empty file */
                        result = cgutils_file_fchown(*fd, 0, 0);

                        if (result != 0)
                        {
                            fprintf(stderr,
                                    "Error setting the destination file ownership to root: %s\n",
                                    strerror(result));
                        }
                    }

                }
                else
                {
                    result = EINVAL;
                    fprintf(stderr, "File has become a symlink, this is bad.\n");
                }

                if (result == 0)
                {
                    result = cgutils_file_ftruncate(*fd,
                                                    0);

                    if (result == 0)
                    {

                    }
                    else
                    {
                        fprintf(stderr,
                                "Error truncating the destination file: %s\n",
                                strerror(result));

                    }
                }
            }
            else
            {
                fprintf(stderr,
                        "Error verifying the opened destination file: %s\n",
                        strerror(result));
            }

            if (result != 0)
            {
                cgutils_file_close(*fd), *fd = -1;
            }
        }
        else
        {
            fprintf(stderr,
                    "Error opening the destination file: %s\n",
                    strerror(result));
        }
    }
    else
    {
        fprintf(stderr,
                "Error verifying the destination file: %s\n",
                strerror(result));
    }

    return result;
}

int cg_tools_validate_vlan(char const * const vlan)
{
    uint64_t res = 0;

    CGUTILS_ASSERT(vlan != NULL);

    int result = cgutils_str_to_unsigned_int64(vlan,
                                               &res);

    if (result == 0 &&
        res > 0 && res <= 4096)
    {
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cg_tools_set_env_for_suid(void)
{
    /* We overwrite the PATH to be sure that binaries in /sbin and /usr/sbin are present */
    int result = setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

    if (result != 0)
    {
        result = errno;
        fprintf(stderr, "Error setting path: %s\n",
                strerror(result));
    }

    if (result == 0)
    {
        result = setuid(0);

        if (result != 0)
        {
            result = errno;
            fprintf(stderr, "Error setting uid to 0: %s\n",
                    strerror(result));
        }
    }

    if (result == 0)
    {
        result = setgid(0);

        if (result != 0)
        {
            result = errno;
            fprintf(stderr, "Error setting gid to 0: %s\n",
                    strerror(result));
        }
    }

    return result;
}
