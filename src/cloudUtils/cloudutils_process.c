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
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_process.h>

int cgutils_process_signal(pid_t const pid,
                           int  const sig)
{
    int result = kill(pid, sig);

    if (result == -1)
    {
        result = errno;
    }

    return result;
}

static int cgutils_process_parse_waitpid_status(int const value,
                                                bool * const exited,
                                                bool * const signaled,
                                                int * const status)
{
    int result = 0;

    assert(exited != NULL);
    assert(signaled != NULL);
    assert(status != NULL);

    if (WIFEXITED(value) != 0)
    {
        *status = WEXITSTATUS(value);

        *exited = true;
    }
    else if (WIFSIGNALED(value) != 0)
    {
        *status = WTERMSIG(value);

        *signaled = true;
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgutils_process_waitpid(pid_t const pid,
                            int * const status,
                            bool * const exited,
                            bool * const signaled)
{
    int result = EINVAL;

    if (status != NULL && exited != NULL && signaled != NULL)
    {
        int stat_loc = 0;

        pid_t res = waitpid(pid, &stat_loc, 0);

        if (res == pid)
        {
            result = cgutils_process_parse_waitpid_status(stat_loc,
                                                          exited,
                                                          signaled,
                                                          status);
        }
        else
        {
            result = errno;
            *status = 0;
        }
    }

    return result;
}

int cgutils_process_reap(pid_t * const pid,
                         int const options,
                         int * const status,
                         bool * const exited,
                         bool * const signaled)
{
    int result = EINVAL;

    if (pid != NULL && status != NULL && exited != NULL && signaled != NULL)
    {
        int stat_loc = 0;
        *pid = waitpid(-1, &stat_loc, options);

        if (*pid > 0)
        {
            result = cgutils_process_parse_waitpid_status(stat_loc,
                                                          exited,
                                                          signaled,
                                                          status);
        }
        else if (*pid == -1)
        {
            result = errno;
            *status = 0;
        }
        else
        {
            /* No child with an available status to reap */
            result = ENOENT;
            *status = 0;
        }
    }

    return result;
}

int cgutils_process_read_pid(char const * const pid_file,
                             pid_t * const pid)
{
    int result = EINVAL;

    if (pid_file != NULL && pid != NULL)
    {
        FILE * fp = NULL;

        result = cgutils_file_fopen(pid_file,
                                    "r",
                                    &fp);

        if (result == 0)
        {
            unsigned long tmp = 0;

            result = fscanf(fp, "%lu", &tmp);

            if (result == 1 &&
                tmp > 0)
            {
                result = 0;
                *pid = (pid_t) tmp;
            }
            else
            {
                result = EINVAL;
            }

            cgutils_file_fclose(fp), fp = NULL;
        }
    }

    return result;
}

int cgutils_process_write_pid(char const * const pid_file)
{
    int result = EINVAL;

    if (pid_file != NULL)
    {
        FILE * fp = NULL;

        result = cgutils_file_fopen(pid_file,
                                    "w",
                                    &fp);

        if (result == 0)
        {
            pid_t const tmp = getpid();

            fprintf(fp, "%ld", (long) tmp);

            cgutils_file_fclose(fp), fp = NULL;
        }
    }

    return result;
}

int cgutils_process_reopen_stderr(char const * const stderr_filename)
{
    int result = EINVAL;

    if (stderr_filename != NULL)
    {
        FILE * stderr_file = freopen(stderr_filename,
                                     "a",
                                     stderr);

        if (stderr_file != NULL)
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

int cgutils_process_daemonize(char const * const stderr_filename,
                              bool * const is_master)
{
    int result = EINVAL;

    if (is_master != NULL)
    {
        bool success = false;
        result = 0;
        *is_master = false;

        if (getppid() != 1)
        {
            pid_t pid = fork();

            if (pid == 0)
            {
                *is_master = true;

                pid_t const sid = setsid();

                if (sid > 0)
                {
                    umask(0);

                    if ((chdir("/")) == 0)
                    {
                        FILE * dev_null = fopen("/dev/null", "rw");

                        if (dev_null != NULL)
                        {
                            int fd = fileno(dev_null);

                            if (dup2(fd, STDIN_FILENO) != -1)
                            {
                                if (dup2(fd, STDOUT_FILENO) != -1)
                                {
                                    if (stderr_filename != NULL)
                                    {
                                        int res = cgutils_process_reopen_stderr(stderr_filename);

                                        if (res == 0)
                                        {
                                            success = true;
                                        }
                                    }
                                    else
                                    {
                                        if (dup2(fd, STDERR_FILENO) != -1)
                                        {
                                            success = true;
                                        }
                                    }
                                }
                            }

                            fclose(dev_null), dev_null = NULL;
                        }
                    }
                }
            }
            else
            {
                success = true;
            }
        }

        if (*is_master == true && success == false)
        {
            result = errno;
        }
    }

    return result;
}

pid_t cgutils_process_getppid(void)
{
    pid_t result = getppid();

    return result;
}

int cgutils_process_execute(char const * const argv[],
                            char * const * const envi,
                            pid_t * const pid_out,
                            int * const exit_value_out)
{
    int result = EINVAL;

    if (argv != NULL)
    {
        pid_t const pid = fork();

        if (pid == 0)
        {
            /* child */
            execve(argv[0],
                   (char **) argv,
                   envi);
            result = errno;
            CGUTILS_ERROR("Error, execve(%s) failed with %d",
                          argv[0],
                          result);
            exit(result);
        }
        else if (pid > 0)
        {
            /* parent */

            int exit_value = 0;
            bool exited = false;
            bool signaled = false;
            int stat_loc = 0;

            pid_t res = waitpid(pid, &stat_loc, WNOHANG);

            if (pid_out != NULL)
            {
                *pid_out = pid;
            }

            if (res == pid)
            {
                result = cgutils_process_parse_waitpid_status(stat_loc,
                                                              &exited,
                                                              &signaled,
                                                              &exit_value);

                if (result == 0)
                {
                    if (exit_value_out != NULL)
                    {
                        *exit_value_out = 0;
                    }
                }
            }
            else if (res == 0)
            {
                /* process is running */
                result = 0;

                if (exit_value_out != NULL)
                {
                    *exit_value_out = 0;
                }
            }
            else
            {
                result = errno;
            }
        }
        else
        {
            result = errno;
            CGUTILS_ERROR("Error in fork(): %d", result);
        }
    }

    return result;
}
