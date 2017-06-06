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

#ifndef CLOUD_UTILS_PROCESS_H_
#define CLOUD_UTILS_PROCESS_H_

#include <stdbool.h>
#include <signal.h>

#include <cloudutils/cloudutils.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_process_signal(pid_t pid,
                           int sig);

int cgutils_process_waitpid(pid_t pid,
                            int * status,
                            bool * exited,
                            bool * signaled);

int cgutils_process_reap(pid_t * pid,
                         int options,
                         int * status,
                         bool * exited,
                         bool * signaled);

int cgutils_process_read_pid(char const * pid_file,
                             pid_t * pid);

int cgutils_process_write_pid(char const * pid_file);

int cgutils_process_daemonize(char const * stderr_filename,
                              bool * is_master);

pid_t cgutils_process_getppid(void);

int cgutils_process_execute(char const * const argv[],
                            char * const * envi,
                            pid_t * pid_out,
                            int * exit_value_out);

int cgutils_process_reopen_stderr(char const * stderr_filename);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GUTILS_PROCESS_H_ */
