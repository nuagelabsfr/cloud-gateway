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

#ifndef CLOUD_UTILS_FILE_H_
#define CLOUD_UTILS_FILE_H_

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/statvfs.h>

#include <cloudutils/cloudutils_compiler_specifics.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

bool cgutils_file_exists(char const * file);
int cgutils_file_mkdir(char const * dir,
                       mode_t mode);
int cgutils_file_rmdir(char const * dir);
int cgutils_file_touch(char const * path,
                       mode_t mode);
int cgutils_file_lock(int fd,
                      short type);
int cgutils_file_unlock(int fd);
int cgutils_file_unlink(char const * file);
int cgutils_file_rename(char const * from,
                        char const * to);

int cgutils_file_set_closeonexec(int fd);
int cgutils_file_set_non_block(int fd);
int cgutils_file_set_block(int fd);

int cgutils_file_open(char const * path,
                      int flags,
                      mode_t mode,
                      int * fd);

int cgutils_file_read(int fd,
                      char * buffer,
                      size_t buffer_size,
                      size_t * got);

int cgutils_file_write(int fd,
                       char const * buffer,
                       size_t buffer_size,
                       size_t * written);

void cgutils_file_close(int fd);

int cgutils_file_get_size(int fd,
                          size_t * size);

int cgutils_file_dirname(char const * path,
                         char ** out);

int cgutils_file_basename(char const * path,
                          char ** out);

int cgutils_file_stat(char const * file,
                      struct stat * out);

int cgutils_file_lstat(char const * file,
                       struct stat * out);

int cgutils_file_chmod(char const * file,
                       mode_t mode);

int cgutils_file_chown(char const * file,
                       uid_t uid,
                       gid_t gid);

int cgutils_file_symlink(char const * point_to,
                         char const * name);

int cgutils_file_truncate(char const * path,
                          off_t offset);

int cgutils_file_fopen(char const * path,
                       char const * mode,
                       FILE ** fp);
int cgutils_file_fclose(FILE * fp);

int cgutils_file_ftruncate(int fd,
                           off_t len);

int cgutils_file_mkstemp(char * template,
                         int * fd);

int cgutils_file_tell(int fd,
                      off_t * pos);

int cgutils_file_lseek(int fd,
                       int whence,
                       off_t pos);

int cgutils_file_get_fs_usage(char const * path,
                              uint64_t * total,
                              uint64_t * free,
                              uint64_t * non_priv_free);

int cgutils_file_get_size_by_seek(int fd,
                                  size_t * size);

int cgutils_file_flock(int fd,
                       int flags);

int cgutils_file_utimens(char const * path,
                         struct timespec const ts[2]);

int cgutils_file_futimens(int fd,
                          struct timespec const ts[2]);

int cgutils_file_pipe(int pipefd[2],
                      bool non_blocking);

int cgutils_file_fdopen(int fd,
                        char const * mode,
                        FILE ** out);

int cgutils_file_fchmod(int fd,
                        mode_t mode);

int cgutils_file_fflush(FILE * fp);

int cgutils_file_fchown(int fd,
                        uid_t uid,
                        gid_t gid);

int cgutils_file_fsync(int fd);

int cgutils_file_fstat(int fd,
                       struct stat * out);

int cgutils_file_readlink(char const * path,
                          char * buffer,
                          size_t buffer_size,
                          size_t * got);

int cgutils_file_hardlink(char const * existing,
                          char const * new_path);

int cgutils_file_statfs(char const * path,
                        struct statvfs * stats);

int cgutils_file_opendir(char const * path,
                         DIR ** out);

int cgutils_file_readdir_r(DIR * dirp,
                           struct dirent * dirent,
                           struct dirent ** out);

void cgutils_file_closedir(DIR * dirp);

int cgutils_file_copy(char const * from,
                      char const * to,
                      bool destination_exists);

int cgutils_file_copy_fds(int from_fd,
                          int to_fd);

int cgutils_file_get_content_sync(char const * filename,
                                  char ** content,
                                  size_t * content_size);

int cgutils_file_write_content_sync(char const * filename,
                                    char const * content,
                                    size_t content_size);

int cgutils_file_write_content_sync_fd(int fd,
                                       char const * buffer,
                                       size_t buffer_size);

int cgutils_file_get_proc_content_sync(char const * filename,
                                       char ** content,
                                       size_t * content_size);

bool cgutils_file_are_writable_flags(int flags);

int cgutils_file_pread(int fd,
                       void * buf,
                       size_t count,
                       off_t off,
                       size_t * got);

int cgutils_file_compute_hashed_path(char const * base_dir,
                                     size_t base_dir_len,
                                     char const * base_name,
                                     size_t base_name_len,
                                     size_t depth,
                                     char ** out,
                                     size_t * out_len);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_FILE_H_ */
