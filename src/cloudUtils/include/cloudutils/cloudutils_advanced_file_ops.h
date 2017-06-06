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

#ifndef CLOUD_UTILS_ADVANCED_FILE_OPS_H_
#define CLOUD_UTILS_ADVANCED_FILE_OPS_H_

#include <cloudutils/cloudutils_aio.h>

typedef void (cgutils_file_hash_cb)(int status,
                                    void * hash,
                                    size_t hash_size,
                                    void * cb_data);

#include <cloudutils/cloudutils_crypto.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_file_hash(cgutils_aio * aio,
                      char const * path,
                      cgutils_crypto_digest_algorithm algorithm,
                      cgutils_file_hash_cb * cb,
                      void * cb_data);

int cgutils_file_hash_sync(char const * path,
                           cgutils_crypto_digest_algorithm algorithm,
                           void ** hash,
                           size_t * hash_size);

int cgutils_file_descriptor_hash_sync(int fd,
                                      cgutils_crypto_digest_algorithm algorithm,
                                      void ** hash,
                                      size_t * hash_size);

int cgutils_file_fill_with_pseudo_random_data(int fd,
                                              size_t file_size);

int cgutils_file_fill_with_urandom_data(int fd,
                                        size_t file_size);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_ADVANCED_FILE_OPS_H_ */
