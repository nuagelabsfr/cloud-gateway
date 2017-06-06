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

#ifndef CLOUD_UTILS_JSON_READER_H_
#define CLOUD_UTILS_JSON_READER_H_

#include <stdbool.h>
#include <stdint.h>

typedef struct cgutils_json_reader cgutils_json_reader;

#include <cloudutils/cloudutils_llist.h>
#include <cloudutils/cloudutils_compiler_specifics.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_json_reader_from_file(char const * file,
                                  cgutils_json_reader ** out);

int cgutils_json_reader_from_buffer(char const * data,
                                    size_t data_size,
                                    cgutils_json_reader ** out);

int cgutils_json_reader_from_key(cgutils_json_reader * reader,
                                 char const * key,
                                 cgutils_json_reader ** out);

int cgutils_json_reader_get_all(cgutils_json_reader * reader,
                                char const * key,
                                cgutils_llist ** confs_list);

int cgutils_json_reader_get_string(cgutils_json_reader const * reader,
                                   char const * key,
                                   char ** out);

int cgutils_json_reader_get_boolean(cgutils_json_reader const * reader,
                                    char const * key,
                                    bool * out);

int cgutils_json_reader_get_unsigned_integer(cgutils_json_reader const * reader,
                                            char const * key,
                                            uint64_t * out);

int cgutils_json_reader_get_integer(cgutils_json_reader const * reader,
                                    char const * key,
                                    int64_t * out);

void cgutils_json_reader_free(cgutils_json_reader * reader);
void cgutils_json_reader_delete(void * reader);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_JSON_READER_H_ */
