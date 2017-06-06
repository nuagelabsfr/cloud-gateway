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

#ifndef CLOUD_UTILS_CONFIGURATION_H_
#define CLOUD_UTILS_CONFIGURATION_H_

#include <stdbool.h>
#include <stdint.h>

typedef struct cgutils_configuration cgutils_configuration;

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_llist.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_configuration_init(void);
void cgutils_configuration_destroy(void);

int cgutils_configuration_from_xml_file(char const * const file,
                                        cgutils_configuration ** out);

int cgutils_configuration_from_xml_memory(char const * const xml,
                                          size_t const xml_size,
                                          cgutils_configuration ** out);

int cgutils_configuration_from_path(cgutils_configuration const * config,
                                    char const * path,
                                    cgutils_configuration ** out);

int cgutils_configuration_get_all(cgutils_configuration const * config,
                                  char const * path,
                                  cgutils_llist ** confs_list);

int cgutils_configuration_get_string(cgutils_configuration const * config,
                                     char const * path,
                                     char ** out);

int cgutils_configuration_get_boolean(cgutils_configuration const * config,
                                      char const * path,
                                      bool * out);

int cgutils_configuration_get_unsigned_integer(cgutils_configuration const * config,
                                               char const * path,
                                               uint64_t * out);

int cgutils_configuration_get_size(cgutils_configuration const * config,
                                   char const * path,
                                   size_t * out);

int cgutils_configuration_get_integer(cgutils_configuration const * config,
                                      char const * path,
                                      int64_t * out);

void cgutils_configuration_free(cgutils_configuration * config);
void cgutils_configuration_delete(void * config);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_CONFIGURATION_H_ */
