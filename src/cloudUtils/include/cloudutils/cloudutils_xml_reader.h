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

#ifndef CLOUD_UTILS_XML_READER_H_
#define CLOUD_UTILS_XML_READER_H_

#include <stdbool.h>
#include <stdint.h>

typedef struct cgutils_xml_reader cgutils_xml_reader;

#include <cloudutils/cloudutils_llist.h>
#include <cloudutils/cloudutils_compiler_specifics.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_xml_reader_init(void);
void cgutils_xml_reader_destroy(void);

int cgutils_xml_reader_from_file(char const * const file,
                                 cgutils_xml_reader ** out);

int cgutils_xml_reader_from_path(cgutils_xml_reader * reader,
                                 char const * path,
                                 cgutils_xml_reader ** out);

int cgutils_xml_reader_register_namespace(cgutils_xml_reader * this,
                                          char const * prefix,
                                          char const * namespace);

int cgutils_xml_reader_from_buffer(char const * data,
                                   size_t data_size,
                                   cgutils_xml_reader ** out);

int cgutils_xml_reader_get_all(cgutils_xml_reader * reader,
                               char const * path,
                               cgutils_llist ** confs_list);

int cgutils_xml_reader_get_string(cgutils_xml_reader const * reader,
                                  char const * path,
                                  char ** out);

int cgutils_xml_reader_get_boolean(cgutils_xml_reader const * reader,
                                   char const * path,
                                   bool * out);

int cgutils_xml_reader_get_unsigned_integer(cgutils_xml_reader const * reader,
                                            char const * path,
                                            uint64_t * out);

int cgutils_xml_reader_get_integer(cgutils_xml_reader const * reader,
                                   char const * path,
                                   int64_t * out);

int cgutils_xml_reader_get_size(cgutils_xml_reader const * reader,
                                char const * path,
                                size_t * out);

int cgutils_xml_reader_get_c14n_string(cgutils_xml_reader const * reader,
                                       char const * path,
                                       char ** out,
                                       size_t * out_len);

void cgutils_xml_reader_free(cgutils_xml_reader * reader);
void cgutils_xml_reader_delete(void * reader);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_XML_READER_H_ */
