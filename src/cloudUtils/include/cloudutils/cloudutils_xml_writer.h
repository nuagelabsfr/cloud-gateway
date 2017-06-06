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

#ifndef CLOUD_UTILS_XML_WRITER_H_
#define CLOUD_UTILS_XML_WRITER_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef struct cgutils_xml_writer cgutils_xml_writer;

typedef struct cgutils_xml_writer_element cgutils_xml_writer_element;

#include <cloudutils/cloudutils_compiler_specifics.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_xml_writer_new(cgutils_xml_writer ** writer);

int cgutils_xml_writer_from_file(char const * file,
                                 cgutils_xml_writer ** out);

int cgutils_xml_writer_create_root(cgutils_xml_writer * writer,
                                   char const * root_name,
                                   cgutils_xml_writer_element ** element);

int cgutils_xml_writer_element_add_child(cgutils_xml_writer_element * parent,
                                         char const * element_name,
                                         char const * element_value,
                                         cgutils_xml_writer_element ** child);

int cgutils_xml_writer_element_add_size_child(cgutils_xml_writer_element * parent,
                                              char const * element_name,
                                              size_t element_value,
                                              cgutils_xml_writer_element ** child);

int cgutils_xml_writer_element_add_integer_child(cgutils_xml_writer_element * parent,
                                                 char const * element_name,
                                                 int64_t element_value,
                                                 cgutils_xml_writer_element ** child);

int cgutils_xml_writer_element_add_unsigned_integer_child(cgutils_xml_writer_element * parent,
                                                          char const * element_name,
                                                          uint64_t element_value,
                                                          cgutils_xml_writer_element ** child);

int cgutils_xml_writer_element_add_boolean_child(cgutils_xml_writer_element * parent,
                                                 char const * element_name,
                                                 bool element_value,
                                                 cgutils_xml_writer_element ** child);

int cgutils_xml_writer_element_add_prop(cgutils_xml_writer_element * elt,
                                        char const * prop_name,
                                        char const * prop_value);

int cgutils_xml_writer_get_output(cgutils_xml_writer const * writer,
                                  char ** out,
                                  size_t * out_size);

int cgutils_xml_writer_save(cgutils_xml_writer const * writer);

int cgutils_xml_writer_save_to_file(cgutils_xml_writer const * writer,
                                    char const * file);

cgutils_xml_writer_element * cgutils_xml_writer_get_root(cgutils_xml_writer const * writer) COMPILER_PURE_FUNCTION;

void cgutils_xml_writer_element_release(cgutils_xml_writer_element * element);

void cgutils_xml_writer_free(cgutils_xml_writer * writer);
void cgutils_xml_writer_delete(void * writer);

void cgutils_xml_writer_string_free(char * string);

int cgutils_xml_writer_element_set_ns(cgutils_xml_writer_element * elt,
                                      char const * href,
                                      char const * prefix);

int cgutils_xml_writer_get_c14n_string(cgutils_xml_writer const * writer,
                                       char const * path,
                                       char ** out,
                                       size_t * out_len);

int cgutils_xml_writer_set_element_value(cgutils_xml_writer * writer,
                                         char const * xpath,
                                         char const * value);

int cgutils_xml_writer_get_element_from_path(cgutils_xml_writer * writer,
                                             char const * xpath,
                                             cgutils_xml_writer_element ** element);

int cgutils_xml_writer_element_get_from_path(cgutils_xml_writer_element * element,
                                             char const * xpath,
                                             cgutils_xml_writer_element ** out);

int cgutils_xml_writer_element_remove_from_tree(cgutils_xml_writer_element * element);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_XML_WRITER_H_ */
