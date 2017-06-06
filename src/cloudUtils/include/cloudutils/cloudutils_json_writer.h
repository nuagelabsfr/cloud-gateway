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

#ifndef CLOUD_GATEWAY_UTILS_JSON_WRITER_H_
#define CLOUD_GATEWAY_UTILS_JSON_WRITER_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef struct cgutils_json_writer cgutils_json_writer;

typedef struct cgutils_json_writer_element cgutils_json_writer_element;

#include <cloudutils/cloudutils_compiler_specifics.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_json_writer_new(cgutils_json_writer ** writer);

int cgutils_json_writer_new_element(cgutils_json_writer_element ** elt);

int cgutils_json_writer_element_add_child(cgutils_json_writer_element * parent,
                                         char const * element_name,
                                         cgutils_json_writer_element ** child);

int cgutils_json_writer_element_add_list_child(cgutils_json_writer_element * parent,
                                               char const * element_name,
                                               cgutils_json_writer_element ** child);

int cgutils_json_writer_add_element_to_list(cgutils_json_writer_element * parent,
                                            cgutils_json_writer_element * child);

int cgutils_json_writer_element_add_uint64_prop(cgutils_json_writer_element * elt,
                                                char const * prop_name,
                                                uint64_t prop_value);

int cgutils_json_writer_element_add_boolean_prop(cgutils_json_writer_element * elt,
                                                 char const * prop_name,
                                                 bool prop_value);

int cgutils_json_writer_element_add_string_prop(cgutils_json_writer_element * elt,
                                                char const * prop_name,
                                                char const * prop_value);

int cgutils_json_writer_get_output(cgutils_json_writer const * writer,
                                  char ** out,
                                  size_t * out_size);

cgutils_json_writer_element * cgutils_json_writer_get_root(cgutils_json_writer const * writer) COMPILER_PURE_FUNCTION;

void cgutils_json_writer_element_release(cgutils_json_writer_element * element);

void cgutils_json_writer_element_free(cgutils_json_writer_element * element);
void cgutils_json_writer_free(cgutils_json_writer * writer);
void cgutils_json_writer_delete(void * writer);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_UTILS_JSON_WRITER_H_ */
