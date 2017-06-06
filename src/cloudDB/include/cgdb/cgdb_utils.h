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

#ifndef CLOUD_GATEWAY_DB_UTILS_H_
#define CLOUD_GATEWAY_DB_UTILS_H_

#include <stdint.h>

typedef enum
{
    CGDB_FIELD_VALUE_TYPE_STRING,
    CGDB_FIELD_VALUE_TYPE_IMMUTABLE_STRING,
    CGDB_FIELD_VALUE_TYPE_UINT16,
    CGDB_FIELD_VALUE_TYPE_INT32,
    CGDB_FIELD_VALUE_TYPE_INT64,
    CGDB_FIELD_VALUE_TYPE_UINT64,
    CGDB_FIELD_VALUE_TYPE_BOOLEAN,
    CGDB_FIELD_VALUE_TYPE_FIELD,
    CGDB_FIELD_VALUE_TYPE_NULL,
} cgdb_field_value_type;

typedef enum
{
#define TYPE(type) CGDB_FIELD_OPERATOR_ ## type,
#include "cgdb_operators.itm"
#undef TYPE
    CGDB_FIELD_OPERATOR_MAX
} cgdb_field_operator_type;

typedef struct
{
    char const * name;
    cgdb_field_value_type value_type;
    cgdb_field_operator_type operator_type;
    union
    {
        char * value_str;
        uint64_t value_uint64;
        int64_t value_int64;
        int32_t value_int32;
        uint16_t value_uint16;
        bool value_bool;
    };
    size_t name_len;
} cgdb_field;

typedef struct
{
    void const * value;
    cgdb_field_value_type type;
} cgdb_param;

typedef struct cgdb_row cgdb_row;

COMPILER_BLOCK_VISIBILITY_DEFAULT

void cgdb_param_array_init(cgdb_param params[],
                           size_t count);

void cgdb_param_set_uint64(cgdb_param params[],
                           size_t * position,
                           uint64_t const * value);

void cgdb_param_set_int64(cgdb_param params[],
                          size_t * position,
                          int64_t const * value);

void cgdb_param_set_int32(cgdb_param params[],
                          size_t * position,
                          int32_t const * value);

void cgdb_param_set_uint16(cgdb_param params[],
                           size_t * position,
                           uint16_t const * value);

void cgdb_param_set_boolean(cgdb_param params[],
                            size_t * position,
                            bool const * value);

void cgdb_param_set_string(cgdb_param params[],
                           size_t * position,
                           char const * value);

void cgdb_param_set_immutable_string(cgdb_param params[],
                                     size_t * position,
                                     char const * value);

void cgdb_param_set_null(cgdb_param params[],
                         size_t * position);

int cgdb_field_set_string(cgdb_field * field,
                          char const * name,
                          size_t name_len,
                          char const * value);

int cgdb_field_set_uint64(cgdb_field * field,
                          char const * name,
                          size_t name_len,
                          uint64_t value);

int cgdb_field_set_int64(cgdb_field * field,
                         char const * name,
                         size_t name_len,
                         int64_t value);

int cgdb_field_set_uint16(cgdb_field * field,
                          char const * name,
                          size_t name_len,
                          uint16_t value);

int cgdb_field_set_int32(cgdb_field * field,
                         char const * name,
                         size_t name_len,
                         int32_t value);

int cgdb_field_set_boolean(cgdb_field * field,
                           char const * name,
                           size_t name_len,
                           bool value);

int cgdb_field_set_null(cgdb_field * field,
                        char const * name,
                        size_t name_len);

void cgdb_field_clean(cgdb_field * this);
void cgdb_field_free(cgdb_field * this);

static inline void cgdb_field_delete(void * this)
{
    cgdb_field_free(this);
}

int cgdb_row_init(cgdb_row ** row,
                  size_t const fields_count);

int cgdb_row_get_field_by_name(cgdb_row const * row,
                               char const * field_name,
                               cgdb_field ** field);

int cgdb_row_get_field_by_idx(cgdb_row const * row,
                              size_t idx,
                              cgdb_field ** field);

int cgdb_row_get_field_value_as_boolean(cgdb_row const * row,
                                        char const * field_name,
                                        bool * value);

int cgdb_row_get_field_value_as_boolean_by_idx(cgdb_row const * row,
                                               size_t idx,
                                               bool * value);

int cgdb_row_get_field_value_as_string(cgdb_row const * row,
                                       char const * field_name,
                                       char ** value);

int cgdb_row_get_field_value_as_string_by_idx(cgdb_row const * row,
                                              size_t idx,
                                              char ** value);

int cgdb_row_get_field_value_as_uint8(cgdb_row const * row,
                                      char const * field_name,
                                      uint8_t * value);

int cgdb_row_get_field_value_as_uint16(cgdb_row const * row,
                                       char const * field_name,
                                       uint16_t * value);

int cgdb_row_get_field_value_as_uint16_by_idx(cgdb_row const * row,
                                              size_t idx,
                                              uint16_t * value);

int cgdb_row_get_field_value_as_uint64(cgdb_row const * row,
                                       char const * field_name,
                                       uint64_t * value);

int cgdb_row_get_field_value_as_uint64_by_idx(cgdb_row const * row,
                                              size_t idx,
                                              uint64_t * value);

void cgdb_row_free(cgdb_row * this);

static inline void cgdb_row_delete(void * this)
{
    cgdb_row_free(this);
}

bool cgdb_limit_is_valid(cgdb_limit_type type) COMPILER_CONST_FUNCTION;
bool cgdb_skip_is_valid(cgdb_skip_type type) COMPILER_CONST_FUNCTION;

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_DB_UTILS_H_ */
