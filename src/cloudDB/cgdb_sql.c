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
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <cloudutils/cloudutils.h>

#include "cgdb/cgdb.h"
#include "cgdb/cgdb_backend.h"
#include "cgdb/cgdb_sql.h"
#include "cgdb/cgdb_utils.h"

static struct
{
    char const * const str;
    size_t const str_len;
} const cgdb_sql_operators[] =
{
#define TYPE(type, value) { value, sizeof value - 1},
#include "cgdb/cgdb_sql_operators.itm"
#undef TYPE
};

static size_t const cgdb_sql_operators_count = sizeof cgdb_sql_operators / sizeof *cgdb_sql_operators;

//COMPILER_STATIC_ASSERT(cgdb_sql_operators_count == CGDB_FIELD_OPERATOR_MAX, "CloudDB SQL operators count is different from CGDB operators count");

char const * cgdb_sql_operator_to_string(cgdb_field_operator_type const type)
{
    char const * result = NULL;

    assert(type < cgdb_sql_operators_count);

    if (CGUTILS_COMPILER_LIKELY(type < cgdb_sql_operators_count))
    {
        result = cgdb_sql_operators[type].str;
    }

    return result;
}

size_t cgdb_sql_operator_to_string_len(cgdb_field_operator_type const type)
{
    size_t result = 0;

    assert(type < cgdb_sql_operators_count);

    if (CGUTILS_COMPILER_LIKELY(type < cgdb_sql_operators_count))
    {
        result = cgdb_sql_operators[type].str_len;
    }

    return result;
}

typedef struct
{
    char const * field_name;
    char const * operator_str;
    char * field_value;
    size_t field_name_len;
    size_t operator_str_len;
    size_t field_value_len;
    bool field_value_backend_allocated;
} cgdb_sql_operator_info;

#define CGDB_SQL_PARAMS_FIELD_AND_SEP " AND "
#define CGDB_SQL_PARAMS_FIELD_COMMA_SEP ", "
#define CGDB_SQL_FIND_REQUEST_START "SELECT * FROM "
#define CGDB_SQL_INSERT_REQUEST_START "INSERT INTO "
#define CGDB_SQL_INSERT_REQUEST_VALUES ") VALUES ("
#define CGDB_SQL_REQUEST_WHERE " WHERE "
#define CGDB_SQL_DELETE_REQUEST_START "DELETE FROM "
#define CGDB_SQL_UPDATE_REQUEST_START "UPDATE "
#define CGDB_SQL_UPDATE_REQUEST_SET " SET "
#define CGDB_SQL_INC_OPERATOR "+"
#define CGDB_SQL_LIMIT_KEYWORD " LIMIT "
#define CGDB_SQL_OFFSET_KEYWORD " OFFSET "

static int cgdb_sql_get_str_from_params(void * const backend_data,
                                        cgdb_sql_escaper * const escaper,
                                        cgdb_field const * const field,
                                        char ** const str,
                                        size_t * const str_len,
                                        bool * const backend_allocated)
{
    int result = 0;

    assert(escaper != NULL);
    assert(field != NULL);
    assert(str != NULL);
    assert(str_len != NULL);
    assert(backend_allocated != NULL);

    *str = NULL;
    *str_len = 0;
    *backend_allocated = false;

    switch(field->value_type)
    {
    case CGDB_FIELD_VALUE_TYPE_STRING:
    case CGDB_FIELD_VALUE_TYPE_IMMUTABLE_STRING:
        result = (*escaper)(backend_data,
                            field->value_str,
                            strlen(field->value_str),
                            str);

        if (result == 0)
        {
            *backend_allocated = true;
        }
        else
        {
            CGUTILS_ERROR("Backend escaping function returned %d for value %s, len %zu",
                          result,
                          (char *) field->value_str,
                          strlen(field->value_str));
        }
        break;
    case CGDB_FIELD_VALUE_TYPE_FIELD:
        *str = cgutils_strdup(field->value_str);

        if (*str != NULL)
        {
            *backend_allocated = true;
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for %s, len %zu",
                          (char *) field->value_str,
                          strlen(field->value_str));
        }
        break;
    case CGDB_FIELD_VALUE_TYPE_UINT64:
        result = cgutils_asprintf(str, "%"PRIu64, field->value_uint64);
        break;
    case CGDB_FIELD_VALUE_TYPE_INT64:
        result = cgutils_asprintf(str, "%"PRId64, field->value_int64);
        break;
    case CGDB_FIELD_VALUE_TYPE_INT32:
        result = cgutils_asprintf(str, "%"PRId32, field->value_int32);
        break;
    case CGDB_FIELD_VALUE_TYPE_UINT16:
        result = cgutils_asprintf(str, "%"PRIu16, field->value_uint16);
        break;
    case CGDB_FIELD_VALUE_TYPE_BOOLEAN:
        *str = cgutils_strdup(field->value_bool == true ? "true" : "false");
        if (*str == NULL)
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for boolean");
        }
        break;
    case CGDB_FIELD_VALUE_TYPE_NULL:
        *str = cgutils_strdup("NULL");
        if (*str == NULL)
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for NULL");
        }
        break;
    }

    if (result == 0)
    {
        assert(*str != NULL);
        *str_len = strlen(*str);
    }
    else
    {
        CGUTILS_ERROR("Error converting field value to string: %d", result);
    }

    return result;
}

static int cgdb_sql_names_values_str_from_fields_list(void * const backend_data,
                                                      cgdb_sql_escaper * const backend_escaper,
                                                      cgdb_sql_free * const backend_free,
                                                      cgutils_llist * const params_fields,
                                                      char const * const separator,
                                                      size_t const separator_len,
                                                      char ** const str,
                                                      size_t * const str_len)
{
    int result = 0;

    assert(backend_escaper != NULL);
    assert(backend_free != NULL);
    assert(params_fields != NULL);
    assert(str != NULL);
    assert(str_len != NULL);
    assert(separator != NULL);

    size_t len = 0;
    size_t const params_fields_count = cgutils_llist_get_count(params_fields);

    *str = NULL;
    *str_len = 0;

    if (params_fields_count > 0)
    {
        cgdb_sql_operator_info * fields = NULL;

        CGUTILS_MALLOC(fields, params_fields_count, sizeof *fields);

        if (fields != NULL)
        {
            cgutils_llist_elt * elt = cgutils_llist_get_iterator(params_fields);
            size_t idx = 0;

            while (result == 0 && elt != NULL)
            {
                cgdb_field * field = cgutils_llist_elt_get_object(elt);
                assert(field != NULL);
                assert(field->name != NULL);

                cgdb_sql_operator_info * info = &(fields[idx]);
                info->field_name = field->name;
                info->field_name_len = strlen(field->name);

                info->operator_str = cgdb_sql_operator_to_string(field->operator_type);
                assert(info->operator_str != NULL);
                info->operator_str_len = cgdb_sql_operator_to_string_len(field->operator_type);

                result = cgdb_sql_get_str_from_params(backend_data,
                                                      backend_escaper,
                                                      field,
                                                      &(info->field_value),
                                                      &(info->field_value_len),
                                                      &(info->field_value_backend_allocated));
                if (len > 0)
                {
                    len += separator_len;
                }

                len += info->field_name_len + info->operator_str_len + info->field_value_len;

                idx++;
                elt = cgutils_llist_elt_get_next(elt);
            }

            if (result == 0)
            {
                assert(idx == params_fields_count);

                CGUTILS_MALLOC(*str, len + 1, 1);

                if (*str != NULL)
                {
                    size_t str_pos = 0;

                    for (size_t cnt = 0; cnt < idx; cnt++)
                    {
                        cgdb_sql_operator_info * info = &(fields[cnt]);

                        if (str_pos > 0)
                        {
                            memcpy(*str + str_pos, separator, separator_len);
                            str_pos += separator_len;
                        }

                        memcpy(*str + str_pos, info->field_name, info->field_name_len);
                        str_pos += info->field_name_len;
                        memcpy(*str + str_pos, info->operator_str, info->operator_str_len);
                        str_pos += info->operator_str_len;
                        memcpy(*str + str_pos, info->field_value, info->field_value_len);
                        str_pos += info->field_value_len;
                    }

                    if (result != 0)
                    {
                        CGUTILS_FREE(*str);
                    }
                }
                else
                {
                    result = ENOMEM;
                }
            }

            for (size_t cnt = 0; cnt < idx; cnt++)
            {
                if (fields[cnt].field_value_backend_allocated == true)
                {
                    (*backend_free)(fields[cnt].field_value), fields[cnt].field_value = NULL;
                }
                else
                {
                    CGUTILS_FREE(fields[cnt].field_value);
                }
            }

            CGUTILS_FREE(fields);
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating fields array: %d", result);
        }
    }

    if (*str != NULL)
    {
        *str_len = len;
    }

    return result;
}

static int cgdb_sql_get_increments_from_fields_list(void * const backend_data,
                                                    cgdb_sql_escaper * const backend_escaper,
                                                    cgdb_sql_free * const backend_free,
                                                    cgutils_llist * const params_fields,
                                                    char const * const separator,
                                                    size_t const separator_len,
                                                    char ** const str,
                                                    size_t * const str_len)
{
    int result = 0;

    assert(backend_data != NULL);
    assert(backend_escaper != NULL);
    assert(backend_free != NULL);
    assert(params_fields != NULL);
    assert(str != NULL);
    assert(str_len != NULL);
    assert(separator != NULL);

    size_t len = 0;
    size_t const params_fields_count = cgutils_llist_get_count(params_fields);

    *str = NULL;
    *str_len = 0;

    if (params_fields_count > 0)
    {
        cgdb_sql_operator_info * fields = NULL;

        CGUTILS_MALLOC(fields, params_fields_count, sizeof *fields);

        if (fields != NULL)
        {
            cgutils_llist_elt * elt = cgutils_llist_get_iterator(params_fields);
            size_t idx = 0;

            while (result == 0 && elt != NULL)
            {
                cgdb_field * field = cgutils_llist_elt_get_object(elt);
                assert(field != NULL);
                assert(field->name != NULL);

                cgdb_sql_operator_info * info = &(fields[idx]);
                info->field_name = field->name;
                info->field_name_len = strlen(field->name);

                assert(field->operator_type == CGDB_FIELD_OPERATOR_EQUAL);
                info->operator_str = cgdb_sql_operator_to_string(field->operator_type);
                assert(info->operator_str != NULL);
                info->operator_str_len = cgdb_sql_operator_to_string_len(field->operator_type);

                result = cgdb_sql_get_str_from_params(backend_data,
                                                      backend_escaper,
                                                      field,
                                                      &(info->field_value),
                                                      &(info->field_value_len),
                                                      &(info->field_value_backend_allocated));
                if (len > 0)
                {
                    len += separator_len;
                }

                len += info->field_name_len + info->operator_str_len + info->field_name_len + (sizeof CGDB_SQL_INC_OPERATOR -1) + info->field_value_len;

                idx++;
                elt = cgutils_llist_elt_get_next(elt);
            }

            if (result == 0)
            {
                assert(idx == params_fields_count);

                CGUTILS_MALLOC(*str, len + 1, 1);

                if (*str != NULL)
                {
                    size_t str_pos = 0;

                    for (size_t cnt = 0; cnt < idx; cnt++)
                    {
                        cgdb_sql_operator_info * info = &(fields[cnt]);

                        if (str_pos > 0)
                        {
                            memcpy(*str + str_pos, separator, separator_len);
                            str_pos += separator_len;
                        }

                        memcpy(*str + str_pos, info->field_name, info->field_name_len);
                        str_pos += info->field_name_len;
                        memcpy(*str + str_pos, info->operator_str, info->operator_str_len);
                        str_pos += info->operator_str_len;
                        memcpy(*str + str_pos, info->field_name, info->field_name_len);
                        str_pos += info->field_name_len;
                        memcpy(*str + str_pos, CGDB_SQL_INC_OPERATOR, sizeof CGDB_SQL_INC_OPERATOR - 1);
                        str_pos += sizeof CGDB_SQL_INC_OPERATOR -1;
                        memcpy(*str + str_pos, info->field_value, info->field_value_len);
                        str_pos += info->field_value_len;
                    }

                    if (result != 0)
                    {
                        CGUTILS_FREE(*str);
                    }
                }
                else
                {
                    result = ENOMEM;
                }
            }

            for (size_t cnt = 0; cnt < idx; cnt++)
            {
                if (fields[cnt].field_value_backend_allocated == true)
                {
                    (*backend_free)(fields[cnt].field_value), fields[cnt].field_value = NULL;
                }
                else
                {
                    CGUTILS_FREE(fields[cnt].field_value);
                }
            }

            CGUTILS_FREE(fields);
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating fields array: %d", result);
        }
    }

    if (*str != NULL)
    {
        *str_len = len;
    }

    return result;
}

static int cgdb_sql_insert_str_from_fields_list(void * const backend_data,
                                                cgdb_sql_escaper * const backend_escaper,
                                                cgdb_sql_free * const backend_free,
                                                cgutils_llist * const params_fields,
                                                char ** const names_str,
                                                size_t * const names_str_len,
                                                char ** const values_str,
                                                size_t * const values_str_len)
{
    int result = 0;

    assert(backend_data != NULL);
    assert(backend_escaper != NULL);
    assert(backend_free != NULL);
    assert(params_fields != NULL);
    assert(names_str != NULL);
    assert(names_str_len != NULL);
    assert(values_str != NULL);
    assert(values_str_len != NULL);

    size_t const params_fields_count = cgutils_llist_get_count(params_fields);

    *names_str = NULL;
    *names_str_len = 0;

    *values_str = NULL;
    *values_str_len = 0;

    if (params_fields_count > 0)
    {
        cgdb_sql_operator_info * fields = NULL;

        CGUTILS_MALLOC(fields, params_fields_count, sizeof *fields);

        if (fields != NULL)
        {
            cgutils_llist_elt * elt = cgutils_llist_get_iterator(params_fields);
            size_t idx = 0;

            while (result == 0 && elt != NULL)
            {
                cgdb_field * field = cgutils_llist_elt_get_object(elt);
                assert(field != NULL);
                assert(field->name != NULL);

                cgdb_sql_operator_info * info = &(fields[idx]);
                info->field_name = field->name;
                info->field_name_len = strlen(field->name);

                result = cgdb_sql_get_str_from_params(backend_data,
                                                      backend_escaper,
                                                      field,
                                                      &(info->field_value),
                                                      &(info->field_value_len),
                                                      &(info->field_value_backend_allocated));


                if (idx > 0)
                {
                    *names_str_len += sizeof CGDB_SQL_PARAMS_FIELD_COMMA_SEP - 1;
                    *values_str_len += sizeof CGDB_SQL_PARAMS_FIELD_COMMA_SEP - 1;
                }

                *names_str_len += info->field_name_len;
                *values_str_len += info->field_value_len;

                idx++;
                elt = cgutils_llist_elt_get_next(elt);

            }

            if (result == 0)
            {
                assert(idx == params_fields_count);

                CGUTILS_MALLOC(*names_str, *names_str_len + 1, 1);

                if (*names_str != NULL)
                {
                    char * str = *names_str;
                    size_t str_pos = 0;

                    for (size_t cnt = 0; cnt < idx; cnt++)
                    {
                        cgdb_sql_operator_info * info = &(fields[cnt]);

                        if (str_pos > 0)
                        {
                            memcpy(str + str_pos, CGDB_SQL_PARAMS_FIELD_COMMA_SEP, sizeof CGDB_SQL_PARAMS_FIELD_COMMA_SEP - 1);
                            str_pos += sizeof CGDB_SQL_PARAMS_FIELD_COMMA_SEP - 1;
                        }

                        memcpy(str + str_pos, info->field_name, info->field_name_len);
                        str_pos += info->field_name_len;
                    }

                    str[str_pos] = '\0';

                    CGUTILS_MALLOC(*values_str, *values_str_len + 1, 1);

                    if (*values_str != NULL)
                    {
                        str = *values_str;
                        str_pos = 0;

                        for (size_t cnt = 0; cnt < idx; cnt++)
                        {
                            cgdb_sql_operator_info * info = &(fields[cnt]);
                            if (str_pos > 0)
                            {
                                memcpy(str + str_pos, CGDB_SQL_PARAMS_FIELD_COMMA_SEP, sizeof CGDB_SQL_PARAMS_FIELD_COMMA_SEP - 1);
                                str_pos += sizeof CGDB_SQL_PARAMS_FIELD_COMMA_SEP - 1;
                            }

                            memcpy(str + str_pos, info->field_value, info->field_value_len);
                            str_pos += info->field_value_len;
                        }

                        str[str_pos] = '\0';
                    }
                    else
                    {
                        result = ENOMEM;
                    }

                    if (result != 0)
                    {
                        CGUTILS_FREE(*names_str);
                    }
                }
                else
                {
                    result = ENOMEM;
                }
            }

            for (size_t cnt = 0; cnt < idx; cnt++)
            {
                if (fields[cnt].field_value_backend_allocated == true)
                {
                    (*backend_free)(fields[cnt].field_value), fields[cnt].field_value = NULL;
                }
                else
                {
                    CGUTILS_FREE(fields[cnt].field_value);
                }
            }

            CGUTILS_FREE(fields);
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating fields array: %d", result);
        }
    }

    return result;
}

static int cgdb_sql_handle_limit_skip(cgdb_limit_type const limit,
                                      cgdb_skip_type const skip,
                                      char ** const out,
                                      size_t * const out_len)
{
    int result = 0;
    assert(out != NULL);
    assert(out_len != NULL);

    char * limit_str = NULL;
    size_t limit_str_len = 0;
    char * skip_str = NULL;
    size_t skip_str_len = 0;
    size_t str_len = 0;

    if (cgdb_limit_is_valid(limit) == true)
    {
        uint32_t const limit_temp = (uint32_t) limit;

        result = cgutils_asprintf(&limit_str, "%"PRIu32, limit_temp);

        if (result == 0)
        {
            limit_str_len = strlen(limit_str);
            str_len += sizeof CGDB_SQL_LIMIT_KEYWORD - 1 + limit_str_len;
        }
        else
        {
            CGUTILS_ERROR("Error allocating limit string: %d", result);
        }
    }

    if (result == 0 && cgdb_skip_is_valid(skip) == true)
    {
        uint32_t const skip_temp = (uint32_t) skip;

        result = cgutils_asprintf(&skip_str, "%"PRIu32, skip_temp);

        if (result == 0)
        {
            skip_str_len = strlen(skip_str);
            str_len += sizeof CGDB_SQL_OFFSET_KEYWORD - 1 + skip_str_len;
        }
        else
        {
            CGUTILS_ERROR("Error allocating skip string: %d", result);
        }

    }

    if (result == 0 && str_len > 0)
    {
        char * result_str = NULL;
        CGUTILS_MALLOC(result_str, str_len + 1, 1);

        if (result_str != NULL)
        {
            size_t pos = 0;

            if (limit_str_len > 0)
            {
                memcpy(result_str + pos, CGDB_SQL_LIMIT_KEYWORD, sizeof CGDB_SQL_LIMIT_KEYWORD - 1);
                pos += sizeof CGDB_SQL_LIMIT_KEYWORD - 1;
                memcpy(result_str + pos, limit_str, limit_str_len);
                pos += limit_str_len;
            }

            if (skip_str_len > 0)
            {
                memcpy(result_str + pos, CGDB_SQL_OFFSET_KEYWORD, sizeof CGDB_SQL_OFFSET_KEYWORD - 1);
                pos += sizeof CGDB_SQL_OFFSET_KEYWORD - 1;
                memcpy(result_str + pos, skip_str, skip_str_len);
                pos += skip_str_len;
            }

            (result_str)[pos] = '\0';
        }
        else
        {
            CGUTILS_ERROR("Error allocating limit/skip result string: %d", result);
            result = ENOMEM;
        }

        *out = result_str;
    }
    else
    {
        *out = NULL;
    }

    if (limit_str != NULL)
    {
        CGUTILS_FREE(limit_str);
    }

    if (skip_str != NULL)
    {
        CGUTILS_FREE(skip_str);
    }

    *out_len = str_len;

    return result;
}

static int cgdb_sql_handle_order_by(cgutils_llist * const order_by_params,
                                    char ** const order_str,
                                    size_t * const order_str_len)
{
    int result = 0;
    char * str = NULL;
    size_t str_len = 0;
    assert(order_str != NULL);
    assert(order_str_len != NULL);

    if (order_by_params != NULL)
    {
        size_t const params_count = cgutils_llist_get_count(order_by_params);

        if (params_count > 0)
        {
            struct
            {
                char const * value;
                size_t len;
            } * tab = NULL;

            CGUTILS_MALLOC(tab, params_count, sizeof *tab);

            if (tab != NULL)
            {
                bool first = true;
                cgutils_llist_elt * elt = cgutils_llist_get_first(order_by_params);
                size_t idx = 0;

                while (result == 0 && elt != NULL)
                {
                    char const * const value = cgutils_llist_elt_get_object(elt);
                    assert(value != NULL);
                    size_t value_len = strlen(value);
                    assert(idx < params_count);

                    tab[idx].len = value_len;
                    tab[idx].value = value;
                    str_len += (value_len + 1 /* for the leading space */);

                    if (first == true)
                    {
                        first = false;
                    }
                    else
                    {
                        str_len += 1 /* for the comma */;
                    }

                    idx++;
                    elt = cgutils_llist_elt_get_next(elt);
                }

                if (result == 0 && str_len > 0 && idx == params_count)
                {
                    char const order_by[] = " ORDER BY";
                    size_t order_by_len = sizeof order_by - 1;

                    str_len += order_by_len;
                    str_len += 1 /* for the trailing space */;

                    CGUTILS_MALLOC(str, str_len + 1, 1);

                    if (str != NULL)
                    {
                        size_t pos = 0;

                        first = true;

                        memcpy(str + pos, order_by, order_by_len);
                        pos += order_by_len;

                        for (idx = 0; idx < params_count; idx++)
                        {
                            assert(tab[idx].value != NULL);

                            if (tab[idx].len > 0)
                            {
                                if (first == true)
                                {
                                    first = false;
                                }
                                else
                                {
                                    str[pos] = ',';
                                    pos++;
                                }

                                str[pos] = ' ';
                                pos++;
                                memcpy(str + pos, tab[idx].value, tab[idx].len);
                                pos += tab[idx].len;
                            }
                        }

                        str[pos] = ' ';
                        pos++;
                        str[pos] = '\0';
                    }
                    else
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Error allocating memory for order by str: %d", result);
                    }
                }
                else
                {
                    str_len = 0;
                }

                CGUTILS_FREE(tab);
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for order by params: %d", result);
            }
        }
    }

    *order_str = str;
    *order_str_len = str_len;

    return result;
}

int cgdb_sql_construct_find_query(void * const backend_data,
                                  char const * const table,
                                  cgutils_llist * const cond_fields,
                                  cgutils_llist * const order_by_params,
                                  cgdb_sql_escaper * const backend_escaper,
                                  cgdb_sql_free * const backend_free,
                                  cgdb_limit_type const limit,
                                  cgdb_skip_type const skip,
                                  char ** const query_out)
{
    int result = EINVAL;

    if (backend_data != NULL && table != NULL && cond_fields != NULL && backend_escaper != NULL
        && backend_free != NULL && query_out != NULL)
    {
        cgutils_llist * const params_fields = cond_fields;

        /* SELECT * FROM <table> WHERE <param1>=<condition1> AND <param2> ... LIMIT <skip>,<limit>*/
        char * where_block = NULL;
        size_t where_block_len = 0;

        result = cgdb_sql_names_values_str_from_fields_list(backend_data,
                                                            backend_escaper,
                                                            backend_free,
                                                            params_fields,
                                                            CGDB_SQL_PARAMS_FIELD_AND_SEP,
                                                            sizeof CGDB_SQL_PARAMS_FIELD_AND_SEP -1,
                                                            &where_block,
                                                            &where_block_len);

        if (result == 0)
        {
            char * limit_str = NULL;
            size_t limit_str_len = 0;

            result = cgdb_sql_handle_limit_skip(limit, skip, &limit_str, &limit_str_len);

            if (result == 0)
            {
                char * order_str = NULL;
                size_t order_str_len = 0;

                result = cgdb_sql_handle_order_by(order_by_params, &order_str, &order_str_len);

                if (result == 0)
                {
                    size_t const table_len = strlen(table);

                    size_t const query_len = sizeof CGDB_SQL_FIND_REQUEST_START - 1 +
                        table_len +
                        ( where_block_len > 0 ?
                          ( sizeof CGDB_SQL_REQUEST_WHERE - 1 +
                            where_block_len) : 0)
                        + limit_str_len
                        + order_str_len;

                    char * query = NULL;

                    CGUTILS_MALLOC(query, query_len + 1, 1);

                    if (query != NULL)
                    {
                        size_t query_pos = 0;
                        memcpy(query + query_pos, CGDB_SQL_FIND_REQUEST_START, sizeof CGDB_SQL_FIND_REQUEST_START - 1);
                        query_pos += sizeof CGDB_SQL_FIND_REQUEST_START - 1;
                        memcpy(query + query_pos, table, table_len);
                        query_pos += table_len;

                        if (where_block_len > 0)
                        {
                            memcpy(query + query_pos, CGDB_SQL_REQUEST_WHERE, sizeof CGDB_SQL_REQUEST_WHERE - 1);
                            query_pos += sizeof CGDB_SQL_REQUEST_WHERE - 1;
                            memcpy(query + query_pos, where_block, where_block_len);
                            query_pos += where_block_len;
                        }

                        if (order_str_len > 0)
                        {
                            memcpy(query + query_pos, order_str, order_str_len);
                            query_pos += order_str_len;
                        }

                        if (limit_str_len > 0)
                        {
                            memcpy(query + query_pos, limit_str, limit_str_len);
                            query_pos += limit_str_len;
                        }

                        query[query_pos] = '\0';

                        *query_out = query;
                        query = NULL;
                    }
                    else
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Error allocating query: %d", result);
                    }

                    if (order_str != NULL)
                    {
                        CGUTILS_FREE(order_str);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error handling order by parameters: %d", result);
                }

                if (limit_str != NULL)
                {
                    CGUTILS_FREE(limit_str);
                }
            }
            else
            {
                CGUTILS_ERROR("Error handling limit / skip parameters: %d", result);
            }

            CGUTILS_FREE(where_block);
        }
        else
        {
            CGUTILS_ERROR("Error constructing where string from parameters list: %d", result);
        }
    }

    return result;
}


int cgdb_sql_construct_insert_query(void * const backend_data,
                                    char const * const table,
                                    cgutils_llist * const op_fields,
                                    cgdb_sql_escaper * const backend_escaper,
                                    cgdb_sql_free * const backend_free,
                                    char ** const query_out)
{
    int result = EINVAL;

    if (backend_data != NULL && table != NULL && op_fields != NULL && backend_escaper != NULL
        && backend_free != NULL && query_out != NULL)
    {
        cgutils_llist * const fields = op_fields;
        /* INSERT INTO <table>(<param1>, <param2>, <param3>) VALUES (<value1>, <value2>, <value3>);*/

        char * fields_names_block = NULL;
        size_t fields_names_block_len = 0;

        char * fields_values_block = NULL;
        size_t fields_values_block_len = 0;

        result = cgdb_sql_insert_str_from_fields_list(backend_data,
                                                      backend_escaper,
                                                      backend_free,
                                                      fields,
                                                      &fields_names_block,
                                                      &fields_names_block_len,
                                                      &fields_values_block,
                                                      &fields_values_block_len);
        if (result == 0)
        {
            size_t const table_len = strlen(table);

            size_t const query_len = sizeof CGDB_SQL_INSERT_REQUEST_START - 1 +
                table_len +
                1 /* ( */ +
                fields_names_block_len +
                sizeof CGDB_SQL_INSERT_REQUEST_VALUES - 1 + /* ) VALUES ( */
                fields_values_block_len +
                1 /* ) */;

            char * query = NULL;

            CGUTILS_MALLOC(query, query_len + 1, 1);

            if (query != NULL)
            {
                static char const insert_request_values[] = CGDB_SQL_INSERT_REQUEST_VALUES;

                size_t query_pos = 0;
                memcpy(query + query_pos, CGDB_SQL_INSERT_REQUEST_START, sizeof CGDB_SQL_INSERT_REQUEST_START - 1);
                query_pos += sizeof CGDB_SQL_INSERT_REQUEST_START - 1;
                memcpy(query + query_pos, table, table_len);
                query_pos += table_len;
                query[query_pos++] = '(';
                if (fields_names_block_len > 0)
                {
                    assert(fields_names_block != NULL);
                    memcpy(query + query_pos, fields_names_block, fields_names_block_len);
                    query_pos += fields_names_block_len;
                }

                memcpy(query + query_pos, insert_request_values, sizeof CGDB_SQL_INSERT_REQUEST_VALUES - 1);
                query_pos += sizeof CGDB_SQL_INSERT_REQUEST_VALUES - 1;

                if (fields_values_block_len > 0)
                {
                    assert(fields_values_block != NULL);
                    memcpy(query + query_pos, fields_values_block, fields_values_block_len);
                    query_pos += fields_values_block_len;
                }

                query[query_pos++] = ')';
                query[query_pos] = '\0';

                *query_out = query;
                query = NULL;
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating query: %d", result);
            }

            CGUTILS_FREE(fields_names_block);
            CGUTILS_FREE(fields_values_block);
        }
        else
        {
            CGUTILS_ERROR("Error constructing where string from parameters list: %d", result);
        }
    }

    return result;
}

int cgdb_sql_construct_update_query(void * const backend_data,
                                    char const * const table,
                                    cgutils_llist * const cond_fields,
                                    cgutils_llist * const op_fields,
                                    cgdb_sql_escaper * const backend_escaper,
                                    cgdb_sql_free * const backend_free,
                                    char ** const query_out)
{
    int result = EINVAL;

    if (backend_data != NULL && table != NULL && cond_fields != NULL && op_fields != NULL && backend_escaper != NULL
        && backend_free != NULL && query_out != NULL)
    {
        /* UPDATE <table> SET <name1>=<param1>, <name2>=<param2> WHERE <opname1>=<opparam1> AND <opname2>=<opparam2>;*/

        char * set_block = NULL;
        size_t set_block_len = 0;

        result = cgdb_sql_names_values_str_from_fields_list(backend_data,
                                                            backend_escaper,
                                                            backend_free,
                                                            op_fields,
                                                            CGDB_SQL_PARAMS_FIELD_COMMA_SEP,
                                                            sizeof CGDB_SQL_PARAMS_FIELD_COMMA_SEP -1,
                                                            &set_block,
                                                            &set_block_len);

        if (result == 0)
        {
            char * where_block = NULL;
            size_t where_block_len = 0;

            result = cgdb_sql_names_values_str_from_fields_list(backend_data,
                                                                backend_escaper,
                                                                backend_free,
                                                                cond_fields,
                                                                CGDB_SQL_PARAMS_FIELD_AND_SEP,
                                                                sizeof CGDB_SQL_PARAMS_FIELD_AND_SEP - 1,
                                                                &where_block,
                                                                &where_block_len);

            if (result == 0)
            {
                size_t const table_len = strlen(table);

                size_t const query_len = sizeof CGDB_SQL_UPDATE_REQUEST_START - 1 + /* 'UPDATE ' */
                    table_len +
                    sizeof CGDB_SQL_UPDATE_REQUEST_SET /* ' SET ' */ +
                    set_block_len +
                    ( where_block_len > 0 ?
                      (
                          sizeof CGDB_SQL_REQUEST_WHERE /* ' WHERE ' */ +
                          where_block_len ) : 0);

                char * query = NULL;

                CGUTILS_MALLOC(query, query_len + 1, 1);

                if (query != NULL)
                {
                    size_t query_pos = 0;
                    memcpy(query + query_pos, CGDB_SQL_UPDATE_REQUEST_START, sizeof CGDB_SQL_UPDATE_REQUEST_START - 1);
                    query_pos += sizeof CGDB_SQL_UPDATE_REQUEST_START - 1;
                    memcpy(query + query_pos, table, table_len);
                    query_pos += table_len;
                    memcpy(query + query_pos, CGDB_SQL_UPDATE_REQUEST_SET, sizeof CGDB_SQL_UPDATE_REQUEST_SET - 1);
                    query_pos += sizeof CGDB_SQL_UPDATE_REQUEST_SET - 1;
                    memcpy(query + query_pos, set_block, set_block_len);
                    query_pos += set_block_len;

                    if (where_block_len > 0)
                    {
                        memcpy(query + query_pos, CGDB_SQL_REQUEST_WHERE, sizeof CGDB_SQL_REQUEST_WHERE - 1);
                        query_pos += sizeof CGDB_SQL_REQUEST_WHERE - 1;
                        memcpy(query + query_pos, where_block, where_block_len);
                        query_pos += where_block_len;
                    }

                    query[query_pos] = '\0';

                    *query_out = query;
                    query = NULL;
                }
                else
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error allocating query: %d", result);
                }

                CGUTILS_FREE(where_block);
            }
            else
            {
                CGUTILS_ERROR("Error constructing where string from parameters list: %d", result);
            }

            CGUTILS_FREE(set_block);
        }
        else
        {
            CGUTILS_ERROR("Error constructing where string from parameters list: %d", result);
        }
    }

    return result;
}

int cgdb_sql_construct_delete_query(void * const backend_data,
                                    char const * const table,
                                    cgutils_llist * const cond_fields,
                                    cgdb_sql_escaper * const backend_escaper,
                                    cgdb_sql_free * const backend_free,
                                    char ** const query_out)
{
    int result = EINVAL;

    if (backend_data != NULL && table != NULL && cond_fields != NULL && backend_escaper != NULL
        && backend_free != NULL && query_out != NULL)
    {
        cgutils_llist * const fields = cond_fields;
        /* DELETE FROM <table> WHERE <name1>=<param1> AND <name2>=<param2>;*/

        char * where_block = NULL;
        size_t where_block_len = 0;

        result = cgdb_sql_names_values_str_from_fields_list(backend_data,
                                                            backend_escaper,
                                                            backend_free,
                                                            fields,
                                                            CGDB_SQL_PARAMS_FIELD_AND_SEP,
                                                            sizeof CGDB_SQL_PARAMS_FIELD_AND_SEP - 1,
                                                            &where_block,
                                                            &where_block_len);

        if (result == 0)
        {
            size_t const table_len = strlen(table);

            size_t const query_len = sizeof CGDB_SQL_DELETE_REQUEST_START - 1 + /* 'DELETE FROM ' */
                table_len +
                ( where_block_len > 0  ?
                  (
                      sizeof CGDB_SQL_REQUEST_WHERE /* ' WHERE ' */ +
                      where_block_len ) : 0);

            char * query = NULL;

            CGUTILS_MALLOC(query, query_len + 1, 1);

            if (query != NULL)
            {
                size_t query_pos = 0;
                memcpy(query + query_pos, CGDB_SQL_DELETE_REQUEST_START, sizeof CGDB_SQL_DELETE_REQUEST_START - 1);
                query_pos += sizeof CGDB_SQL_DELETE_REQUEST_START - 1;
                memcpy(query + query_pos, table, table_len);
                query_pos += table_len;

                if (where_block_len > 0)
                {
                    assert(where_block != NULL);
                    memcpy(query + query_pos, CGDB_SQL_REQUEST_WHERE, sizeof CGDB_SQL_REQUEST_WHERE - 1);
                    query_pos += sizeof CGDB_SQL_REQUEST_WHERE - 1;
                    memcpy(query + query_pos, where_block, where_block_len);
                    query_pos += where_block_len;
                }

                query[query_pos] = '\0';

                *query_out = query;
                query = NULL;
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating query: %d", result);
            }

            CGUTILS_FREE(where_block);
        }
        else
        {
            CGUTILS_ERROR("Error constructing where string from parameters list: %d", result);
        }
    }

    return result;
}

int cgdb_sql_construct_increment_query(void * const backend_data,
                                       char const * const table,
                                       cgutils_llist * const cond_fields,
                                       cgutils_llist * const inc_fields,
                                       cgdb_sql_escaper * const backend_escaper,
                                       cgdb_sql_free * const backend_free,
                                       char ** const query_out)
{
    int result = EINVAL;

    if (backend_data != NULL && table != NULL && cond_fields != NULL && backend_escaper != NULL
        && backend_free != NULL && query_out != NULL)
    {
        /* UPDATE <table> SET <opname1> = <opname1> + <opvalue1>, <opname2> = <opname2> + <opvalue2> WHERE <condname1>=<condparam1> AND <condname2>=<condparam2>;*/

        char * where_block = NULL;
        size_t where_block_len = 0;

        result = cgdb_sql_names_values_str_from_fields_list(backend_data,
                                                            backend_escaper,
                                                            backend_free,
                                                            cond_fields,
                                                            CGDB_SQL_PARAMS_FIELD_AND_SEP,
                                                            sizeof CGDB_SQL_PARAMS_FIELD_AND_SEP - 1,
                                                            &where_block,
                                                            &where_block_len);

        if (result == 0)
        {
            char * set_block = NULL;
            size_t set_block_len = 0;

            result = cgdb_sql_get_increments_from_fields_list(backend_data,
                                                              backend_escaper,
                                                              backend_free,
                                                              inc_fields,
                                                              CGDB_SQL_PARAMS_FIELD_COMMA_SEP,
                                                              sizeof CGDB_SQL_PARAMS_FIELD_COMMA_SEP -1,
                                                              &set_block,
                                                              &set_block_len);

            if (result == 0)
            {
                size_t const table_len = strlen(table);

                size_t const query_len = sizeof CGDB_SQL_UPDATE_REQUEST_START - 1 + /* 'UPDATE ' */
                    table_len +
                    sizeof CGDB_SQL_UPDATE_REQUEST_SET /* ' SET ' */ +
                    set_block_len +
                    ( where_block_len > 0 ? (
                        sizeof CGDB_SQL_REQUEST_WHERE /* ' WHERE ' */ +
                        where_block_len ) : 0);

                char * query = NULL;

                CGUTILS_MALLOC(query, query_len + 1, 1);

                if (query != NULL)
                {
                    size_t query_pos = 0;
                    memcpy(query + query_pos, CGDB_SQL_UPDATE_REQUEST_START, sizeof CGDB_SQL_UPDATE_REQUEST_START - 1);
                    query_pos += sizeof CGDB_SQL_UPDATE_REQUEST_START - 1;
                    memcpy(query + query_pos, table, table_len);
                    query_pos += table_len;
                    memcpy(query + query_pos, CGDB_SQL_UPDATE_REQUEST_SET, sizeof CGDB_SQL_UPDATE_REQUEST_SET - 1);
                    query_pos += sizeof CGDB_SQL_UPDATE_REQUEST_SET - 1;

                    if (set_block_len > 0)
                    {
                        assert(set_block != NULL);
                        memcpy(query + query_pos, set_block, set_block_len);
                        query_pos += set_block_len;
                    }

                    if (where_block_len > 0)
                    {
                        assert(where_block != NULL);
                        memcpy(query + query_pos, CGDB_SQL_REQUEST_WHERE, sizeof CGDB_SQL_REQUEST_WHERE - 1);
                        query_pos += sizeof CGDB_SQL_REQUEST_WHERE - 1;
                        memcpy(query + query_pos, where_block, where_block_len);
                        query_pos += where_block_len;
                    }

                    query[query_pos] = '\0';

                    *query_out = query;
                    query = NULL;
                }
                else
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error allocating query: %d", result);
                }

                CGUTILS_FREE(set_block);
            }
            else
            {
                CGUTILS_ERROR("Error constructing set string from parameters list: %d", result);
            }

            CGUTILS_FREE(where_block);
        }
        else
        {
            CGUTILS_ERROR("Error constructing where string from parameters list: %d", result);
        }
    }

    return result;
}
