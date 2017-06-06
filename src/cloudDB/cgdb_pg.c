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
#include <cloudutils/cloudutils_event.h>
#include <cloudutils/cloudutils_network.h>
#include <cloudutils/cloudutils_pool.h>

#include "cgdb/cgdb.h"
#include "cgdb/cgdb_backend.h"
#include "cgdb/cgdb_utils.h"

#include <libpq-fe.h>
/* Needed for OID definitions
#include <postgresql/server/catalog/pg_type.h>

but it doesn't seem to be usable outside of PG so,
I'm really sorry guys: */
#define BOOLOID 16
#define INT8OID 20
#define INT2OID 21
#define INT4OID 23
#define TEXTOID 25
#define VOIDOID 2278

#define CGDB_PG_DEFAULT_POOL_SIZE (20)
#define CGDB_PG_DEFAULT_CONNECTION_RETRY (3)

#define CGDB_PG_NO_STATUS_CB (NULL)
#define CGDB_PG_NO_STATUS_RETURNING_CB (NULL)
#define CGDB_PG_NO_CURSOR_CB (NULL)

typedef struct cgdb_pg_data cgdb_pg_data;
typedef struct cgdb_pg_cursor cgdb_pg_cursor;

struct cgdb_pg_data
{
    cgutils_event_data * event_data;
    char * conn_str;
    char * read_only_conn_str;
    cgutils_pool * conn_pool;
    cgutils_pool * read_only_conn_pool;
    size_t connections_max_retry;
};

typedef struct
{
    PGconn * conn;
    cgutils_event * conn_event;
    bool stmts[cgdb_backend_statement_count];
    bool read_only;
    bool blocking;
} cgdb_pg_conn;

typedef enum
{
    cgdb_pg_state_sending_query,
    cgdb_pg_state_preparing_statement,
    cgdb_pg_state_executing_statement
} cgdb_pg_state;

typedef struct
{
    union
    {
        uint64_t uint64;
        int64_t int64;
        int32_t int32;
        uint16_t uint16;
        uint8_t uint8;
    } * value_holders;
    void ** values;
    int * lengths;
    int * formats;
    bool * allocated;
    size_t count;
} cgdb_pg_prepared_stmt_params;

typedef struct
{
    Oid type;
    char * name;
    size_t name_len;
} cgdb_field_description;

struct cgdb_pg_cursor
{
    cgdb_pg_conn * conn;
    PGresult * result;

    cgdb_pg_data * data;

    cgdb_backend_cursor_cb * cursor_cb;
    cgdb_backend_status_cb * status_cb;
    cgdb_backend_status_returning_cb * status_returning_cb;

    void * cb_data;

    char * last_error_msg;

    char * query;

    cgdb_field_description * fields_descriptions;

    cgdb_pg_prepared_stmt_params * stmt_params;

    cgutils_vector * rows;

    size_t rows_count;
    size_t fields_count;

    /* In single row mode, how many rows we were asked for. */
    size_t wanted_rows;

    size_t connection_try_count;

    uint64_t returned_id;

    cgdb_limit_type limit;
    cgdb_skip_type skip;

    int last_error;
    cgdb_backend_statement statement;
    cgdb_pg_state state;
    /* Single row mode, used for cursor queries */
    bool single_row_mode;
    /* In single row mode, whether we have got
       the maximum of rows we were asked for. */
    bool full;
    bool blocking;
    bool read_only;
    bool returning_id;
    bool fatal_error;
};

static struct
{
    char const * name;
    char const * str;
    size_t params_count;
} cgdb_pg_statements[cgdb_backend_statement_count];

static int cgdb_pg_statements_str_init(void)
{
    int result = 0;

    for (size_t idx = 0; idx < cgdb_backend_statement_count - 1; idx++)
    {
        cgdb_pg_statements[idx].name = NULL;
        cgdb_pg_statements[idx].str = NULL;
    }
#define STMT(id, stmt_str, count)                                       \
    cgdb_pg_statements[cgdb_backend_statement_ ## id].name = #id;       \
    cgdb_pg_statements[cgdb_backend_statement_ ## id].str = stmt_str; \
    cgdb_pg_statements[cgdb_backend_statement_ ## id].params_count = count; \
    CGUTILS_ASSERT(count == cgdb_backend_statement_params_count[cgdb_backend_statement_ ## id]);
#include "cgdb/cgdb_pg_statements.itm"
#undef STMT

    return result;
}

static void cgdb_pg_conn_clean(cgdb_pg_conn * const conn)
{
    assert(conn != NULL);

    if (conn->conn_event != NULL)
    {
        cgutils_event_free(conn->conn_event), conn->conn_event = NULL;
    }
}

static void cgdb_pg_conn_free(cgdb_pg_conn * conn)
{
    if (conn != NULL)
    {
        cgdb_pg_conn_clean(conn);

        if (conn->conn != NULL)
        {
            PQfinish(conn->conn), conn->conn = NULL;
        }

        for (size_t idx = 0;
             idx < cgdb_backend_statement_count - 1;
             idx++)
        {
            conn->stmts[idx] = false;
        }

        conn->read_only = false;
        conn->blocking = false;

        CGUTILS_FREE(conn);
    }
}

static void cgdb_pg_conn_delete(void * conn)
{
    cgdb_pg_conn_free(conn);
}

static void cgdb_pg_free(void * this)
{
    if (this != NULL)
    {
        cgdb_pg_data * data = this;

        if (data->conn_str != NULL)
        {
            CGUTILS_FREE(data->conn_str);
        }

        if (data->read_only_conn_str != NULL)
        {
            CGUTILS_FREE(data->read_only_conn_str);
        }

        if (data->conn_pool != NULL)
        {
            cgutils_pool_free(data->conn_pool), data->conn_pool = NULL;
        }

        if (data->read_only_conn_pool != NULL)
        {
            cgutils_pool_free(data->read_only_conn_pool), data->read_only_conn_pool = NULL;
        }

        data->event_data = NULL;

        CGUTILS_FREE(data);
    }
}

static void cgdb_pg_prepared_stmt_params_free(cgdb_pg_prepared_stmt_params * this)
{
    if (this != NULL)
    {
        if (this->values != NULL)
        {
            for (size_t idx = 0;
                 idx < this->count;
                 idx++)
            {
                if (this->allocated != NULL &&
                    this->allocated[idx] == true)
                {
                    CGUTILS_FREE(this->values[idx]);
                }
                else
                {
                    this->values[idx] = NULL;
                }
            }

            CGUTILS_FREE(this->values);
        }

        CGUTILS_FREE(this->allocated);
        CGUTILS_FREE(this->lengths);
        CGUTILS_FREE(this->formats);
        CGUTILS_FREE(this->value_holders);
        this->count = 0;
        CGUTILS_FREE(this);
    }
}

static int cgdb_pg_init(cgutils_event_data * const event_data,
                        cgutils_configuration const * const config,
                        void ** const out)
{
    int result = EINVAL;

    if (event_data != NULL && config != NULL && out != NULL)
    {
        char * conn_str = NULL;

        result = cgutils_configuration_get_string(config, "ConnectionString", &conn_str);

        if (result == 0)
        {
            char * read_only_conn_str = NULL;

            result = cgutils_configuration_get_string(config,
                                                      "ReadOnlyConnectionString",
                                                      &read_only_conn_str);

            if (result == 0 ||
                result == ENOENT)
            {
                uint64_t pool_size = 0;

                if (read_only_conn_str != NULL &&
                    strlen(read_only_conn_str) == 0)
                {
                    CGUTILS_FREE(read_only_conn_str);
                }

                result = cgutils_configuration_get_unsigned_integer(config,
                                                                    "PoolSize",
                                                                    &pool_size);

                if (result == 0 || result == ENOENT)
                {
                    size_t connection_retry = 0;

                    if (result == ENOENT)
                    {
                        pool_size = CGDB_PG_DEFAULT_POOL_SIZE;
                    }

                    result = cgutils_configuration_get_size(config,
                                                            "ConnectionRetry",
                                                            &connection_retry);

                    if (result == 0 || result == ENOENT)
                    {
                        cgdb_pg_data ** data = (cgdb_pg_data ** )out;

                        if (result == ENOENT)
                        {
                            result = 0;
                            connection_retry = CGDB_PG_DEFAULT_CONNECTION_RETRY;
                        }

                        CGUTILS_ALLOCATE_STRUCT(*data);

                        if (*data != NULL)
                        {
                            if (pool_size > 0)
                            {
                                result = cgutils_pool_init((size_t) pool_size,
                                                           &cgdb_pg_conn_delete,
                                                           false,
                                                           false,
                                                           &((*data)->conn_pool));

                                if (result == 0
                                    && read_only_conn_str != NULL)
                                {
                                    result = cgutils_pool_init((size_t) pool_size,
                                                               &cgdb_pg_conn_delete,
                                                               false,
                                                               false,
                                                               &((*data)->read_only_conn_pool));
                                }
                            }

                            if (result == 0)
                            {
                                (*data)->event_data = event_data;
                                (*data)->conn_str = conn_str;

                                (*data)->read_only_conn_str = read_only_conn_str;
                                read_only_conn_str = NULL;
                                (*data)->connections_max_retry = connection_retry;

                                conn_str = NULL;

                                /* We let libpq know that libssl and libcrypto have already been initialized,
                                 otherwise attempting to connect to a PG server over TLS will fail. */
                                PQinitOpenSSL(0, 0);

                                result = cgdb_pg_statements_str_init();

                                if (result != 0)
                                {
                                    CGUTILS_ERROR("Error in statements init: %d", result);
                                }
                            }
                            else
                            {
                                CGUTILS_ERROR("Error in pool init: %d", result);
                            }

                            if (result != 0)
                            {
                                cgdb_pg_free(*data), *data = NULL;
                            }
                        }
                        else
                        {
                            result = ENOMEM;
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error getting MaxConnectionRetry for PG database: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error getting PoolSize for PG database: %d", result);
                }

                if (read_only_conn_str != NULL)
                {
                    CGUTILS_FREE(read_only_conn_str);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting ReadOnlyConnectionString for PG database: %d", result);
            }

            if (conn_str != NULL)
            {
                CGUTILS_FREE(conn_str);
            }
        }
        else
        {
            CGUTILS_ERROR("Error getting ConnectionString for PG database: %d", result);
        }
    }

    return result;
}

static int cgdb_pg_get_prepared_stmt_param(cgdb_field_value_type const type,
                                           void const * const value,
                                           size_t const idx,
                                           cgdb_pg_prepared_stmt_params * const params)
{
    int result = 0;

    assert(params != NULL);
    assert(idx < params->count);

    params->allocated[idx] = false;

    if (value != NULL)
    {
        switch(type)
        {
        case CGDB_FIELD_VALUE_TYPE_IMMUTABLE_STRING:
            params->values[idx] = (char* ) value;
            /* Documentation says "is ignored for null parameters and text-format parameters" */
            /* *out_len = (int) strlen(field->value); */
            params->lengths[idx] = 0;
            params->formats[idx] = 0;
            break;
        case CGDB_FIELD_VALUE_TYPE_STRING:
        {
            void * new_value = cgutils_strdup((char *) value);
            if (COMPILER_LIKELY(new_value != NULL))
            {
                params->allocated[idx] = true;
                params->values[idx] = new_value;
            }
            else
            {
                result = ENOMEM;
            }
            /* Documentation says "is ignored for null parameters and text-format parameters" */
            /* *out_len = (int) strlen(field->value); */
            params->lengths[idx] = 0;
            params->formats[idx] = 0;
            break;
        }
        case CGDB_FIELD_VALUE_TYPE_UINT64:
            params->lengths[idx] = sizeof (uint64_t);
            params->value_holders[idx].uint64 = cgutils_htonll(*((uint64_t*) value));
            params->values[idx] = &(params->value_holders[idx].uint64);
            /* Binary format. Means that non-text content will not be sent as a string */
            params->formats[idx] = 1;
            break;
        case CGDB_FIELD_VALUE_TYPE_INT64:
            params->lengths[idx] = sizeof (int64_t);
            params->value_holders[idx].int64 = (int64_t) cgutils_htonll((uint64_t) *((int64_t*) value));
            params->values[idx] = &(params->value_holders[idx].int64);
            /* Binary format. Means that non-text content will not be sent as a string */
            params->formats[idx] = 1;
            break;
        case CGDB_FIELD_VALUE_TYPE_INT32:
            params->lengths[idx] = sizeof (int32_t);
            params->value_holders[idx].int32 = (int32_t) cgutils_htonl(*((uint32_t*) value));
            params->values[idx] = &(params->value_holders[idx].int32);
            /* Binary format. Means that non-text content will not be sent as a string */
            params->formats[idx] = 1;
            break;
        case CGDB_FIELD_VALUE_TYPE_UINT16:
            params->lengths[idx] = sizeof (uint16_t);
            params->value_holders[idx].uint16 = cgutils_htons(*((uint16_t*) value));
            params->values[idx] = &(params->value_holders[idx].uint16);
            /* Binary format. Means that non-text content will not be sent as a string */
            params->formats[idx] = 1;
            break;
        case CGDB_FIELD_VALUE_TYPE_BOOLEAN:
            params->lengths[idx] = sizeof (uint8_t);
            params->value_holders[idx].uint8 = *((bool*) value) == true ? (uint8_t) 1 : (uint8_t) 0;
            params->values[idx] = &(params->value_holders[idx].uint8);
            /* Binary format. Means that non-text content will not be sent as a string */
            params->formats[idx] = 1;
            break;
        case CGDB_FIELD_VALUE_TYPE_NULL:
            /* NULL value */
            params->lengths[idx] = 0;
            params->values[idx] = NULL;
            params->formats[idx] = 0;
            break;
        case CGDB_FIELD_VALUE_TYPE_FIELD:
            /* skip */
            params->lengths[idx] = 0;
            params->values[idx] = NULL;
            params->formats[idx] = 1;
            result = EOPNOTSUPP;
            break;
        }
    }
    else
    {
        /* NULL value */
        params->formats[idx] = 0;
        params->lengths[idx] = 0;
        params->values[idx] = NULL;
    }

    return result;
}

static int cgdb_pg_get_prepared_stmt_params(cgdb_param const * const params,
                                            size_t const params_count,
                                            cgdb_limit_type const limit,
                                            cgdb_skip_type const skip,
                                            cgdb_pg_prepared_stmt_params ** const stmt_params)
{
    int result = ENOMEM;

    assert(params != NULL || params_count == 0);
    assert(stmt_params != NULL);

    size_t count = params_count +
        (cgdb_limit_is_valid(limit) == true ? 1 : 0) +
        (cgdb_skip_is_valid(skip) == true ? 1 : 0);

    CGUTILS_ALLOCATE_STRUCT(*stmt_params);

    if (COMPILER_LIKELY(*stmt_params != NULL))
    {
        cgdb_pg_prepared_stmt_params * const stmt_params_ptr = *stmt_params;
        stmt_params_ptr->count = count;

        if (COMPILER_LIKELY(count > 0))
        {
            CGUTILS_MALLOC(stmt_params_ptr->value_holders, count, sizeof *(stmt_params_ptr->value_holders));

            if (COMPILER_LIKELY(stmt_params_ptr->value_holders != NULL))
            {
                CGUTILS_MALLOC(stmt_params_ptr->values, count, sizeof *(stmt_params_ptr->values));

                if (COMPILER_LIKELY(stmt_params_ptr->values != NULL))
                {
                    for (size_t init_idx = 0;
                         init_idx < count;
                         init_idx++)
                    {
                        (stmt_params_ptr->values)[init_idx] = NULL;
                    }

                    CGUTILS_MALLOC(stmt_params_ptr->lengths, count, sizeof *(stmt_params_ptr->lengths));

                    if (COMPILER_LIKELY(stmt_params_ptr->lengths != NULL))
                    {
                        CGUTILS_MALLOC(stmt_params_ptr->formats, count, sizeof *(stmt_params_ptr->formats));

                        if (COMPILER_LIKELY(stmt_params_ptr->formats != NULL))
                        {
                            CGUTILS_MALLOC(stmt_params_ptr->allocated, count, sizeof *(stmt_params_ptr->allocated));

                            if (COMPILER_LIKELY(stmt_params_ptr->allocated != NULL))
                            {
                                size_t idx = 0;

                                result = 0;

                                for (;
                                     idx < params_count &&
                                         result == 0;
                                     idx++)
                                {
                                    cgdb_param const * const param = &(params[idx]);

                                    result = cgdb_pg_get_prepared_stmt_param(param->type,
                                                                             param->value,
                                                                             idx,
                                                                             stmt_params_ptr);

                                    if (COMPILER_UNLIKELY(result != 0))
                                    {
                                        CGUTILS_ERROR("Error handling prepared statement parameter %zu: %d",
                                                      idx,
                                                      result);
                                    }
                                }

                                if (COMPILER_LIKELY(result == 0))
                                {
                                    if (result == 0 &&
                                        cgdb_limit_is_valid(limit) == true)
                                    {
                                        uint64_t const limit_temp = (uint32_t) limit;

                                        result = cgdb_pg_get_prepared_stmt_param(CGDB_FIELD_VALUE_TYPE_UINT64,
                                                                                 &limit_temp,
                                                                                 idx,
                                                                                 stmt_params_ptr);
                                        idx++;
                                    }

                                    if (result == 0 &&
                                        cgdb_skip_is_valid(skip) == true)
                                    {
                                        uint64_t const skip_temp = (uint64_t) skip;

                                        result = cgdb_pg_get_prepared_stmt_param(CGDB_FIELD_VALUE_TYPE_UINT64,
                                                                                 &skip_temp,
                                                                                 idx,
                                                                                 stmt_params_ptr);
                                        idx++;
                                    }

                                    assert(idx == count || result != 0);

                                    if (idx != count &&
                                        result == 0)
                                    {
                                        result = EINVAL;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                cgdb_pg_prepared_stmt_params_free(*stmt_params), *stmt_params = NULL;
            }
        }
        else
        {
            /* No params, no limit, no skip. Nothing to do. */
            result = 0;
        }
    }

    return result;
}

static PGconn * cgdb_pg_cursor_get_conn(cgdb_pg_cursor * const cursor)
{
    assert(cursor != NULL);
    PGconn * result = NULL;

    if (cursor->conn != NULL)
    {
        result = cursor->conn->conn;
    }

    return result;
}

static cgutils_event * cgdb_pg_cursor_get_conn_event(cgdb_pg_cursor * const cursor)
{
    cgutils_event * result = NULL;
    assert(cursor != NULL);

    if (cursor->conn != NULL)
    {
        result = cursor->conn->conn_event;
    }

    return result;
}

static bool cgdb_pg_cursor_is_read_only(cgdb_pg_cursor * const cursor)
{
    assert(cursor != NULL);

    bool result = cursor->read_only;

    return result;
}

static void cgdb_pg_conn_release(cgdb_pg_data * const data,
                                 cgdb_pg_conn * conn)
{
    assert(data != NULL);
    assert(conn != NULL);

    if (data->conn_pool != NULL)
    {
        bool reused = false;

        cgutils_pool * pool = data->conn_pool;

        if (conn->read_only == true &&
            data->read_only_conn_pool != NULL)
        {
            pool = data->read_only_conn_pool;
        }

        cgdb_pg_conn_clean(conn);

        if (conn->blocking == false)
        {
            int result = cgutils_pool_add(pool,
                                          conn);

            if (result == 0)
            {
                reused = true;
            }
        }

        if (reused == false)
        {
            cgdb_pg_conn_free(conn);
        }
    }
}

static void cgdb_pg_cursor_free(cgdb_pg_cursor * cursor)
{
    if (cursor != NULL)
    {
        if (cursor->last_error_msg != NULL)
        {
            CGUTILS_FREE(cursor->last_error_msg);
        }

        if (cursor->query != NULL)
        {
            CGUTILS_FREE(cursor->query);
        }

        if (cursor->result != NULL)
        {
            PQclear(cursor->result), cursor->result = NULL;
        }

        if (cursor->conn != NULL)
        {
            if (cursor->last_error == 0)
            {
                cgdb_pg_conn_release(cursor->data, cursor->conn);
            }
            else
            {
                cgdb_pg_conn_free(cursor->conn);
            }

            cursor->conn = NULL;
        }

        if (cursor->fields_descriptions != NULL)
        {
            for (size_t idx = 0;
                 idx < cursor->fields_count;
                 idx++)
            {
                CGUTILS_FREE(cursor->fields_descriptions[idx].name);
            }

            CGUTILS_FREE(cursor->fields_descriptions);
        }

        if (cursor->stmt_params != NULL)
        {
            cgdb_pg_prepared_stmt_params_free(cursor->stmt_params), cursor->stmt_params = NULL;
        }

        cursor->data = NULL;
        cursor->cursor_cb = NULL;
        cursor->status_cb = NULL;
        cursor->cb_data = NULL;
        cursor->rows_count = 0;
        cursor->fields_count = 0;
        cursor->wanted_rows = 0;
        cursor->limit = CGDB_LIMIT_NONE;
        cursor->skip = CGDB_SKIP_NONE;
        cursor->read_only = false;
        cursor->blocking = false;
        cursor->single_row_mode = false;

        CGUTILS_FREE(cursor);
    }
}

static int cgdb_pg_cursor_init(cgdb_pg_data * const data,
                               cgdb_backend_statement const statement,
                               cgdb_backend_status_cb * const status_cb,
                               cgdb_backend_cursor_cb * const cursor_cb,
                               cgdb_backend_status_returning_cb * const status_returning_cb,
                               void * const cb_data,
                               cgdb_param const * const params,
                               size_t const params_count,
                               cgdb_limit_type const limit,
                               cgdb_skip_type const skip,
                               bool const read_only,
                               bool const blocking,
                               cgdb_pg_cursor ** const out)
{
    int result = EINVAL;

    if (data != NULL && out != NULL)
    {
        CGUTILS_ALLOCATE_STRUCT(*out);

        if (*out != NULL)
        {
            cgdb_pg_cursor * cursor = *out;

            cursor->data = data;
            cursor->status_cb = status_cb;
            cursor->cursor_cb = cursor_cb;
            cursor->status_returning_cb = status_returning_cb;
            cursor->cb_data = cb_data;
            cursor->statement = statement;
            cursor->limit = limit;
            cursor->skip = skip;
            cursor->read_only = read_only;
            cursor->blocking = blocking;

            if (statement > cgdb_backend_statement_none &&
                statement < cgdb_backend_statement_count)
            {
                cursor->state = cgdb_pg_state_preparing_statement;

                result = cgdb_pg_get_prepared_stmt_params(params,
                                                          params_count,
                                                          limit,
                                                          skip,
                                                          &(cursor->stmt_params));
            }
            else
            {
                cursor->state = cgdb_pg_state_sending_query;
            }

            if (result != 0)
            {
                cgdb_pg_cursor_free(*out), *out = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

static void cgdb_pg_cursor_reset_for_reconnection(cgdb_pg_cursor * cursor)
{
    assert(cursor != NULL);

    if (cursor->query != NULL)
    {
        CGUTILS_FREE(cursor->query);
    }

    if (cursor->result != NULL)
    {
        PQclear(cursor->result), cursor->result = NULL;
    }

    if (cursor->conn != NULL)
    {
        cgdb_pg_conn_free(cursor->conn);
        cursor->conn = NULL;
    }

    if (cursor->fields_descriptions != NULL)
    {
        for (size_t idx = 0;
             idx < cursor->fields_count;
             idx++)
        {
            CGUTILS_FREE(cursor->fields_descriptions[idx].name);
        }

        CGUTILS_FREE(cursor->fields_descriptions);
    }

    if (cursor->last_error_msg != NULL)
    {
        CGUTILS_FREE(cursor->last_error_msg);
    }

    if (cursor->statement > cgdb_backend_statement_none &&
        cursor->statement < cgdb_backend_statement_count)
    {
        cursor->state = cgdb_pg_state_preparing_statement;
    }
    else
    {
        cursor->state = cgdb_pg_state_sending_query;
    }

    cursor->last_error = 0;
    cursor->fatal_error = false;

    cursor->connection_try_count++;
}

static void cgdb_pg_cursor_do_callback(cgdb_pg_cursor * cursor,
                                       int const status)
{
    assert(cursor != NULL);

    if (cursor->status_cb != NULL)
    {
        if (cursor->rows != NULL)
        {
            cgutils_vector_deep_free(&(cursor->rows), &cgdb_row_delete);
        }

        (*(cursor->status_cb))(cursor->data,
                               status,
                               cursor->cb_data);

    }
    else if (cursor->returning_id == true &&
             cursor->status_returning_cb != NULL)
    {
        if (cursor->rows != NULL)
        {
            cgutils_vector_deep_free(&(cursor->rows), &cgdb_row_delete);
        }

        (*(cursor->status_returning_cb))(cursor->data,
                                         status,
                                         cursor->returned_id,
                                         cursor->cb_data);
    }
    else if (cursor->cursor_cb != NULL)
    {
        assert(cursor->rows == NULL ||
               cursor->rows_count == cgutils_vector_count(cursor->rows));

        (*(cursor->cursor_cb))(cursor,
                               status != 0 ? status : cursor->last_error,
                               cursor->last_error != 0,
                               cursor->last_error_msg,
                               cursor->rows_count,
                               cursor->rows,
                               cursor->cb_data);

        /* cursor is freed by the callback */
        cursor = NULL;
    }

    if (cursor != NULL)
    {
        cgdb_pg_cursor_free(cursor);
    }
}

static void cgdb_pg_cursor_set_error(cgdb_pg_cursor * const cursor,
                                     int const error,
                                     bool const fatal)
{
    assert(cursor != NULL);
    cursor->last_error = error;

    if (fatal == true &&
        cursor->fatal_error == false)
    {
        cursor->fatal_error = fatal;
    }

    if (cursor->conn != NULL)
    {
        PGconn * const conn = cgdb_pg_cursor_get_conn(cursor);
        assert(conn != NULL);

        char const * const error_str = PQerrorMessage(conn);
        if (error_str != NULL)
        {
            if (cursor->last_error_msg != NULL)
            {
                CGUTILS_FREE(cursor->last_error_msg);
            }

            cursor->last_error_msg = cgutils_strdup(error_str);
        }
    }
}

static int cgdb_pg_parse_field(Oid const type,
                               void const * const field_value,
                               int const field_size,
                               char const * const name,
                               size_t const name_len,
                               cgdb_field * const field)
{
    int result = 0;
    assert(name != NULL);
    assert(field != NULL);

    switch(type)
    {
    case INT8OID:
        if (COMPILER_LIKELY(field_size == sizeof (uint64_t) ||
                            field_size == 0))
        {
            uint64_t host_value = 0;

            if (COMPILER_LIKELY(field_size == sizeof (uint64_t)))
            {
                host_value = cgutils_ntohll(*((uint64_t const *) field_value));
            }

            result = cgdb_field_set_uint64(field,
                                           name,
                                           name_len,
                                           host_value);
        }
        else
        {
            result = EINVAL;
            CGUTILS_WARN("Expected field size of %zu, got %d for type %d",
                         sizeof (uint64_t),
                         field_size,
                         type);
        }
        break;
    case INT4OID:
        if (COMPILER_LIKELY(field_size == sizeof (int32_t) ||
                            field_size == 0))
        {
            uint32_t host_value = 0;

            if (COMPILER_LIKELY(field_size == sizeof (int32_t)))
            {
                host_value = cgutils_ntohl(*((uint32_t const *) field_value));
            }

            result = cgdb_field_set_int32(field,
                                          name,
                                          name_len,
                                          (int32_t) host_value);
        }
        else
        {
            result = EINVAL;
            CGUTILS_WARN("Expected field size of %zu, got %d for type %d",
                         sizeof (int32_t),
                         field_size,
                         type);
        }
        break;
    case INT2OID:
        if (COMPILER_LIKELY(field_size == sizeof (uint16_t) ||
                            field_size == 0))
        {
            uint16_t host_value = 0;

            if (COMPILER_LIKELY(field_size == sizeof (uint16_t)))
            {
                host_value = cgutils_ntohs(*((uint16_t const *) field_value));
            }

            result = cgdb_field_set_uint16(field,
                                           name,
                                           name_len,
                                           host_value);
        }
        else
        {
            result = EINVAL;
            CGUTILS_WARN("Expected field size of %zu, got %d for type %d",
                         sizeof (int16_t),
                         field_size,
                         type);
        }
        break;
    case BOOLOID:
        if (COMPILER_LIKELY(field_size == sizeof (uint8_t)))
        {
            uint8_t host_value = 0;

            if (COMPILER_LIKELY(field_size == sizeof (uint8_t)))
            {
                host_value = *((uint8_t const *) field_value);
            }

            result = cgdb_field_set_boolean(field,
                                            name,
                                            name_len,
                                            host_value);
        }
        else
        {
            result = EINVAL;
            CGUTILS_WARN("Expected field size of %zu, got %d for type %d",
                         sizeof (int8_t),
                         field_size,
                         type);
        }
        break;
    case TEXTOID:
        result = cgdb_field_set_string(field,
                                       name,
                                       name_len,
                                       (char const *) field_value);
        break;
    case VOIDOID:
        /* Silently ignore */
        result = 0;
        break;
    default:
        CGUTILS_WARN("Field type %d not handled for field named %s, ignoring.",
                     type,
                     name);
    }

    return result;
}

static int cgdb_pg_parse_row(cgdb_pg_cursor * const cursor,
                             size_t const row_idx,
                             PGresult * const pgres,
                             cgdb_row ** const row)
{
    int result = 0;
    assert(cursor != NULL);
    assert(pgres != NULL);
    assert(row_idx < (size_t) PQntuples(pgres));
    assert(row != NULL);

    result = cgdb_row_init(row,
                           cursor->fields_count);

    if (COMPILER_LIKELY(result == 0))
    {
        bool has_fields = false;

        CGUTILS_ASSERT(*row != NULL);

        for (size_t field_idx = 0;
             result == 0 &&
                 field_idx < cursor->fields_count;
             field_idx++)
        {
            cgdb_field * field = NULL;

            cgdb_row_get_field_by_idx(*row,
                                      field_idx,
                                      &field);

            /* Sorry for the casts, but the PQ API needs to be fixed. */
            int const field_size = PQgetlength(pgres, (int) row_idx, (int) field_idx);
            void const * const field_value = PQgetvalue(pgres, (int) row_idx, (int) field_idx);
            cgdb_field_description const * const description = &(cursor->fields_descriptions[field_idx]);
            char const * const name = description->name;
            size_t const name_len = description->name_len;
            Oid const type = description->type;

            result = cgdb_pg_parse_field(type,
                                         field_value,
                                         field_size,
                                         name,
                                         name_len,
                                         field);

            if (COMPILER_LIKELY(result == 0 &&
                                field != NULL))
            {
                has_fields = true;

                field = NULL;
            }
            else if (result != 0)
            {
                CGUTILS_ERROR("Error creating new field (name is %s, type is %d): %d",
                              name,
                              type,
                              result);
            }
        }

        if (COMPILER_UNLIKELY(has_fields == false))
        {
            /* empty row */
            result = ENOENT;
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            cgdb_row_free(*row), *row = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Error creating row: %d", result);
    }

    return result;
}

static int cgdb_pg_handle_returning_id(cgdb_pg_cursor * const cursor,
                                       PGresult * const pgres)
{
    int result = 0;
    assert(cursor != NULL);
    assert(cursor->conn != NULL);
    assert(cursor->returning_id == true);

    /* PQ API .. */
    size_t const current_rows = (size_t) PQntuples(pgres);

    if (current_rows == 1)
    {
        Oid const type = PQftype(pgres, 0);
        char const * const name = PQfname(pgres, 0);
        CGUTILS_ASSERT(name != NULL);
        size_t const name_len = strlen(name);
        int const field_size = PQgetlength(pgres, 0, 0);
        void const * const field_value = PQgetvalue(pgres, 0, 0);

        cgdb_field field = (cgdb_field) { 0 };

        result = cgdb_pg_parse_field(type,
                                     field_value,
                                     field_size,
                                     name,
                                     name_len,
                                     &field);

        if (result == 0)
        {
            if (field.value_type == CGDB_FIELD_VALUE_TYPE_UINT64)
            {
                cursor->returned_id = field.value_uint64;
            }
            else
            {
                result = EIO;

                CGUTILS_ERROR("Error, expecting a row of type BIGINT, got %d: %d",
                              field.value_type,
                              result);
            }

            cgdb_field_clean(&field);
        }
        else if (result != 0)
        {
            CGUTILS_ERROR("Error creating new field (name is %s, type is %d): %d",
                          name,
                          type,
                          result);
        }
    }
    else
    {
        result = EIO;
        CGUTILS_ERROR("Error, expecting 1 row, %zu received", current_rows);
    }

    return result;
}


static int cgdb_pg_handle_rows(cgdb_pg_cursor * const cursor,
                               PGresult * const pgres)
{
    int result = 0;
    assert(cursor != NULL);
    assert(cursor->conn != NULL);

    /* PQ API .. */
    size_t const current_rows = (size_t) PQntuples(pgres);

    if (COMPILER_LIKELY(current_rows > 0))
    {
        size_t vector_size = current_rows;

        if (cursor->fields_descriptions == NULL)
        {
            cursor->fields_count = (size_t) PQnfields(pgres);

            if (COMPILER_LIKELY(cursor->fields_count > 0))
            {
                CGUTILS_MALLOC(cursor->fields_descriptions, cursor->fields_count, sizeof *(cursor->fields_descriptions));

                if (COMPILER_LIKELY(cursor->fields_descriptions != NULL))
                {
                    for (size_t idx = 0;
                         idx < cursor->fields_count;
                         idx++)
                    {
                        (cursor->fields_descriptions)[idx].name = NULL;
                    }

                    for (size_t idx = 0;
                         result == 0 &&
                             idx < cursor->fields_count;
                         idx++)
                    {
                        /* PQ API */
                        cgdb_field_description * const description = &(cursor->fields_descriptions[idx]);
                        char const * const field_name = PQfname(pgres, (int) idx);
                        CGUTILS_ASSERT(field_name != NULL);
                        size_t const field_name_len = strlen(field_name);

                        CGUTILS_MALLOC(description->name, field_name_len + 1, 1);

                        if (COMPILER_LIKELY(description->name != NULL))
                        {
                            memcpy(description->name, field_name, field_name_len);
                            description->name[field_name_len] = '\0';

                            description->name_len = field_name_len;

                            /* PQ API */
                            description->type = PQftype(pgres, (int) idx);
                        }
                        else
                        {
                            result = ENOMEM;
                            CGUTILS_ERROR("Error allocating field name: %d", result);
                        }
                    }

                    if (COMPILER_UNLIKELY(result != 0))
                    {
                        for (size_t idx = 0;
                             idx < cursor->fields_count;
                             idx++)
                        {
                            CGUTILS_FREE(cursor->fields_descriptions[idx].name);
                        }

                        CGUTILS_FREE(cursor->fields_descriptions);
                        cursor->fields_count = 0;
                    }
                }
                else
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error allocating fields descriptions array: %d", result);
                }
            }
            else
            {
                result = EIO;
                CGUTILS_ERROR("Invalid fields count of %zu: %d", cursor->fields_count, result);
            }
        }

        if (result == 0 &&
            cursor->rows == NULL)
        {
            if (cursor->single_row_mode == true)
            {
                vector_size = cursor->wanted_rows;
            }

            result = cgutils_vector_init(vector_size,
                                         &(cursor->rows));

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error creating rows list: %d", result);
            }
        }

        if (COMPILER_LIKELY(result == 0))
        {
            for (size_t idx = 0;
                 result == 0 &&
                     idx < vector_size &&
                     cursor->full == false;
                 idx++)
            {
                cgdb_row * row = NULL;
                result = cgdb_pg_parse_row(cursor, idx, pgres, &row);

                if (COMPILER_LIKELY(result == 0))
                {
                    CGUTILS_ASSERT(row != NULL);

                    result = cgutils_vector_add(cursor->rows,
                                                row);

                    if (COMPILER_LIKELY(result == 0))
                    {
                        cursor->rows_count++;

                        if (cursor->single_row_mode == true &&
                            cursor->rows_count >= cursor->wanted_rows)
                        {
                            cursor->full = true;
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error while inserting row %zu into list: %d", idx, result);
                        cgdb_row_free(row), row = NULL;
                    }
                }
                else if (result == ENOENT)
                {
                    result = 0;
                }
                else
                {
                    CGUTILS_ERROR("Error parsing row %zu: %d", idx, result);
                }
            }
        }
    }

    return result;
}

static int cgdb_pg_send_data(cgdb_pg_cursor * const cursor,
                             bool const initial_flush);

static int cgdb_pg_handle_statement(cgdb_pg_cursor * const cursor)
{
    int result = 0;
    assert(cursor != NULL);
    PGconn * const conn = cgdb_pg_cursor_get_conn(cursor);
    assert(conn != NULL);
    assert(cursor->state == cgdb_pg_state_preparing_statement);

    if (COMPILER_LIKELY(cursor->statement > cgdb_backend_statement_none &&
                        cursor->statement < cgdb_backend_statement_count))
    {
        if (COMPILER_UNLIKELY(cursor->conn->stmts[cursor->statement] == false))
        {
            if (COMPILER_LIKELY(cgdb_pg_statements[cursor->statement].str != NULL))
            {
                CGUTILS_ASSERT(cgdb_pg_statements[cursor->statement].params_count ==
                               cursor->stmt_params->count);

                result = PQsendPrepare(conn,
                                       cgdb_pg_statements[cursor->statement].name,
                                       cgdb_pg_statements[cursor->statement].str,
                                       0,
                                       NULL);

                if (COMPILER_LIKELY(result == 1))
                {
                    result = 0;
                }
                else
                {
                    char const * const error_str = PQerrorMessage(cgdb_pg_cursor_get_conn(cursor));
                    CGUTILS_ERROR("Error in PQsendPrepare while preparing statement %s (%s): %s (%d)",
                                  cgdb_pg_statements[cursor->statement].name,
                                  cgdb_pg_statements[cursor->statement].str,
                                  error_str != NULL ? error_str : "",
                                  result);
                    result = EIO;
                }
            }
            else
            {
                result = ENOENT;
            }
        }
        else
        {
            CGUTILS_ASSERT(cursor->stmt_params != NULL);

            cursor->state = cgdb_pg_state_executing_statement;

            result = PQsendQueryPrepared(conn,
                                         cgdb_pg_statements[cursor->statement].name,
                                         (int) cursor->stmt_params->count,
                                         (char const * const *) cursor->stmt_params->values,
                                         cursor->stmt_params->lengths,
                                         cursor->stmt_params->formats,
                                         1);


            if (COMPILER_LIKELY(result == 1))
            {
                if (cursor->single_row_mode == true)
                {
                    if (PQsetSingleRowMode(conn) == 0)
                    {
                        CGUTILS_WARN("Error setting the connection to single row mode!");
                    }
                }

                result = 0;
            }
            else
            {
                char const * const error_str = PQerrorMessage(conn);
                CGUTILS_ERROR("Error sending prepared statement %s(%s): %d(%s)",
                              cgdb_pg_statements[cursor->statement].name,
                              cgdb_pg_statements[cursor->statement].str,
                              result,
                              error_str);
                result = EIO;
            }

        }

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgdb_pg_send_data(cursor,
                                       true);
        }
        else if (result != ENOENT)
        {
            cgdb_pg_cursor_set_error(cursor, result, false);
            CGUTILS_ERROR("Error sending query: %d", result);
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

static int cgdb_pg_handle_results(cgdb_pg_cursor * const cursor)
{
    int result = 0;
    assert(cursor != NULL);
    assert(cursor->conn != NULL);
    assert(cursor->fields_descriptions == NULL);
    assert(cursor->rows_count == 0);
    assert(cursor->fields_count == 0);

    PGconn * const conn = cgdb_pg_cursor_get_conn(cursor);
    assert(conn != NULL);
    bool statement_ready = false;

    for (cursor->result = PQgetResult(conn);
         result == 0 &&
             cursor->result != NULL &&
             cursor->full == false;
         cursor->result = PQgetResult(conn))
    {
        ExecStatusType const status = PQresultStatus(cursor->result);

        switch(status)
        {
        case PGRES_SINGLE_TUPLE:
            result = cgdb_pg_handle_rows(cursor, cursor->result);
            break;
        case PGRES_TUPLES_OK:
            if (cursor->returning_id == false)
            {
                result = cgdb_pg_handle_rows(cursor, cursor->result);
            }
            else
            {
                result = cgdb_pg_handle_returning_id(cursor, cursor->result);
            }
            break;
        case PGRES_COMMAND_OK:
            /* Query (UPDATE for example) does not return rows */
            if (cursor->state == cgdb_pg_state_preparing_statement)
            {
                cursor->conn->stmts[cursor->statement] = true;

                statement_ready = true;
            }
            break;
        case PGRES_EMPTY_QUERY:
            /* We sent an empty query (shame on us). */
            CGUTILS_INFO("Silently ignoring an empty query: %d", status);
            break;
        case PGRES_NONFATAL_ERROR:
            /* There has been a notice or warning level error. */
            CGUTILS_INFO("Silently ignoring a non fatal error: %d", status);
            break;
        case PGRES_FATAL_ERROR:
        {
            char const * const error_str = PQerrorMessage(cgdb_pg_cursor_get_conn(cursor));
            CGUTILS_ERROR("Fatal error received on DB %s, aborting. %s",
                          PQdb(conn),
                          error_str != NULL ? error_str : "");
            result = EIO;
            cgdb_pg_cursor_set_error(cursor, result, true);
            break;
        }
        case PGRES_COPY_BOTH:
        case PGRES_COPY_IN:
        case PGRES_COPY_OUT:
        case PGRES_BAD_RESPONSE:
        default:
            CGUTILS_ERROR("Unexpected result: %d", status);
            result = EIO;
            cgdb_pg_cursor_set_error(cursor, result, false);
            break;
        }

        PQclear(cursor->result), cursor->result = NULL;
    }

    if (result == 0)
    {
        if (statement_ready == true &&
            cursor->state == cgdb_pg_state_preparing_statement)
        {
            result = cgdb_pg_handle_statement(cursor);

            if (result != 0)
            {
                CGUTILS_ERROR("Error handling statement: %d", result);
            }
        }
        else if (cursor->blocking == false)
        {
            cgdb_pg_cursor_do_callback(cursor,
                                       result);
        }
    }

    return result;
}

#if 0
static int cgdb_pg_cursor_get_more(cgdb_pg_cursor * cursor,
                                   size_t const wanted_rows)
{
    CGUTILS_ASSERT(cursor != NULL);

    int result = EINVAL;

    if (COMPILER_LIKELY(cursor->single_row_mode == true))
    {
        if (cursor->rows != NULL)
        {
            cgutils_vector_deep_free(&(cursor->rows), &cgdb_row_delete);
        }

        cursor->rows_count = 0;
        cursor->full = false;
        cursor->wanted_rows = wanted_rows;

        result = cgdb_pg_handle_results(cursor);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error handling results: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Single-row mode needs to be enabled!");
    }

    return result;
}
#endif /* 0 */

static int cgdb_pg_recv_results(cgdb_pg_cursor * const cursor,
                                bool const intial_recv);

static void cgdb_pg_recv_cb(int const fd,
                            short const flags,
                            void * const cb_data)
{
    cgdb_pg_cursor * cursor = cb_data;
    int result = 0;
    assert(cb_data != NULL);

    (void) fd;
    (void) flags;

    result = cgdb_pg_recv_results(cursor,
                                  false);

    if (COMPILER_UNLIKELY(result != 0))
    {
        cgdb_pg_cursor_do_callback(cursor,
                                   result);
    }
}

static int cgdb_pg_recv_results(cgdb_pg_cursor * const cursor,
                                bool const intial_recv)
{
    int result = 0;

    assert(cursor != NULL);
    assert(cursor->conn != NULL);
    PGconn * const conn = cgdb_pg_cursor_get_conn(cursor);
    assert(conn != NULL);

    result = PQconsumeInput(conn);

    if (result == 1)
    {
        result = PQisBusy(conn);

        if (result == 1)
        {
            cgutils_event * const conn_event = cgdb_pg_cursor_get_conn_event(cursor);
            assert(conn_event != NULL);

            result = 0;

            if (COMPILER_UNLIKELY(intial_recv == true))
            {
                result = cgutils_event_reassign(conn_event,
                                                CGUTILS_EVENT_READ,
                                                &cgdb_pg_recv_cb);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error reassigning event: %d", result);
                }
            }

            if (COMPILER_LIKELY(result == 0))
            {
                result = cgutils_event_enable(conn_event, NULL);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error enabling connection event: %d", result);
                }
            }
        }
        else
        {
            result = cgdb_pg_handle_results(cursor);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error handling results: %d", result);
            }
        }
    }
    else
    {
        char const * const error_str = PQerrorMessage(cgdb_pg_cursor_get_conn(cursor));
        CGUTILS_ERROR("Error consuming input from connection: %s (%d)",
                      error_str ?: "no error message",
                      result);
        result = EIO;
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cgdb_pg_cursor_set_error(cursor,
                                 result,
                                 false);
    }

    return result;
}

static void cgdb_pg_flush_cb(int const fd,
                             short const flags,
                             void * const cb_data)
{
    cgdb_pg_cursor * cursor = cb_data;
    int result = 0;
    assert(cb_data != NULL);

    (void) fd;
    (void) flags;

    result = cgdb_pg_send_data(cursor,
                               false);

    if (COMPILER_UNLIKELY(result != 0))
    {
        cgdb_pg_cursor_do_callback(cursor,
                                   result);
    }
}

static int cgdb_pg_send_data(cgdb_pg_cursor * const cursor,
                             bool const initial_flush)
{
    int result = 0;

    assert(cursor != NULL);
    assert(cursor->conn != NULL);
    PGconn * const conn = cgdb_pg_cursor_get_conn(cursor);
    assert(conn != NULL);

    result = PQflush(conn);

    if (result == 0)
    {
        /* Query / Stmt / Stmt params sent, recv the results */
        result = cgdb_pg_recv_results(cursor, true);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error receving results: %d", result);
        }
    }
    else if (result == 1)
    {
        cgutils_event * const conn_event = cgdb_pg_cursor_get_conn_event(cursor);
        assert(conn_event != NULL);

        result = 0;

        if (COMPILER_UNLIKELY(initial_flush == true))
        {
            result = cgutils_event_reassign(conn_event,
                                            CGUTILS_EVENT_WRITE,
                                            &cgdb_pg_flush_cb);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error reassigning event: %d", result);
            }
        }

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgutils_event_enable(conn_event, NULL);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error enabling connection event: %d", result);
            }
        }
    }
    else
    {
        result = EIO;
        CGUTILS_ERROR("Error flushing query: %d", result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cgdb_pg_cursor_set_error(cursor,
                                 result,
                                 false);
    }

    return result;
}

static int cgdb_pg_new_connection(cgdb_pg_cursor * const cursor,
                                  bool const blocking);

static int cgdb_pg_setup_connection(cgdb_pg_cursor * const cursor,
                                    cgdb_pg_conn * const conn);

static void cgdb_pg_connection_cb(int const fd,
                                  short const flags,
                                  void * const cb_data)
{
    int result = 0;
    assert(cb_data != NULL);
    cgdb_pg_cursor * cursor = cb_data;
    assert(cursor->conn != NULL);
    PGconn * const conn = cgdb_pg_cursor_get_conn(cursor);
    assert(conn != NULL);
    ConnStatusType const conn_status = PQstatus(conn);

    (void) fd;
    (void) flags;

    if (conn_status != CONNECTION_BAD)
    {
        PostgresPollingStatusType const status = PQconnectPoll(conn);

        if (status != PGRES_POLLING_FAILED)
        {
            cgutils_event * const conn_event = cgdb_pg_cursor_get_conn_event(cursor);
            assert(conn_event != NULL);

            cgutils_event_disable(conn_event);

            if (status == PGRES_POLLING_OK)
            {
                if (cursor->state == cgdb_pg_state_preparing_statement)
                {
                    result = cgdb_pg_handle_statement(cursor);
                }
            }
            else if (status == PGRES_POLLING_READING ||
                     status == PGRES_POLLING_WRITING)
            {
                assert(conn_event != NULL);

                result = cgutils_event_change_action(conn_event,
                                                     status == PGRES_POLLING_READING ?
                                                     CGUTILS_EVENT_READ :
                                                     CGUTILS_EVENT_WRITE);

                if (result == 0)
                {
                    result = cgutils_event_enable(conn_event, NULL);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error enabling event on connection (%d, polling %d) to database %s: %d",
                                      conn_status,
                                      status,
                                      PQdb(conn),
                                      result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error changing IO action on connection (%d, polling %d) to database %s: %d",
                                  conn_status,
                                  status,
                                  PQdb(conn),
                                  result);
                }
            }
            else
            {
                /* Polling failed */
                result = EIO;
                CGUTILS_ERROR("Error while polling connection (%d, polling %d) to database %s: %d",
                              conn_status,
                              status,
                              PQdb(conn),
                              result);
            }
        }
        else
        {
            char const * const error_str = PQerrorMessage(conn);

            result = EIO;
            CGUTILS_ERROR("Database %s connection (connection status was %d, polling status %d) failed: %s (%d)",
                          PQdb(conn),
                          conn_status,
                          status,
                          error_str ?: "no error message",
                          result);
        }
    }
    else
    {
        char const * const error_str = PQerrorMessage(conn);

        result = EIO;
        CGUTILS_ERROR("Error (%d) while communicating with database %s: %s",
                      conn_status,
                      PQdb(conn),
                      error_str ?: "no error message");
    }

    if (result != 0)
    {
        if (cursor->fatal_error == false)
        {
            while(result != 0 &&
                  cursor->connection_try_count < cursor->data->connections_max_retry)
            {
                cgdb_pg_cursor_reset_for_reconnection(cursor);

                result = cgdb_pg_new_connection(cursor,
                                                cursor->blocking);

                if (result == 0)
                {
                    result = cgdb_pg_setup_connection(cursor,
                                                      cursor->conn);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error setting connection up: %d", result);
                    }
                }

                else
                {
                    CGUTILS_ERROR("Error getting connection: %d", result);
                }
            }
        }

        if (result != 0)
        {
            cgdb_pg_cursor_set_error(cursor,
                                     result,
                                     false);

            cgdb_pg_cursor_do_callback(cursor,
                                       result);
        }
    }
}

static int cgdb_pg_setup_connection(cgdb_pg_cursor * const cursor,
                                    cgdb_pg_conn * const conn)
{
    int result = 0;
    assert(cursor->data->event_data != NULL);
    assert(conn != NULL);
    assert(conn->conn != NULL);
    int conn_fd = PQsocket(conn->conn);

    if (conn_fd >= 0)
    {
        cgutils_event * conn_event = NULL;
        cursor->conn = conn;

        result = cgutils_event_create_fd_event(cursor->data->event_data,
                                               conn_fd,
                                               &cgdb_pg_connection_cb,
                                               cursor,
                                               CGUTILS_EVENT_WRITE,
                                               &conn_event);

        if (result == 0)
        {
            assert(conn_event != NULL);
            /* Connection timeout ? .. */
            conn->conn_event = conn_event;

            result = cgutils_event_enable(conn_event, NULL);

            if (result != 0)
            {
                CGUTILS_ERROR("Error enabling connection event: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating connection event: %d", result);
        }
    }
    else
    {
        result = EIO;
        CGUTILS_ERROR("Error getting FD from connection: %d", result);
    }

    return result;
}

static bool cgdb_pg_connection_is_valid(cgdb_pg_conn * const conn)
{
    bool result = false;

    assert(conn != NULL);

    if (conn->conn != NULL)
    {
        ConnStatusType status = PQstatus(conn->conn);

        if (status == CONNECTION_OK || status == CONNECTION_MADE)
        {
            int conn_fd = PQsocket(conn->conn);
            if (conn_fd >= 0)
            {
                int res = cgutils_network_check_socket_usability(conn_fd,
                                                                 &result);

                if (res != 0)
                {
                    result = false;
                    CGUTILS_WARN("Error checking socket usability: %d", res);
                }
            }
            else
            {
                result = false;
                CGUTILS_WARN("Error getting socket from PG connection");
            }
        }
    }

    return result;
}

static int cgdb_pg_get_connection_from_pool(cgdb_pg_cursor * const cursor,
                                            cgutils_pool * const pool)
{
    int result = 0;
    assert(cursor != NULL);
    assert(cursor->data != NULL);
    assert(pool != NULL);

    if (pool != NULL)
    {
        bool connection_found = false;

        while(result == 0 &&
              connection_found == false)
        {
            void * obj = NULL;

            result = cgutils_pool_get(pool,
                                      &obj);

            if (result == 0)
            {
                cgdb_pg_conn * conn = obj;

                if (cgdb_pg_connection_is_valid(conn) == true)
                {
                    result = cgdb_pg_setup_connection(cursor, conn);

                    if (result == 0)
                    {
                        cursor->conn = conn;
                        connection_found = true;
                    }
                    else
                    {
                        cursor->conn = NULL;
                        cgdb_pg_conn_free(conn), conn = NULL;
                    }
                }
                else
                {
                    cgdb_pg_conn_free(conn), conn = NULL;
                }
            }
        }
    }
    else
    {
        result = ENOENT;
    }

    return result;
}

static int cgdb_pg_new_connection(cgdb_pg_cursor * const cursor,
                                  bool const blocking)
{
    int result = 0;

    assert(cursor != NULL);
    assert(cursor->data != NULL);
    assert(cursor->data->event_data != NULL);
    assert(cursor->data->conn_str != NULL);

    if (cursor->conn == NULL)
    {
        CGUTILS_ALLOCATE_STRUCT(cursor->conn);

        if (cursor->conn != NULL)
        {
            cursor->conn->blocking = blocking;
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for connection: %d", result);
        }
    }

    if (result == 0)
    {
        char const * conn_str = NULL;

        if (cgdb_pg_cursor_is_read_only(cursor) == true &&
            cursor->data->read_only_conn_str != NULL)
        {
            conn_str = cursor->data->read_only_conn_str;
            cursor->conn->read_only = true;
        }
        else
        {
            conn_str = cursor->data->conn_str;
            cursor->conn->read_only = false;
        }

        PGconn * conn = NULL;

        if (blocking == true)
        {
            conn = PQconnectdb(conn_str);
        }
        else
        {
            conn = PQconnectStart(conn_str);
        }

        if (conn != NULL)
        {
            assert(cursor->conn != NULL);
            assert(cursor->conn->conn == NULL);
            ConnStatusType const status = PQstatus(conn);

            if (status != CONNECTION_BAD)
            {
                cursor->conn->conn = conn;

                if (blocking == false)
                {
                    result = PQsetnonblocking(conn, 1);

                    if (result != 0)
                    {
                        result = EIO;
                        CGUTILS_ERROR("Error setting connection to a non-blocking state: %d", result);
                    }
                }
            }
            else
            {
                result = EIO;
                char const * const error_str = PQerrorMessage(conn);
                CGUTILS_ERROR("Error connecting to database %s: %s", PQdb(conn),
                              error_str ?: "no error message");
                PQfinish(conn), conn = NULL;
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error connecting to database: %d", result);
        }
    }

    return result;
}

static int cgdb_pg_query(cgdb_pg_cursor * const cursor)
{
    int result = 0;

    assert(cursor != NULL);

    if (result == 0)
    {
        if (cgdb_pg_cursor_is_read_only(cursor) == true &&
            cursor->data->read_only_conn_pool != NULL)
        {
            result = cgdb_pg_get_connection_from_pool(cursor,
                                                      cursor->data->read_only_conn_pool);
        }
        else
        {
            result = cgdb_pg_get_connection_from_pool(cursor,
                                                      cursor->data->conn_pool);
        }

        if (result == 0)
        {
            /* We may get a read-write connection for a read-only query if there is no
               read-only connection string */
            assert(cursor->conn->read_only == false ||
                   cgdb_pg_cursor_is_read_only(cursor) == true);
        }
        else
        {
            if (result != ENOENT)
            {
                CGUTILS_WARN("Error getting connection from pool: %d", result);
            }

            result = cgdb_pg_new_connection(cursor, false);

            if (result == 0)
            {
                /* We may get a read-write connection for a read-only query if there is no
                   read-only connection string */
                assert(cursor->conn->read_only == false ||
                       cgdb_pg_cursor_is_read_only(cursor) == true);

                result = cgdb_pg_setup_connection(cursor,
                                                  cursor->conn);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error setting connection up: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting connection: %d", result);
            }
        }
    }

    return result;
}

static int cgdb_pg_find(void * const data,
                        cgdb_backend_statement const statement,
                        cgdb_param const * const params,
                        size_t const params_count,
                        cgdb_limit_type const limit,
                        cgdb_skip_type const skip,
                        cgdb_backend_cursor_cb * cb,
                        void * const cb_data)
{
    int result = EINVAL;

    if (data != NULL)
    {
        cgdb_pg_data * this = data;
        cgdb_pg_cursor * cursor = NULL;

        result = cgdb_pg_cursor_init(this,
                                     statement,
                                     CGDB_PG_NO_STATUS_CB,
                                     cb,
                                     CGDB_PG_NO_STATUS_RETURNING_CB,
                                     cb_data,
                                     params,
                                     params_count,
                                     limit,
                                     skip,
                                     true,
                                     false,
                                     &cursor);

        if (result == 0)
        {
            result = cgdb_pg_query(cursor);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending query: %d", result);
                cgdb_pg_cursor_free(cursor), cursor = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating PG cursor: %d", result);
        }
    }

    return result;
}

static int cgdb_pg_insert(void * const data,
                          cgdb_backend_statement const statement,
                          cgdb_param const * const params,
                          size_t const params_count,
                          cgdb_backend_status_cb * const cb,
                          void * const cb_data)
{
    int result = EINVAL;

    if (data != NULL &&
        (params != NULL || params_count == 0))
    {
        cgdb_pg_data * this = data;
        cgdb_pg_cursor * cursor = NULL;

        result = cgdb_pg_cursor_init(this,
                                     statement,
                                     cb,
                                     CGDB_PG_NO_CURSOR_CB,
                                     CGDB_PG_NO_STATUS_RETURNING_CB,
                                     cb_data,
                                     params,
                                     params_count,
                                     CGDB_LIMIT_NONE,
                                     CGDB_SKIP_NONE,
                                     false,
                                     false,
                                     &cursor);

        if (result == 0)
        {
            result = cgdb_pg_query(cursor);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending query: %d", result);
                cgdb_pg_cursor_free(cursor), cursor = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating PG cursor: %d", result);
        }
    }

    return result;
}

static int cgdb_pg_insert_returning(void * const data,
                                    cgdb_backend_statement const statement,
                                    cgdb_param const * const params,
                                    size_t const params_count,
                                    cgdb_backend_status_returning_cb * const cb,
                                    void * const cb_data)
{
    int result = EINVAL;

    if (data != NULL &&
        (params != NULL || params_count == 0))
    {
        cgdb_pg_data * this = data;
        cgdb_pg_cursor * cursor = NULL;

        result = cgdb_pg_cursor_init(this,
                                     statement,
                                     CGDB_PG_NO_STATUS_CB,
                                     CGDB_PG_NO_CURSOR_CB,
                                     cb,
                                     cb_data,
                                     params,
                                     params_count,
                                     CGDB_LIMIT_NONE,
                                     CGDB_SKIP_NONE,
                                     false,
                                     false,
                                     &cursor);

        if (result == 0)
        {
            cursor->returning_id = true;

            result = cgdb_pg_query(cursor);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending query: %d", result);
                cgdb_pg_cursor_free(cursor), cursor = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating PG cursor: %d", result);
        }
    }

    return result;
}

static int cgdb_pg_update(void * const data,
                          cgdb_backend_statement const statement,
                          cgdb_param const * const params,
                          size_t const params_count,
                          cgdb_backend_status_cb * const cb,
                          void * const cb_data)
{
    int result = EINVAL;

    if (data != NULL &&
        (params != NULL || params_count == 0))
    {
        cgdb_pg_data * this = data;
        cgdb_pg_cursor * cursor = NULL;

        result = cgdb_pg_cursor_init(this,
                                     statement,
                                     cb,
                                     CGDB_PG_NO_CURSOR_CB,
                                     CGDB_PG_NO_STATUS_RETURNING_CB,
                                     cb_data,
                                     params,
                                     params_count,
                                     CGDB_LIMIT_NONE,
                                     CGDB_SKIP_NONE,
                                     false,
                                     false,
                                     &cursor);

        if (result == 0)
        {
            result = cgdb_pg_query(cursor);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending query: %d", result);
            }

            if (result != 0)
            {
                cgdb_pg_cursor_free(cursor), cursor = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating PG cursor: %d", result);
        }
    }

    return result;
}

static int cgdb_pg_delete(void * const data,
                          cgdb_backend_statement const statement,
                          cgdb_param const * const params,
                          size_t const params_count,
                          cgdb_backend_status_cb * const cb,
                          void * const cb_data)
{
    int result = EINVAL;

    if (data != NULL &&
        (params != NULL || params_count == 0))
    {
        cgdb_pg_data * this = data;
        cgdb_pg_cursor * cursor = NULL;

        result = cgdb_pg_cursor_init(this,
                                     statement,
                                     cb,
                                     CGDB_PG_NO_CURSOR_CB,
                                     CGDB_PG_NO_STATUS_RETURNING_CB,
                                     cb_data,
                                     params,
                                     params_count,
                                     CGDB_LIMIT_NONE,
                                     CGDB_SKIP_NONE,
                                     false,
                                     false,
                                     &cursor);

        if (result == 0)
        {
            result = cgdb_pg_query(cursor);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending query: %d", result);
                cgdb_pg_cursor_free(cursor), cursor = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating PG cursor: %d", result);
        }
    }

    return result;
}

static int cgdb_pg_exec_stmt(void * const data,
                             cgdb_backend_statement const statement,
                             cgdb_param const * const params,
                             size_t const params_count,
                             cgdb_backend_status_cb * const cb,
                             void * const cb_data)
{
    int result = EINVAL;

    if (data != NULL &&
        (params != NULL || params_count == 0))
    {
        cgdb_pg_data * this = data;
        cgdb_pg_cursor * cursor = NULL;

        result = cgdb_pg_cursor_init(this,
                                     statement,
                                     cb,
                                     CGDB_PG_NO_CURSOR_CB,
                                     CGDB_PG_NO_STATUS_RETURNING_CB,
                                     cb_data,
                                     params,
                                     params_count,
                                     CGDB_LIMIT_NONE,
                                     CGDB_SKIP_NONE,
                                     false, /* NOT read only */
                                     false, /* NOT blocking */
                                     &cursor);

        if (result == 0)
        {
            result = cgdb_pg_query(cursor);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending query: %d", result);
                cgdb_pg_cursor_free(cursor), cursor = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating PG cursor: %d", result);
        }
    }

    return result;
}

static int cgdb_pg_exec_rows_stmt(void * const data,
                                  cgdb_backend_statement const statement,
                                  cgdb_param const * const params,
                                  size_t const params_count,
                                  cgdb_backend_cursor_cb * cb,
                                  void * const cb_data)
{
    int result = EINVAL;

    if (data != NULL)
    {
        cgdb_pg_data * this = data;
        cgdb_pg_cursor * cursor = NULL;

        result = cgdb_pg_cursor_init(this,
                                     statement,
                                     CGDB_PG_NO_STATUS_CB,
                                     cb,
                                     CGDB_PG_NO_STATUS_RETURNING_CB,
                                     cb_data,
                                     params,
                                     params_count,
                                     CGDB_LIMIT_NONE,
                                     CGDB_SKIP_NONE,
                                     false, /* NOT read only */
                                     false, /* NOT blocking */
                                     &cursor);

        if (result == 0)
        {
            result = cgdb_pg_query(cursor);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending query: %d", result);
                cgdb_pg_cursor_free(cursor), cursor = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating PG cursor: %d", result);
        }
    }

    return result;
}

static int cgdb_pg_increment(void * const data,
                             cgdb_backend_statement const statement,
                             cgdb_param const * const params,
                             size_t const params_count,
                             cgdb_backend_status_cb * const cb,
                             void * const cb_data)
{
    int result = EINVAL;

    if (data != NULL &&
        (params != NULL || params_count == 0))
    {
        cgdb_pg_data * this = data;
        cgdb_pg_cursor * cursor = NULL;

        result = cgdb_pg_cursor_init(this,
                                     statement,
                                     cb,
                                     CGDB_PG_NO_CURSOR_CB,
                                     CGDB_PG_NO_STATUS_RETURNING_CB,
                                     cb_data,
                                     params,
                                     params_count,
                                     CGDB_LIMIT_NONE,
                                     CGDB_SKIP_NONE,
                                     false,
                                     false,
                                     &cursor);

        if (result == 0)
        {
            result = cgdb_pg_query(cursor);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending query: %d", result);
            }

            if (result != 0)
            {

                cgdb_pg_cursor_free(cursor), cursor = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating PG cursor: %d", result);
        }
    }

    return result;
}

static void cgdb_pg_cursor_destroy(void * const data,
                                   cgdb_backend_cursor * const this)
{
    (void) data;
    cgdb_pg_cursor_free((cgdb_pg_cursor *) this);
}

static int cgdb_pg_exec_rows_stmt_sync(void * const data,
                                       cgdb_backend_statement const statement,
                                       cgdb_param const * const params,
                                       size_t const params_count,
                                       cgdb_limit_type const limit,
                                       cgdb_skip_type const skip,
                                       cgdb_backend_cursor ** const cursor_out,
                                       size_t * const rows_count,
                                       cgutils_vector ** const rows)
{
    int result = EINVAL;

    if (data != NULL &&
        (params != NULL || params_count == 0) &&
        cursor_out != NULL &&
        rows_count != NULL &&
        rows != NULL &&
        statement > cgdb_backend_statement_none &&
        statement < cgdb_backend_statement_count)
    {
        cgdb_pg_data * this = data;
        cgdb_pg_cursor * cursor = NULL;

        /* Synchronous connection should not be pooled with
           asynchronous ones. For now, we are simply not using pooling for
           synchronous connection.
        */

        result = cgdb_pg_cursor_init(this,
                                     statement,
                                     CGDB_PG_NO_STATUS_CB, /* no status cb */
                                     CGDB_PG_NO_CURSOR_CB, /* no cursor cb */
                                     CGDB_PG_NO_STATUS_RETURNING_CB, /* no status returning cb */
                                     NULL, /* hence no cb data */
                                     params,
                                     params_count,
                                     limit,
                                     skip,
                                     false, /* NOT read only */
                                     true, /* blocking */
                                     &cursor);

        if (result == 0)
        {
            result = cgdb_pg_new_connection(cursor,
                                            true);

            if (result == 0)
            {
                cursor->state = cgdb_pg_state_executing_statement;

                result = PQsendQueryParams(cursor->conn->conn,
                                           cgdb_pg_statements[cursor->statement].str,
                                           (int) cursor->stmt_params->count,
                                           NULL, /* let the server guess the type */
                                           (char const * const *) cursor->stmt_params->values,
                                           cursor->stmt_params->lengths,
                                           cursor->stmt_params->formats,
                                           1);

                if (result == 1)
                {
                    result = cgdb_pg_handle_results(cursor);

                    if (result == 0)
                    {
                        *rows = cursor->rows;
                        *rows_count = cursor->rows_count;
                        *cursor_out = cursor;
                    }
                    else
                    {
                        char const * const error_str = PQerrorMessage(cursor->conn->conn);
                        CGUTILS_ERROR("Error handling results: %d(%s)",
                                      result,
                                      error_str);

                        if (cursor->rows != NULL)
                        {
                            cgutils_vector_deep_free(&(cursor->rows), &cgdb_row_delete);
                        }

                        result = EIO;
                    }
                }
                else
                {
                    char const * const error_str = PQerrorMessage(cursor->conn->conn);
                    CGUTILS_ERROR("Error sending prepared statement %s(%s): %d(%s)",
                                  cgdb_pg_statements[cursor->statement].name,
                                  cgdb_pg_statements[cursor->statement].str,
                                  result,
                                  error_str);
                    result = EIO;
                }

                cgdb_pg_prepared_stmt_params_free(cursor->stmt_params), cursor->stmt_params = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error getting connection: %d", result);
            }

            if (result != 0)
            {
                cgdb_pg_cursor_free(cursor), cursor = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating PG cursor: %d", result);
        }
    }

    return result;
}

static int cgdb_pg_sync_test_credentials(void * const data,
                                         char ** const error_str_out)
{
    int result = EINVAL;

    if (data != NULL)
    {
        cgdb_pg_data * this = data;
        PGconn * conn = PQconnectdb(this->conn_str);

        if (conn != NULL)
        {
            ConnStatusType const status = PQstatus(conn);

            if (status != CONNECTION_BAD)
            {
                result = 0;
            }
            else
            {
                result = EIO;
                char const * const error_str = PQerrorMessage(conn);

                if (error_str != NULL &&
                    error_str_out != NULL)
                {
                    *error_str_out = cgutils_strdup(error_str);
                }
            }

            PQfinish(conn), conn = NULL;
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error connecting to database: %d", result);
        }
    }

    return result;
}

COMPILER_BLOCK_VISIBILITY_DEFAULT

extern cgdb_backend_ops const cgdb_backend_pg_ops;

cgdb_backend_ops const cgdb_backend_pg_ops =
{
    .init = &cgdb_pg_init,
    .free = &cgdb_pg_free,
    .find = &cgdb_pg_find,
    .insert = &cgdb_pg_insert,
    .insert_returning = &cgdb_pg_insert_returning,
    .update = &cgdb_pg_update,
    .remove = &cgdb_pg_delete,
    .destroy_cursor = &cgdb_pg_cursor_destroy,
    .increment = &cgdb_pg_increment,
    .exec_stmt = &cgdb_pg_exec_stmt,
    .exec_rows_stmt = &cgdb_pg_exec_rows_stmt,
    .exec_rows_stmt_sync = &cgdb_pg_exec_rows_stmt_sync,
    .sync_test_credentials = &cgdb_pg_sync_test_credentials,
};

COMPILER_BLOCK_VISIBILITY_END
