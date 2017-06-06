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

#ifndef CLOUD_GATEWAY_BD_BACKEND_H_
#define CLOUD_GATEWAY_BD_BACKEND_H_

#include <stdint.h>

#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_vector.h>
#include <cgdb/cgdb.h>
#include <cgdb/cgdb_utils.h>

typedef void cgdb_backend_cursor;

typedef enum cgdb_backend_statements
{
    cgdb_backend_statement_none = 0,
#define STMT(name, count) cgdb_backend_statement_ ## name,
#include "cgdb/cgdb_backend_statements.itm"
#undef STMT
    cgdb_backend_statement_count
} cgdb_backend_statement;

static size_t const cgdb_backend_statement_params_count[] =
{
    0,
#define STMT(name, count) count,
#include "cgdb/cgdb_backend_statements.itm"
#undef STMT
    0
};

typedef int (cgdb_backend_cursor_cb)(cgdb_backend_cursor *,
                                     int status,
                                     bool has_error,
                                     char const * error_str,
                                     size_t rows_count,
                                     cgutils_vector * rows,
                                     void * cb_data);

typedef void (cgdb_backend_status_cb)(void * data,
                                      int status,
                                      void * cb_data);

typedef void (cgdb_backend_status_returning_cb)(void * data,
                                                int status,
                                                uint64_t id,
                                                void * cb_data);

typedef int (cgdb_backend_op_init)(cgutils_event_data * event_data,
                                   cgutils_configuration const * specifics,
                                   void ** data);

typedef int (cgdb_backend_op_insert)(void * data,
                                     cgdb_backend_statement statement,
                                     cgdb_param const * params,
                                     size_t params_count,
                                     cgdb_backend_status_cb * cb,
                                     void * cb_data);

typedef int (cgdb_backend_op_insert_returning)(void * data,
                                               cgdb_backend_statement statement,
                                               cgdb_param const * params,
                                               size_t params_count,
                                               cgdb_backend_status_returning_cb * cb,
                                               void * cb_data);

typedef int (cgdb_backend_op_find)(void * data,
                                   cgdb_backend_statement statement,
                                   cgdb_param const * params,
                                   size_t params_count,
                                   cgdb_limit_type limit,
                                   cgdb_skip_type skip,
                                   cgdb_backend_cursor_cb * cb,
                                   void * cb_data);

typedef int (cgdb_backend_op_exec_stmt)(void * data,
                                        cgdb_backend_statement statement,
                                        cgdb_param const * params,
                                        size_t params_count,
                                        cgdb_backend_status_cb * cb,
                                        void * cb_data);

typedef int (cgdb_backend_op_exec_rows_stmt)(void * data,
                                             cgdb_backend_statement statement,
                                             cgdb_param const * params,
                                             size_t params_count,
                                             cgdb_backend_cursor_cb * cb,
                                             void * cb_data);

typedef int (cgdb_backend_op_exec_rows_stmt_sync)(void * data,
                                                  cgdb_backend_statement statement,
                                                  cgdb_param const * params,
                                                  size_t params_count,
                                                  cgdb_limit_type limit,
                                                  cgdb_skip_type skip,
                                                  cgdb_backend_cursor ** cursor_out,
                                                  size_t * rows_count,
                                                  cgutils_vector ** rows);

typedef int (cgdb_backend_op_update)(void * data,
                                     cgdb_backend_statement statement,
                                     cgdb_param const * params,
                                     size_t params_count,
                                     cgdb_backend_status_cb * cb,
                                     void * cb_data);

typedef int (cgdb_backend_op_remove)(void * data,
                                     cgdb_backend_statement statement,
                                     cgdb_param const * params,
                                     size_t params_count,
                                     cgdb_backend_status_cb * cb,
                                     void * cb_data);

typedef int (cgdb_backend_op_increment)(void * data,
                                        cgdb_backend_statement statement,
                                        cgdb_param const * params,
                                        size_t params_count,
                                        cgdb_backend_status_cb * cb,
                                        void * cb_data);

typedef int (cgdb_backend_op_sync_test_credentials)(void * data,
                                                    char ** error_str_out);

typedef void (cgdb_backend_op_destroy_cursor)(void * data,
                                              cgdb_backend_cursor * cursor);

typedef void (cgdb_backend_op_free)(void * data);

typedef struct cgdb_backend_ops
{
    cgdb_backend_op_init * init;
    cgdb_backend_op_insert * insert;
    cgdb_backend_op_insert_returning * insert_returning;
    cgdb_backend_op_increment * increment;
    cgdb_backend_op_find * find;
    cgdb_backend_op_update * update;
    cgdb_backend_op_remove * remove;
    cgdb_backend_op_destroy_cursor * destroy_cursor;
    cgdb_backend_op_free * free;
    cgdb_backend_op_exec_stmt * exec_stmt;
    cgdb_backend_op_exec_rows_stmt * exec_rows_stmt;
    cgdb_backend_op_exec_rows_stmt_sync * exec_rows_stmt_sync;
    cgdb_backend_op_sync_test_credentials * sync_test_credentials;
} cgdb_backend_ops;

typedef struct cgdb_backend cgdb_backend;

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgdb_backend_init(char const * name,
                      char const * backends_path,
                      cgutils_event_data * event_data,
                      cgutils_configuration * specifics,
                      cgdb_backend ** backend);

int cgdb_backend_insert(cgdb_backend * backend,
                        cgdb_backend_statement statement,
                        cgdb_param const * params,
                        size_t params_count,
                        cgdb_backend_status_cb * cb,
                        void * cb_data);

int cgdb_backend_insert_returning(cgdb_backend * backend,
                                  cgdb_backend_statement statement,
                                  cgdb_param const * params,
                                  size_t params_count,
                                  cgdb_backend_status_returning_cb * cb,
                                  void * cb_data);

int cgdb_backend_find(cgdb_backend * backend,
                      cgdb_backend_statement statement,
                      cgdb_param const * params,
                      size_t params_count,
                      cgdb_limit_type limit,
                      cgdb_skip_type skip,
                      cgdb_backend_cursor_cb * cb,
                      void * cb_data);

int cgdb_backend_update(cgdb_backend * backend,
                        cgdb_backend_statement statement,
                        cgdb_param const * params,
                        size_t params_count,
                        cgdb_backend_status_cb * cb,
                        void * cb_data);

int cgdb_backend_remove(cgdb_backend * backend,
                        cgdb_backend_statement statement,
                        cgdb_param const * params,
                        size_t params_count,
                        cgdb_backend_status_cb * cb,
                        void * cb_data);

int cgdb_backend_increment(cgdb_backend * backend,
                           cgdb_backend_statement statement,
                           cgdb_param const * params,
                           size_t params_count,
                           cgdb_backend_status_cb * cb,
                           void * cb_data);

int cgdb_backend_exec_stmt(cgdb_backend * backend,
                           cgdb_backend_statement statement,
                           cgdb_param const * params,
                           size_t params_count,
                           cgdb_backend_status_cb * cb,
                           void * cb_data);

int cgdb_backend_exec_rows_stmt(cgdb_backend * backend,
                                cgdb_backend_statement statement,
                                cgdb_param const * params,
                                size_t params_count,
                                cgdb_backend_cursor_cb * cb,
                                void * cb_data);

void cgdb_backend_cursor_destroy(cgdb_backend * backend,
                                 cgdb_backend_cursor * cursor);


void cgdb_backend_free(cgdb_backend * backend);

int cgdb_backend_exec_rows_stmt_sync(cgdb_backend * backend,
                                     cgdb_backend_statement statement,
                                     cgdb_param const * params,
                                     size_t params_count,
                                     cgdb_limit_type limit,
                                     cgdb_skip_type skip,
                                     cgdb_backend_cursor ** cursor_out,
                                     size_t * rows_count,
                                     cgutils_vector ** rows);

int cgdb_backend_sync_test_credentials(cgdb_backend * backend,
                                       char ** error_str_out);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_BD_BACKEND_H_ */
