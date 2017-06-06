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

#ifndef CLOUD_GATEWAY_DB_SQL_H_
#define CLOUD_GATEWAY_DB_SQL_H_

#include <stdint.h>
#include <cloudutils/cloudutils_llist.h>

#include <cgdb/cgdb_utils.h>

typedef void (cgdb_sql_free)(void *);
typedef int (cgdb_sql_escaper)(void * data,
                               char const * str,
                               size_t str_len,
                               char ** out);

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgdb_sql_construct_find_query(void * backend_data,
                                  char const * table,
                                  /* llist of cgdb_field * */
                                  cgutils_llist * cond_fields,
                                  /* llist of char * */
                                  cgutils_llist * order_by_params,
                                  cgdb_sql_escaper * backend_escaper,
                                  cgdb_sql_free * backend_free,
                                  cgdb_limit_type type,
                                  cgdb_skip_type skip,
                                  char ** query_out);

int cgdb_sql_construct_insert_query(void * backend_data,
                                    char const * table,
                                    /* llist of cgdb_field * */
                                    cgutils_llist * op_fields,
                                    cgdb_sql_escaper * backend_escaper,
                                    cgdb_sql_free * backend_free,
                                    char ** query_out);

int cgdb_sql_construct_update_query(void * backend_data,
                                    char const * table,
                                    /* llist of cgdb_field * */
                                    cgutils_llist * cond_fields,
                                    /* llist of cgdb_field * */
                                    cgutils_llist * op_fields,
                                    cgdb_sql_escaper * backend_escaper,
                                    cgdb_sql_free * backend_free,
                                    char ** query_out);

int cgdb_sql_construct_delete_query(void * backend_data,
                                    char const * table,
                                    /* llist of cgdb_field * */
                                    cgutils_llist * cond_fields,
                                    cgdb_sql_escaper * backend_escaper,
                                    cgdb_sql_free * backend_free,
                                    char ** query_out);

int cgdb_sql_construct_increment_query(void * backend_data,
                                       char const * table,
                                       /* llist of cgdb_field * */
                                       cgutils_llist * cond_fields,
                                       /* llist of cgdb_field * */
                                       cgutils_llist * inc_fields,
                                       cgdb_sql_escaper * backend_escaper,
                                       cgdb_sql_free * backend_free,
                                       char ** query_out);

char const * cgdb_sql_operator_to_string(cgdb_field_operator_type type) COMPILER_CONST_FUNCTION;
size_t cgdb_sql_operator_to_string_len(cgdb_field_operator_type type) COMPILER_CONST_FUNCTION;

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_DB_SQL_H_ */
