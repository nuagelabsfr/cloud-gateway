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

#ifndef CLOUD_GATEWAY_STORAGE_FILTER_BACKEND_H_
#define CLOUD_GATEWAY_STORAGE_FILTER_BACKEND_H_

typedef enum
{
    cg_storage_filter_enc = 0,
    cg_storage_filter_dec
} cg_storage_filter_mode;

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_configuration.h>

#include <cgsm/cg_storage_filter.h>

typedef int (cg_storage_filter_op_init)(cgutils_configuration const * specifics,
                                 void ** data);

typedef int (cg_storage_filter_op_init_context)(void * data,
                                                cg_storage_filter_mode mode,
                                                void ** ctx);

typedef cg_storage_filter_type (cg_storage_filter_op_get_type)(void const * data);

typedef int (cg_storage_filter_op_do)(void * ctx,
                                      char const * in,
                                      size_t in_size,
                                      char ** out,
                                      size_t * out_size);

typedef size_t (cg_storage_filter_op_max_input_for_buffer)(void * ctx,
                                                           size_t buffer_size);


typedef int (cg_storage_filter_op_get_max_final_size)(void * ctx,
                                                      size_t in_size,
                                                      size_t * out_size);

typedef int (cg_storage_filter_op_finish)(void * ctx,
                                         char ** out,
                                         size_t * out_size);

typedef void (cg_storage_filter_op_free_context)(void * ctx);

typedef void (cg_storage_filter_op_free)(void * data);

typedef struct
{
    cg_storage_filter_op_init * init;
    cg_storage_filter_op_get_type * get_type;
    cg_storage_filter_op_init_context * init_context;
    cg_storage_filter_op_do * do_filter;
    cg_storage_filter_op_max_input_for_buffer * max_input_for_buffer;
    cg_storage_filter_op_get_max_final_size * get_max_final_size;
    cg_storage_filter_op_finish * finish;
    cg_storage_filter_op_free_context * free_context;
    cg_storage_filter_op_free * free;
    bool predictable_output_size;
} cg_storage_filter_ops;

#endif /* CLOUD_GATEWAY_STORAGE_FILTER_BACKEND_H_ */
