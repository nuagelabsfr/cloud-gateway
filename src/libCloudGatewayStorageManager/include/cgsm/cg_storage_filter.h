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

#ifndef CLOUD_GATEWAY_STORAGE_FILTER_H_
#define CLOUD_GATEWAY_STORAGE_FILTER_H_

typedef struct cg_storage_filter cg_storage_filter;
typedef struct cg_storage_filter_ctx cg_storage_filter_ctx;

typedef enum
{
    cg_storage_filter_type_none = 0,
    cg_storage_filter_type_compression,
    cg_storage_filter_type_encryption,
} cg_storage_filter_type;

#include <cgsm/cg_storage_filter_backend.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cg_storage_filter_init(char const * name,
                           char const * filters_path,
                           cgutils_configuration * specifics,
                           cg_storage_filter ** out);

void cg_storage_filter_free(cg_storage_filter * filter);

static inline void cg_storage_filter_delete(void * const filter)
{
    cg_storage_filter_free(filter);
}

bool cg_storage_filter_support_predictable_output_size(cg_storage_filter const * filter) COMPILER_PURE_FUNCTION;
bool cg_storage_filter_ctx_support_predictable_output_size(cg_storage_filter_ctx const * ctx) COMPILER_PURE_FUNCTION;

int cg_storage_filter_ctx_init(cg_storage_filter * filter,
                               cg_storage_filter_mode mode,
                               cg_storage_filter_ctx ** ctx);

size_t cg_storage_filter_max_input_for_buffer(cg_storage_filter_ctx * ctx,
                                              size_t buffer_size);

int cg_storage_filter_get_max_final_size(cg_storage_filter_ctx const * ctx,
                                         size_t in_size,
                                         size_t * out_size);

int cg_storage_filter_do(cg_storage_filter_ctx * filter_ctx,
                         char const * in,
                         size_t in_size,
                         char ** out,
                         size_t * out_size);

int cg_storage_filter_finish(cg_storage_filter_ctx * filter_ctx,
                             char ** out,
                             size_t * out_size);

char const * cg_storage_filter_get_name(cg_storage_filter const *) COMPILER_PURE_FUNCTION;

cg_storage_filter_type cg_storage_filter_get_type(cg_storage_filter const *) COMPILER_PURE_FUNCTION;

void cg_storage_filter_ctx_free(cg_storage_filter_ctx * ctx);

static inline void cg_storage_filter_ctx_delete(void * ctx)
{
    cg_storage_filter_ctx_free(ctx);
}


COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_STORAGE_FILTER_H_ */
