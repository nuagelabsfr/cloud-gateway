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

#ifndef CLOUD_GATEWAY_STORAGE_IO_H_
#define CLOUD_GATEWAY_STORAGE_IO_H_

#include <stdbool.h>
#include <stddef.h>

#include <cloudutils/cloudutils_aio.h>
#include <cloudutils/cloudutils_llist.h>

typedef struct cg_storage_io_ctx cg_storage_io_ctx;
typedef struct cg_storage_io cg_storage_io;

typedef int (cg_storage_io_cb)(int status,
                               size_t completion,
                               void * cb_data);

typedef int (cg_storage_io_read_cb)(int status,
                                    void * cb_data);

#include <cgsm/cg_storage_filter.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cg_storage_io_ctx_write(cg_storage_io_ctx * this,
                            char const * buffer,
                            size_t buffer_size,
                            cg_storage_io_cb * cb,
                            void * cb_data);

int cg_storage_io_ctx_read(cg_storage_io_ctx * this,
                           char * buffer,
                           size_t buffer_size,
                           size_t * written,
                           bool * eof,
                           bool * io_pending,
                           cg_storage_io_read_cb * cb,
                           void * cb_data );

int cg_storage_io_ctx_source_init(cg_storage_io * io,
                                  size_t support_offset,
                                  size_t ctx_size,
                                  cg_storage_io_ctx ** ctx);

int cg_storage_io_ctx_destination_init(cg_storage_io * io,
                                       cg_storage_io_ctx ** ctx);

int cg_storage_io_compute_hash(cg_storage_io * this,
                               cgutils_crypto_digest_algorithm algorithm);

int cg_storage_io_get_hash(cg_storage_io * io,
                           void ** hash,
                           size_t * hash_size);

void cg_storage_io_ctx_free(cg_storage_io_ctx * ctx);

bool cg_storage_io_support_parallel_ops(cg_storage_io const * const this) COMPILER_PURE_FUNCTION;
bool cg_storage_io_is_final_size_known(cg_storage_io const * this) COMPILER_PURE_FUNCTION;
bool cg_storage_io_is_chunk_size_known(cg_storage_io const * this) COMPILER_PURE_FUNCTION;

bool cg_storage_io_ctx_source_has_data_ready(cg_storage_io_ctx const * ctx) COMPILER_PURE_FUNCTION;

int cg_storage_io_ctx_source_get_final_size(cg_storage_io_ctx const * this,
                                            size_t * out_size);

size_t cg_storage_io_get_support_size(cg_storage_io const * this) COMPILER_PURE_FUNCTION;
size_t cg_storage_io_get_final_size(cg_storage_io const * this);
size_t cg_storage_io_get_max_final_size(cg_storage_io const * this);

int cg_storage_io_source_init_from_fd(cgutils_aio * aio,
                                      int fd,
                                      size_t file_size,
                                      cg_storage_io ** out);

int cg_storage_io_destination_init_mem(cg_storage_io ** out);

int cg_storage_io_destination_init_from_fd(cgutils_aio * aio,
                                           int fd,
                                           cg_storage_io ** out);

void cg_storage_io_free(cg_storage_io * this);

int cg_storage_io_add_filter(cg_storage_io * this,
                             cg_storage_filter * filter);

size_t cg_storage_io_mem_get_output_size(cg_storage_io_ctx * ctx) COMPILER_PURE_FUNCTION;

int cg_storage_io_mem_get_output(cg_storage_io_ctx * ctx,
                                 char const ** out);

int cg_storage_io_destination_finish(cg_storage_io * this,
                                     cg_storage_io_cb * cb,
                                     void * cb_data);

bool cg_storage_io_ctx_destination_need_suspend(cg_storage_io_ctx const * this) COMPILER_PURE_FUNCTION;

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_STORAGE_IO_H_ */
