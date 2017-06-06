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
#ifndef CLOUDUTILS_SHARED_MEMORY_SEGMENT_H_
#define CLOUDUTILS_SHARED_MEMORY_SEGMENT_H_

#include <stdbool.h>

typedef struct cloudutils_shared_memory_segment_handler cloudutils_shared_memory_segment_handler;

#include <cloudutils/cloudutils_compiler_specifics.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cloudutils_shared_memory_segment_handler_create(char const * path,
                                                    size_t data_size,
                                                    cloudutils_shared_memory_segment_handler ** out);

int cloudutils_shared_memory_segment_handler_attach(char const * path,
                                                    bool writable,
                                                    size_t data_size,
                                                    cloudutils_shared_memory_segment_handler ** out);

int cloudutils_shared_memory_segment_handler_copy(cloudutils_shared_memory_segment_handler * this,
                                                  void * buffer,
                                                  size_t buffer_size);

int cloudutils_shared_memory_segment_handler_update(cloudutils_shared_memory_segment_handler * this,
                                                    void const * new_data,
                                                    size_t new_data_size);

int cloudutils_shared_memory_segment_handler_lock(cloudutils_shared_memory_segment_handler * this);
int cloudutils_shared_memory_segment_handler_unlock(cloudutils_shared_memory_segment_handler * this);

void cloudutils_shared_memory_segment_handler_detach(cloudutils_shared_memory_segment_handler * this);

int cloudutils_shared_memory_segment_handler_destroy(cloudutils_shared_memory_segment_handler * this);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUDUTILS_SHARED_MEMORY_SEGMENT_H_ */
