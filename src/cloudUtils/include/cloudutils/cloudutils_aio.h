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
#ifndef CLOUD_UTILS_AIO_H_
#define CLOUD_UTILS_AIO_H_

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct cgutils_aio cgutils_aio;

typedef int cgutils_aio_cb(int status,
                           size_t completion,
                           void * cb_data);

#include <cloudutils/cloudutils_event.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_aio_init(cgutils_event_data * event_data,
                     cgutils_aio ** aio);

void cgutils_aio_free(cgutils_aio * aio);

int cgutils_aio_read(cgutils_aio * aio,
                     int fd,
                     char * buffer,
                     size_t buffer_size,
                     off_t offset,
                     cgutils_aio_cb * cb,
                     void * cb_data);

int cgutils_aio_write(cgutils_aio * aio,
                      int fd,
                      char const * buffer,
                      size_t buffer_size,
                      off_t offset,
                      cgutils_aio_cb * cb,
                      void * cb_data);

int cgutils_aio_append(cgutils_aio * aio,
                       int fd,
                       char const * buffer,
                       size_t buffer_size,
                       cgutils_aio_cb * cb,
                       void * cb_data);

int cgutils_aio_fsync(cgutils_aio * aio,
                      int fd,
                      int op,
                      cgutils_aio_cb * cb,
                      void * cb_data);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_AIO_H_ */
