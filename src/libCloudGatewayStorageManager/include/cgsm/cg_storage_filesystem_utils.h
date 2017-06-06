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

#ifndef CG_STORAGE_FILESYSTEM_UTILS_H_
#define CG_STORAGE_FILESYSTEM_UTILS_H_

#include <cgsm/cg_storage_filesystem.h>

#include <cgsm/cg_storage_fs_cb_data.h>

void cg_storage_filesystem_return_to_handler(int status,
                                             cg_storage_fs_cb_data * data);

void cg_storage_filesystem_timespec_to_uint64(struct timespec const * ts,
                                              uint64_t * out);

void cg_storage_filesystem_uint64_to_timespec(uint64_t timestamp,
                                              struct timespec * out);

void cg_storage_filesystem_time_to_timespec(time_t timestamp,
                                            struct timespec * out);

#endif /* CG_STORAGE_FILESYSTEM_UTILS_H_ */
