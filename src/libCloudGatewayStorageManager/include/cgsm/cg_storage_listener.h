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

#ifndef CLOUD_GATEWAY_STORAGE_LISTENER_H_
#define CLOUD_GATEWAY_STORAGE_LISTENER_H_

typedef struct cg_storage_listener cg_storage_listener;

#include <cgsm/cg_storage_manager_data.h>

typedef void (listener_callback)(cg_storage_manager_data * data,
                                 cg_storage_listener * listener,
                                 int sock,
                                 void * cb_data);

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cg_storage_listener_enable(cg_storage_listener * this,
                               cg_storage_manager_data * data,
                               listener_callback * cb,
                               void * cb_data);

int cg_storage_listener_init(cg_storage_manager_data * data,
                             cg_storage_listener ** out,
                             bool immediate_bind,
                             int backlog);

int cg_storage_listener_bind(cg_storage_listener * listener);

void cg_storage_listener_free(cg_storage_listener * this);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_STORAGE_LISTENER_H_ */
