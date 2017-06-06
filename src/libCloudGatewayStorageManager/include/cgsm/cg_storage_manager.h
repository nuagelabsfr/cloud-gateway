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
#ifndef CLOUD_GATEWAY_STORAGE_MANAGER_H_
#define CLOUD_GATEWAY_STORAGE_MANAGER_H_

#include <cgsm/cg_storage_manager_data.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cg_storage_manager_loop(cg_storage_manager_data * data);

void cg_storage_manager_exit_loop(cg_storage_manager_data * data);

int cg_storage_manager_load_configuration(cg_storage_manager_data * data,
                                          bool load_instances,
                                          bool load_filesystems);

int cg_storage_manager_setup(cg_storage_manager_data * data,
                             bool const setup_providers);

int cg_storage_manager_release_configuration(cg_storage_manager_data * data);

int cg_storage_manager_load_storage_provider_with_defaults(cg_storage_manager_data * data,
                                                           char const * name,
                                                           cg_storage_provider ** out);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_STORAGE_MANAGER_H_ */
