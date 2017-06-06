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

#ifndef TOOLS_PROVIDER_STATS_COMMON_H_
#define TOOLS_PROVIDER_STATS_COMMON_H_

#include <cloudutils/cloudutils_configuration.h>

int tools_provider_stats_compute_instances_mapping(cgutils_configuration const * conf,
                                                   char *** names_out,
                                                   size_t * names_count_out);

int tools_provider_stats_compute_monitor_info_path(cgutils_configuration const * conf,
                                                   char ** out);

#endif /* TOOLS_PROVIDER_STATS_COMMON_H_ */
