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

#ifndef CLOUD_GATEWAY_MONITOR_DATA_H_
#define CLOUD_GATEWAY_MONITOR_DATA_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CG_MONITOR_DATA_COUNT (10)

typedef struct
{
    uint64_t milliseconds;
    bool success;
} cg_monitor_data_instance_value;

typedef struct
{
    cg_monitor_data_instance_value get_values[CG_MONITOR_DATA_COUNT];
    cg_monitor_data_instance_value put_values[CG_MONITOR_DATA_COUNT];
    uint64_t average_get_values;
    uint64_t average_put_values;
    size_t instance_index;
    size_t get_weight;
    size_t put_weight;
    bool last_success;
} cg_monitor_data_instance_status_data;

typedef struct
{
    size_t instances_count;
    size_t values_set;
    cg_monitor_data_instance_status_data instances_data[];
} cg_monitor_data_instance_status_tab;

typedef struct cg_monitor_data cg_monitor_data;

#include <cloudutils/cloudutils.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

/* Peek at the segment (attach and read instances_count only),
   allocate the necessary space, attach and copy (checking that the size
   did not change) and return the copy.*/
int cg_monitor_data_peek(char const * monitor_info_path,
                         cg_monitor_data_instance_status_tab ** copy);

int cg_monitor_data_create(char const * monitor_info_path,
                           size_t instances_count,
                           cg_monitor_data ** out);

int cg_monitor_data_get(char const * monitor_info_path,
                        bool const writable,
                        size_t instances_count,
                        cg_monitor_data ** out);

int cg_monitor_data_update(cg_monitor_data * this,
                           cg_monitor_data_instance_status_tab const * new_values);

int cg_monitor_data_retrieve(cg_monitor_data * this,
                             cg_monitor_data_instance_status_tab * values);

int cg_monitor_data_set_readonly(cg_monitor_data * this);

int cg_monitor_data_destroy(cg_monitor_data * this);

void cg_monitor_data_free(cg_monitor_data * this);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_MONITOR_DATA_H_ */
