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

#ifndef CLOUD_GATEWAY_STORAGE_MANAGER_DATA_H_
#define CLOUD_GATEWAY_STORAGE_MANAGER_DATA_H_

typedef struct cg_storage_manager_data cg_storage_manager_data;

#include <cloudutils/cloudutils_aio.h>
#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_event.h>
#include <cloudutils/cloudutils_htable.h>
#include <cloudutils/cloudutils_http.h>

#include <cgsm/cg_storage_filesystem.h>
#include <cgsm/cg_storage_instance.h>
#include <cgsm/cg_storage_provider.h>

#include <cgmonitor/cg_monitor_data.h>

#include <cgdb/cgdb.h>

typedef struct
{
    char * file_id;
    char * file_template_value;
    char * file_template_path;
    char * digest_algo;
    uint64_t delay;
    size_t file_size;
} cg_storage_manager_monitor_config;

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cg_storage_manager_data_init(cgutils_configuration * ,
                                 cg_storage_manager_data ** );
int cg_storage_manager_data_setup(cg_storage_manager_data * );
void cg_storage_manager_data_free(cg_storage_manager_data *);

char const * cg_storage_manager_data_get_providers_path(cg_storage_manager_data const *) COMPILER_PURE_FUNCTION;
char const * cg_storage_manager_data_get_db_backends_path(cg_storage_manager_data const *) COMPILER_PURE_FUNCTION;
char const * cg_storage_manager_data_get_storage_filters_path(cg_storage_manager_data const *) COMPILER_PURE_FUNCTION;
char const * cg_storage_manager_data_get_pid_file(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;
char const * cg_storage_manager_data_get_log_file(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;
char const * cg_storage_manager_data_get_communication_socket(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;
char const * cg_storage_manager_data_get_monitor_informations_path(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;
char const * cg_storage_manager_data_get_resources_path(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;
char const * cg_storage_manager_data_get_stats_json_file(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;

size_t cg_storage_manager_data_get_cleaner_delay(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;
size_t cg_storage_manager_data_get_cleaner_db_slots(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;

size_t cg_storage_manager_data_get_syncer_delay(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;
size_t cg_storage_manager_data_get_syncer_dirtyness_delay(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;
size_t cg_storage_manager_data_get_syncer_max_db_objects_per_call(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;
size_t cg_storage_manager_data_get_syncer_db_slots(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;
bool cg_storage_manager_data_get_syncer_dump_http_states(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;

size_t cg_storage_manager_data_get_checker_delay(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;
bool cg_storage_manager_data_get_checker_checks_disabled(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;

size_t cg_storage_manager_data_get_max_requests_per_connection(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;

cgutils_configuration * cg_storage_manager_data_get_configuration(cg_storage_manager_data const *) COMPILER_PURE_FUNCTION;
cgutils_event_data * cg_storage_manager_data_get_event(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;
cgutils_http_data * cg_storage_manager_data_get_http(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;
cgutils_aio * cg_storage_manager_data_get_aio(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;

cgutils_http_global_params const * cg_storage_manager_data_get_http_global_params(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;

int cg_storage_manager_data_add_provider(cg_storage_manager_data * data,
                                         cg_storage_provider * provider);

int cg_storage_manager_data_add_instance(cg_storage_manager_data * data,
                                         cg_storage_instance * instance);

int cg_storage_manager_data_add_filesystem(cg_storage_manager_data * data,
                                           cg_storage_filesystem * filesystem);

int cg_storage_manager_data_get_provider(cg_storage_manager_data * data,
                                         char const * provider_name,
                                         cg_storage_provider ** provider);

int cg_storage_manager_data_get_all_filesystems(cg_storage_manager_data * data,
                                                cgutils_htable_iterator ** filesystem);

size_t cg_storage_manager_data_get_instances_count(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;

int cg_storage_manager_data_get_all_instances(cg_storage_manager_data * data,
                                              cgutils_htable_iterator ** instances);

int cg_storage_manager_data_get_instance(cg_storage_manager_data * data,
                                         char const * instance_name,
                                         cg_storage_instance ** instance);

int cg_storage_manager_data_get_filesystem(cg_storage_manager_data * data,
                                           char const * filesystem_name,
                                           cg_storage_filesystem ** filesystem);

int cg_storage_manager_data_get_instance_by_id(cg_storage_manager_data * data,
                                               uint64_t instance_id,
                                               cg_storage_instance ** instance);

int cg_storage_manager_data_get_filesystem_by_id(cg_storage_manager_data * data,
                                                 uint64_t filesystem_id,
                                                 cg_storage_filesystem ** filesystem);

size_t cg_storage_manager_data_get_filesystems_count(cg_storage_manager_data const * data) COMPILER_PURE_FUNCTION;

cgdb_data * cg_storage_manager_data_get_db(cg_storage_manager_data * data) COMPILER_PURE_FUNCTION;

int cg_storage_manager_data_get_signal_event(cg_storage_manager_data * data,
                                             size_t idx,
                                             cgutils_event ** event);

int cg_storage_manager_data_set_signal_event(cg_storage_manager_data * data,
                                             size_t idx,
                                             cgutils_event * event);

int cg_storage_manager_data_configuration_finished(cg_storage_manager_data * data);

void cg_storage_manager_data_set_provider_init_pending(cg_storage_manager_data * this);
void cg_storage_manager_data_set_provider_init_finished(cg_storage_manager_data * this,
                                                        int result);

size_t cg_storage_manager_data_provider_init_remaining(cg_storage_manager_data const * this) COMPILER_PURE_FUNCTION;

bool cg_storage_manager_data_get_nofork(cg_storage_manager_data const * const this) COMPILER_PURE_FUNCTION;
bool cg_storage_manager_data_get_daemonize(cg_storage_manager_data const * const this) COMPILER_PURE_FUNCTION;

cg_monitor_data * cg_storage_manager_data_get_monitor_data(cg_storage_manager_data const * this) COMPILER_PURE_FUNCTION;
void cg_storage_manager_data_set_monitor_data(cg_storage_manager_data * this,
                                              cg_monitor_data * monitor_data);

void cg_storage_manager_data_set_mirroring_in_use(cg_storage_manager_data * this);
void cg_storage_manager_data_set_striping_in_use(cg_storage_manager_data * this);
void cg_storage_manager_data_set_encryption_in_use(cg_storage_manager_data * this);
void cg_storage_manager_data_set_compression_in_use(cg_storage_manager_data * this);

bool cg_storage_manager_data_is_mirroring_in_use(cg_storage_manager_data const * this) COMPILER_PURE_FUNCTION;
bool cg_storage_manager_data_is_striping_in_use(cg_storage_manager_data const * this) COMPILER_PURE_FUNCTION;
bool cg_storage_manager_data_is_encryption_in_use(cg_storage_manager_data const * this) COMPILER_PURE_FUNCTION;
bool cg_storage_manager_data_is_compression_in_use(cg_storage_manager_data const * this) COMPILER_PURE_FUNCTION;

size_t cg_storage_manager_data_get_filesystems_with_mirroring_count(cg_storage_manager_data const * this);
size_t cg_storage_manager_data_get_filesystems_with_striping_count(cg_storage_manager_data const * this);
size_t cg_storage_manager_data_get_instances_with_encryption_count(cg_storage_manager_data const * this);
size_t cg_storage_manager_data_get_instances_with_compression_count(cg_storage_manager_data const * this);

size_t cg_storage_manager_data_get_instances_amazon_count(cg_storage_manager_data const * this);
size_t cg_storage_manager_data_get_instances_openstack_count(cg_storage_manager_data const * this);

cg_storage_manager_monitor_config * cg_storage_manager_data_get_monitor_config(cg_storage_manager_data * this);

int cg_storage_manager_data_setup_event(cg_storage_manager_data * this);
void cg_storage_manager_data_destroy_event(cg_storage_manager_data * this);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_STORAGE_MANAGER_DATA_H_ */
