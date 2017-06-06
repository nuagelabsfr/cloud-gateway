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
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <strings.h>

#include <openssl/crypto.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_crypto.h>
#include <cloudutils/cloudutils_htable.h>

#include <cgsm/cg_storage_filesystem.h>

#include <cgmonitor/cg_monitor_data.h>

#include "cgsm/cg_storage_manager_data.h"

#define CG_STORAGE_MANAGER_DATA_DEFAULT_HTTP_CA_BUNDLE_PATH "/etc/ssl/certs/"
#define CG_STORAGE_MANAGER_DATA_DEFAULT_HTTP_CA_BUNDLE_FILE "/etc/ssl/certs/ca-certificates.crt"

struct cg_storage_manager_data
{
    cgutils_http_global_params http_params;
    cg_storage_manager_monitor_config monitor_config;
    cgdb_data * db;
    cgutils_htable * instances;
    cgutils_htable * providers;
    cgutils_htable * filesystems;
    cgutils_configuration * conf;
    cgutils_event_data * event_data;
    cgutils_aio * aio;
    cgutils_http_data * http;
    cg_monitor_data * monitor_data;
    char * db_backends_path;
    char * providers_path;
    char * storage_filters_path;
    char * resources_path;
    char * pid_file;
    char * log_file;
    char * communication_socket;
    char * monitor_info_path;
    char * stats_json_file;
    size_t providers_initializing;
    size_t cleaner_delay;
    size_t cleaner_db_slots;
    size_t syncer_delay;
    size_t syncer_dirtyness_delay;
    size_t syncer_db_slots;
    size_t syncer_max_db_objects_per_call;
    size_t cgsm_max_requests_per_connection;
    size_t checker_delay;
    bool syncer_dump_http_states;
    bool daemonize;
    bool nofork;
    bool encryption_in_use;
    bool compression_in_use;
    bool mirroring_in_use;
    bool striping_in_use;
    bool checker_checks_disabled;
};

static int cg_storage_manager_data_load_parameters(cg_storage_manager_data * const data)
{
    assert(data != NULL);
    assert(data->conf != NULL);

    int result = 0;

#define STRING_PARAMETER(storage, path, required)                       \
    if (result == 0)                                                    \
    {                                                                   \
        result = cgutils_configuration_get_string(data->conf,           \
                                                  path,                 \
                                                  &(data->storage));    \
        if (result == ENOENT && required == false)                      \
        {                                                               \
            result = 0;                                                 \
            data->storage = NULL;                                       \
        }                                                               \
        else if (result != 0)                                           \
        {                                                               \
            CGUTILS_ERROR("Required parameter [%s] not found.",         \
                          path);                                        \
        }                                                               \
    }
#define BOOLEAN_PARAMETER(storage, path, required)                      \
    if (result == 0)                                                    \
    {                                                                   \
        result = cgutils_configuration_get_boolean(data->conf,          \
                                                   path,                \
                                                   &(data->storage));   \
        if (result == ENOENT && required == false)                      \
        {                                                               \
            result = 0;                                                 \
            data->storage = false;                                      \
        }                                                               \
        else if (result != 0)                                           \
        {                                                               \
            CGUTILS_ERROR("Required parameter [%s] not found.",         \
                          path);                                        \
        }                                                               \
    }
#define SIZE_PARAMETER(storage, path, required)                         \
    if (result == 0)                                                    \
    {                                                                   \
        result = cgutils_configuration_get_size(data->conf, \
                                                path,                   \
                                                &(data->storage));      \
                                                                        \
        if (result == ENOENT && required == false)                      \
        {                                                               \
            result = 0;                                                 \
            data->storage = 0;                                          \
        }                                                               \
        else if (result != 0)                                           \
        {                                                               \
            CGUTILS_ERROR("Required parameter [%s] not found.",         \
                          path);                                        \
        }                                                               \
    }
#include "cg_storage_manager_config_parameters.itm"
#undef SIZE_PARAMETER
#undef BOOLEAN_PARAMETER
#undef STRING_PARAMETER

    if (data->monitor_config.digest_algo != NULL)
    {
        cgutils_crypto_digest_algorithm const algo = cgutils_crypto_digest_algorithm_from_str(data->monitor_config.digest_algo);

        if (algo == cgutils_crypto_digest_algorithm_none ||
            algo == cgutils_crypto_digest_algorithm_max)
        {
            result = ENOENT;
            CGUTILS_ERROR("Error loading invalid Monitor digest algorithm (%s): %d",
                          data->monitor_config.digest_algo,
                          result);
        }
    }

    return result;
}

int cg_storage_manager_data_setup_event(cg_storage_manager_data * const this)
{
    int result = EINVAL;

    if (this != NULL)
    {
        result = cgutils_event_init(&(this->event_data));

        if (result != 0)
        {
            CGUTILS_ERROR("Error setting event up: %d", result);
        }
    }

    return result;
}

void cg_storage_manager_data_destroy_event(cg_storage_manager_data * const this)
{
    if (this != NULL && this->event_data != NULL)
    {
        cgutils_event_clear(this->event_data);

        cgutils_event_destroy(this->event_data), this->event_data = NULL;
    }
}

int cg_storage_manager_data_setup(cg_storage_manager_data * const this)
{
    int result = EINVAL;

    if (this != NULL)
    {
        cgutils_configuration * db_conf = NULL;
        result = cgutils_configuration_from_path(this->conf,
                                                 "DB",
                                                 &db_conf);

        if (result == 0)
        {
            result = cgutils_event_init(&(this->event_data));

            if (result == 0)
            {
                result = cgdb_data_init(this->db_backends_path, db_conf, this->event_data, &(this->db));

                if (result == 0)
                {
                    if (this->http_params.ca_bundle_file == NULL)
                    {
                        this->http_params.ca_bundle_file = cgutils_strdup(CG_STORAGE_MANAGER_DATA_DEFAULT_HTTP_CA_BUNDLE_FILE);
                    }
                    else if (strcasecmp(this->http_params.ca_bundle_file, "None") == 0)
                    {
                        CGUTILS_FREE(this->http_params.ca_bundle_file);
                    }

                    if (this->http_params.ca_bundle_path == NULL)
                    {
                        this->http_params.ca_bundle_path = cgutils_strdup(CG_STORAGE_MANAGER_DATA_DEFAULT_HTTP_CA_BUNDLE_PATH);
                    }
                    else if (strcasecmp(this->http_params.ca_bundle_path, "None") == 0)
                    {
                        CGUTILS_FREE(this->http_params.ca_bundle_path);
                    }

                    result = cgutils_http_data_init(this->event_data,
                                                    &(this->http_params),
                                                    &(this->http));

                    if (result == 0)
                    {
                        result = cgutils_aio_init(this->event_data, &(this->aio));

                        if (result == 0)
                        {
                        }
                        else
                        {
                            CGUTILS_ERROR("Error initializing AIO data: %d", result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error initializing HTTP data: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error initializing DB data: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error initializing event data: %d", result);
            }


            cgutils_configuration_free(db_conf), db_conf = NULL;
        }
        else
        {
            CGUTILS_ERROR("No database configuration found. Exiting.");
        }
    }

    return result;
}

int cg_storage_manager_data_init(cgutils_configuration * conf,
                                 cg_storage_manager_data ** const cgsm_data)
{
    int result = EINVAL;

    if (conf != NULL && cgsm_data != NULL)
    {
        CGUTILS_ALLOCATE_STRUCT(*cgsm_data);

        if (*cgsm_data != NULL)
        {
            result = cgutils_htable_easy_create(&((*cgsm_data)->providers));

            if (result == 0)
            {
                result = cgutils_htable_easy_create(&((*cgsm_data)->instances));

                if (result == 0)
                {
                    result = cgutils_htable_easy_create(&((*cgsm_data)->filesystems));

                    if (result == 0)
                    {
                        (*cgsm_data)->conf = conf;
                        conf = NULL;
                        result = cg_storage_manager_data_load_parameters(*cgsm_data);
                    }
                }
            }

            if (result != 0)
            {
                cg_storage_manager_data_free(*cgsm_data), *cgsm_data = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    if (result != 0 && conf != NULL)
    {
        cgutils_configuration_free(conf), conf = NULL;
    }

    return result;
}

int cg_storage_manager_data_add_provider(cg_storage_manager_data * const data,
                                         cg_storage_provider * const provider)
{
    int result = EINVAL;

    if (data != NULL && provider != NULL)
    {
        char const * const name = cg_storage_provider_get_name(provider);
        assert(name != NULL);

        result = cgutils_htable_insert(data->providers,
                                       name,
                                       provider);
    }

    return result;
}

int cg_storage_manager_data_add_instance(cg_storage_manager_data * const data,
                                         cg_storage_instance * const instance)
{
    int result = EINVAL;

    if (data != NULL && instance != NULL)
    {
        char const * const name = cg_storage_instance_get_name(instance);
        assert(name != NULL);

        result = cgutils_htable_insert(data->instances,
                                       name,
                                       instance);
    }

    return result;
}

int cg_storage_manager_data_add_filesystem(cg_storage_manager_data * const data,
                                           cg_storage_filesystem * const filesystem)
{
    int result = EINVAL;

    if (data != NULL && filesystem != NULL)
    {
        char const * const name = cg_storage_filesystem_get_name(filesystem);
        assert(name != NULL);

        result = cgutils_htable_insert(data->filesystems,
                                       name,
                                       filesystem);
    }

    return result;
}

static void cg_storage_manager_data_http_global_params_clean(cgutils_http_global_params * const params)
{
    assert(params != NULL);

    params->connections_cache_size = 0;
    params->max_connections_by_host = 0;
    params->max_concurrent_connections = 0;

    if (params->ca_bundle_file != NULL)
    {
        CGUTILS_FREE(params->ca_bundle_file);
    }

    if (params->ca_bundle_path != NULL)
    {
        CGUTILS_FREE(params->ca_bundle_path);
    }
}

static void cg_storage_manager_data_monitor_config_clean(cg_storage_manager_monitor_config * this)
{
    if (this != NULL)
    {
        if (this->file_id != NULL)
        {
            CGUTILS_FREE(this->file_id);
        }

        if (this->file_template_value != NULL)
        {
            CGUTILS_FREE(this->file_template_value);
        }

        if (this->file_template_path != NULL)
        {
            CGUTILS_FREE(this->file_template_path);
        }

        if (this->digest_algo != NULL)
        {
            CGUTILS_FREE(this->digest_algo);
        }

        this->delay = 0;
        this->file_size = 0;
    }
}

void cg_storage_manager_data_free(cg_storage_manager_data * data)
{
    if (data != NULL)
    {
        cg_storage_manager_data_monitor_config_clean(&(data->monitor_config));

        if (data->instances != NULL)
        {
            cgutils_htable_free(&data->instances, &cg_storage_instance_delete);
        }

        if (data->filesystems != NULL)
        {
            cgutils_htable_free(&data->filesystems, &cg_storage_filesystem_delete);
        }

        if (data->providers != NULL)
        {
            cgutils_htable_free(&data->providers, &cg_storage_provider_delete);
        }

        CRYPTO_set_locking_callback(NULL);
        CRYPTO_set_id_callback(NULL);

        if (data->http != NULL)
        {
            cgutils_http_data_free(data->http), data->http = NULL;
        }

        if (data->db != NULL)
        {
            cgdb_data_free(data->db), data->db = NULL;
        }

        if (data->aio != NULL)
        {
            cgutils_aio_free(data->aio), data->aio = NULL;
        }

        if (data->event_data != NULL)
        {
            cgutils_event_destroy(data->event_data), data->event_data = NULL;
        }

        if (data->conf != NULL)
        {
            cgutils_configuration_free(data->conf), data->conf = NULL;
        }

        if (data->monitor_data != NULL)
        {
            cg_monitor_data_free(data->monitor_data);
            data->monitor_data = NULL;
        }

        cg_storage_manager_data_http_global_params_clean(&(data->http_params));

#define STRING_PARAMETER(storage, path, required)       \
        if (data->storage != NULL)                      \
        {                                               \
            CGUTILS_FREE(data->storage);                \
        }
#define BOOLEAN_PARAMETER(storage, path, required)
#define SIZE_PARAMETER(storage, path, required)
#include "cg_storage_manager_config_parameters.itm"
#undef SIZE_PARAMETER
#undef BOOLEAN_PARAMETER
#undef STRING_PARAMETER

        CGUTILS_FREE(data);
    }
}

char const * cg_storage_manager_data_get_providers_path(cg_storage_manager_data const * const data)
{
    char const * result = NULL;

    if (data != NULL)
    {
        result = data->providers_path;
    }

    return result;
}

char const * cg_storage_manager_data_get_db_backends_path(cg_storage_manager_data const * const data)
{
    char const * result = NULL;

    if (data != NULL)
    {
        result = data->db_backends_path;
    }

    return result;
}

char const * cg_storage_manager_data_get_storage_filters_path(cg_storage_manager_data const * const data)
{
    char const * result = NULL;

    if (data != NULL)
    {
        result = data->storage_filters_path;
    }

    return result;
}

char const * cg_storage_manager_data_get_pid_file(cg_storage_manager_data const * const data)
{
    char const * result = NULL;

    if (data != NULL)
    {
        result = data->pid_file;
    }

    return result;
}

char const * cg_storage_manager_data_get_log_file(cg_storage_manager_data const * const data)
{
    char const * result = NULL;

    if (data != NULL)
    {
        result = data->log_file;
    }

    return result;
}

char const * cg_storage_manager_data_get_communication_socket(cg_storage_manager_data const * const data)
{
    char const * result = NULL;

    if (data != NULL)
    {
        result = data->communication_socket;
    }

    return result;
}

char const * cg_storage_manager_data_get_monitor_informations_path(cg_storage_manager_data const * const data)
{
    char const * result = NULL;

    if (data != NULL)
    {
        result = data->monitor_info_path;
    }

    return result;
}

cgutils_configuration * cg_storage_manager_data_get_configuration(cg_storage_manager_data const * const data)
{
    cgutils_configuration * result = NULL;

    if (data != NULL)
    {
        result = data->conf;
    }

    return result;
}

cgutils_event_data * cg_storage_manager_data_get_event(cg_storage_manager_data const * const data)
{
    cgutils_event_data * result = NULL;

    if (data != NULL)
    {
        result = data->event_data;
    }

    return result;
}

int cg_storage_manager_data_get_provider(cg_storage_manager_data * const data,
                                         char const * const provider_name,
                                         cg_storage_provider ** const provider)
{
    int result = EINVAL;

    if (data != NULL && provider_name != NULL && provider != NULL)
    {
        void * object = NULL;

        result = cgutils_htable_get(data->providers, provider_name, &object);

        if (result == 0)
        {
            assert(object != NULL);

            *provider = object;
        }
    }

    return result;
}

int cg_storage_manager_data_get_instance(cg_storage_manager_data * const data,
                                         char const * const instance_name,
                                         cg_storage_instance ** const instance)
{
    int result = EINVAL;

    if (data != NULL && instance_name != NULL && instance != NULL)
    {
        void * object = NULL;

        result = cgutils_htable_get(data->instances, instance_name, &object);

        if (result == 0)
        {
            assert(object != NULL);

            *instance = object;
        }
    }

    return result;
}

int cg_storage_manager_data_get_instance_by_id(cg_storage_manager_data * const this,
                                               uint64_t const instance_id,
                                               cg_storage_instance ** const instance)
{
    int result = EINVAL;

    if (this != NULL &&
        instance != NULL)
    {
        cgutils_htable_iterator * it = NULL;

        result = cgutils_htable_get_iterator(this->instances,
                                             &it);

        if (result == 0)
        {
            bool ok = true;

            result = ENOENT;

            while (ok == true &&
                   result == ENOENT)
            {
                cg_storage_instance * inst = cgutils_htable_iterator_get_value(it);
                uint64_t const id = cg_storage_instance_get_id(inst);

                if (id == instance_id)
                {
                    *instance = inst;
                    result = 0;
                }

                ok = cgutils_htable_iterator_next(it);
            }

            cgutils_htable_iterator_free(it), it = NULL;
        }
    }

    return result;
}

int cg_storage_manager_data_get_filesystem(cg_storage_manager_data * const data,
                                           char const * const filesystem_name,
                                           cg_storage_filesystem ** const filesystem)
{
    int result = EINVAL;

    if (data != NULL && filesystem_name != NULL && filesystem != NULL)
    {
        void * object = NULL;

        result = cgutils_htable_get(data->filesystems, filesystem_name, &object);

        if (result == 0)
        {
            assert(object != NULL);

            *filesystem = object;
        }
    }

    return result;
}

int cg_storage_manager_data_get_filesystem_by_id(cg_storage_manager_data * const this,
                                                 uint64_t const filesystem_id,
                                                 cg_storage_filesystem ** const filesystem)
{
    int result = EINVAL;

    if (this != NULL &&
        filesystem != NULL)
    {
        cgutils_htable_iterator * it = NULL;

        result = cgutils_htable_get_iterator(this->filesystems,
                                             &it);

        if (result == 0)
        {
            bool ok = true;

            result = ENOENT;

            while (ok == true &&
                   result == ENOENT)
            {
                cg_storage_filesystem * fs = cgutils_htable_iterator_get_value(it);
                uint64_t const id = cg_storage_filesystem_get_id(fs);

                if (id == filesystem_id)
                {
                    *filesystem = fs;
                    result = 0;
                }

                ok = cgutils_htable_iterator_next(it);
            }

            cgutils_htable_iterator_free(it), it = NULL;
        }
    }

    return result;
}

int cg_storage_manager_data_get_all_filesystems(cg_storage_manager_data * const data,
                                                cgutils_htable_iterator ** const filesystem)
{
    int result = EINVAL;

    if (data != NULL && filesystem != NULL)
    {
        result = cgutils_htable_get_iterator(data->filesystems,
                                             filesystem);
    }

    return result;
}

int cg_storage_manager_data_get_all_instances(cg_storage_manager_data * const data,
                                              cgutils_htable_iterator ** const instances)
{
    int result = EINVAL;

    if (data != NULL && instances != NULL)
    {
        result = cgutils_htable_get_iterator(data->instances,
                                             instances);
    }

    return result;
}

size_t cg_storage_manager_data_get_instances_count(cg_storage_manager_data const * const data)
{
    size_t result = 0;

    if (data != NULL && data->instances != NULL)
    {
        result = cgutils_htable_get_count(data->instances);
    }

    return result;
}

size_t cg_storage_manager_data_get_filesystems_count(cg_storage_manager_data const * const data)
{
    size_t result = 0;

    if (data != NULL && data->filesystems != NULL)
    {
        result = cgutils_htable_get_count(data->filesystems);
    }

    return result;
}

cgdb_data * cg_storage_manager_data_get_db(cg_storage_manager_data * const data)
{
    cgdb_data * result = NULL;

    if (data != NULL)
    {
        result = data->db;
    }

    return result;
}

cgutils_http_data * cg_storage_manager_data_get_http(cg_storage_manager_data const * const data)
{
    cgutils_http_data * result = NULL;

    if (data != NULL)
    {
        result = data->http;
    }

    return result;
}

cgutils_aio * cg_storage_manager_data_get_aio(cg_storage_manager_data const * const data)
{
    cgutils_aio * result = NULL;

    if (data != NULL)
    {
        result = data->aio;
    }

    return result;
}

void cg_storage_manager_data_set_provider_init_pending(cg_storage_manager_data * const this)
{
    if (this != NULL)
    {
        this->providers_initializing++;
    }
}

void cg_storage_manager_data_set_provider_init_finished(cg_storage_manager_data * const this,
                                                        int const result)
{
    if (this != NULL && this->providers_initializing > 0)
    {
        (void) result;

        this->providers_initializing--;

        if (this->providers_initializing == 0)
        {
            cgutils_event_exit_loop(this->event_data);
        }
    }
}

size_t cg_storage_manager_data_provider_init_remaining(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        result = this->providers_initializing;
    }

    return result;
}

bool cg_storage_manager_data_get_daemonize(cg_storage_manager_data const * const data)
{
    bool result = false;

    if (data != NULL)
    {
        result = data->daemonize;
    }

    return result;
}

bool cg_storage_manager_data_get_nofork(cg_storage_manager_data const * const data)
{
    bool result = false;

    if (data != NULL)
    {
        result = data->nofork;
    }

    return result;
}

int cg_storage_manager_data_configuration_finished(cg_storage_manager_data * const this)
{
    int result = EINVAL;

    if (this != NULL)
    {
        result = 0;

        if (this->conf != NULL)
        {
            cgutils_configuration_free(this->conf), this->conf = NULL;
        }
    }

    return result;
}

cg_monitor_data * cg_storage_manager_data_get_monitor_data(cg_storage_manager_data const * const this)
{
    cg_monitor_data * result = NULL;

    if (this != NULL)
    {
        result = this->monitor_data;
    }

    return result;
}

void cg_storage_manager_data_set_monitor_data(cg_storage_manager_data * const this,
                                              cg_monitor_data * const monitor_data)
{
    if (this != NULL)
    {
        this->monitor_data = monitor_data;
    }
}

char const * cg_storage_manager_data_get_resources_path(cg_storage_manager_data const * const data)
{
    char const * result = NULL;

    if (data != NULL)
    {
        result = data->resources_path;
    }

    return result;
}

char const * cg_storage_manager_data_get_stats_json_file(cg_storage_manager_data const * const data)
{
    char const * result = NULL;

    if (data != NULL)
    {
        result = data->stats_json_file;
    }

    return result;
}

void cg_storage_manager_data_set_mirroring_in_use(cg_storage_manager_data * const this)
{
    if (this != NULL && this->mirroring_in_use == false)
    {
        this->mirroring_in_use = true;
    }
}

void cg_storage_manager_data_set_striping_in_use(cg_storage_manager_data * const this)
{
    if (this != NULL && this->striping_in_use == false)
    {
        this->striping_in_use = true;
    }
}

void cg_storage_manager_data_set_encryption_in_use(cg_storage_manager_data * const this)
{
    if (this != NULL && this->encryption_in_use == false)
    {
        this->encryption_in_use = true;
    }
}

void cg_storage_manager_data_set_compression_in_use(cg_storage_manager_data * const this)
{
    if (this != NULL && this->compression_in_use == false)
    {
        this->compression_in_use = true;
    }
}

bool cg_storage_manager_data_is_mirroring_in_use(cg_storage_manager_data const * const this)
{
    bool result = false;

    if (this != NULL && this->mirroring_in_use == true)
    {
        result = true;
    }

    return result;
}

bool cg_storage_manager_data_is_striping_in_use(cg_storage_manager_data const * const this)
{
    bool result = false;

    if (this != NULL && this->striping_in_use == true)
    {
        result = true;
    }

    return result;
}

bool cg_storage_manager_data_is_encryption_in_use(cg_storage_manager_data const * const this)
{
    bool result = false;

    if (this != NULL && this->encryption_in_use == true)
    {
        result = true;
    }

    return result;
}

bool cg_storage_manager_data_is_compression_in_use(cg_storage_manager_data const * const this)
{
    bool result = false;

    if (this != NULL && this->compression_in_use == true)
    {
        result = true;
    }

    return result;
}

size_t cg_storage_manager_data_get_filesystems_with_mirroring_count(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        cgutils_htable_iterator * fs_it = NULL;

        int res = cgutils_htable_get_iterator(this->filesystems,
                                              &fs_it);

        if (res == 0)
        {
            bool ok = true;

            while (res == 0 && ok == true)
            {
                cg_storage_filesystem const * fs = cgutils_htable_iterator_get_value(fs_it);
                cg_storage_filesystem_type const type = cg_storage_filesystem_get_type(fs);

                if (type == cg_storage_filesystem_type_mirroring)
                {
                    result++;
                }

                ok = cgutils_htable_iterator_next(fs_it);
            }

            cgutils_htable_iterator_free(fs_it), fs_it = NULL;
        }
        else if (res != ENOENT)
        {
            CGUTILS_ERROR("Error getting filesystems: %d", res);
        }
    }

    return result;
}

size_t cg_storage_manager_data_get_filesystems_with_striping_count(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        cgutils_htable_iterator * fs_it = NULL;

        int res = cgutils_htable_get_iterator(this->filesystems,
                                              &fs_it);

        if (res == 0)
        {
            bool ok = true;

            while (res == 0 && ok == true)
            {
                cg_storage_filesystem const * fs = cgutils_htable_iterator_get_value(fs_it);
                cg_storage_filesystem_type const type = cg_storage_filesystem_get_type(fs);

                if (type == cg_storage_filesystem_type_striping)
                {
                    result++;
                }

                ok = cgutils_htable_iterator_next(fs_it);
            }

            cgutils_htable_iterator_free(fs_it), fs_it = NULL;
        }
        else if (res != ENOENT)
        {
            CGUTILS_ERROR("Error getting filesystems: %d", res);
        }
    }

    return result;
}

size_t cg_storage_manager_data_get_instances_with_encryption_count(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        cgutils_htable_iterator * it = NULL;

        int res = cgutils_htable_get_iterator(this->instances,
                                              &it);

        if (res == 0)
        {
            bool ok = true;

            while (res == 0 && ok == true)
            {
                cg_storage_instance const * const inst = cgutils_htable_iterator_get_value(it);

                if (cg_storage_instance_use_encryption(inst) == true)
                {
                    result++;
                }

                ok = cgutils_htable_iterator_next(it);
            }

            cgutils_htable_iterator_free(it), it = NULL;
        }
        else if (res != ENOENT)
        {
            CGUTILS_ERROR("Error getting instances: %d", res);
        }
    }

    return result;
}

size_t cg_storage_manager_data_get_instances_with_compression_count(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        cgutils_htable_iterator * it = NULL;

        int res = cgutils_htable_get_iterator(this->instances,
                                              &it);

        if (res == 0)
        {
            bool ok = true;

            while (res == 0 && ok == true)
            {
                cg_storage_instance const * const inst = cgutils_htable_iterator_get_value(it);

                if (cg_storage_instance_use_compression(inst) == true)
                {
                    result++;
                }

                ok = cgutils_htable_iterator_next(it);
            }

            cgutils_htable_iterator_free(it), it = NULL;
        }
        else if (res != ENOENT)
        {
            CGUTILS_ERROR("Error getting instances: %d", res);
        }
    }

    return result;
}

size_t cg_storage_manager_data_get_instances_amazon_count(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        cgutils_htable_iterator * inst_it = NULL;

        int res = cgutils_htable_get_iterator(this->instances,
                                              &inst_it);

        if (res == 0)
        {
            bool ok = true;

            while (res == 0 && ok == true)
            {
                cg_storage_instance const * inst = cgutils_htable_iterator_get_value(inst_it);
                char const * const provider_name = cg_storage_instance_get_provider_name(inst);

                if (provider_name != NULL &&
                    strcasecmp(provider_name, "Amazon") == 0)
                {
                    result++;
                }

                ok = cgutils_htable_iterator_next(inst_it);
            }

            cgutils_htable_iterator_free(inst_it), inst_it = NULL;
        }
        else if (res != ENOENT)
        {
            CGUTILS_ERROR("Error getting instances: %d", res);
        }
    }

    return result;
}

size_t cg_storage_manager_data_get_instances_openstack_count(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        cgutils_htable_iterator * inst_it = NULL;

        int res = cgutils_htable_get_iterator(this->instances,
                                              &inst_it);

        if (res == 0)
        {
            bool ok = true;

            while (res == 0 && ok == true)
            {
                cg_storage_instance const * inst = cgutils_htable_iterator_get_value(inst_it);
                char const * const provider_name = cg_storage_instance_get_provider_name(inst);

                if (provider_name != NULL &&
                    strcasecmp(provider_name, "Openstack") == 0)
                {
                    result++;
                }

                ok = cgutils_htable_iterator_next(inst_it);
            }

            cgutils_htable_iterator_free(inst_it), inst_it = NULL;
        }
        else if (res != ENOENT)
        {
            CGUTILS_ERROR("Error getting instances: %d", res);
        }
    }

    return result;
}

size_t cg_storage_manager_data_get_cleaner_delay(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        result = this->cleaner_delay;
    }

    return result;
}

size_t cg_storage_manager_data_get_cleaner_db_slots(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        result = this->cleaner_db_slots;
    }

    return result;
}

size_t cg_storage_manager_data_get_syncer_delay(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        result = this->syncer_delay;
    }

    return result;
}

size_t cg_storage_manager_data_get_syncer_dirtyness_delay(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        result = this->syncer_dirtyness_delay;
    }

    return result;
}

size_t cg_storage_manager_data_get_syncer_db_slots(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        result = this->syncer_db_slots;
    }

    return result;
}

size_t cg_storage_manager_data_get_syncer_max_db_objects_per_call(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        result = this->syncer_max_db_objects_per_call;
    }

    return result;
}

bool cg_storage_manager_data_get_syncer_dump_http_states(cg_storage_manager_data const * const this)
{
    bool result = false;

    if (this != NULL)
    {
        result = this->syncer_dump_http_states;
    }

    return result;
}

size_t cg_storage_manager_data_get_checker_delay(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        result = this->checker_delay;
    }

    return result;
}

bool cg_storage_manager_data_get_checker_checks_disabled(cg_storage_manager_data const * const this)
{
    bool result = true;

    if (this != NULL)
    {
        result = this->checker_checks_disabled;
    }

    return result;
}

size_t cg_storage_manager_data_get_max_requests_per_connection(cg_storage_manager_data const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        result = this->cgsm_max_requests_per_connection;
    }

    return result;
}

cgutils_http_global_params const * cg_storage_manager_data_get_http_global_params(cg_storage_manager_data const * const data)
{
    cgutils_http_global_params const * result = NULL;

    if (data != NULL)
    {
        result = &(data->http_params);
    }

    return result;
}

cg_storage_manager_monitor_config * cg_storage_manager_data_get_monitor_config(cg_storage_manager_data * const this)
{
    cg_storage_manager_monitor_config * result = NULL;

    if (this != NULL)
    {
        result = &(this->monitor_config);
    }

    return result;
}
