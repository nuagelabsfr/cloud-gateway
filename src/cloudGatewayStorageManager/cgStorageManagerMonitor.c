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
#include <inttypes.h>
#include <string.h>

#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>
#include <cgsm/cg_storage_instance.h>

#include <cgdb/cgdb.h>

#include <cloudutils/cloudutils_advanced_file_ops.h>
#include <cloudutils/cloudutils_crypto.h>
#include <cloudutils/cloudutils_encoding.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_htable.h>
#include <cloudutils/cloudutils_llist.h>
#include <cloudutils/cloudutils_time_counter.h>

#include <cgmonitor/cg_monitor_data.h>

#include "cgStorageManagerMonitor.h"
#include "cgStorageManagerCommon.h"

#define CG_STORAGE_MANAGER_MONITOR_DEFAULT_DELAY (20)
#define CG_STORAGE_MANAGER_MONITOR_DEFAULT_FILE_SIZE (1024*1024)
#define CG_STORAGE_MANAGER_MONITOR_DEFAULT_FILE_TEMPLATE_PATH "/tmp/"
#define CG_STORAGE_MANAGER_MONITOR_FILE_TEMPLATE_VALUE "cg_storage_manager_monitor_XXXXXX"
#define CG_STORAGE_MANAGER_MONITOR_DEFAULT_FILE_HASH_ALGO "md5"

typedef enum
{
    cg_storage_manager_monitor_state_init = 0,
    cg_storage_manager_monitor_state_put = 1,
    cg_storage_manager_monitor_state_get = 2,
    cg_storage_manager_monitor_state_delete = 3,
    cg_storage_manager_monitor_state_done = 4,
} cg_storage_manager_monitor_state;

typedef struct cg_storage_manager_monitor_data cg_storage_manager_monitor_data;

typedef struct
{
    cg_storage_manager_monitor_data * monitor_data;
    cg_storage_instance * instance;
    char * file_path;
    void * hash;
    cgutils_time_counter counter;
    uint64_t milli_put_delay;
    uint64_t milli_get_delay;
    size_t hash_size;
    int fd;
    cg_storage_manager_monitor_state state;
    bool get_valid;
    bool put_valid;
} cg_storage_manager_monitor_instance_data;

struct cg_storage_manager_monitor_data
{
    cg_storage_manager_data * data;
    cgutils_event * timer_event;
    cg_storage_manager_monitor_instance_data * instances_data;
    cg_monitor_data_instance_status_tab * status_tab;
    cg_monitor_data * monitor_data;
    cg_storage_manager_monitor_config * config;
    size_t instances_count;
    size_t remaining;
    cgutils_crypto_digest_algorithm digest;
    bool running;
    bool exiting;
};

static void cg_storage_manager_monitor_graceful_exit(int const sig,
                                                     void * const cb_data)
{
    cg_storage_manager_monitor_data * monitor_data = cb_data;

    assert(sig == CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG);
    assert(cb_data != NULL);

    (void) sig;

    if (monitor_data->exiting == false)
    {
        if (monitor_data->timer_event != NULL)
        {
            cgutils_event_disable(monitor_data->timer_event);
        }

        monitor_data->exiting = true;

        if (monitor_data->running == false)
        {
            cgutils_event_data * event_data = cg_storage_manager_data_get_event(monitor_data->data);
            assert(event_data != NULL);
            cgutils_event_exit_after_loop(event_data, NULL);
        }
    }
}

static void cg_storage_monitor_instance_clean(cg_storage_manager_monitor_instance_data * const this)
{
    if (this != NULL)
    {
        if (this->hash != NULL)
        {
            CGUTILS_FREE(this->hash);
        }

        if (this->fd >= 0)
        {
            cgutils_file_close(this->fd), this->fd = -1;
        }

        if (this->file_path != NULL)
        {
            if (cgutils_file_exists(this->file_path))
            {
                cgutils_file_unlink(this->file_path);
            }

            CGUTILS_FREE(this->file_path);
        }

        this->hash_size = 0;
    }
}

static void cg_storage_manager_monitor_data_free(cg_storage_manager_monitor_data * this)
{
    if (this != NULL)
    {
        if (this->timer_event != NULL)
        {
            cgutils_event_disable(this->timer_event);
            cgutils_event_free(this->timer_event), this->timer_event = NULL;
        }

        if (this->instances_data != NULL)
        {
            for (size_t idx = 0; idx < this->instances_count; idx++)
            {
                cg_storage_monitor_instance_clean(&(this->instances_data[idx]));
            }

            CGUTILS_FREE(this->instances_data);
        }

        if (this->status_tab != NULL)
        {
            CGUTILS_FREE(this->status_tab);
        }

        this->instances_count = 0;
        this->remaining = 0;
        this->running = false;
        this->data = NULL;

        CGUTILS_FREE(this);
    }
}

static void cg_storage_manager_monitor_shift_values(cg_monitor_data_instance_status_data * const status_data,
                                                    size_t const values_set)
{
    size_t const values_to_move = values_set == CG_MONITOR_DATA_COUNT ? CG_MONITOR_DATA_COUNT - 1 : values_set;

    if (values_to_move > 0)
    {
        void * from = status_data->get_values;
        void * to = &(status_data->get_values[1]);
        size_t size_to_move = sizeof *(status_data->get_values) * values_to_move;
        memmove(to, from, size_to_move);

        from = status_data->put_values;
        to = &(status_data->put_values[1]);
        size_to_move = sizeof *(status_data->put_values) * values_to_move;
        memmove(to, from, size_to_move);
    }
}

static void cg_storage_manager_monitor_compute_average(cg_monitor_data_instance_status_data * const status_data,
                                                       size_t const values_set)
{
    uint64_t get_average = 0;
    uint64_t put_average = 0;

    for (size_t idx = 0;
         idx < values_set;
         idx++)
    {
        get_average += status_data->get_values[idx].milliseconds / values_set;
        put_average += status_data->put_values[idx].milliseconds / values_set;
    }

    status_data->average_get_values = get_average;
    status_data->average_put_values = put_average;
}

static int cg_storage_manager_monitor_compute_results(cg_storage_manager_monitor_data * const data)
{
    int result = 0;

    assert(data != NULL);

    for (size_t idx = 0; idx < data->instances_count; idx++)
    {
        cg_storage_manager_monitor_instance_data const * const inst_data = &((data->instances_data)[idx]);
        cg_monitor_data_instance_status_data * const inst_status_data = &((data->status_tab->instances_data)[idx]);

        cg_storage_manager_monitor_shift_values(inst_status_data, data->status_tab->values_set);

        inst_status_data->get_values[0].success = inst_data->get_valid;
        inst_status_data->get_values[0].milliseconds = inst_data->milli_get_delay;
        inst_status_data->put_values[0].success = inst_data->put_valid;
        inst_status_data->put_values[0].milliseconds = inst_data->milli_put_delay;
        inst_status_data->last_success = inst_data->get_valid && inst_data->put_valid;
        inst_status_data->put_weight = inst_status_data->last_success ? 1 : 0;
        inst_status_data->get_weight = inst_status_data->last_success ? 1 : 0;

        if (data->status_tab->values_set < CG_MONITOR_DATA_COUNT)
        {
            data->status_tab->values_set++;
        }

        cg_storage_manager_monitor_compute_average(inst_status_data, data->status_tab->values_set);

#if 0
        CGUTILS_DEBUG("[%zu : %s] GET valid %d, last %zu, average %zu",
                      idx,
                      cg_storage_instance_get_name(inst_data->instance),
                      inst_status_data->get_values[0].success,
                      inst_status_data->get_values[0].milliseconds,
                      inst_status_data->average_get_values);

        CGUTILS_DEBUG("[%zu : %s] PUT valid %d, last %zu, average %zu",
                      idx,
                      cg_storage_instance_get_name(inst_data->instance),
                      inst_status_data->put_values[0].success,
                      inst_status_data->put_values[0].milliseconds,
                      inst_status_data->average_put_values);
#endif /* 0 */
    }

    return result;
}

static void cg_storage_manager_monitor_validate_received_file(cg_storage_manager_monitor_instance_data * const instance_data)
{
    int result = 0;
    size_t file_size = 0;

    assert(instance_data != NULL);

    result = cgutils_file_get_size(instance_data->fd, &file_size);

    if (result == 0)
    {
        if (file_size == instance_data->monitor_data->config->file_size)
        {
            void * hash = NULL;
            size_t hash_size = 0;

            result = cgutils_file_descriptor_hash_sync(instance_data->fd,
                                                       instance_data->monitor_data->digest,
                                                       &(hash),
                                                       &(hash_size));

            if (result == 0)
            {
                CGUTILS_ASSERT(hash != NULL);

                if (hash_size == instance_data->hash_size)
                {
                    result = memcmp(hash, instance_data->hash, hash_size);

                    if (result == 0)
                    {
                        instance_data->get_valid = true;
                    }
                    else
                    {
                        void * initial_hash_b64 = NULL;
                        void * received_hash_b64 = NULL;
                        size_t initial_hash_b64_size = 0;
                        size_t received_hash_b64_size = 0;

                        CGUTILS_INFO("Hash does not match for instance %s",
                                     cg_storage_instance_get_name(instance_data->instance));

                        int res = cgutils_encoding_base64_encode(instance_data->hash,
                                                                 instance_data->hash_size,
                                                                 &initial_hash_b64,
                                                                 &initial_hash_b64_size);

                        if (res == 0)
                        {
                            res = cgutils_encoding_base64_encode(hash,
                                                                 hash_size,
                                                                 &received_hash_b64,
                                                                 &received_hash_b64_size);

                            if (res == 0)
                            {
                                CGUTILS_TRACE("Expected %s, got %s", (char * ) initial_hash_b64, (char* ) received_hash_b64);
                                CGUTILS_FREE(received_hash_b64);
                            }
                            else
                            {
                                CGUTILS_TRACE("Error computing b64 for received hash: %d", res);
                            }

                            CGUTILS_FREE(initial_hash_b64);
                        }
                        else
                        {
                            CGUTILS_TRACE("Error computing b64 for initial hash: %d", res);
                        }
                    }
                }
                else
                {
                    CGUTILS_INFO("Hash size does not match for instance %s",
                                 cg_storage_instance_get_name(instance_data->instance));
                }

                CGUTILS_FREE(hash);
            }
            else
            {
                CGUTILS_ERROR("Error computing file hash for instance %s: %d",
                              cg_storage_instance_get_name(instance_data->instance),
                              result);
            }
        }
        else
        {
            CGUTILS_INFO("File size does not match (%zu / %zu) for instance %s",
                         file_size,
                         instance_data->monitor_data->config->file_size,
                         cg_storage_instance_get_name(instance_data->instance));
        }
    }
    else
    {
        CGUTILS_ERROR("Error getting file size for instance %s: %d",
                      cg_storage_instance_get_name(instance_data->instance),
                      result);
    }
}

static char const * cg_storage_manager_state_to_str(cg_storage_manager_monitor_state const state)
{
    static char const * const str[] =
        {
            "initiating",
            "putting",
            "getting",
            "deleting",
            "finishing",
        };
    static size_t const str_size = sizeof str / sizeof *str;

    char const * result = NULL;

    if (state < str_size)
    {
        result = str[state];
    }

    return result;
}

static int cg_storage_manager_monitor_test_handler(int status,
                                                   void * cb_data);

static int cg_storage_manager_monitor_test_put_handler(int const status,
                                                       cg_storage_instance_infos * const infos,
                                                       void * cb_data)
{
    if (infos != NULL &&
        infos->digest != NULL)
    {
        cg_storage_manager_monitor_instance_data * instance_data = cb_data;
        assert(cb_data != NULL);

        if (infos->digest_size == instance_data->hash_size)
        {
            int result = memcmp(infos->digest, instance_data->hash, infos->digest_size);

            if (result == 0)
            {
//                CGUTILS_DEBUG("Digest matches!");
            }
            else
            {
                CGUTILS_WARN("Error: the digest of the monitor test file on disk is not the same as the one of the data we sent on instance %s!",
                             cg_storage_instance_get_name(instance_data->instance));
            }
        }
        else
        {
            CGUTILS_WARN("Error: the digest size of the monitor test file on disk (%zu) is not the same as the one of the data we sent (%zu) on instance %s!",
                         instance_data->hash_size,
                         infos->digest_size,
                         cg_storage_instance_get_name(instance_data->instance));
        }

        CGUTILS_FREE(infos->digest);
    }

    return cg_storage_manager_monitor_test_handler(status,
                                                   cb_data);
}

static int cg_storage_manager_monitor_test_get_handler(int const status,
                                                       cg_storage_instance_infos * const infos,
                                                       void * cb_data)
{
    if (infos != NULL &&
        infos->digest != NULL)
    {
        cg_storage_manager_monitor_instance_data * instance_data = cb_data;
        assert(cb_data != NULL);

        if (infos->digest_size == instance_data->hash_size)
        {
            int result = memcmp(infos->digest, instance_data->hash, infos->digest_size);

            if (result == 0)
            {
//                CGUTILS_DEBUG("Digest matches!");
            }
            else
            {
                CGUTILS_WARN("Error: the digest of the monitor test file on disk is not the same as the one of the data we received on instance %s!",
                             cg_storage_instance_get_name(instance_data->instance));
            }
        }
        else
        {
            CGUTILS_WARN("Error: the digest size of the monitor test file on disk (%zu) is not the same as the one of the data we received (%zu) on instance %s!",
                         instance_data->hash_size,
                         infos->digest_size,
                         cg_storage_instance_get_name(instance_data->instance));
        }

        CGUTILS_FREE(infos->digest);
    }

    return cg_storage_manager_monitor_test_handler(status,
                                                   cb_data);
}

static int cg_storage_manager_monitor_test_handler(int const status,
                                                   void * const cb_data)
{
    int result = status;
    cg_storage_manager_monitor_instance_data * instance_data = cb_data;
    assert(cb_data != NULL);

    if (status == 0)
    {
        switch(instance_data->state)
        {
        case cg_storage_manager_monitor_state_init:
            instance_data->state = cg_storage_manager_monitor_state_put;

            cgutils_time_counter_init(&(instance_data->counter));
            cgutils_time_counter_start(&(instance_data->counter));

            result = cg_storage_instance_put_file(instance_data->instance,
                                                  instance_data->monitor_data->config->file_id,
                                                  instance_data->fd,
                                                  instance_data->monitor_data->config->file_size,
                                                  NULL,
                                                  instance_data->monitor_data->digest,
                                                  &cg_storage_manager_monitor_test_put_handler,
                                                  instance_data);

            if (result != 0)
            {
                if (result == EACCES)
                {
                    CGUTILS_INFO("Instance %s has an authentication issue: (%d) %s",
                                 cg_storage_instance_get_name(instance_data->instance),
                                 result,
                                 strerror(result));
                }
                else
                {
                    CGUTILS_ERROR("Error putting test file for instance %s: %d",
                                  cg_storage_instance_get_name(instance_data->instance),
                                  result);
                }
            }
            break;

        case cg_storage_manager_monitor_state_put:

            instance_data->state = cg_storage_manager_monitor_state_get;

            cgutils_time_counter_stop(&(instance_data->counter));
            cgutils_time_counter_to_milliseconds(&(instance_data->counter),
                                                 &(instance_data->milli_put_delay));

            instance_data->put_valid = true;

            cgutils_time_counter_init(&(instance_data->counter));
            cgutils_time_counter_start(&(instance_data->counter));

            result = cgutils_file_ftruncate(instance_data->fd,
                                            0);

            if (result == 0)
            {
                result = cg_storage_instance_get_file(instance_data->instance,
                                                      instance_data->monitor_data->config->file_id,
                                                      instance_data->fd,
                                                      instance_data->monitor_data->digest,
                                                      &cg_storage_manager_monitor_test_get_handler,
                                                      instance_data);

                if (result != 0)
                {
                    if (result == EACCES)
                    {
                        CGUTILS_INFO("Instance %s has an authentication issue: (%d) %s",
                                     cg_storage_instance_get_name(instance_data->instance),
                                     result,
                                     strerror(result));
                    }
                    else
                    {
                        CGUTILS_ERROR("Error getting test file for instance %s: %d",
                                      cg_storage_instance_get_name(instance_data->instance),
                                      result);
                    }
                }
            }
            else
            {
                CGUTILS_ERROR("Error truncating test file for instance %s: %d",
                              cg_storage_instance_get_name(instance_data->instance),
                              result);
            }
            break;

        case cg_storage_manager_monitor_state_get:
            instance_data->state = cg_storage_manager_monitor_state_delete;

            cgutils_time_counter_stop(&(instance_data->counter));
            cgutils_time_counter_to_milliseconds(&(instance_data->counter),
                                                 &(instance_data->milli_get_delay));

            cg_storage_manager_monitor_validate_received_file(instance_data);

            result = cg_storage_instance_delete_file(instance_data->instance,
                                                     instance_data->monitor_data->config->file_id,
                                                     &cg_storage_manager_monitor_test_handler,
                                                     instance_data);
            if (result != 0)
            {
                CGUTILS_INFO("Error deleting test file for instance %s: %d",
                             cg_storage_instance_get_name(instance_data->instance),
                             result);
            }
            break;

        case cg_storage_manager_monitor_state_delete:
            instance_data->state = cg_storage_manager_monitor_state_done;
            cg_storage_monitor_instance_clean(instance_data);
            instance_data->monitor_data->remaining--;
            break;

        case cg_storage_manager_monitor_state_done:
            CGUTILS_ERROR("cg_storage_manager_monitor_state_done !?");
            break;
        }
    }

    if (result != 0)
    {
        CGUTILS_WARN("Error while %s test file on instance %s: %d",
                     cg_storage_manager_state_to_str(instance_data->state),
                     cg_storage_instance_get_name(instance_data->instance),
                     result);

        if (instance_data->hash != NULL)
        {
            char * hash_hex = NULL;
            size_t hash_hex_size = 0;

            int res = cgutils_encoding_hex_sprint(instance_data->hash,
                                                  instance_data->hash_size,
                                                  &hash_hex,
                                                  &hash_hex_size);

            if (res == 0)
            {
                CGUTILS_WARN("Test file hash was %s",
                             hash_hex);
                CGUTILS_FREE(hash_hex), hash_hex = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error converting hash to hex value: %d", res);
            }
        }

        instance_data->monitor_data->remaining--;
        cg_storage_monitor_instance_clean(instance_data);
    }

    if (instance_data->monitor_data->remaining == 0)
    {
        result = cg_storage_manager_monitor_compute_results(instance_data->monitor_data);

        if (result == 0)
        {
            result = cg_monitor_data_update(instance_data->monitor_data->monitor_data,
                                            instance_data->monitor_data->status_tab);

            if (result == 0)
            {
            }
            else
            {
                CGUTILS_ERROR("Error updating shared memory data: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error while computing results for insance %s: %d",
                          cg_storage_instance_get_name(instance_data->instance),
                          result);
        }

        instance_data->monitor_data->running = false;

        if (instance_data->monitor_data->exiting == false)
        {
            struct timeval tv = {
                .tv_sec = (long int) instance_data->monitor_data->config->delay,
                .tv_usec = 0
            };

            result = cgutils_event_enable(instance_data->monitor_data->timer_event, &tv);

            if (result != 0)
            {
                CGUTILS_ERROR("Error enabling timer event: %d", result);
            }
        }
        else
        {
            cgutils_event_data * event_data = cg_storage_manager_data_get_event(instance_data->monitor_data->data);
            assert(event_data != NULL);
            cgutils_event_exit_after_loop(event_data, NULL);
        }
    }

    return result;
}

static int cg_storage_manager_monitor_create_test_file(cg_storage_manager_monitor_instance_data * const instance_data)
{
    int result = 0;
    assert(instance_data != NULL);
    assert(instance_data->fd == -1);

    instance_data->file_path = cgutils_strdup(instance_data->monitor_data->config->file_template_value);

    if (instance_data->file_path != NULL)
    {
        result = cgutils_file_mkstemp(instance_data->file_path, &(instance_data->fd));

        if (result == 0)
        {
            result = cgutils_file_fill_with_urandom_data(instance_data->fd,
                                                         instance_data->monitor_data->config->file_size);

            if (result == 0)
            {
                result = cgutils_file_descriptor_hash_sync(instance_data->fd,
                                                           instance_data->monitor_data->digest,
                                                           &(instance_data->hash),
                                                           &(instance_data->hash_size));
                if (result == 0)
                {
                }
                else
                {
                    CGUTILS_ERROR("Error computing the test file's hash for instance %s: %d",
                                  cg_storage_instance_get_name(instance_data->instance),
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error filling test file for instance %s: %d",
                              cg_storage_instance_get_name(instance_data->instance),
                              result);
            }

            if (result != 0)
            {
                cgutils_file_close(instance_data->fd), instance_data->fd = -1;
                cgutils_file_unlink(instance_data->file_path);
            }
        }
        else
        {
            CGUTILS_ERROR("Error getting file descriptor from template for instance %s: %d",
                          cg_storage_instance_get_name(instance_data->instance),
                          result);
        }

        if (result != 0)
        {
            CGUTILS_FREE(instance_data->file_path);
        }
    }
    else
    {
        result = ENOMEM;
        CGUTILS_ERROR("Error allocating memory for test file path: %d", result);
    }

    return result;
}

static void cg_storage_manager_monitor_do(void * cb_data)
{
    cg_storage_manager_monitor_data * data = cb_data;
    assert(cb_data != NULL);

    if (data->running == false)
    {
        int result = 0;

        data->running = true;
        data->remaining = 0;

        for (size_t idx = 0; result == 0 && idx < data->instances_count; idx++)
        {
            cg_storage_manager_monitor_instance_data * const instance_data = &(data->instances_data[idx]);

            result = cg_storage_manager_monitor_create_test_file(instance_data);

            if (result == 0)
            {
                instance_data->state = cg_storage_manager_monitor_state_init;
                data->remaining++;

                result = cg_storage_manager_monitor_test_handler(0, instance_data);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error launching test for instance %s: %d",
                                  cg_storage_instance_get_name(instance_data->instance),
                                  result);
                }

            }
            else
            {
                data->remaining--;
                CGUTILS_ERROR("Error creating the test file for instance %s: %d",
                              cg_storage_instance_get_name(instance_data->instance),
                              result);
            }
        }
    }
}

static int cg_storage_manager_monitor_data_init(cg_storage_manager_data * const data,
                                                cg_storage_manager_monitor_config * config,
                                                cgutils_htable_iterator * instance_elt,
                                                cg_storage_manager_monitor_data ** const monitor_data)
{
    int result = 0;

    assert(data != NULL);
    assert(config != NULL);
    assert(instance_elt != NULL);
    assert(monitor_data != NULL);

    size_t const instances_count = cg_storage_manager_data_get_instances_count(data);

    CGUTILS_ALLOCATE_STRUCT(*monitor_data);

    if (*monitor_data != NULL)
    {
        cg_storage_manager_monitor_data * this = *monitor_data;
        *this = (cg_storage_manager_monitor_data) { 0 };

        this->data = data;
        this->instances_count = instances_count;
        this->config = config;
        config = NULL;

        CGUTILS_MALLOC(this->status_tab, 1, sizeof *(this->status_tab) +
                       (sizeof *(this->status_tab->instances_data) * instances_count));

        if (this->status_tab != NULL)
        {
            *(this->status_tab) = (cg_monitor_data_instance_status_tab) { 0 };
            this->status_tab->instances_count = instances_count;

            this->monitor_data = cg_storage_manager_data_get_monitor_data(data);

            if (result == 0)
            {
                result = cg_monitor_data_retrieve(this->monitor_data,
                                                  this->status_tab);

                if (result == 0)
                {
                    CGUTILS_MALLOC(this->instances_data, instances_count, sizeof *(this->instances_data));

                    if (this->instances_data != NULL)
                    {
                        bool remain = true;

                        do
                        {
                            cg_storage_instance * const instance = cgutils_htable_iterator_get_value(instance_elt);
                            assert(instance != NULL);
                            size_t const idx = cg_storage_instance_get_index(instance);

                            cg_storage_manager_monitor_instance_data * const inst_data = &(this->instances_data[idx]);
                            *inst_data = (cg_storage_manager_monitor_instance_data) { 0 };

                            inst_data->monitor_data = this;
                            inst_data->instance = instance;
                            inst_data->fd = -1;

                            remain = cgutils_htable_iterator_next(instance_elt);
                        }
                        while(remain == true);

                        this->digest = cgutils_crypto_digest_algorithm_from_str(this->config->digest_algo);
                    }
                    else
                    {
                        result = ENOMEM;
                    }

                }
                else
                {
                    CGUTILS_ERROR("Error retrieving monitor data: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting monitor data: %d", result);
            }
        }
        else
        {
            result = ENOMEM;
        }

        if (result != 0)
        {
            cg_storage_manager_monitor_data_free(*monitor_data), *monitor_data = NULL;
        }
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static int cg_storage_manager_monitor_normalize_conf(cg_storage_manager_monitor_config * const config)
{
    int result = 0;

    assert(config != NULL);

    if (config->delay == 0)
    {
        config->delay = CG_STORAGE_MANAGER_MONITOR_DEFAULT_DELAY;
    }

    if (config->file_size == 0)
    {
        config->file_size = CG_STORAGE_MANAGER_MONITOR_DEFAULT_FILE_SIZE;
    }

    if (config->digest_algo == NULL)
    {
        config->digest_algo = cgutils_strdup(CG_STORAGE_MANAGER_MONITOR_DEFAULT_FILE_HASH_ALGO);

        if (config->digest_algo == NULL)
        {
            result = ENOMEM;
                    CGUTILS_ERROR("Error allocating memory for digest algo: %d", result);
        }
    }

    if (result == 0)
    {
        cgutils_crypto_digest_algorithm algo = cgutils_crypto_digest_algorithm_from_str(config->digest_algo);

        if (algo == cgutils_crypto_digest_algorithm_none ||
            algo == cgutils_crypto_digest_algorithm_max)
        {
            result = ENOENT;
            CGUTILS_ERROR("Error loading invalid digest algorithm (%s): %d", config->digest_algo, result);
        }
    }

    if (result == 0 && config->file_template_value == NULL)
    {
        result = cgutils_asprintf(&(config->file_template_value),
                                  "%s/" CG_STORAGE_MANAGER_MONITOR_FILE_TEMPLATE_VALUE,
                                  config->file_template_path != NULL ?
                                  config->file_template_path :
                                  CG_STORAGE_MANAGER_MONITOR_DEFAULT_FILE_TEMPLATE_PATH);

        if (result != 0)
        {
            CGUTILS_ERROR("Error allocating memory for file template_value: %d", result);
        }
    }

    return result;
}

int cg_storage_manager_monitor_run(cg_storage_manager_data * const data,
                                   bool const graceful)
{
    assert(data != NULL);
    cg_storage_manager_monitor_config * config = cg_storage_manager_data_get_monitor_config(data);
    assert(config != NULL);

    int result = cg_storage_manager_monitor_normalize_conf(config);

    (void) graceful;

    if (result == 0)
    {
        cgutils_htable_iterator * instance_elt = NULL;

        result = cg_storage_manager_data_get_all_instances(data, &instance_elt);

        if (result == 0)
        {
            cg_storage_manager_monitor_data * monitor_data = NULL;

            result = cg_storage_manager_monitor_data_init(data,
                                                          config,
                                                          instance_elt,
                                                          &monitor_data);

            if (result == 0)
            {
                cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
                assert(event_data != NULL);

                config = NULL;

                result = cgutils_event_create_timer_event(event_data,
                                                          0,
                                                          &cg_storage_manager_monitor_do,
                                                          monitor_data,
                                                          &(monitor_data->timer_event));

                if (result == 0)
                {
                    result = cg_storage_manager_common_register_signal(data,
                                                                       CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG,
                                                                       &cg_storage_manager_monitor_graceful_exit,
                                                                       monitor_data);

                    if (result == 0)
                    {
                        struct timeval tv = { .tv_sec = (long int) monitor_data->config->delay, .tv_usec = 0 };

                        result = cgutils_event_enable(monitor_data->timer_event, &tv);

                        if (result == 0)
                        {
                            cg_storage_manager_loop(data);
                            cgutils_event_disable(monitor_data->timer_event);
                        }
                        else
                        {
                            CGUTILS_ERROR("Error enabling timer event: %d", result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error registering signal event: %d", result);
                    }

                    cgutils_event_free(monitor_data->timer_event), monitor_data->timer_event = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error creating timer event: %d", result);
                }

                cg_storage_manager_monitor_data_free(monitor_data), monitor_data = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error in cg_storage_manager_monitor_data_init: %d", result);
            }

            cgutils_htable_iterator_free(instance_elt), instance_elt = NULL;
        }
        else if (result == ENOENT)
        {
            /* No instance, unusual but hey, nothing to do. */
            result = 0;
        }
        else
        {
            CGUTILS_ERROR("Error getting instances: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error parsing config: %d", result);
    }

    return result;
}
