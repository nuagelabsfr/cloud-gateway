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

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_json_writer.h>
#include <cloudutils/cloudutils_system.h>

#include "common.h"
#include "tools_provider_stats_common.h"

#define CG_STATS_FILE_DEFAULT "/tmp/cgStatsFile.json"
#define CG_STATS_LOG_FILE_DEFAULT "/tmp/CloudGatewayStats.err"

#define CG_STATS_KEEP_DEFAULT (60)
#define CG_STATS_DELAY_DEFAULT (1)

#define CG_STATS_NUMBER_OF_VALUES ((CG_STATS_KEEP_DEFAULT) / (CG_STATS_DELAY_DEFAULT))

typedef struct
{
    cg_monitor_data_instance_status_tab * storages_status_tab;
    char ** names;
    size_t names_count;
} cg_stats_storage_instant;

typedef struct
{
    cgutils_system_cpu_stats cpu;
    cgutils_system_memory_stats memory;
    cg_stats_storage_instant storages;
    /* vector of cgutils_system_network_itf_stats * */
    cgutils_vector * itfs;
    time_t time;
} cg_stats_instant;

typedef struct
{
    cg_stats_instant values[CG_STATS_NUMBER_OF_VALUES];

    cgutils_event_data * event_data;
    cgutils_event * timer_event;
    cgutils_event * sigusr_event;
    cgutils_event * sigint_event;
    cgutils_event * sigterm_event;

    char * conf_file;
    char const * json_file;
    size_t json_file_len;

    size_t first_value;
    size_t last_value;
    size_t nb_values;

    bool running;
    bool exiting;
} cg_stats_data;

static int cg_stats_register_signal(cg_stats_data * const stats_data,
                                    int const sig,
                                    cgutils_event ** const event,
                                    cgutils_event_signal_cb * const signal_cb,
                                    void * const cb_data)
{
    int result = 0;
    CGUTILS_ASSERT(event != NULL);
    CGUTILS_ASSERT(stats_data != NULL);
    cgutils_event_data * event_data = stats_data->event_data;
    CGUTILS_ASSERT(event_data != NULL);

    result = cgutils_event_create_signal_event(event_data,
                                               sig,
                                               signal_cb,
                                               cb_data,
                                               event);

    if (result == 0)
    {
        CGUTILS_ASSERT(*event != NULL);

        result = cgutils_event_enable(*event, NULL);

        if (result == 0)
        {
        }
        else
        {
            CGUTILS_ERROR("Error enabling signal %d handler: %d", sig, result);
        }

        if (result != 0)
        {
            cgutils_event_free(*event), *event = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Error creating signal %d handler: %d", sig, result);
    }

    return result;
}

static void cg_stats_clean_instant(cg_stats_instant * instant)
{
    if (instant != NULL)
    {
        if (instant->itfs != NULL)
        {
            cgutils_vector_deep_free(&(instant->itfs), &free);
        }

        if (instant->storages.names != NULL)
        {
            for (size_t idx = 0;
                 idx < instant->storages.names_count;
                 idx++)
            {
                CGUTILS_FREE(instant->storages.names[idx]);
            }

            CGUTILS_FREE(instant->storages.names);
        }

        CGUTILS_FREE(instant->storages.storages_status_tab);

        instant->time = 0;
    }
}

static void cg_stats_data_free(cg_stats_data * data)
{
    if (data != NULL)
    {
        if (data->timer_event != NULL)
        {
            cgutils_event_free(data->timer_event), data->timer_event = NULL;
        }

        if (data->sigusr_event != NULL)
        {
            cgutils_event_free(data->sigusr_event), data->sigusr_event = NULL;
        }

        if (data->sigint_event != NULL)
        {
            cgutils_event_free(data->sigint_event), data->sigint_event = NULL;
        }

        if (data->sigterm_event != NULL)
        {
            cgutils_event_free(data->sigterm_event), data->sigterm_event = NULL;
        }

        for (size_t idx = 0;
             idx < data->nb_values;
             idx++)
        {
            cg_stats_instant * instant = &(data->values[idx]);

            cg_stats_clean_instant(instant);
        }

        CGUTILS_FREE(data->conf_file);
        CGUTILS_FREE(data);
    }
}

static void cg_stats_graceful_exit(int const sig,
                                   void * const cb_data)
{
    cg_stats_data * stats_data = cb_data;

    CGUTILS_ASSERT(sig == SIGUSR1 ||
           sig == SIGTERM ||
           sig == SIGINT);
    CGUTILS_ASSERT(cb_data != NULL);

    (void) sig;

    if (stats_data->exiting == false)
    {
        if (stats_data->timer_event != NULL)
        {
            cgutils_event_disable(stats_data->timer_event);
        }

        stats_data->exiting = true;

        if (stats_data->running == false)
        {
            cgutils_event_data * event_data = stats_data->event_data;
            CGUTILS_ASSERT(event_data != NULL);
            cgutils_event_exit_after_loop(event_data, NULL);
        }
    }
}

static int cg_stats_get_storages_stats(cg_stats_data const * const stats_data,
                                       cg_stats_storage_instant * const storage_instant)
{
    int result = 0;
    CGUTILS_ASSERT(stats_data != NULL);
    CGUTILS_ASSERT(stats_data->conf_file != NULL);
    CGUTILS_ASSERT(storage_instant != NULL);

    cgutils_configuration * conf = NULL;
    /* We parse this configuration file every time,
       as it may have been modified between two runs. */

    result = cgutils_configuration_from_xml_file(stats_data->conf_file,
                                                 &conf);

    if (result == 0)
    {
        char * monitor_info_path = NULL;

        result = tools_provider_stats_compute_monitor_info_path(conf,
                                                                &monitor_info_path);

        if (result == 0)
        {
            storage_instant->names = NULL;
            storage_instant->names_count = 0;

            /* Idem for storages mapping, instances may have been added / removed */
            result = tools_provider_stats_compute_instances_mapping(conf,
                                                                    &(storage_instant->names),
                                                                    &(storage_instant->names_count));

            if (result == 0)
            {
                storage_instant->storages_status_tab = NULL;

                result = cg_monitor_data_peek(monitor_info_path,
                                              &(storage_instant->storages_status_tab));

                if (result != 0)
                {
                    CGUTILS_ERROR("Error getting status informations: %d",
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error computing instances mapping: %d",
                              result);
            }

            CGUTILS_FREE(monitor_info_path);
        }
        else if (result != ENOENT)
        {
            CGUTILS_ERROR("Error getting monitor informations path: %d",
                          result);
        }

        cgutils_configuration_free(conf), conf = NULL;
    }
    else
    {
        CGUTILS_ERROR("Error loading configuration from file %s: %d",
                      stats_data->conf_file,
                      result);
    }

    return result;
}

static int cg_stats_populate_instant(cg_stats_data const * const stats_data,
                                     cg_stats_instant * const instant)
{
    int result = 0;
    CGUTILS_ASSERT(stats_data != NULL);
    CGUTILS_ASSERT(instant != NULL);

    cg_stats_clean_instant(instant);

    int res = cgutils_system_get_memory_stats(&(instant->memory));

    if (res != 0)
    {
        result = res;
        CGUTILS_ERROR("Error getting memory stats: %d", res);
    }

    res = cgutils_system_get_cpu_stats(&(instant->cpu));

    if (res != 0)
    {
        if (result == 0)
        {
            result = res;
        }

        CGUTILS_ERROR("Error getting CPU stats: %d", res);
    }

    res = cgutils_system_network_get_interfaces_stats(&(instant->itfs));

    if (res != 0)
    {
        if (result == 0)
        {
            result = res;
        }

        CGUTILS_ERROR("Error getting network stats: %d", res);
    }

    res = cg_stats_get_storages_stats(stats_data,
                                      &(instant->storages));

    if (res != 0 &&
        res != ENOENT)
    {
        if (result == 0)
        {
            result = res;
        }

        CGUTILS_ERROR("Error getting storages stats: %d", res);
    }

    instant->time = time(NULL);

    return result;
}

static int cg_stats_get_itf_by_idx(cgutils_vector * const previous_itfs,
                                   size_t const itf_index,
                                   cgutils_system_network_itf_stats const ** const out)
{
    int result = ENOENT;
    CGUTILS_ASSERT(previous_itfs != NULL);
    CGUTILS_ASSERT(out != NULL);
    size_t const previous_itfs_count = cgutils_vector_count(previous_itfs);

    for (size_t idx = 0;
         result == ENOENT &&
             *out == NULL &&
             idx < previous_itfs_count;
         idx++)
    {
        cgutils_system_network_itf_stats const * itf = NULL;

        int res = cgutils_vector_get(previous_itfs,
                                     idx,
                                     (void **) &itf);

        if (res == 0)
        {
            if (itf->index == itf_index)
            {
                *out = itf;
                result = 0;
            }
        }
        else
        {
            result = res;
            CGUTILS_ERROR("Error getting itf %zu: %d",
                          idx,
                          result);
        }
    }

    return result;
}

#define DIFF_WRAP(prev_value, cur_value)     \
    ((prev_value <= cur_value) ? (cur_value - prev_value) : (cur_value))

static int cg_stats_compute_network(cg_stats_instant const * const current,
                                    cg_stats_instant const * const previous,
                                    cgutils_json_writer_element * const elt)
{
    int result = 0;
    cgutils_json_writer_element * network_elt = NULL;

    CGUTILS_ASSERT(current != NULL);
    CGUTILS_ASSERT(previous != NULL);
    CGUTILS_ASSERT(elt != NULL);

    result = cgutils_json_writer_element_add_child(elt,
                                                   "network",
                                                   &network_elt);

    if (result == 0)
    {
        cgutils_json_writer_element * itfs_elt = NULL;

        result = cgutils_json_writer_element_add_list_child(network_elt,
                                                            "interfaces",
                                                            &itfs_elt);

        if (result == 0)
        {
            size_t const itfs_count = cgutils_vector_count(current->itfs);

            for (size_t idx = 0;
                 result == 0 &&
                     idx < itfs_count;
                 idx++)
            {
                cgutils_system_network_itf_stats const * itf = NULL;

                result = cgutils_vector_get(current->itfs,
                                            idx,
                                            (void **) &itf);

                if (result == 0)
                {
                    /* Did we have this interface previously? */
                    cgutils_system_network_itf_stats const * previous_itf = NULL;

                    result = cg_stats_get_itf_by_idx(previous->itfs,
                                                     itf->index,
                                                     &previous_itf);

                    if (result == 0)
                    {
                        /* Diff the counter with these of the previous interface stats.
                           Maybe we should verify that the name is the same.
                        */
                        cgutils_json_writer_element * itf_elt = NULL;

                        CGUTILS_ASSERT(previous_itf != NULL);

                        result = cgutils_json_writer_new_element(&itf_elt);

                        if (result == 0)
                        {
                            result = cgutils_json_writer_element_add_string_prop(itf_elt,
                                                                                 "name",
                                                                                 itf->name);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error adding name to the interface elt: %d", result);
                            }


#define ADD_PROP(property)                                              \
                            cgutils_json_writer_element_add_uint64_prop(itf_elt, \
                                                                        #property, \
                                                                        DIFF_WRAP(previous_itf->property, itf->property));

        ADD_PROP(rx_packets)
        ADD_PROP(tx_packets)
        ADD_PROP(rx_bytes)
        ADD_PROP(tx_bytes)
        ADD_PROP(rx_errors)
        ADD_PROP(tx_errors)
#undef ADD_PROP

                            if (result == 0)
                            {
                                result = cgutils_json_writer_add_element_to_list(itfs_elt,
                                                                         itf_elt);

                                if (result == 0)
                                {
                                    cgutils_json_writer_element_release(itf_elt), itf_elt = NULL;
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error adding interface element to list: %d", result);
                                }
                            }

                            if (result != 0)
                            {
                                    cgutils_json_writer_element_free(itf_elt), itf_elt = NULL;
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error creating the interface element: %d", result);
                        }
                    }
                    else if (result == ENOENT)
                    {
                        /* No previous values for this interface, skipping */
                        result = 0;
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error getting itf %zu from vector: %d",
                                  idx,
                                  result);
                }
            }

            cgutils_json_writer_element_release(itfs_elt);
        }
        else
        {
            CGUTILS_ERROR("Adding interfaces elt: %d", result);
        }

        cgutils_json_writer_element_release(network_elt);
    }
    else
    {
        CGUTILS_ERROR("Error adding CPU element: %d", result);
    }

    return result;
}

static int cg_stats_compute_cpu(cg_stats_instant const * const current,
                                cg_stats_instant const * const previous,
                                cgutils_json_writer_element * const elt)
{
    int result = 0;
    cgutils_json_writer_element * cpu_elt = NULL;

    CGUTILS_ASSERT(current != NULL);
    CGUTILS_ASSERT(previous != NULL);
    CGUTILS_ASSERT(elt != NULL);

    result = cgutils_json_writer_element_add_child(elt,
                                                   "cpu",
                                                   &cpu_elt);

    if (result == 0)
    {
#define ADD_PROP(property)                                          \
        cgutils_json_writer_element_add_uint64_prop(cpu_elt,            \
                                                    #property,          \
                                                    DIFF_WRAP(previous->cpu.property, current->cpu.property));

        ADD_PROP(user)
        ADD_PROP(nice)
        ADD_PROP(system)
        ADD_PROP(idle)
        ADD_PROP(iowait)
        ADD_PROP(irq)
        ADD_PROP(softirq)
        ADD_PROP(steal)
#undef ADD_PROP

        cgutils_json_writer_element_release(cpu_elt);
    }
    else
    {
        CGUTILS_ERROR("Error adding CPU element: %d", result);
    }

    return result;
}

static int cg_stats_compute_memory(cg_stats_instant const * const current,
                                   cgutils_json_writer_element * const elt)
{
    int result = 0;
    cgutils_json_writer_element * memory_elt = NULL;

    CGUTILS_ASSERT(current != NULL);
    CGUTILS_ASSERT(elt != NULL);

    result = cgutils_json_writer_element_add_child(elt,
                                                   "memory",
                                                   &memory_elt);

    if (result == 0)
    {
#define ADD_PROP(property)                                              \
        cgutils_json_writer_element_add_uint64_prop(memory_elt,         \
                                                    #property,          \
                                                    current->memory.property); \

        ADD_PROP(total);
        ADD_PROP(free);
        ADD_PROP(buffers);
        ADD_PROP(swap_total);
        ADD_PROP(swap_free);
#undef ADD_PROP

        cgutils_json_writer_element_release(memory_elt);
    }
    else
    {
        CGUTILS_ERROR("Error adding MEMORY element: %d", result);
    }

    return result;
}

static int cg_stats_compute_storages(cg_stats_instant const * const current,
                                     cgutils_json_writer_element * const elt)
{
    int result = 0;
    CGUTILS_ASSERT(current != NULL);
    CGUTILS_ASSERT(elt != NULL);

    cgutils_json_writer_element * storages_elt = NULL;

    result = cgutils_json_writer_element_add_list_child(elt,
                                                        "storages",
                                                        &storages_elt);

    if (result == 0)
    {
        cg_monitor_data_instance_status_tab const * const status_tab = current->storages.storages_status_tab;

        if (status_tab != NULL)
        {
            /* Check that the instances name mapping is consistent
               with what we got from the SHM */
            if (current->storages.names_count == status_tab->instances_count)
            {
                for (size_t idx = 0;
                     result == 0 &&
                         idx < status_tab->instances_count;
                     idx ++)
                {
                    cg_monitor_data_instance_status_data const * const data = &(status_tab->instances_data[idx]);
                    char ** const names = current->storages.names;
                    size_t const names_count = current->storages.names_count;

                    if (data->instance_index < names_count)
                    {
                        cgutils_json_writer_element * storage_elt = NULL;

                        result = cgutils_json_writer_new_element(&storage_elt);

                        if (result == 0)
                        {
                            result = cgutils_json_writer_add_element_to_list(storages_elt,
                                                                             storage_elt);

                            if (result == 0)
                            {
                                cgutils_json_writer_element_add_string_prop(storage_elt,
                                                                            "name",
                                                                            names[data->instance_index]);

                                cgutils_json_writer_element_add_boolean_prop(storage_elt,
                                                                             "status",
                                                                             data->last_success);

                                cgutils_json_writer_element_add_uint64_prop(storage_elt,
                                                                            "get",
                                                                            data->average_get_values);

                                cgutils_json_writer_element_add_uint64_prop(storage_elt,
                                                                            "put",
                                                                            data->average_put_values);

                            }
                            else
                            {
                                CGUTILS_ERROR("Error adding storage elt to list: %d", result);
                            }

                            cgutils_json_writer_element_release(storage_elt), storage_elt = NULL;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error creating storage elt: %d", result);
                        }
                    }
                    else
                    {
                        CGUTILS_WARN("Skipping instance with invalid index (%zu/%zu)",
                                     data->instance_index,
                                     names_count);
                    }
                }
            }
            else
            {
                CGUTILS_ERROR("Error adding providers element: %d", result);
            }
        }

        cgutils_json_writer_element_release(storages_elt), storages_elt = NULL;
    }
    else
    {
        CGUTILS_WARN("Skipping providers instant because the data retrieved from SHM is not consistent with the configuration");
    }

    return result;
}

static int cg_stats_compute_elt(cg_stats_instant const * const current,
                                cg_stats_instant const * const previous,
                                cgutils_json_writer_element * const elt)
{
    int result = 0;
    CGUTILS_ASSERT(current != NULL);
    CGUTILS_ASSERT(previous != NULL);
    CGUTILS_ASSERT(elt != NULL);

    cgutils_json_writer_element_add_uint64_prop(elt,
                                                "begin",
                                                (uint64_t) previous->time);

    cgutils_json_writer_element_add_uint64_prop(elt,
                                                "end",
                                                (uint64_t) current->time);

    cg_stats_compute_cpu(current,
                         previous,
                         elt);

    cg_stats_compute_memory(current,
                            elt);

    cg_stats_compute_network(current,
                             previous,
                             elt);

    cg_stats_compute_storages(current,
                              elt);

    return result;
}

static int cg_stats_write_stats_to_disk(char const * const json_file,
                                        size_t const json_file_len,
                                        cgutils_json_writer const * const writer)
{
    CGUTILS_ASSERT(json_file != NULL);
    CGUTILS_ASSERT(writer != NULL);
    char * buffer = NULL;
    size_t buffer_size = 0;

    int result = cgutils_json_writer_get_output(writer,
                                                &buffer,
                                                &buffer_size);

    if (result == 0)
    {
        static char const suffix[] = ".XXXXXX";
        static size_t const suffix_len = sizeof suffix - 1;
        size_t const temp_name_len = json_file_len + suffix_len;

        char * temp_name = NULL;

        CGUTILS_MALLOC(temp_name, temp_name_len + 1, 1);

        if (temp_name != NULL)
        {
            memcpy(temp_name, json_file, json_file_len);
            memcpy(temp_name + json_file_len, suffix, suffix_len);
            temp_name[temp_name_len] = '\0';

            int fd = -1;

            result = cgutils_file_mkstemp(temp_name,
                                          &fd);

            if (result == 0)
            {
                result = cgutils_file_write_content_sync_fd(fd,
                                                            buffer,
                                                            buffer_size);

                if (result == 0)
                {
                    result = cgutils_file_rename(temp_name, json_file);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error renaming temporary stats file from %s to %s: %d",
                                      temp_name,
                                      json_file,
                                      result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error writing content to %s: %d",
                                  temp_name,
                                  result);
                }

                if (result != 0)
                {
                    cgutils_file_unlink(temp_name);
                }

                cgutils_file_close(fd), fd = -1;
            }
            else
            {
                CGUTILS_ERROR("Error opening temp file: %d", result);
            }

            CGUTILS_FREE(temp_name);
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for temp name: %d", result);
        }

        CGUTILS_FREE(buffer);
    }
    else
    {
        CGUTILS_ERROR("Error getting JSON content: %d", result);
    }

    return result;
}

static int cg_stats_write_stats(cg_stats_data const * const stats_data)
{
    int result = 0;
    CGUTILS_ASSERT(stats_data);

    cgutils_json_writer * writer = NULL;

    result = cgutils_json_writer_new(&writer);

    if (result == 0)
    {
        cgutils_json_writer_element * root = cgutils_json_writer_get_root(writer);
        cgutils_json_writer_element * list = NULL;

        CGUTILS_ASSERT(root != NULL);

        result = cgutils_json_writer_element_add_list_child(root,
                                                            "stats",
                                                            &list);

        if (result == 0)
        {
            size_t pos = stats_data->first_value;
            cg_stats_instant const * previous = NULL;

            for (size_t idx = 0;
                 result == 0 &&
                     idx < stats_data->nb_values;
                 idx++)
            {
                cg_stats_instant const * current = &(stats_data->values[pos]);

                if (previous != NULL &&
                    current->time >= previous->time)
                {
                    cgutils_json_writer_element * elt = NULL;

                    result = cgutils_json_writer_new_element(&elt);

                    if (result == 0)
                    {
                        result = cg_stats_compute_elt(current,
                                                      previous,
                                                      elt);

                        if (result == 0)
                        {
                            result = cgutils_json_writer_add_element_to_list(list,
                                                                             elt);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error adding element to list: %d", result);
                            }
                        }

                        if (result == 0)
                        {
                            cgutils_json_writer_element_release(elt), elt = NULL;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error computing stats element: %d", result);
                            cgutils_json_writer_element_free(elt), elt = NULL;
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating json element: %d", result);
                    }
                }
                else
                {
                    /* We skip the first value since we have nothing to interpret the gauge with */
                }

                /* Next */
                previous = current;

                pos++;

                if (pos >= CG_STATS_NUMBER_OF_VALUES)
                {
                    pos = 0;
                }
            }

            if (result == 0)
            {
                result = cg_stats_write_stats_to_disk(stats_data->json_file,
                                                      stats_data->json_file_len,
                                                      writer);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error writing JSON content to disk: %d", result);
                }
            }

            cgutils_json_writer_element_release(list), list = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error adding list child: %d", result);
        }

        cgutils_json_writer_free(writer), writer = NULL;
    }
    else
    {
        CGUTILS_ERROR("Error creating JSON writer: %d", result);
    }

    return result;
}

static void cg_stats_timer_cb(void * cb_data)
{
    cg_stats_data * stats_data = cb_data;
    CGUTILS_ASSERT(cb_data != NULL);

    if (stats_data->running == false)
    {
        int result = 0;
        cg_stats_instant * current = NULL;

        stats_data->running = true;

        if (stats_data->nb_values < CG_STATS_NUMBER_OF_VALUES)
        {
            current = &(stats_data->values[stats_data->nb_values]);
            stats_data->last_value = stats_data->nb_values;
            stats_data->nb_values++;
        }
        else
        {
            current = &(stats_data->values[stats_data->first_value]);

            stats_data->last_value = stats_data->first_value;

            stats_data->first_value++;

            if (stats_data->first_value >= CG_STATS_NUMBER_OF_VALUES)
            {
                stats_data->first_value = 0;
            }
        }

        result = cg_stats_populate_instant(stats_data,
                                           current);

        if (result == 0)
        {
            result = cg_stats_write_stats(stats_data);

            if (result != 0)
            {
                CGUTILS_ERROR("Error writing values: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error populating values: %d", result);
        }

        stats_data->running = false;
    }
}

static int cg_stats_run(cgutils_event_data * const event_data,
                        char const * const conf_file,
                        char const * json_file)
{
    int result = 0;
    CGUTILS_ASSERT(event_data != NULL);
    CGUTILS_ASSERT(conf_file != NULL);
    CGUTILS_ASSERT(json_file != NULL);

    cg_stats_data * stats_data = NULL;

    CGUTILS_ALLOCATE_STRUCT(stats_data);

    if (stats_data != NULL)
    {
        size_t const json_file_len = strlen(json_file);

        stats_data->json_file = json_file;
        stats_data->json_file_len = json_file_len;
        stats_data->event_data = event_data;

        stats_data->conf_file = cgutils_strdup(conf_file);

        if (stats_data->conf_file != NULL)
        {
            result = cgutils_event_create_timer_event(event_data,
                                                      CGUTILS_EVENT_PERSIST,
                                                      &cg_stats_timer_cb,
                                                      stats_data,
                                                      &(stats_data->timer_event));

            if (result == 0)
            {
                result = cg_stats_register_signal(stats_data,
                                                  SIGUSR1,
                                                  &(stats_data->sigusr_event),
                                                  &cg_stats_graceful_exit,
                                                  stats_data);
                if (result == 0)
                {
                    result = cg_stats_register_signal(stats_data,
                                                      SIGINT,
                                                      &(stats_data->sigint_event),
                                                      &cg_stats_graceful_exit,
                                                      stats_data);
                }

                if (result == 0)
                {
                    result = cg_stats_register_signal(stats_data,
                                                      SIGTERM,
                                                      &(stats_data->sigterm_event),
                                                      &cg_stats_graceful_exit,
                                                      stats_data);
                }


                if (result == 0)
                {

                    struct timeval tv =
                        {
                            .tv_sec = (CG_STATS_DELAY_DEFAULT) * 60,
                            .tv_usec = 0
                        };

                    /* First run */
                    cg_stats_timer_cb(stats_data);

                    result = cgutils_event_enable(stats_data->timer_event, &tv);

                    if (result == 0)
                    {
                        result = cgutils_event_dispatch(event_data);
                        cgutils_event_disable(stats_data->timer_event);
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
            }
            else
            {
                CGUTILS_ERROR("Error creating timer event: %d", result);
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for configuration file: %d", result);
        }

        cg_stats_data_free(stats_data), stats_data = NULL;
    }
    else
    {
        result = ENOMEM;
        CGUTILS_ERROR("Error allocating memory for healer data: %d", result);
    }

    return result;
}

int main(int argc, char ** argv)
{
    int result = 0;

    if (argc == 2)
    {
        result = cg_tools_init_all();

        if (result == 0)
        {
            char const * const conf_file = argv[1];
            cgutils_configuration * conf = NULL;

            result = cgutils_configuration_from_xml_file(conf_file,
                                                         &conf);

            if (result == 0)
            {
                bool const nodaemon = getenv("CG_STATS_NODAEMON") != NULL;
                bool master = true;

                if (nodaemon == false)
                {
                    char * log_file = NULL;

                    result = cgutils_configuration_get_string(conf,
                                                              "General/LogFile",
                                                              &log_file);

                    if (result != 0)
                    {
                        result = 0;

                        log_file = cgutils_strdup(CG_STATS_LOG_FILE_DEFAULT);

                        if (log_file == NULL)
                        {
                            result = ENOMEM;
                            CGUTILS_ERROR("Error allocating memory: %d", result);
                        }
                    }

                    if (result == 0)
                    {
                        result = cgutils_process_daemonize(log_file, &master);

                        if (result != 0)
                        {
                            CGUTILS_ERROR("Error in daemonize: %d", result);
                        }
                    }

                    CGUTILS_FREE(log_file);
                }

                if (result == 0 &&
                    master == true)
                {
                    cgutils_event_data * event_data = NULL;

                    result = cgutils_event_init(&event_data);

                    if (result == 0)
                    {
                        char * json_file = NULL;

                        result = cgutils_configuration_get_string(conf,
                                                                  "General/StatsJSONFile",
                                                                  &json_file);

                        if (result != 0)
                        {
                            json_file = cgutils_strdup(CG_STATS_FILE_DEFAULT);
                        }

                        if (json_file != NULL)
                        {
                            result = cg_stats_run(event_data,
                                                  conf_file,
                                                  json_file);

                            CGUTILS_FREE(json_file);
                        }
                        else
                        {
                            fprintf(stderr,
                                    "Error allocating memory for JSON file parameter: %s\n",
                                    strerror(result));
                        }

                        cgutils_event_clear(event_data);
                        cgutils_event_destroy(event_data), event_data = NULL;
                    }
                    else
                    {
                        fprintf(stderr,
                                "Error allocating event loop: %s\n",
                                strerror(result));
                    }
                }

                cgutils_configuration_free(conf), conf = NULL;
            }
            else
            {
                fprintf(stderr,
                        "Error loading configuration from file (%s): %s\n",
                        conf_file,
                        strerror(result));
            }

            cg_tools_destroy_all();
        }
        else
        {
            fprintf(stderr,
                    "Error in cgutils_init_all(): %s\n",
                    strerror(result));
        }
    }
    else
    {
        fprintf(stderr,
                "%s <Cloud Gateway configuration file>\n",
                argv[0]);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
