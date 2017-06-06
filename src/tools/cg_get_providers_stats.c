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
#include <string.h>

#include <cloudutils/cloudutils.h>

#include <cgmonitor/cg_monitor_data.h>

#include "tools_provider_stats_common.h"

static void print_status(char * const * const names,
                         size_t const names_count,
                         cg_monitor_data_instance_status_tab const * const status_tab)
{
    CGUTILS_ASSERT(names != NULL);
    CGUTILS_ASSERT(names_count > 0);
    CGUTILS_ASSERT(status_tab != NULL);

    if (names_count == status_tab->instances_count)
    {
        for (size_t idx = 0;
             idx < status_tab->instances_count;
             idx++)
        {
            cg_monitor_data_instance_status_data const * const data = &(status_tab->instances_data[idx]);

            if (data->instance_index < names_count)
            {
                fprintf(stdout,
                        "%20s: %10s %10"PRIu64" %10"PRIu64"\n",
                        names[data->instance_index],
                        data->last_success == true ? "up" : "down",
                        data->average_get_values,
                        data->average_put_values);
            }
            else
            {
                fprintf(stderr,
                        "Invalid instance index %zu (%zu), skipping instance.\n",
                        data->instance_index,
                        names_count);
            }
        }
    }
    else
    {
        fprintf(stderr,
                "The number of instances in the configuration file does not match the one found in shared memory. Exiting.\n");
    }
}

int main(int argc,
         char const * const * const argv)
{
    int result = EINVAL;

    if (argc == 2)
    {
        char const * const conf_file_path = argv[1];
        cgutils_configuration * conf = NULL;

        cgutils_configuration_init();

        result = cgutils_configuration_from_xml_file(conf_file_path,
                                                     &conf);

        if (result == 0)
        {
            char * monitor_info_path = NULL;

            result = tools_provider_stats_compute_monitor_info_path(conf,
                                                                    &monitor_info_path);

            if (result == 0)
            {
                char ** names = NULL;
                size_t names_count = 0;

                result = tools_provider_stats_compute_instances_mapping(conf,
                                                                        &names,
                                                                        &names_count);

                if (result == 0)
                {
                    cg_monitor_data_instance_status_tab * status_tab = NULL;

                    result = cg_monitor_data_peek(monitor_info_path,
                                                  &status_tab);

                    if (result == 0)
                    {
                        print_status(names,
                                     names_count,
                                     status_tab);


                        CGUTILS_FREE(status_tab);
                    }
                    else
                    {
                        fprintf(stderr,
                                "Error getting status informations: %s\n",
                                strerror(result));
                    }

                    for (size_t count = 0;
                         count < names_count;
                         count++)
                    {
                        CGUTILS_FREE(names[count]);
                    }

                    CGUTILS_FREE(names);
                }
                else
                {
                    fprintf(stderr,
                            "Error computing instances mapping: %s\n",
                            strerror(result));
                }

                CGUTILS_FREE(monitor_info_path);
            }
            else
            {
                fprintf(stderr,
                        "Error getting monitor informations path: %s\n",
                        strerror(result));
            }

            cgutils_configuration_free(conf), conf = NULL;
        }
        else
        {
            fprintf(stderr,
                    "Error loading configuration from file %s: %s\n",
                    conf_file_path,
                    strerror(result));
        }

        cgutils_configuration_destroy();
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
