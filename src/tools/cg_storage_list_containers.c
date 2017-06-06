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
#include <stdio.h>
#include <string.h>

#include <cgsm/cg_storage_instance.h>
#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>

#include "common.h"

static int containers_list_cb(int const status,
                              cgutils_llist * containers,
                              void * const cb_data)
{
    int result = status;
    cg_storage_manager_data * const data = cb_data;
    CGUTILS_ASSERT(cb_data != NULL);

    if (result == 0)
    {
        for (cgutils_llist_elt * elt = cgutils_llist_get_first(containers);
             elt != NULL;
             elt = cgutils_llist_elt_get_next(elt))
        {
            char const * const name = cgutils_llist_elt_get_object(elt);
            CGUTILS_ASSERT(name != NULL);

            fprintf(stdout,
                    "%s\n",
                    name);
        }
    }

    if (containers != NULL)
    {
        cgutils_llist_free(&containers, &free);
    }

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    cgutils_event_exit_loop(event_data);

    return result;
}

int main(int const argc,
         char const ** const argv)
{
    int result = 0;

    if (argc == 3)
    {
        result = cg_tools_init_all();

        if (result == 0)
        {
            char const * const conf_file = argv[1];
            char const * const instance_name = argv[2];
            cgutils_configuration * conf = NULL;

            result = cgutils_configuration_from_xml_file(conf_file,
                                                         &conf);

            if (result == 0)
            {
                cg_storage_manager_data * data = NULL;

                result = cg_storage_manager_data_init(conf,
                                                      &data);

                if (result == 0)
                {
                    conf = NULL;

                    result = cg_storage_manager_load_configuration(data,
                                                                   true,
                                                                   true);

                    if (result == 0)
                    {
                        result = cg_storage_manager_setup(data,
                                                          true);

                        if (result == 0)
                        {
                            cg_storage_instance * instance = NULL;

                            result = cg_storage_manager_data_get_instance(data,
                                                                          instance_name,
                                                                          &instance);

                            if (result == 0)
                            {
                                result = cg_storage_instance_list_containers(instance,
                                                                             &containers_list_cb,
                                                                             data);

                                if (result == 0)
                                {
                                    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
                                    assert(event_data != NULL);

                                    cgutils_event_dispatch(event_data);
                                }
                                else
                                {
                                    fprintf(stderr,
                                            "Error listing containers on instance %s: %s\n",
                                            instance_name,
                                            strerror(result));
                                }

                            }
                            else
                            {
                                fprintf(stderr,
                                        "Error getting an instance named %s: %s\n",
                                        instance_name,
                                        strerror(result));
                            }
                        }
                        else
                        {
                            fprintf(stderr,
                                    "Error setting up configuration: %s\n",
                                    strerror(result));
                        }
                    }
                    else
                    {
                        fprintf(stderr,
                                "Error loading configuration: %s\n",
                                strerror(result));
                    }

                    cg_storage_manager_data_free(data), data = NULL;
                }
                else
                {
                    fprintf(stderr,
                            "Error in config init: %s\n",
                            strerror(result));

                    cgutils_configuration_free(conf), conf = NULL;
                }
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
                "%s <Cloud Gateway configuration file> <Storage/Instance Name>\n",
                argv[0]);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
