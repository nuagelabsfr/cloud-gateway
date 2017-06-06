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

#include <cgdb/cgdb.h>

#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>

#include "common.h"

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
                cg_storage_manager_data * data = NULL;

                result = cg_storage_manager_data_init(conf,
                                                      &data);

                if (result == 0)
                {
                    conf = NULL;

                    result = cg_storage_manager_load_configuration(data,
                                                                   false,
                                                                   false);

                    if (result == 0)
                    {
                        result = cg_storage_manager_setup(data,
                                                          false);

                        if (result == 0)
                        {
                            cgdb_data * db = cg_storage_manager_data_get_db(data);
                            char * version = NULL;

                            result = cgdb_sync_get_version(db,
                                                           &version);

                            if (result == 0)
                            {
                                puts(version);

                                CGUTILS_FREE(version);
                            }
                            else
                            {
                                fprintf(stderr, "Error getting database version: %s\n", strerror(result));
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
                "%s <Cloud Gateway configuration file>\n",
                argv[0]);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
