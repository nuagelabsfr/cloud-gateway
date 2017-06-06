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

static char const db_configuration_template[] = "<DB>\n"
    "<Type>PG</Type>\n"
    "<Specifics>\n"
    "<ConnectionString>%s</ConnectionString>\n"
    "</Specifics>\n"
    "</DB>\n";

int main(int argc, char ** argv)
{
    int result = 0;

    if (argc == 3)
    {
        result = cg_tools_init_all();

        if (result == 0)
        {
            char const * const conf_file = argv[1];
            char const * const conn_str = argv[2];

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
                            char * db_configuration = NULL;

                            result = cgutils_asprintf(&db_configuration,
                                                      db_configuration_template,
                                                      conn_str);

                            if (result == 0)
                            {
                                cgutils_configuration * db_config = NULL;

                                result = cgutils_configuration_from_xml_memory(db_configuration,
                                                                               strlen(db_configuration),
                                                                               &db_config);

                                if (result == 0)
                                {
                                    cgdb_data * db = NULL;

                                    result = cgdb_data_init(cg_storage_manager_data_get_db_backends_path(data),
                                                            db_config,
                                                            cg_storage_manager_data_get_event(data),
                                                            &db);

                                    if (result == 0)
                                    {
                                        char * error = NULL;

                                        result = cgdb_sync_test_credentials(db,
                                                                            &error);

                                        if (result != 0 &&
                                            error != NULL)
                                        {
                                            fputs(error, stderr);
                                            CGUTILS_FREE(error);
                                        }

                                        cgdb_data_free(db), db = NULL;
                                    }
                                    else
                                    {
                                        fprintf(stderr,
                                                "Error setting up database connection: %s\n",
                                                strerror(result));
                                    }

                                    cgutils_configuration_free(db_config), db_config = NULL;
                                }
                                else
                                {
                                    fprintf(stderr,
                                            "Error constructing database configuration: %s\n",
                                            strerror(result));
                                }

                                CGUTILS_FREE(db_configuration), db_configuration = NULL;
                            }
                            else
                            {
                                fprintf(stderr,
                                        "Error allocating memory: %s\n",
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
                "%s <Cloud Gateway configuration file> <Database connection string>\n",
                argv[0]);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
