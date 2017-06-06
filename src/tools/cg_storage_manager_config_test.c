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

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_configuration.h>

#include <cgsm/cg_storage_manager.h>
#include <cgsm/cg_storage_manager_data.h>

#include <cgStorageManagerMonitor.h>

#include "common.h"

int main(int argc, char ** argv)
{
    int result = EINVAL;

    if (argc == 2)
    {
        char const * const cg_conf_file = argv[1];

        result = cg_tools_init_all();

        if (result == 0)
        {
            cgutils_configuration * conf = NULL;

            result = cgutils_configuration_from_xml_file(cg_conf_file,
                                                         &conf);

            if (result == 0)
            {
                cg_storage_manager_data * data = NULL;

                result = cg_storage_manager_data_init(conf,
                                                      &data);

                if (result == 0)
                {
                    result = cg_storage_manager_load_configuration(data,
                                                                   true,
                                                                   true);

                    if (result == 0)
                    {
                        result = cg_storage_manager_data_setup(data);
                    }

                    cg_storage_manager_data_free(data), data = NULL;
                }
            }
        }
        else
        {
            fprintf(stderr,
                    "Error in init all: %s\n",
                    strerror(result));
        }

        cg_tools_destroy_all();
    }
    else
    {
        fprintf(stderr,
                "CloudGatewayStorageManagerConfigTest <Cloud Gateway Storage Manager configuration file>\n");
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;

}
