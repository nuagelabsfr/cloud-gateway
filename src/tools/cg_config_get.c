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

#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_xml.h>
#include <cloudutils/cloudutils_xml_writer.h>

#include "common.h"

int main(int argc, char ** argv)
{
    int result = 0;

    if (argc == 3)
    {
        cgutils_configuration * conf = NULL;

        cgutils_xml_init();

        result = cgutils_configuration_from_xml_file(argv[1],
                                                     &conf);

        if (result == 0)
        {
            char * value = NULL;
            result = cgutils_configuration_get_string(conf,
                                                      argv[2],
                                                      &value);

            if (result == 0)
            {
                puts(value);

                CGUTILS_FREE(value);
            }
            else if (result == ENOENT)
            {
            }
            else
            {
                fprintf(stderr,
                        "Error looking parameter by XPath: %d\n",
                        result);
            }

            cgutils_configuration_free(conf), conf = NULL;
        }
        else
        {
            fprintf(stderr,
                    "Error loading configuration file %s: %d\n",
                    argv[1],
                    result);
        }

        cgutils_xml_destroy();
    }
    else
    {
        fprintf(stderr,
                "%s <Cloud Gateway configuration file> <XPath Expression>\n",
                argv[0]);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
