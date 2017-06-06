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

#include <cloudutils/cloudutils_xml.h>
#include <cloudutils/cloudutils_xml_writer.h>

#include "common.h"

int main(int argc, char ** argv)
{
    int result = 0;

    if (argc == 4)
    {
        cgutils_xml_init();

        cgutils_xml_writer * writer = NULL;

        result = cgutils_xml_writer_from_file(argv[1],
                                              &writer);

        if (result == 0)
        {
            assert(writer != NULL);

            result = cgutils_xml_writer_set_element_value(writer,
                                                          argv[2],
                                                          argv[3]);

            if (result == 0)
            {
                int res = cgutils_xml_writer_save(writer);

                if (res != 0)
                {
                    fprintf(stderr,
                            "Error writing the configuration to file %s: %s\n",
                            argv[1],
                            strerror(res));
                }
            }
            else
            {
                fprintf(stderr,
                        "Error looking parameter %s by XPath: %d\n",
                        argv[2],
                        result);
            }

            cgutils_xml_writer_free(writer), writer = NULL;
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
                "%s <Cloud Gateway configuration file> <XPath Expression> <value>\n",
                argv[0]);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
