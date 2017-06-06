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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_xml.h>
#include <cloudutils/cloudutils_xml_writer.h>

static void print_usage(void)
{
    fprintf(stderr, "Usage: CloudGatewayAddMount [OPTIONS] ...\n");
    fprintf(stderr, "Required options are:\n");
#define ITEM(longname, variable, shortname, xmlname, required, expl)     \
    if (required == true)                                       \
    {                                                           \
        fprintf(stderr, "\t-%c --%-25s %s\n", shortname, longname, expl);  \
    }
#include "cg_config_create_mount.itm"
#undef ITEM
    fprintf(stderr, "Optional options are:\n");
#define ITEM(longname, variable, shortname, xmlname, required, expl)     \
    if (required == false)                                      \
    {                                                           \
        fprintf(stderr, "\t-%c --%-25s %s\n", shortname, longname, expl);  \
    }
#include "cg_config_create_mount.itm"
#undef ITEM
    fprintf(stderr, "Please look at the product documentation for more information.\n");
}

int main (int argc, char **argv)
{

#define ITEM(longname, variable, shortname, xmlname, required, expl) char * variable = NULL;
#include "cg_config_create_mount.itm"
#undef ITEM

    static struct option const long_options[] =
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl) { longname, required_argument, NULL, shortname },
#include "cg_config_create_mount.itm"
#undef ITEM
            { 0, 0, 0, 0 }
        };

    int result = 0;
    int indexptr = 0;

    opterr = 1;

    while ((result = getopt_long(argc,
                                 argv,
                                 "+i:m:o:f:",
                                 long_options,
                                 &indexptr)) != -1)
    {
        switch(result)
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl)  \
            case shortname:                                           \
                variable = optarg;                                    \
                break;
#include "cg_config_create_mount.itm"
#undef ITEM
        default:
            print_usage();
        }
    }

    if (optind <= argc)
    {
        if (id != NULL &&
            mount_point != NULL &&
            configuration_file != NULL &&
            file != NULL)
        {
            cgutils_xml_writer * writer = NULL;
            cgutils_configuration * conf = NULL;

            cgutils_xml_init();

            result = cgutils_configuration_from_xml_file(configuration_file,
                                                         &conf);

            if (result == 0)
            {
                char * socket = NULL;
                result = cgutils_configuration_get_string(conf,
                                                          "General/CommunicationSocket",
                                                          &socket);

                if (result == 0)
                {
                    result = cgutils_xml_writer_new(&writer);

                    if (result == 0)
                    {
                        cgutils_xml_writer_element * root = NULL;

                        result = cgutils_xml_writer_create_root(writer,
                                                                "Configuration",
                                                                &root);

                        if (result == 0)
                        {
                            cgutils_xml_writer_element * elt = NULL;

#define ITEM(longname, variable, shortname, xmlname, required, expl)    \
                            if (result == 0 &&                          \
                                variable != NULL &&                     \
                                xmlname != NULL &&                      \
                                strlen(xmlname) > 0)                    \
                            {                                           \
                                result = cgutils_xml_writer_element_add_child(root, \
                                                                              xmlname, \
                                                                              variable, \
                                                                              &elt); \
                                                                        \
                                if (result == 0)                        \
                                {                                       \
                                    cgutils_xml_writer_element_release(elt), elt = NULL; \
                                }                                       \
                                else                                    \
                                {                                       \
                                    fprintf(stderr, "Error while adding element %s: %d\n", xmlname, result); \
                                }                                       \
                            }
#include "cg_config_create_mount.itm"
#undef ITEM

                            if (result == 0)
                            {
                                result = cgutils_xml_writer_element_add_child(root,
                                                                              "StorageManagerSocket",
                                                                              socket,
                                                                              &elt);

                                if (result == 0)
                                {
                                    cgutils_xml_writer_element_release(elt), elt = NULL;
                                }
                                else
                                {
                                    fprintf(stderr, "Error while adding element StorageManagerSocket: %d\n",
                                            result);
                                }
                            }

                            if (result == 0)
                            {
                                int res = cgutils_xml_writer_save_to_file(writer,
                                                                          file);

                                if (res != 0)
                                {
                                    fprintf(stderr, "Error writing the configuration to file %s: %s\n",
                                            file,
                                            strerror(res));
                                }
                            }

                            cgutils_xml_writer_element_release(root), root = NULL;
                        }
                        else
                        {
                            fprintf(stderr, "Error creating root element: %d\n", result);
                        }

                        cgutils_xml_writer_free(writer), writer = NULL;
                    }
                    else
                    {
                        fprintf(stderr, "Error creating XML document: %s\n",
                                strerror(result));
                    }

                    CGUTILS_FREE(socket);
                }
                else
                {
                    fprintf(stderr, "Error getting General/StorageManagerSocket value from %s file: %d\n",
                            configuration_file,
                            result);
                }

                cgutils_configuration_free(conf), conf = NULL;
            }
            else
            {
                fprintf(stderr, "Error opening the Storage Manager configuration file %s: %d\n",
                        configuration_file,
                        result);
            }

             cgutils_xml_destroy();
        }
        else
        {
            result = EINVAL;
            fprintf(stderr, "Id, mount point and file parameters are mandatory.\n");
            print_usage();
        }
    }
    else
    {
        result = EINVAL;
        fprintf(stderr, "Too many arguments\n");
        print_usage();
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
