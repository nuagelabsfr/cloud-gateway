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
#include <cloudutils/cloudutils_xml.h>
#include <cloudutils/cloudutils_xml_writer.h>

static void print_usage(void)
{
    fprintf(stderr, "Usage: CloudGatewayAddFilesystem [OPTIONS] [<instance name>] ...\n");
    fprintf(stderr, "Required options are:\n");
#define ITEM(longname, variable, shortname, xmlname, required, expl)     \
    if (required == true)                                       \
    {                                                           \
        fprintf(stderr, "\t-%c --%-25s %s\n", shortname, longname, expl);  \
    }
#include "cg_config_create_fs.itm"
#undef ITEM
    fprintf(stderr, "Optional options are:\n");
#define ITEM(longname, variable, shortname, xmlname, required, expl)     \
    if (required == false)                                      \
    {                                                           \
        fprintf(stderr, "\t-%c --%-25s %s\n", shortname, longname, expl);  \
    }
#include "cg_config_create_fs.itm"
#undef ITEM
    fprintf(stderr, "Please look at the product documentation for more information.\n");
}

int main (int argc, char **argv)
{

#define ITEM(longname, variable, shortname, xmlname, required, expl) char * variable = NULL;
#include "cg_config_create_fs.itm"
#undef ITEM

    static struct option const long_options[] =
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl) { longname, required_argument, NULL, shortname },
#include "cg_config_create_fs.itm"
#undef ITEM
            { 0, 0, 0, 0 }
        };

    int result = 0;
    int indexptr = 0;

    opterr = 1;

    while ((result = getopt_long(argc,
                                 argv,
                                 "+i:t:c:u:o:s:a:f:d:x:h:m:",
                                 long_options,
                                 &indexptr)) != -1)
    {
        switch(result)
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl)  \
            case shortname:                                           \
                variable = optarg;                                    \
                break;
#include "cg_config_create_fs.itm"
#undef ITEM
        default:
            print_usage();
        }

    }

    if (optind <= argc)
    {
        if (id != NULL &&
            type != NULL &&
            cache_root != NULL &&
            full_threshold != NULL &&
            mount_point != NULL &&
            file != NULL)
        {
            if (strcmp(type, "Mirroring") == 0 ||
                strcmp(type, "Striping") == 0 ||
                strcmp(type, "Single") == 0)
            {
                cgutils_xml_writer * writer = NULL;

                cgutils_xml_init();

                result = cgutils_xml_writer_from_file(file,
                                                      &writer);

                if (result == 0)
                {
                    cgutils_xml_writer_element * filesystems = NULL;

                    assert(writer != NULL);

                    result = cgutils_xml_writer_get_element_from_path(writer,
                                                                      "/Configuration/FileSystems",
                                                                      &filesystems);
                    if (result == 0)
                    {
                        cgutils_xml_writer_element * fs_elt = NULL;

                        result = cgutils_xml_writer_element_add_child(filesystems,
                                                                      "FileSystem",
                                                                      NULL,
                                                                      &fs_elt);

                        if (result == 0)
                        {
                            cgutils_xml_writer_element * elt = NULL;

#define ITEM(longname, variable, shortname, xmlname, required, expl)    \
                            if (result == 0 &&                          \
                                variable != NULL &&                     \
                                xmlname != NULL &&                      \
                                strlen(xmlname) > 0)                    \
                            {                                           \
                                result = cgutils_xml_writer_element_add_child(fs_elt, \
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
#include "cg_config_create_fs.itm"
#undef ITEM

                            if (result == 0)
                            {
                                cgutils_xml_writer_element * instances_elt = NULL;

                                result = cgutils_xml_writer_element_add_child(fs_elt,
                                                                              "Instances",
                                                                              NULL,
                                                                              &instances_elt);

                                if (result == 0)
                                {
                                    while (optind < argc &&
                                           result == 0)
                                    {
                                        char const * const instance_name = argv[optind];
                                        cgutils_xml_writer_element * inst_elt = NULL;

                                        result = cgutils_xml_writer_element_add_child(instances_elt,
                                                                                      "Instance",
                                                                                      instance_name,
                                                                                      &inst_elt);

                                        if (result == 0)
                                        {
                                            cgutils_xml_writer_element_release(inst_elt), inst_elt = NULL;
                                        }
                                        else
                                        {
                                            fprintf(stderr, "Error creating an instance element named %s: %d\n",
                                                    instance_name,
                                                    result);
                                        }

                                        optind++;
                                    }


                                    if (result == 0)
                                    {
                                        int res = cgutils_xml_writer_save(writer);

                                        if (res != 0)
                                        {
                                            fprintf(stderr, "Error writing the configuration to file %s: %s\n",
                                                    file,
                                                    strerror(res));
                                        }
                                    }

                                    cgutils_xml_writer_element_release(instances_elt), instances_elt = NULL;
                                }
                                else
                                {
                                    fprintf(stderr, "Error creating instances element: %d\n", result);
                                }
                            }

                            cgutils_xml_writer_element_release(fs_elt), fs_elt = NULL;
                        }
                        else
                        {
                            fprintf(stderr, "Error creating filesystem element: %d\n", result);
                        }

                        cgutils_xml_writer_element_release(filesystems), filesystems = NULL;
                    }
                    else
                    {
                        fprintf(stderr, "Error getting filesystems element: %d\n", result);
                    }

                    cgutils_xml_writer_free(writer), writer = NULL;
                }
                else
                {
                    fprintf(stderr, "Error opening file %s: %s\n",
                            file,
                            strerror(result));
                }

                cgutils_xml_destroy();
            }
            else
            {
                fprintf(stderr,
                        "Unknown type %s, supported types are Single, Striping and Mirroring.\n",
                        type);
                result = EINVAL;
            }
        }
        else
        {
            result = EINVAL;
            fprintf(stderr, "Id, type, cache-root, full-threshold, mount-point and file parameters are mandatory.\n");
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
