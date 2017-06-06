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

/*
   -i --instance-name Instance Name (required)
   -t --type Filter type (required) Compression, Encryption

   -f --file Configuration File to update
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
    fprintf(stderr, "Usage: CloudGatewayRemoveFilterFromInstance [OPTIONS]\n");
    fprintf(stderr, "Required options are:\n");
#define ITEM(longname, variable, shortname, xmlname, required, expl)     \
    if (required == true)                                       \
    {                                                           \
        fprintf(stderr, "\t-%c --%-35s %s\n", shortname, longname, expl);  \
    }
#include "cg_config_remove_filter_from_instance.itm"
#undef ITEM
    fprintf(stderr, "Please look at the product documentation for more information.\n");
}

int main (int argc, char **argv)
{

#define ITEM(longname, variable, shortname, xmlname, required, expl) char * variable = NULL;
#include "cg_config_remove_filter_from_instance.itm"
#undef ITEM

    static struct option const long_options[] =
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl) { longname, required_argument, NULL, shortname },
#include "cg_config_remove_filter_from_instance.itm"
#undef ITEM
            { 0, 0, 0, 0 }
        };

    int result = 0;
    int indexptr = 0;

    opterr = 1;

    while ((result = getopt_long(argc,
                                 argv,
                                 "+i:t:f:",
                                 long_options,
                                 &indexptr)) != -1)
    {
        switch(result)
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl)  \
            case shortname:                                           \
                variable = optarg;                                    \
                break;
#include "cg_config_remove_filter_from_instance.itm"
#undef ITEM
        default:
            print_usage();
        }

    }

    if (optind == argc)
    {
        if (instance_name != NULL &&
            filter_type != NULL &&
            file != NULL)
        {
            cgutils_xml_writer * writer = NULL;

            cgutils_xml_init();

            result = cgutils_xml_writer_from_file(file,
                                                  &writer);

            if (result == 0)
            {
                char * xpath = NULL;

                result = cgutils_asprintf(&xpath,
                                          "/Configuration/Instances/Instance[Name='%s']/Filters/Filter[Type='%s']",
                                          instance_name,
                                          filter_type);

                if (result == 0)
                {
                    cgutils_xml_writer_element * filter_elt = NULL;

                    result = cgutils_xml_writer_get_element_from_path(writer,
                                                                      xpath,
                                                                      &filter_elt);

                    if (result == 0)
                    {
                        result = cgutils_xml_writer_element_remove_from_tree(filter_elt);

                        if (result == 0)
                        {
                            filter_elt = NULL;

                            int res = cgutils_xml_writer_save(writer);

                            if (res != 0)
                            {
                                fprintf(stderr, "Error writing the configuration to file %s: %s\n",
                                        file,
                                        strerror(res));
                            }
                        }
                        else
                        {
                            cgutils_xml_writer_element_release(filter_elt), filter_elt = NULL;

                            fprintf(stderr, "Error removing filter of type %s from instance %s: %s\n",
                                    filter_type,
                                    instance_name,
                                    strerror(result));
                        }
                    }
                    else if (result == ENOENT)
                    {
                        fprintf(stderr, "There is no filter of type %s in instance %s.\n",
                                filter_type,
                                instance_name);
                    }
                    else
                    {
                        fprintf(stderr, "Error looking for a filter of type %s in instance %s: %s\n",
                                filter_type,
                                instance_name,
                                strerror(result));
                    }

                    CGUTILS_FREE(xpath);
                }
                else
                {
                    fprintf(stderr, "Error allocating memory for XPath expression: %s\n",
                            strerror(result));
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
            result = EINVAL;
            fprintf(stderr, "Name, type and file parameters are mandatory.\n");
            print_usage();
        }
    }
    else
    {
        result = EINVAL;
        fprintf(stderr, "Too many arguments\n");
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
