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

   -l --level Compression Level (required for Compression filter)

   -c --cipher Cipher (required for Encryption filter)
   -d --digest Digest (required for Encryption filter)
   -k --key-iteration-count Key Iteration Count (required for Encryption filter)
   -p --password Password (required for Encryption filter)

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
    fprintf(stderr, "Usage: CloudGatewayAddFilterToInstance [OPTIONS]\n");
    fprintf(stderr, "Required options are:\n");
#define ITEM(longname, variable, shortname, xmlname, required, expl)     \
    if (required == true)                                       \
    {                                                           \
        fprintf(stderr, "\t-%c --%-35s %s\n", shortname, longname, expl);  \
    }
#include "cg_config_add_filter_to_instance.itm"
#undef ITEM
    fprintf(stderr, "Optional options are:\n");
#define ITEM(longname, variable, shortname, xmlname, required, expl)     \
    if (required == false)                                      \
    {                                                           \
        fprintf(stderr, "\t-%c --%-35s %s\n", shortname, longname, expl);  \
    }
#include "cg_config_add_filter_to_instance.itm"
#undef ITEM
    fprintf(stderr, "Please look at the product documentation for more information.\n");
}

int main (int argc, char **argv)
{

#define ITEM(longname, variable, shortname, xmlname, required, expl) char * variable = NULL;
#include "cg_config_add_filter_to_instance.itm"
#undef ITEM

    static struct option const long_options[] =
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl) { longname, required_argument, NULL, shortname },
#include "cg_config_add_filter_to_instance.itm"
#undef ITEM
            { 0, 0, 0, 0 }
        };

    int result = 0;
    int indexptr = 0;

    opterr = 1;

    while ((result = getopt_long(argc,
                                 argv,
                                 "+i:t:l:c:d:k:p:f:",
                                 long_options,
                                 &indexptr)) != -1)
    {
        switch(result)
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl)  \
            case shortname:                                           \
                variable = optarg;                                    \
                break;
#include "cg_config_add_filter_to_instance.itm"
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
            bool compression = false;
            bool encryption = false;

            if (strcmp(filter_type, "Compression") == 0)
            {
                if (compression_level != NULL)
                {
                    result = 0;
                    compression = true;
                }
                else
                {
                    fprintf(stderr, "Error, at least one parameter is missing for a Compression filter. Required parameters are:\n"
                            "\t level: %s\n",
                            compression_level ?: "");
                    result = EINVAL;
                }
            }
            else if (strcmp(filter_type, "Encryption") == 0)
            {
                if (encryption_cipher != NULL &&
                    encryption_digest != NULL &&
                    encryption_key_iteration_count != NULL &&
                    encryption_password != NULL)
                {
                    encryption = true;
                    result = 0;
                }
                else
                {
                    fprintf(stderr, "Error, at least one parameter is missing for an Encryption filter. Required parameters are:\n"
                            "\t cipher: %s\n"
                            "\t digest: %s\n"
                            "\t key-iteration-count: %s\n"
                            "\t password: %s\n",
                            encryption_cipher ?: "",
                            encryption_digest ?: "",
                            encryption_key_iteration_count ?: "",
                            encryption_password ?: "");
                    result = EINVAL;
                }
            }
            else
            {
                fprintf(stderr, "Unknown filter type %s, supported types are Compression and Encryption.\n",
                        filter_type);
                result = EINVAL;
            }

            if (result == 0)
            {
                cgutils_xml_writer * writer = NULL;

                cgutils_xml_init();

                result = cgutils_xml_writer_from_file(file,
                                                      &writer);

                if (result == 0)
                {
                    char * xpath = NULL;

                    result = cgutils_asprintf(&xpath,
                                              "/Configuration/Instances/Instance[Name='%s']",
                                              instance_name);

                    if (result == 0)
                    {
                        cgutils_xml_writer_element * instance = NULL;

                        assert(writer != NULL);

                        result = cgutils_xml_writer_get_element_from_path(writer,
                                                                          xpath,
                                                                          &instance);
                        if (result == 0)
                        {
                            cgutils_xml_writer_element * filters = NULL;

                            result = cgutils_xml_writer_element_get_from_path(instance,
                                                                              "Filters",
                                                                              &filters);

                            if (result == ENOENT)
                            {
                                result = cgutils_xml_writer_element_add_child(instance,
                                                                              "Filters",
                                                                              NULL,
                                                                              &filters);
                            }

                            if (result == 0)
                            {
                                cgutils_xml_writer_element * filter_elt = NULL;
                                cgutils_xml_writer_element * specifics_elt = NULL;

                                result = cgutils_xml_writer_element_add_child(filters,
                                                                              "Filter",
                                                                              NULL,
                                                                              &filter_elt);

                                if (result == 0)
                                {
                                    cgutils_xml_writer_element * type_elt = NULL;

                                    result = cgutils_xml_writer_element_add_child(filter_elt,
                                                                                  "Type",
                                                                                  filter_type,
                                                                                  &type_elt);

                                    if (result == 0)
                                    {
                                        cgutils_xml_writer_element_release(type_elt), type_elt = NULL;
                                    }
                                    else
                                    {
                                        fprintf(stderr, "Error creating type element: %d\n", result);
                                    }
                                }

                                if (result == 0)
                                {
                                    cgutils_xml_writer_element * enabled_elt = NULL;

                                    result = cgutils_xml_writer_element_add_child(filter_elt,
                                                                                  "Enabled",
                                                                                  "true",
                                                                                  &enabled_elt);

                                    if (result == 0)
                                    {
                                        cgutils_xml_writer_element_release(enabled_elt), enabled_elt = NULL;
                                    }
                                    else
                                    {
                                        fprintf(stderr, "Error creating enabled element: %d\n", result);
                                    }
                                }

                                if (result == 0)
                                {
                                    result = cgutils_xml_writer_element_add_child(filter_elt,
                                                                                  "Specifics",
                                                                                  NULL,
                                                                                  &specifics_elt);

                                    if (result != 0)
                                    {
                                        fprintf(stderr, "Error creating specifics element: %d\n", result);
                                    }
                                }

                                if (result == 0)
                                {
                                    if (compression == true)
                                    {
                                        cgutils_xml_writer_element * elt = NULL;

#define ITEM(longname, variable, shortname, xmlname, required, expl)    \
                                        if (result == 0 &&              \
                                            variable != NULL)           \
                                        {                               \
                                            result = cgutils_xml_writer_element_add_child(specifics_elt, \
                                                                                          xmlname, \
                                                                                          variable, \
                                                                                          &elt); \
                                                                        \
                                            if (result == 0)            \
                                            {                           \
                                                cgutils_xml_writer_element_release(elt), elt = NULL; \
                                            }                           \
                                            else                        \
                                            {                           \
                                                fprintf(stderr, "Error while adding specifics %s: %d\n", xmlname, result); \
                                            }                           \
                                        }
#include "cg_config_add_compression_filter.itm"
#undef ITEM
                                    }
                                    else if (encryption == true)
                                    {
                                        cgutils_xml_writer_element * elt = NULL;

#define ITEM(longname, variable, shortname, xmlname, required, expl)    \
                                        if (result == 0 &&              \
                                            variable != NULL)           \
                                        {                               \
                                            result = cgutils_xml_writer_element_add_child(specifics_elt, \
                                                                                          xmlname, \
                                                                                          variable, \
                                                                                          &elt); \
                                                                        \
                                            if (result == 0)            \
                                            {                           \
                                                cgutils_xml_writer_element_release(elt), elt = NULL; \
                                            }                           \
                                            else                        \
                                            {                           \
                                                fprintf(stderr, "Error while adding specifics %s\n: %d", xmlname, result); \
                                            }                           \
                                        }
#include "cg_config_add_encryption_filter.itm"
#undef ITEM
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
                                }

                                cgutils_xml_writer_element_release(specifics_elt), specifics_elt = NULL;
                                cgutils_xml_writer_element_release(filter_elt), filter_elt = NULL;

                                cgutils_xml_writer_element_release(filters), filters = NULL;
                            }
                            else
                            {
                                fprintf(stderr, "Error getting filters element: %s\n",
                                        strerror(result));
                            }

                            cgutils_xml_writer_element_release(instance), instance = NULL;
                        }
                        else
                        {
                            fprintf(stderr, "Error getting instance named %s: %s\n",
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
