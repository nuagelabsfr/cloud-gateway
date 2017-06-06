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
#include <cloudutils/cloudutils_xml_reader.h>

static void print_usage(void)
{
    fprintf(stderr, "Usage: CloudGatewayShowInstance [OPTIONS]\n");
    fprintf(stderr, "Required options are:\n");
#define ITEM(longname, variable, shortname, xmlname, required, expl)     \
    if (required == true)                                       \
    {                                                           \
        fprintf(stderr, "\t-%c --%-35s %s\n", shortname, longname, expl);  \
    }
#include "cg_config_show_instance.itm"
#undef ITEM
    fprintf(stderr, "Please look at the product documentation for more information.\n");
}

static void print_s3_instance(cgutils_xml_reader * const inst)
{
    static struct
    {
        char const * const print_name;
        char const * const xpath;
    }
    const values[] =
        {
            { "Endpoint", "Specifics/Endpoint"},
            { "Endpoint Port", "Specifics/EndpointPort"},
            { "Secure Transaction", "Specifics/SecureTransaction"},
            { "Bucket", "Specifics/Bucket"},
        };
    static size_t const values_count = sizeof values / sizeof *values;
    assert(inst != NULL);

    for (size_t idx = 0;
         idx < values_count;
         idx++)
    {
        char * value = NULL;

        int res = cgutils_xml_reader_get_string(inst,
                                                values[idx].xpath,
                                                &value);

        if (res == 0)
        {
            fprintf(stdout, "%s: %s\n",
                    values[idx].print_name,
                    value);
            CGUTILS_FREE(value);
        }
        else if (res != ENOENT)
        {
            fprintf(stderr, "Error getting value for %s: %s\n",
                    values[idx].print_name,
                    strerror(res));
        }
    }
}

static void print_openstack_instance(cgutils_xml_reader * const inst)
{
    static struct
    {
        char const * const print_name;
        char const * const xpath;
    }
    const values[] =
        {
            { "Identity Version", "Specifics/IdentityVersion"},
            { "Authentication Format", "Specifics/AuthenticationFormat"},
            { "Authentication Endpoint", "Specifics/AuthenticationEndpoint"},
            { "Container", "Specifics/Container"},
            { "Allow Insecure HTTPS", "Specifics/AllowInsecureHTTPS"},
        };
    static size_t const values_count = sizeof values / sizeof *values;
    assert(inst != NULL);

    for (size_t idx = 0;
         idx < values_count;
         idx++)
    {
        char * value = NULL;

        int res = cgutils_xml_reader_get_string(inst,
                                                values[idx].xpath,
                                                &value);

        if (res == 0)
        {
            fprintf(stdout, "%s: %s\n",
                    values[idx].print_name,
                    value);
            CGUTILS_FREE(value);
        }
        else if (res != ENOENT)
        {
            fprintf(stderr, "Error getting value for %s: %s\n",
                    values[idx].print_name,
                    strerror(res));
        }
    }
}

static void print_compression_filter(cgutils_xml_reader * const filter)
{
    static struct
    {
        char const * const print_name;
        char const * const xpath;
    }
    const values[] =
        {
            { "Level", "Specifics/Level"},
        };
    static size_t const values_count = sizeof values / sizeof *values;
    assert(filter != NULL);

    for (size_t idx = 0;
         idx < values_count;
         idx++)
    {
        char * value = NULL;
        int res = cgutils_xml_reader_get_string(filter,
                                                values[idx].xpath,
                                                &value);

        if (res == 0)
        {
            fprintf(stdout, "%s: %s\n",
                    values[idx].print_name,
                    value);
            CGUTILS_FREE(value);
        }
        else if (res != ENOENT)
        {
            fprintf(stderr, "Error getting value for %s: %s\n",
                    values[idx].print_name,
                    strerror(res));
        }
    }
}

static void print_encryption_filter(cgutils_xml_reader * const filter)
{
    static struct
    {
        char const * const print_name;
        char const * const xpath;
    }
    const values[] =
        {
            { "Cipher", "Specifics/Cipher"},
            { "Digest", "Specifics/Digest"},
            { "Key Iteration Count", "Specifics/KeyIterationCount"},
        };
    static size_t const values_count = sizeof values / sizeof *values;
    assert(filter != NULL);

    for (size_t idx = 0;
         idx < values_count;
         idx++)
    {
        char * value = NULL;
        int res = cgutils_xml_reader_get_string(filter,
                                                values[idx].xpath,
                                                &value);

        if (res == 0)
        {
            fprintf(stdout, "%s: %s\n",
                    values[idx].print_name,
                    value);
            CGUTILS_FREE(value);
        }
        else if (res != ENOENT)
        {
            fprintf(stderr, "Error getting value for %s: %s\n",
                    values[idx].print_name,
                    strerror(res));
        }
    }
}

static void print_filter(cgutils_xml_reader * const filter)
{
    static struct
    {
        char const * const print_name;
        char const * const xpath;
    }
    const values[] =
        {
            { "Enabled", "Enabled"},
        };
    static size_t const values_count = sizeof values / sizeof *values;
    char * type = NULL;
    int res = cgutils_xml_reader_get_string(filter,
                                            "Type",
                                            &type);
    assert(filter != NULL);

    if (res == 0)
    {
        fprintf(stdout, "Type: %s\n",
                type);

        for (size_t idx = 0;
             idx < values_count;
             idx++)
        {
            char * value = NULL;

            res = cgutils_xml_reader_get_string(filter,
                                                values[idx].xpath,
                                                &value);

            if (res == 0)
            {
                fprintf(stdout, "%s: %s\n",
                        values[idx].print_name,
                        value);
                CGUTILS_FREE(value);
            }
            else if (res != ENOENT)
            {
                fprintf(stderr, "Error getting value for %s: %s\n",
                        values[idx].print_name,
                        strerror(res));
            }
        }

        if (strcasecmp(type, "Compression") == 0)
        {
            print_compression_filter(filter);
        }
        else if (strcasecmp(type, "Encryption") == 0)
        {
            print_encryption_filter(filter);
        }

        CGUTILS_FREE(type);
    }
    else if (res != ENOENT)
    {
        fprintf(stderr, "Error getting value for Type: %s\n",
                strerror(res));
    }
}

static void print_instance(cgutils_xml_reader * const inst)
{
    static struct
    {
        char const * const print_name;
        char const * const xpath;
    }
    const values[] =
        {
            { "Name", "Name"},
        };
    static size_t const values_count = sizeof values / sizeof *values;
    cgutils_llist * filters_list = NULL;
    char * value = NULL;
    int res = 0;

    assert(inst != NULL);

    for (size_t idx = 0;
         idx < values_count;
         idx++)
    {
        res = cgutils_xml_reader_get_string(inst,
                                            values[idx].xpath,
                                            &value);

        if (res == 0)
        {
            fprintf(stdout, "%s: %s\n",
                    values[idx].print_name,
                    value);
            CGUTILS_FREE(value);
        }
        else if (res != ENOENT)
        {
            fprintf(stderr, "Error getting value for %s: %s\n",
                    values[idx].print_name,
                    strerror(res));
        }
    }

    res = cgutils_xml_reader_get_string(inst,
                                        "Provider",
                                        &value);

    if (res == 0)
    {
        fprintf(stdout, "Provider: %s\n",
                value);

        if (strcasecmp(value, "Amazon") == 0)
        {
            print_s3_instance(inst);
        }
        else if (strcasecmp(value, "Openstack") == 0)
        {
            print_openstack_instance(inst);
        }

        CGUTILS_FREE(value);
    }
    else if (res != ENOENT)
    {
        fprintf(stderr, "Error getting value for Provider: %s\n",
                strerror(res));
    }

    res = cgutils_xml_reader_get_all(inst,
                                     "Filters/Filter",
                                     &filters_list);

    if (res == 0)
    {
        for (cgutils_llist_elt * elt = cgutils_llist_get_first(filters_list);
             elt != NULL;
             elt = cgutils_llist_elt_get_next(elt))
        {
            cgutils_xml_reader * filter = cgutils_llist_elt_get_object(elt);

            fprintf(stdout, "\nFilter:\n");

            print_filter(filter);
        }

        cgutils_llist_free(&filters_list, &cgutils_xml_reader_delete);
    }
}

int main (int argc, char **argv)
{

#define ITEM(longname, variable, shortname, xmlname, required, expl) char * variable = NULL;
#include "cg_config_show_instance.itm"
#undef ITEM

    static struct option const long_options[] =
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl) { longname, required_argument, NULL, shortname },
#include "cg_config_show_instance.itm"
#undef ITEM
            { 0, 0, 0, 0 }
        };

    int result = 0;
    int indexptr = 0;

    opterr = 1;

    while ((result = getopt_long(argc,
                                 argv,
                                 "+i:f:",
                                 long_options,
                                 &indexptr)) != -1)
    {
        switch(result)
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl)  \
            case shortname:                                           \
                variable = optarg;                                    \
                break;
#include "cg_config_show_instance.itm"
#undef ITEM
        default:
            print_usage();
        }

    }

    if (optind == argc)
    {
        if (instance_name != NULL &&
            file != NULL)
        {
            cgutils_xml_reader * reader = NULL;

            cgutils_xml_init();

            result = cgutils_xml_reader_from_file(file,
                                                  &reader);

            if (result == 0)
            {
                char * xpath = NULL;

                result = cgutils_asprintf(&xpath,
                                          "/Configuration/Instances/Instance[Name='%s']",
                                          instance_name);

                if (result == 0)
                {
                    cgutils_xml_reader * inst = NULL;

                    result = cgutils_xml_reader_from_path(reader,
                                                          xpath,
                                                          &inst);

                    if (result == 0)
                    {
                        print_instance(inst);

                        cgutils_xml_reader_free(inst), inst = NULL;
                    }
                    else if (result == ENOENT)
                    {
                        fprintf(stderr, "There is no instance named %s.\n",
                                instance_name);
                    }
                    else
                    {
                        fprintf(stderr, "Error looking for an instance named %s: %s\n",
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

                cgutils_xml_reader_free(reader), reader = NULL;
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
            fprintf(stderr, "Name and file parameters are mandatory.\n");
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
