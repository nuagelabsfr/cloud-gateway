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
   -n --name Name (required)
   -P --provider provider (required) Amazon, Openstack
   -a --access-key-id Access Key ID (required for type Amazon)
   -s --secret-access-key Secret Access Key (required for type Amazon)
   -e --endpoint Endpoint (required for type Amazon)
   -g --endpoint-port Endpoint port (required for type Amazon)
   -b --bucket Bucket (required for type Amazon)
   -S --secure-transaction Whether to use HTTPs (required for Amazon)
   -i --identity-version Identity Version for Openstack (default to 2)
   -u --user-name Username (required for Openstack)
   -p --password Password (required for Openstack v2)
   -t --tenant-id Tenant ID
   -T --tenant-name Tenant Name
   -I --api-access-key (required for Openstack v1)
   -A --authentication-endpoint Authentication Endpoint (required for Openstack)
   -c --container Container (required for Openstack)
   -r --preferred-region Preferred region to use with Openstack, if any
   -m --authentication-max-life-time Authentication max lifetime for an Openstack token
   -R --authentication-token-recent-delay (Openstack)
   -F --authentication-format (Openstack)
   -k --allow-insecure Allow insecure (invalid certificate) communication

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
    fprintf(stderr, "Usage: CloudGatewayAddInstance [OPTIONS]\n");
    fprintf(stderr, "Required options are:\n");
#define ITEM(longname, variable, shortname, xmlname, required, expl)     \
    if (required == true)                                       \
    {                                                           \
        fprintf(stderr, "\t-%c --%-35s %s\n", shortname, longname, expl);  \
    }
#include "cg_config_create_instance.itm"
#undef ITEM
    fprintf(stderr, "Optional options are:\n");
#define ITEM(longname, variable, shortname, xmlname, required, expl)     \
    if (required == false)                                      \
    {                                                           \
        fprintf(stderr, "\t-%c --%-35s %s\n", shortname, longname, expl);  \
    }
#include "cg_config_create_instance.itm"
#undef ITEM
    fprintf(stderr, "Please look at the product documentation for more information.\n");
}

int main (int argc, char **argv)
{

#define ITEM(longname, variable, shortname, xmlname, required, expl) char * variable = NULL;
#include "cg_config_create_instance.itm"
#undef ITEM

    static struct option const long_options[] =
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl) { longname, required_argument, NULL, shortname },
#include "cg_config_create_instance.itm"
#undef ITEM
            { 0, 0, 0, 0 }
        };

    int result = 0;
    int indexptr = 0;

    opterr = 1;

    while ((result = getopt_long(argc,
                                 argv,
                                 "+n:P:a:s:e:g:b:S:i:u:p:t:T:I:A:c:k:r:m:R:F:f:",
                                 long_options,
                                 &indexptr)) != -1)
    {
        switch(result)
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl)  \
            case shortname:                                           \
                variable = optarg;                                    \
                break;
#include "cg_config_create_instance.itm"
#undef ITEM
        default:
            print_usage();
        }

    }

    if (optind == argc)
    {
        if (name != NULL &&
            provider != NULL &&
            file != NULL)
        {
            bool amazon = false;
            bool openstack = false;

            if (strcmp(provider, "Amazon") == 0)
            {
                if (access_key_id != NULL &&
                    secret_access_key != NULL &&
                    endpoint != NULL &&
                    endpoint_port != NULL &&
                    bucket != NULL &&
                    secure_transaction != NULL)
                {
                    result = 0;
                    amazon = true;
                }
                else
                {
                    fprintf(stderr, "Error, at least one parameter is missing for an Amazon instance. Required parameters are:\n"
                            "\t access-key-id: %s\n"
                            "\t secret-access-key: %s\n"
                            "\t endpoint: %s\n"
                            "\t endpoint_port: %s\n"
                            "\t bucket: %s\n"
                            "\t secure-transaction: %s\n",
                            access_key_id ?: "",
                            secret_access_key ?: "",
                            endpoint ?: "",
                            endpoint_port ?: "",
                            bucket ?: "",
                            secure_transaction ?: "");
                    result = EINVAL;
                }
            }
            else if (strcmp(provider, "Openstack") == 0)
            {
                if (identity_version != NULL &&
                    user_name != NULL &&
                    authentication_endpoint != NULL &&
                    container != NULL)
                {
                    openstack = true;
                    result = 0;
                }
                else
                {
                    fprintf(stderr, "Error, at least one parameter is missing for an Openstack instance. Required parameters are:\n"
                            "\t identity-version: %s\n"
                            "\t user-name: %s\n"
                            "\t authentication-endpoint: %s\n"
                            "\t container: %s\n",
                            identity_version ?: "",
                            user_name ?: "",
                            authentication_endpoint ?: "",
                            container ?: "");
                    result = EINVAL;
                }
            }
            else
            {
                fprintf(stderr, "Unknown provider %s, supported providers are Amazon and Openstack.\n", provider);
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
                    cgutils_xml_writer_element * instances = NULL;

                    assert(writer != NULL);

                    result = cgutils_xml_writer_get_element_from_path(writer,
                                                                      "/Configuration/Instances",
                                                                      &instances);
                    if (result == 0)
                    {
                        cgutils_xml_writer_element * instance_elt = NULL;
                        cgutils_xml_writer_element * specifics_elt = NULL;

                        result = cgutils_xml_writer_element_add_child(instances,
                                                                      "Instance",
                                                                      NULL,
                                                                      &instance_elt);

                        if (result == 0)
                        {
                            cgutils_xml_writer_element * name_elt = NULL;

                            result = cgutils_xml_writer_element_add_child(instance_elt,
                                                                          "Name",
                                                                          name,
                                                                          &name_elt);

                            if (result == 0)
                            {
                                cgutils_xml_writer_element_release(name_elt), name_elt = NULL;
                            }
                            else
                            {
                                fprintf(stderr, "Error creating name element: %d\n", result);
                            }
                        }

                        if (result == 0)
                        {
                            cgutils_xml_writer_element * provider_elt = NULL;

                            result = cgutils_xml_writer_element_add_child(instance_elt,
                                                                          "Provider",
                                                                          provider,
                                                                          &provider_elt);

                            if (result == 0)
                            {
                                cgutils_xml_writer_element_release(provider_elt), provider_elt = NULL;
                            }
                            else
                            {
                                fprintf(stderr, "Error creating provider element: %d\n", result);
                            }
                        }

                        if (result == 0)
                        {
                            result = cgutils_xml_writer_element_add_child(instance_elt,
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
                            if (allow_insecure != NULL)
                            {
                                cgutils_xml_writer_element * elt = NULL;

                                result = cgutils_xml_writer_element_add_child(specifics_elt,
                                                                              "AllowInsecureHTTPS",
                                                                              allow_insecure,
                                                                              &elt);

                                if (result == 0)
                                {
                                    cgutils_xml_writer_element_release(elt), elt = NULL;
                                }
                                else
                                {
                                    fprintf(stderr, "Error while adding specifics AllowInsecureHTTPS: %d\n", result);
                                }
                            }

                            if (amazon == true)
                            {
                                cgutils_xml_writer_element * elt = NULL;

#define ITEM(longname, variable, shortname, xmlname, required, expl)    \
                                if (result == 0 &&                      \
                                    variable != NULL)                   \
                                {                                       \
                                    result = cgutils_xml_writer_element_add_child(specifics_elt, \
                                                                                  xmlname, \
                                                                                  variable, \
                                                                                  &elt); \
                                                                        \
                                    if (result == 0)                    \
                                    {                                   \
                                            cgutils_xml_writer_element_release(elt), elt = NULL; \
                                    }                                   \
                                    else                                \
                                    {                                   \
                                        fprintf(stderr, "Error while adding specifics %s: %d\n", xmlname, result); \
                                    }                                   \
                                }
#include "cg_config_create_amazon_instance.itm"
#undef ITEM
                            }
                            else if (openstack == true)
                            {
                                cgutils_xml_writer_element * elt = NULL;

#define ITEM(longname, variable, shortname, xmlname, required, expl)    \
                                if (result == 0 &&                      \
                                    variable != NULL)                   \
                                {                                       \
                                    result = cgutils_xml_writer_element_add_child(specifics_elt, \
                                                                                  xmlname, \
                                                                                  variable, \
                                                                                  &elt); \
                                                                        \
                                    if (result == 0)                    \
                                    {                                   \
                                            cgutils_xml_writer_element_release(elt), elt = NULL; \
                                    }                                   \
                                    else                                \
                                    {                                   \
                                        fprintf(stderr, "Error while adding specifics %s\n: %d", xmlname, result); \
                                    }                                   \
                                }
#include "cg_config_create_openstack_instance.itm"
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
                        cgutils_xml_writer_element_release(instance_elt), instance_elt = NULL;
                    }
                    else
                    {
                        fprintf(stderr, "Error getting instances element: %s\n",
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
            fprintf(stderr, "Name, provider and file parameters are mandatory.\n");
            print_usage();
        }
    }
    else
    {
        result = EINVAL;
        print_usage();
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
