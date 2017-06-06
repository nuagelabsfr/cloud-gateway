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
   -t --type type (default to "PG") (required)
   -c --connection-string Connection String
   -u --user User
   -h --host Host
   -H --host-addr Host Numeric Address
   -p --port Port
   -P --password Password
   -b --database Database
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

static void print_usage(char const * const prog_name)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n", prog_name);
    fprintf(stderr, "Required options are:\n");
#define ITEM(longname, variable, shortname, required)           \
    if (required == true)                                       \
    {                                                           \
        fprintf(stderr, "\t-%c %s \n", shortname, longname);    \
    }
#include "cg_config_db_params.itm"
#undef ITEM
    fprintf(stderr, "Optional options are:\n");
#define ITEM(longname, variable, shortname, required)           \
    if (required == false)                                      \
    {                                                           \
        fprintf(stderr, "\t-%c %s \n", shortname, longname);    \
    }
#include "cg_config_db_params.itm"
#undef ITEM
}

int main (int argc, char **argv)
{
#define ITEM(longname, variable, shortname, required) char * variable = NULL;
#include "cg_config_db_params.itm"
#undef ITEM

    static struct option const long_options[] =
        {
#define ITEM(longname, variable, shortname, required) { longname, required_argument, NULL, shortname },
#include "cg_config_db_params.itm"
#undef ITEM
            { 0, 0, 0, 0 }
        };

    int result = 0;
    int indexptr = 0;

    opterr = 1;


    while ((result = getopt_long(argc,
                                 argv,
                                 "+c:t:u:h:H:p:P:d:f:",
                                 long_options,
                                 &indexptr)) != -1)
    {
        switch(result)
        {
#define ITEM(longname, variable, shortname, required)   \
            case shortname:                             \
                variable = optarg;                      \
                break;
#include "cg_config_db_params.itm"
#undef ITEM
        default:
            print_usage(argv[0]);
        }

    }

    if (optind == argc)
    {
        if (type != NULL &&
            file != NULL)
        {
            cgutils_xml_writer * writer = NULL;

            cgutils_xml_init();

            result = cgutils_xml_writer_from_file(file,
                                                  &writer);

            if (result == 0)
            {
                assert(writer != NULL);

                result = cgutils_xml_writer_set_element_value(writer,
                                                              "/Configuration/DB/Type",
                                                              type);

                if (result == 0)
                {
                    bool connection_string_allocated = false;

                    if (user != NULL &&
                        (host != NULL || host_addr != NULL) &&
                        database != NULL)
                    {
                        result = cgutils_asprintf(&connection_string,
                                                  "%s=%s port=%s user=%s dbname=%s %s%s%s%s",
                                                  host != NULL ? "host" : "hostaddr",
                                                  host != NULL ? host : host_addr,
                                                  port != NULL ? port : "5432",
                                                  user,
                                                  database,
                                                  password != NULL ? "password" : "",
                                                  password != NULL ? "='" : "",
                                                  password != NULL ? password : "",
                                                  password != NULL ? "'" : "");

                        if (result == 0)
                        {
                            connection_string_allocated = true;
                        }
                        else
                        {
                            fprintf(stderr,
                                    "Error allocate memory for the connection string: %s\n",
                                    strerror(result));
                        }
                    }

                    if (result == 0)
                    {
                        if (connection_string != NULL)
                        {
                            result = cgutils_xml_writer_set_element_value(writer,
                                                                          "/Configuration/DB/Specifics/ConnectionString",
                                                                          connection_string);

                            if (result != 0)
                            {
                                fprintf(stderr,
                                        "Error setting connection string to %s: %s\n",
                                        connection_string,
                                        strerror(result));
                            }
                        }
                        else
                        {
                            result = EINVAL;
                            fprintf(stderr,
                                    "A connection string or a user, host (or host addr) and database are mandatory.\n");
                            print_usage(argv[0]);
                        }
                    }

                    int res = cgutils_xml_writer_save(writer);

                    if (res != 0)
                    {
                        fprintf(stderr,
                                "Error writing the configuration to file %s: %s\n",
                                file,
                                strerror(res));
                    }

                    if (connection_string_allocated == true)
                    {
                        CGUTILS_FREE(connection_string);
                    }
                }
                else
                {
                    fprintf(stderr,
                            "Error setting type to %s: %s\n",
                            type,
                            strerror(result));
                }

                cgutils_xml_writer_free(writer), writer = NULL;
            }
            else
            {
                fprintf(stderr,
                        "Error opening file %s: %s\n",
                        file,
                        strerror(result));
            }

            cgutils_xml_destroy();
        }
        else
        {
            result = EINVAL;
            fprintf(stderr, "Type and file parameters are mandatory.\n");
            print_usage(argv[0]);
        }
    }
    else
    {
        result = EINVAL;
        fprintf(stderr, "Too many arguments\n");
        print_usage(argv[0]);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
