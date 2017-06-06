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
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <cgdb/cgdb.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_llist.h>
#include <cloudutils/cloudutils_system.h>

#include <cgsm/cg_storage_filesystem.h>
#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>

#include "common.h"

static char const * global_output_file = NULL;
static int copy_result = 0;
static bool override_existing_file = false;

static int path_ready_cb(int const status,
                         char * path,
                         void * cb_data)
{
    int result = status;
    cg_storage_manager_data * const data = cb_data;
    CGUTILS_ASSERT(data != NULL);
    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    CGUTILS_ASSERT(event_data != NULL);

    if (result == 0)
    {
        CGUTILS_ASSERT(global_output_file != NULL);

        result = cgutils_file_copy(path,
                                   global_output_file,
                                   override_existing_file);

        if (result != 0)
        {
            fprintf(stderr,
                    "Error while writing file to %s: %s\n",
                    global_output_file,
                    strerror(result));
        }
    }
    else
    {
        fprintf(stderr,
                "Error getting the file: %s\n",
                strerror(result));
    }

    CGUTILS_FREE(path);

    copy_result = result;

    cgutils_event_exit_loop(event_data);

    return result;
}

static void print_usage(void)
{
    fprintf(stderr, "Usage: CloudGatewayRetrieveDelayedExpungeEntry [OPTIONS]\n");
    fprintf(stderr, "Required options are:\n");
#define ITEM(longname, variable, shortname, required, expl)             \
    if (required == true)                                               \
    {                                                                   \
        fprintf(stderr, "\t-%c --%-35s %s\n", shortname, longname, expl); \
    }
#include "cg_retrieve_delayed_expunge_entry.itm"
#undef ITEM
    fprintf(stderr, "Optional options are:\n");
    fprintf(stderr, "\t-%c --%-35s %s\n", 'e', "override-existing-file", "Override an existing output file");
    fprintf(stderr, "Please look at the product documentation for more information.\n");
}

int main(int argc, char ** argv)
{
#define ITEM(longname, variable, shortname, required, expl) char * variable = NULL;
#include "cg_retrieve_delayed_expunge_entry.itm"
#undef ITEM

    static struct option const long_options[] =
        {
#define ITEM(longname, variable, shortname, required, expl) { longname, required_argument, NULL, shortname },
#include "cg_retrieve_delayed_expunge_entry.itm"
#undef ITEM
            { "override-existing-file", no_argument, NULL, 'e' },
            { 0, 0, 0, 0 }
        };

    int result = 0;
    int indexptr = 0;

    opterr = 1;

    while ((result = getopt_long(argc,
                                 argv,
                                 "+i:f:n:o:e",
                                 long_options,
                                 &indexptr)) != -1)
    {
        switch(result)
        {
        case 'e':
            override_existing_file = true;
            break;
#define ITEM(longname, variable, shortname, required, expl)           \
            case shortname:                                           \
                variable = optarg;                                    \
                break;
#include "cg_retrieve_delayed_expunge_entry.itm"
#undef ITEM
        default:
            print_usage();
        }

    }

    if (optind == argc)
    {
        if (fs_name != NULL &&
            file != NULL &&
            inode_number_str != NULL &&
            output_file != NULL)
        {
            global_output_file = output_file;

            result = cg_tools_init_all();

            if (result == 0)
            {
                cgutils_configuration * conf = NULL;

                result = cgutils_configuration_from_xml_file(file,
                                                             &conf);

                if (result == 0)
                {
                    cg_storage_manager_data * data = NULL;

                    result = cg_storage_manager_data_init(conf,
                                                          &data);

                    if (result == 0)
                    {
                        conf = NULL;

                        result = cg_storage_manager_load_configuration(data,
                                                                       true,
                                                                       true);

                        if (result == 0)
                        {
                            result = cg_storage_manager_setup(data, true);

                            if (result == 0)
                            {
                                cg_storage_filesystem * fs = NULL;

                                result = cg_storage_manager_data_get_filesystem(data,
                                                                                fs_name,
                                                                                &fs);

                                if (result == 0)
                                {
                                    uint64_t inode_number = 0;

                                    result = cgutils_str_to_unsigned_int64(inode_number_str,
                                                                           &inode_number);

                                    if (result == 0)
                                    {
                                        result = cg_storage_filesystem_file_inode_get_path_in_cache(fs,
                                                                                                    inode_number,
                                                                                                    O_RDONLY,
                                                                                                    &path_ready_cb,
                                                                                                    data);

                                        if (result == 0)
                                        {
                                            cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
                                            assert(event_data != NULL);

                                            cgutils_event_dispatch(event_data);

                                            result = copy_result;
                                        }
                                        else
                                        {
                                            fprintf(stderr,
                                                    "Error getting entry: %s\n",
                                                    strerror(result));
                                        }
                                    }
                                    else
                                    {
                                        fprintf(stderr,
                                                "Error parsing inode number: %s\n",
                                                strerror(result));
                                    }
                                }
                                else
                                {
                                    fprintf(stderr,
                                            "Error getting the filesystem named %s: %s\n",
                                            fs_name,
                                            strerror(result));
                                }
                            }
                            else
                            {
                                fprintf(stderr,
                                        "Error setting up configuration: %s\n",
                                        strerror(result));
                            }
                        }
                        else
                        {
                            fprintf(stderr,
                                    "Error loading configuration: %s\n",
                                    strerror(result));
                        }

                        cg_storage_manager_data_free(data), data = NULL;
                    }
                    else
                    {
                        fprintf(stderr,
                                "Error in config init: %s\n",
                                strerror(result));

                        cgutils_configuration_free(conf), conf = NULL;
                    }
                }
                else
                {
                    fprintf(stderr,
                            "Error loading configuration from file (%s): %s\n",
                            file,
                            strerror(result));
                }

                cg_tools_destroy_all();
            }
            else
            {
                fprintf(stderr,
                        "Error in cgutils_init_all(): %s\n",
                        strerror(result));
            }
        }
        else
        {
            print_usage();
        }
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
