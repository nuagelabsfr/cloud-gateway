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
#include <stdio.h>
#include <string.h>

#include <cgdb/cgdb.h>
#include <cloudutils/cloudutils_advanced_file_ops.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_llist.h>
#include <cloudutils/cloudutils_system.h>

#include <cgsm/cg_storage_filesystem.h>
#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>

#include "common.h"
#include "delayed_entries_common.h"

/* llist of cgdb_delayed_expunge_entry * */
static cgutils_llist * global_expired_entries = NULL;
static cgutils_llist_elt * global_current_elt = NULL;
static cg_storage_object * global_current_object = NULL;

static bool global_verbose = false;

static int expired_entry_removed_cb(int const status,
                                    void * cb_data);

static int remove_entry(cgdb_delayed_expunge_entry * const entry,
                        cg_storage_manager_data * const data)
{
    CGUTILS_ASSERT(entry != NULL);
    CGUTILS_ASSERT(data != NULL);

    cg_storage_filesystem * fs = NULL;
    int result = cg_storage_manager_data_get_filesystem_by_id(data,
                                                              entry->entry.fs_id,
                                                              &fs);

    if (result == 0)
    {
        result = cg_storage_object_init_from_entry(fs,
                                                   &(entry->entry),
                                                   &global_current_object);

        if (result == 0)
        {
            if (global_verbose == true)
            {
                delayed_entries_common_print_entry(entry);
            }

            result = cg_storage_filesystem_entry_remove_delayed_entry(fs,
                                                                      global_current_object,
                                                                      &expired_entry_removed_cb,
                                                                      data);

            if (result != 0)
            {
                fprintf(stderr,
                        "Error removing delayed entry: %s\n",
                        strerror(result));

                CGUTILS_FREE(global_current_object);
            }
        }
        else
        {
            fprintf(stderr,
                    "Error getting object from delayed entry: %s\n",
                    strerror(result));
        }
    }
    else
    {
        fprintf(stderr,
                "Error getting filesystem by id: %s\n",
                strerror(result));
    }

    return result;
}

static int expired_entry_removed_cb(int const status,
                                    void * cb_data)
{
    bool pending = false;
    int result = status;
    cg_storage_manager_data * data = cb_data;
    CGUTILS_ASSERT(data != NULL);

    cg_storage_object_free(global_current_object), global_current_object = NULL;

    if (result == 0)
    {
        global_current_elt = cgutils_llist_elt_get_next(global_current_elt);

        if (global_current_elt != NULL)
        {
            cgdb_delayed_expunge_entry * entry = cgutils_llist_elt_get_object(global_current_elt);
            CGUTILS_ASSERT(entry != NULL);

            result = remove_entry(entry,
                                  data);

            if (result == 0)
            {
                pending = true;
            }
        }
    }
    else
    {
        fprintf(stderr,
                "Error removing expired entry: %s\n",
                strerror(result));
    }

    if (pending == false)
    {
        cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
        assert(event_data != NULL);

        cgutils_event_exit_loop(event_data);
    }

    return result;
}

static int expired_entries_cb(int const status,
                              /* llist of cgdb_delayed_expunge_entry * */
                              cgutils_llist * expired_entries,
                              void * cb_data)
{
    int result = status;
    bool pending = false;
    cg_storage_manager_data * data = cb_data;
    CGUTILS_ASSERT(data != NULL);

    if (result == 0)
    {
        global_expired_entries = expired_entries;

        if (expired_entries != NULL &&
            cgutils_llist_get_count(global_expired_entries) > 0)
        {
            if (global_verbose == true)
            {
                delayed_entries_common_print_header();
            }

            global_current_elt = cgutils_llist_get_first(global_expired_entries);

            if (global_current_elt != NULL)
            {
                cgdb_delayed_expunge_entry * entry = cgutils_llist_elt_get_object(global_current_elt);
                CGUTILS_ASSERT(entry != NULL);

                result = remove_entry(entry,
                                      data);

                if (result == 0)
                {
                    pending = true;
                }
            }
        }

        if (result != 0 ||
            pending == false)
        {
            cgutils_llist_free(&global_expired_entries, &cgdb_delayed_expunge_entry_delete);
        }
    }
    else
    {
        fprintf(stderr,
                "Error getting expired delayed entries: %s\n",
                strerror(result));
    }

    if (pending == false)
    {
        cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
        assert(event_data != NULL);

        cgutils_event_exit_loop(event_data);
    }

    return result;
}

static void print_usage(void)
{
    fprintf(stderr, "Usage: CloudGatewayExpungeDelayedEntries [OPTIONS]\n");
    fprintf(stderr, "Required parameters are:\n");
#define ITEM(longname, variable, shortname, required, expl)             \
    if (required == true)                                               \
    {                                                                   \
        fprintf(stderr, "\t-%c --%-35s %s\n", shortname, longname, expl); \
    }
#include "cg_expunge_delayed_entries.itm"
#undef ITEM
    fprintf(stderr, "Options are:\n");
#define ITEM(longname, variable, shortname, required, expl)             \
    if (required == false)                                              \
    {                                                                   \
        fprintf(stderr, "\t-%c --%-35s %s\n", shortname, longname, expl); \
    }
    fprintf(stderr, "\t-%c --%-35s %s\n", 'v', "verbose", "Verbose");
#include "cg_expunge_delayed_entries.itm"
#undef ITEM
    fprintf(stderr, "Please look at the product documentation for more information.\n");
}

int main(int argc, char ** argv)
{
#define ITEM(longname, variable, shortname, required, expl) char * variable = NULL;
#include "cg_expunge_delayed_entries.itm"
#undef ITEM

    static struct option const long_options[] =
        {
#define ITEM(longname, variable, shortname, required, expl) { longname, required_argument, NULL, shortname },
#include "cg_expunge_delayed_entries.itm"
#undef ITEM
            { "verbose", no_argument, NULL, 'v' },
            { 0, 0, 0, 0 }
        };

    int result = 0;
    int indexptr = 0;

    opterr = 1;

    while ((result = getopt_long(argc,
                                 argv,
                                 "+i:f:v",
                                 long_options,
                                 &indexptr)) != -1)
    {
        switch(result)
        {
#define ITEM(longname, variable, shortname, required, expl)           \
            case shortname:                                           \
                variable = optarg;                                    \
                break;
#include "cg_expunge_delayed_entries.itm"
#undef ITEM
        case 'v':
            global_verbose = true;
            break;
        default:
            print_usage();
        }

    }

    if (optind == argc)
    {
        if (fs_name != NULL &&
            file != NULL)
        {
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
                            result = cg_storage_manager_setup(data,
                                                              false);

                            if (result == 0)
                            {
                                cg_storage_filesystem * fs = NULL;

                                result = cg_storage_manager_data_get_filesystem(data,
                                                                                fs_name,
                                                                                &fs);

                                if (result == 0)
                                {
                                    result = cg_storage_filesystem_entry_get_expired_delayed_entries(fs,
                                                                                                     &expired_entries_cb,
                                                                                                     data);

                                    if (result == 0)
                                    {
                                        cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
                                        assert(event_data != NULL);

                                        cgutils_event_dispatch(event_data);

                                        if (global_expired_entries != NULL)
                                        {
                                            cgutils_llist_free(&global_expired_entries, &cgdb_delayed_expunge_entry_delete);
                                        }
                                    }
                                    else
                                    {
                                        fprintf(stderr,
                                                "Error getting entries: %s\n",
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

    cgutils_file_fclose(stdin);
    cgutils_file_fclose(stdout);
    cgutils_file_fclose(stderr);

    return result;
}
