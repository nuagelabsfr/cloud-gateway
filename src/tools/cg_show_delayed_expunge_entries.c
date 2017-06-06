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
#include <cloudutils/cloudutils_json_writer.h>
#include <cloudutils/cloudutils_llist.h>
#include <cloudutils/cloudutils_system.h>

#include <cgsm/cg_storage_filesystem.h>
#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>

#include "common.h"
#include "delayed_entries_common.h"

static char const * json_output_file = NULL;

static int add_db_entry_to_json(cgutils_json_writer_element * const parent,
                                cgdb_delayed_expunge_entry const * const delayed_entry)
{
    int result = 0;
    CGUTILS_ASSERT(parent != NULL);
    CGUTILS_ASSERT(delayed_entry != NULL);
    cgutils_json_writer_element * entry_elt = NULL;

    result = cgutils_json_writer_new_element(&entry_elt);

    if (result == 0)
    {
        cgdb_entry const * const entry = &(delayed_entry->entry);
        cgdb_inode const * const inode = &(entry->inode);
        char * uid = NULL;
        char * gid = NULL;
        char * rights = NULL;
        char * deletion_time = NULL;
        char * delete_after = NULL;
        char * mtime = NULL;

        delayed_entry_to_str(delayed_entry,
                             &uid,
                             &gid,
                             &rights,
                             &deletion_time,
                             &delete_after,
                             &mtime);

        if (result == 0 &&
            delayed_entry->full_path != NULL)
        {
            result = cgutils_json_writer_element_add_string_prop(entry_elt,
                                                                 "path",
                                                                 delayed_entry->full_path);
        }

        if (result == 0)
        {
            result = cgutils_json_writer_element_add_uint64_prop(entry_elt,
                                                                 "inode-number",
                                                                 inode->inode_number);
        }

        if (result == 0)
        {
            result = cgutils_json_writer_element_add_uint64_prop(entry_elt,
                                                                 "size",
                                                                 (size_t) inode->st.st_size);
        }


        if (result == 0 &&
            uid != NULL)
        {
            result = cgutils_json_writer_element_add_string_prop(entry_elt,
                                                                 "uid",
                                                                 uid);
        }

        if (result == 0 &&
            gid != NULL)
        {
            result = cgutils_json_writer_element_add_string_prop(entry_elt,
                                                                 "gid",
                                                                 gid);
        }

        if (result == 0 &&
            rights != NULL)
        {
            result = cgutils_json_writer_element_add_string_prop(entry_elt,
                                                                 "rights",
                                                                 rights);
        }

        if (result == 0 &&
            mtime != NULL)
        {
            result = cgutils_json_writer_element_add_uint64_prop(entry_elt,
                                                                 "mtime",
                                                                 (uint64_t) inode->st.st_mtime);
        }

        if (result == 0 &&
            deletion_time != NULL)
        {
            result = cgutils_json_writer_element_add_uint64_prop(entry_elt,
                                                                 "deletion-time",
                                                                 delayed_entry->deletion_time);
        }

        if (result == 0 &&
            delete_after != NULL)
        {
            result = cgutils_json_writer_element_add_uint64_prop(entry_elt,
                                                                 "delete-after",
                                                                 delayed_entry->delete_after);
        }

        if (result == 0)
        {
            result = cgutils_json_writer_add_element_to_list(parent,
                                                             entry_elt);

            if (result == 0)
            {
                cgutils_json_writer_element_release(entry_elt), entry_elt = NULL;
            }
            else
            {
                cgutils_json_writer_element_free(entry_elt), entry_elt = NULL;
            }
        }
        else
        {
            cgutils_json_writer_element_free(entry_elt), entry_elt = NULL;
        }

        CGUTILS_FREE(uid);
        CGUTILS_FREE(gid);
        CGUTILS_FREE(rights);
        CGUTILS_FREE(deletion_time);
        CGUTILS_FREE(delete_after);
        CGUTILS_FREE(mtime);
    }
    else
    {
    }

    return result;
}

static int db_entries_json_cb(int const status,
                              /* llist of cgdb_delayed_expunge_entry * */
                              cgutils_llist * entries,
                              void * const cb_data)
{
    int result = status;
    cg_storage_manager_data * const data = cb_data;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(json_output_file != NULL);

    if (result == 0 ||
        result == ENOENT)
    {
        cgutils_json_writer * writer = NULL;

        result = cgutils_json_writer_new(&writer);

        if (result == 0)
        {
            cgutils_json_writer_element * root = cgutils_json_writer_get_root(writer);
            cgutils_json_writer_element * entries_elt = NULL;
            CGUTILS_ASSERT(root != NULL);

            result = cgutils_json_writer_element_add_list_child(root,
                                                                "entries",
                                                                &entries_elt);

            if (result == 0)
            {
                CGUTILS_ASSERT(entries_elt != NULL);

                if (entries != NULL &&
                    cgutils_llist_get_count(entries)> 0)
                {
                    for (cgutils_llist_elt * elt = cgutils_llist_get_first(entries);
                         elt != NULL &&
                             result == 0;
                         elt = cgutils_llist_elt_get_next(elt))
                    {
                        cgdb_delayed_expunge_entry const * const delayed_entry = cgutils_llist_elt_get_object(elt);
                        CGUTILS_ASSERT(delayed_entry != NULL);

                        result = add_db_entry_to_json(entries_elt,
                                                      delayed_entry);

                        if (result != 0)
                        {
                            CGUTILS_ERROR("Error adding entry to JSON document: %d", result);
                        }
                    }
                }


                cgutils_json_writer_element_release(entries_elt), entries_elt = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error creating list: %d", result);
            }

            if (result == 0)
            {
                char * out = NULL;
                size_t out_size = 0;

                result = cgutils_json_writer_get_output(writer,
                                                        &out,
                                                        &out_size);

                if (result == 0)
                {

                    result = cgutils_file_write_content_sync(json_output_file,
                                                             out,
                                                             out_size);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error writing to file %s: %d",
                                      json_output_file,
                                      result);
                    }

                    CGUTILS_FREE(out);
                }
                else
                {
                    CGUTILS_ERROR("Error getting JSON output: %d", result);
                }
            }

            cgutils_json_writer_free(writer), writer = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error creating JSON writer: %d", result);
        }
    }
    else
    {
        fprintf(stderr,
                "Error looking for delayed entries: %s\n",
                strerror(result));
    }

    if (entries != NULL)
    {
        cgutils_llist_free(&entries, &cgdb_delayed_expunge_entry_delete);
    }

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    cgutils_event_exit_loop(event_data);

    return result;
}

static int db_entries_cb(int const status,
                         /* llist of cgdb_delayed_expunge_entry * */
                         cgutils_llist * entries,
                         void * const cb_data)
{
    int result = status;
    cg_storage_manager_data * const data = cb_data;
    assert(data != NULL);

    if (result == 0)
    {
        if (entries != NULL &&
            cgutils_llist_get_count(entries)> 0)
        {
            delayed_entries_common_print_header();

            for (cgutils_llist_elt * elt = cgutils_llist_get_first(entries);
                 elt != NULL && result == 0;
                 elt = cgutils_llist_elt_get_next(elt))
            {
                cgdb_delayed_expunge_entry const * const delayed_entry = cgutils_llist_elt_get_object(elt);

                delayed_entries_common_print_entry(delayed_entry);
            }
        }
    }
    else if (result == ENOENT)
    {
    }
    else
    {
        fprintf(stderr,
                "Error looking for delayed entries: %s\n",
                strerror(result));
    }

    if (entries != NULL)
    {
        cgutils_llist_free(&entries, &cgdb_delayed_expunge_entry_delete);
    }

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    cgutils_event_exit_loop(event_data);

    return result;
}

static void print_usage(void)
{
    fprintf(stderr, "Usage: CloudGatewayShowDelayedExpungeEntries [OPTIONS]\n");
    fprintf(stderr, "Required options are:\n");
#define ITEM(longname, variable, shortname, required, expl)             \
    if (required == true)                                               \
    {                                                                   \
        fprintf(stderr, "\t-%c --%-35s %s\n", shortname, longname, expl); \
    }
#include "cg_show_delayed_expunge_entries.itm"
#undef ITEM
    fprintf(stderr, "Others options:\n");
#define ITEM(longname, variable, shortname, required, expl)             \
    if (required == false)                                              \
    {                                                                   \
        fprintf(stderr, "\t-%c --%-35s %s\n", shortname, longname, expl); \
    }
#include "cg_show_delayed_expunge_entries.itm"
#undef ITEM
    fprintf(stderr, "Please look at the product documentation for more information.\n");
}

int main(int argc, char ** argv)
{
#define ITEM(longname, variable, shortname, required, expl) char * variable = NULL;
#include "cg_show_delayed_expunge_entries.itm"
#undef ITEM

    static struct option const long_options[] =
        {
#define ITEM(longname, variable, shortname, required, expl) { longname, required_argument, NULL, shortname },
#include "cg_show_delayed_expunge_entries.itm"
#undef ITEM
            { 0, 0, 0, 0 }
        };

    int result = 0;
    int indexptr = 0;

    opterr = 1;

    while ((result = getopt_long(argc,
                                 argv,
                                 "+i:f:p:d:j:",
                                 long_options,
                                 &indexptr)) != -1)
    {
        switch(result)
        {
#define ITEM(longname, variable, shortname, required, expl)           \
            case shortname:                                           \
                variable = optarg;                                    \
                break;
#include "cg_show_delayed_expunge_entries.itm"
#undef ITEM
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
                                    uint64_t deleted_after_time = 0;

                                    if (deleted_after != NULL)
                                    {
                                        result = cgutils_str_to_unsigned_int64(deleted_after,
                                                                               &deleted_after_time);
                                    }

                                    if (result == 0)
                                    {
                                        json_output_file = json_export;

                                        result = cg_storage_filesystem_entry_get_delayed_entries(fs,
                                                                                                 full_path != NULL ? full_path : "%",
                                                                                                 deleted_after_time,
                                                                                                 json_export != NULL ? &db_entries_json_cb : &db_entries_cb,
                                                                                                 data);

                                        if (result == 0)
                                        {
                                            cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
                                            assert(event_data != NULL);

                                            cgutils_event_dispatch(event_data);
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
                                                "Error parsing date: %s\n",
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
