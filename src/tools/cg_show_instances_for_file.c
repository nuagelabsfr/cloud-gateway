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
#include <stdio.h>
#include <string.h>

#include <cgdb/cgdb.h>
#include <cloudutils/cloudutils_llist.h>

#include <cgsm/cg_storage_instance.h>
#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>

#include "common.h"

static int db_entries_cb(int const status,
                         /* llist of cgdb_inode_instance * */
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
            fprintf(stdout, "%-20s %-45s %-15s %-10s %-10s %-10s %-10s\n",
                    "Instance",
                    "ID",
                    "Status",
                    "Uploading",
                    "Deleting",
//                    "Up fail.",
//                    "Dl fail.",
                    "Compressed",
                    "Encrypted");

            for (cgutils_llist_elt * elt = cgutils_llist_get_first(entries);
                 elt != NULL && result == 0;
                 elt = cgutils_llist_elt_get_next(elt))
            {
                cgdb_inode_instance const * const inode_inst = cgutils_llist_elt_get_object(elt);
                cg_storage_instance * inst = NULL;

                result = cg_storage_manager_data_get_instance_by_id(data,
                                                                    inode_inst->instance_id,
                                                                    &inst);

                if (result == 0)
                {
                    assert(inode_inst != NULL);

                    fprintf(stdout, "%-20s %-45s %-15s %-10s %-10s %-10s %-10s\n",
                            cg_storage_instance_get_name(inst),
                            inode_inst->id_in_instance,
                            cg_storage_instance_status_to_str(inode_inst->status),
                            (inode_inst->uploading == true ? "uploading" : "-"),
                            (inode_inst->deleting == true ? "deleting" : "-"),
//                            inode_inst->upload_failures,
//                            inode_inst->download_failures,
                            inode_inst->compressed == 0 ? "-" : "yes",
                            inode_inst->encrypted == 0 ? "-" : "yes");
                }
                else
                {
                    fprintf(stderr,
                            "Error looking for instance %"PRIu64": %s\n",
                            inode_inst->instance_id,
                            strerror(result));
                }
            }
        }
    }
    else if (result == ENOENT)
    {
    }
    else
    {
        fprintf(stderr,
                "Error looking for inode instances: %s\n",
                strerror(result));
    }

    if (entries != NULL)
    {
        cgutils_llist_free(&entries, &cgdb_inode_instance_delete);
    }

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    cgutils_event_exit_loop(event_data);

    return result;
}

static int entry_cb(int const status,
                    cg_storage_object const * const object,
                    void * cb_data)
{
    int result = status;
    cg_storage_manager_data * const data = cb_data;
    assert(cb_data != NULL);

    if (result == 0)
    {
        cgdb_data * const db = cg_storage_manager_data_get_db(data);
        assert(db != NULL);
        assert(object != NULL);
        cg_storage_filesystem * const fs = cg_storage_object_get_filesystem(object);
        assert(fs != NULL);

        result = cgdb_get_inode_instances(db,
                                          cg_storage_filesystem_get_id(fs),
                                          cg_storage_object_get_inode_number(object),
                                          &db_entries_cb,
                                          data);

        if (result != 0)
        {
            fprintf(stderr,
                    "Error getting instances for inode %"PRIu64" on filesystem %s: %s\n",
                    cg_storage_object_get_inode_number(object),
                    cg_storage_filesystem_get_name(fs),
                    strerror(result));
        }
    }
    else
    {
        fprintf(stderr,
                "Error getting inode: %s\n",
                strerror(result));
    }

    if (result != 0)
    {
        cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
        assert(event_data != NULL);

        cgutils_event_exit_loop(event_data);
    }

    return result;
}

int main(int argc, char ** argv)
{
    int result = 0;

    if (argc == 4)
    {
        result = cg_tools_init_all();

        if (result == 0)
        {
            char const * const conf_file = argv[1];
            char const * const fs_name = argv[2];
            char const * const path = argv[3];
            cgutils_configuration * conf = NULL;

            result = cgutils_configuration_from_xml_file(conf_file,
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
                                result = cg_storage_filesystem_entry_get_object_info_by_path(fs,
                                                                                             path,
                                                                                             &entry_cb,
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
                                            "Error getting object for path %s: %s\n",
                                            path,
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
                        conf_file,
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
        fprintf(stderr,
                "%s <Cloud Gateway configuration file> <Filesystem ID> <Path>\n",
                argv[0]);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
