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

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>

#include <cloudutils/cloudutils_json_writer.h>
#include <cloudutils/cloudutils_system.h>

#include "common.h"

static int return_value = 0;

static int entry_cb(int const status,
                    cg_storage_object const * const object,
                    void * cb_data)
{
    int result = status;
    cg_storage_manager_data * const data = cb_data;
    CGUTILS_ASSERT(cb_data != NULL);

    if (result == 0)
    {
        struct stat st = (struct stat) { 0 };

        result = cg_storage_object_get_stat(object, &st);

        if (result == 0)
        {
            cgutils_json_writer * writer = NULL;

            result = cgutils_json_writer_new(&writer);

            if (result == 0)
            {
                mode_t const mode = st.st_mode;
                cgutils_json_writer_element * root = cgutils_json_writer_get_root(writer);
                char * owner_name = NULL;
                size_t owner_name_size = 0;
                char * group_name = NULL;
                size_t group_name_size = 0;

                int res = cgutils_system_get_uid_name(st.st_uid,
                                                      &owner_name,
                                                      &owner_name_size);

                if (res == 0)
                {
                    cgutils_json_writer_element_add_string_prop(root,
                                                                "owner-name",
                                                                owner_name);

                    CGUTILS_FREE(owner_name);
                }

                res = cgutils_system_get_gid_name(st.st_gid,
                                                  &group_name,
                                                  &group_name_size);

                if (res == 0)
                {
                    cgutils_json_writer_element_add_string_prop(root,
                                                                "group-name",
                                                                group_name);

                    CGUTILS_FREE(group_name);
                }

                cgutils_json_writer_element_add_boolean_prop(root,
                                                             "set-uid",
                                                             mode & S_ISUID);

                cgutils_json_writer_element_add_boolean_prop(root,
                                                             "set-gid",
                                                             mode & S_ISGID);

                cgutils_json_writer_element_add_boolean_prop(root,
                                                             "sticky",
                                                             mode & S_ISVTX);

                cgutils_json_writer_element_add_uint64_prop(root,
                                                            "uid",
                                                            st.st_uid);

                cgutils_json_writer_element_add_uint64_prop(root,
                                                            "gid",
                                                            st.st_gid);


                if (result == 0)
                {
                    cgutils_json_writer_element * user_elt = NULL;

                    result = cgutils_json_writer_element_add_child(root,
                                                                   "user",
                                                                   &user_elt);
                    if (result == 0)
                    {
                        cgutils_json_writer_element_add_boolean_prop(user_elt,
                                                                     "read",
                                                                     mode & S_IRUSR);

                        cgutils_json_writer_element_add_boolean_prop(user_elt,
                                                                     "write",
                                                                     mode & S_IWUSR);

                        cgutils_json_writer_element_add_boolean_prop(user_elt,
                                                                     "execute",
                                                                     mode & S_IXUSR);

                        cgutils_json_writer_element_release(user_elt), user_elt = NULL;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating user element: %d", result);
                    }
                }

                if (result == 0)
                {
                    cgutils_json_writer_element * group_elt = NULL;

                    result = cgutils_json_writer_element_add_child(root,
                                                                   "group",
                                                                   &group_elt);

                    if (result == 0)
                    {
                        cgutils_json_writer_element_add_boolean_prop(group_elt,
                                                                     "read",
                                                                     mode & S_IRGRP);

                        cgutils_json_writer_element_add_boolean_prop(group_elt,
                                                                     "write",
                                                                     mode & S_IWGRP);

                        cgutils_json_writer_element_add_boolean_prop(group_elt,
                                                                     "execute",
                                                                     mode & S_IXGRP);

                        cgutils_json_writer_element_release(group_elt), group_elt = NULL;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating group element: %d", result);
                    }
                }

                if (result == 0)
                {
                    cgutils_json_writer_element * others_elt = NULL;

                    result = cgutils_json_writer_element_add_child(root,
                                                                   "others",
                                                                   &others_elt);

                    if (result == 0)
                    {
                        cgutils_json_writer_element_add_boolean_prop(others_elt,
                                                                     "read",
                                                                     mode & S_IROTH);

                        cgutils_json_writer_element_add_boolean_prop(others_elt,
                                                                     "write",
                                                                     mode & S_IWOTH);

                        cgutils_json_writer_element_add_boolean_prop(others_elt,
                                                                     "execute",
                                                                     mode & S_IXOTH);

                        cgutils_json_writer_element_release(others_elt), others_elt = NULL;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating others element: %d", result);
                    }
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
                        fputs(out, stdout);

                        CGUTILS_FREE(out);
                    }
                    else
                    {
                        CGUTILS_ERROR("Error getting output: %d", result);
                    }
                }

                cgutils_json_writer_free(writer), writer = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error getting writer: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error getting object stats: %d", result);
        }
    }
    else
    {
        fprintf(stderr,
                "Error getting inode: %s\n",
                strerror(result));
        return_value = result;
    }

    if (result != 0)
    {
        return_value = result;
    }

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    CGUTILS_ASSERT(event_data != NULL);

    cgutils_event_exit_loop(event_data);

    return result;
}

int main(int argc, char ** argv)
{
    int result = 0;

    if (argc == 3)
    {
        result = cg_tools_init_all();

        if (result == 0)
        {
            char const * const conf_file = argv[1];
            char const * const fs_name = argv[2];
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
                                result = cg_storage_filesystem_entry_get_object_by_inode(fs,
                                                                                         1,
                                                                                         &entry_cb,
                                                                                         data);

                                if (result == 0)
                                {
                                    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
                                    CGUTILS_ASSERT(event_data != NULL);

                                    cgutils_event_dispatch(event_data);

                                    result = return_value;
                                }
                                else
                                {
                                    fprintf(stderr,
                                            "Error getting object for root entry: %s\n",
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
                "%s <Cloud Gateway configuration file> <Filesystem ID>\n",
                argv[0]);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
