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

#include "common.h"

static int return_value = 0;
static cg_storage_filesystem * fs = NULL;
static struct stat new_st;

static int db_cb(int const status,
                            void * cb_data)
{
    int result = status;
    cg_storage_manager_data * const data = cb_data;
    CGUTILS_ASSERT(cb_data != NULL);

    if (result == 0)
    {
    }
    else
    {
        fprintf(stderr,
                "Error during setattr: %s\n",
                strerror(result));
        return_value = result;
    }

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    CGUTILS_ASSERT(event_data != NULL);

    cgutils_event_exit_loop(event_data);

    return result;
}

static int get_entry_cb(int const status,
                        cg_storage_object const * const object,
                        void * cb_data)
{
    int result = status;
    bool finished = true;
    cg_storage_manager_data * const data = cb_data;
    CGUTILS_ASSERT(cb_data != NULL);
    CGUTILS_ASSERT(fs != NULL);

    (void) object;

    if (result == 0)
    {
        new_st.st_size = 0;
        new_st.st_atime = time(NULL);
        new_st.st_mtime = time(NULL);

        result = cg_storage_filesystem_entry_inode_setattr(fs,
                                                           cg_storage_object_get_inode_number(object),
                                                           &new_st,
                                                           false,
                                                           &db_cb,
                                                           data);

        if (result == 0)
        {
            finished = false;
        }
        else
        {
            fprintf(stderr,
                    "Error calling setattr on volume: %s\n",
                    strerror(result));
        }
    }
    else
    {
        fprintf(stderr,
                "Error fetching entry: %s\n",
                strerror(result));
    }

    if (result != 0)
    {
        return_value = result;
    }

    if (finished == true)
    {
        cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
        CGUTILS_ASSERT(event_data != NULL);

        cgutils_event_exit_loop(event_data);
    }

    return result;
}

int main(int argc, char ** argv)
{
    int result = 0;

    /* argv[0] conf_file fs_name uid gid rights */
    if (argc == 6)
    {
        result = cg_tools_init_all();

        if (result == 0)
        {
            char const * const conf_file = argv[1];
            char const * const fs_name = argv[2];
            char const * const uid_str = argv[3];
            char const * const gid_str = argv[4];
            char const * const mode_str = argv[5];
            uint64_t uid_tmp = 0;

            new_st = (struct stat) { 0 };

            result = cgutils_str_to_unsigned_int64(uid_str,
                                                   &uid_tmp);

            if (result == 0 &&
                uid_tmp <= UINT32_MAX)
            {
                new_st.st_uid = (uid_t) uid_tmp;
                uint64_t gid_tmp = 0;

                result = cgutils_str_to_unsigned_int64(gid_str,
                                                       &gid_tmp);

                if (result == 0 &&
                    gid_tmp <= UINT32_MAX)
                {
                    new_st.st_gid = (gid_t) gid_tmp;
                    uint64_t mode_tmp = 0;

                    result = cgutils_str_to_unsigned_int64(mode_str,
                                                           &mode_tmp);

                    if (result == 0 &&
                        mode_tmp <= UINT32_MAX &&
                        (mode_tmp & S_IFMT) == 0)
                    {
                        cgutils_configuration * conf = NULL;

                        /* We have required that the new mode does not contain an inode type,
                           so explicitely set a directory type.
                        */
                        new_st.st_mode = (mode_t) mode_tmp;
                        new_st.st_mode |= S_IFDIR;

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
                                        result = cg_storage_manager_data_get_filesystem(data,
                                                                                        fs_name,
                                                                                        &fs);

                                        if (result == 0)
                                        {
                                            /* we need to fetch the entry first because otherwise,
                                               it may not exist yet. */
                                            result = cg_storage_filesystem_entry_get_object_by_inode(fs,
                                                                                                     1,
                                                                                                     &get_entry_cb,
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
                                                        "Error getting root entry: %s\n",
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
                    }
                    else
                    {
                        fprintf(stderr,
                                "Invalid mode: %s\n",
                                strerror(result));
                    }
                }
                else
                {
                    fprintf(stderr,
                            "Invalid gid: %s\n",
                            strerror(result));
                }
            }
            else
            {
                fprintf(stderr,
                        "Invalid uid: %s\n",
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
                "%s <Cloud Gateway configuration file> <Filesystem ID> <uid> <gid> <rights>\n",
                argv[0]);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
