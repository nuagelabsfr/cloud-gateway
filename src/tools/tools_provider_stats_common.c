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
#include <string.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_process.h>

#include "tools_provider_stats_common.h"

int tools_provider_stats_compute_instances_mapping(cgutils_configuration const * const conf,
                                                   char *** const names_out,
                                                   size_t * const names_count_out)
{
    int result = 0;
    cgutils_llist * confs_list = NULL;
    CGUTILS_ASSERT(conf != NULL);
    CGUTILS_ASSERT(names_out != NULL);
    CGUTILS_ASSERT(names_count_out != NULL);

    result = cgutils_configuration_get_all(conf,
                                           "Instances/Instance",
                                           &confs_list);

    if (result == 0)
    {
        size_t const names_count = cgutils_llist_get_count(confs_list);
        CGUTILS_ASSERT(confs_list != NULL);

        if (names_count > 0)
        {
            char ** names = NULL;
            CGUTILS_MALLOC(names, names_count, sizeof *names);

            if (names != NULL)
            {
                cgutils_llist_elt * conf_elt = cgutils_llist_get_iterator(confs_list);
                size_t idx = 0;

                while (result == 0 &&
                       conf_elt != NULL &&
                       idx < names_count)
                {
                    cgutils_configuration const * const instance_conf = cgutils_llist_elt_get_object(conf_elt);
                    CGUTILS_ASSERT(instance_conf != NULL);

                    result = cgutils_configuration_get_string(instance_conf,
                                                              "Name",
                                                              &(names[idx]));

                    if (result == 0)
                    {
                        idx++;
                    }
                    else
                    {
                        fprintf(stderr,
                                "Error getting name from instance: %s\n",
                                strerror(result));
                    }

                    conf_elt = cgutils_llist_elt_get_next(conf_elt);
                }

                if (result == 0)
                {
                    *names_out = names;
                    *names_count_out = names_count;
                }
                else
                {
                    for (size_t count = 0;
                         count < idx;
                         count++)
                    {
                        CGUTILS_FREE(names[count]);
                    }

                    CGUTILS_FREE(names);
                }
            }
            else
            {
                result = ENOMEM;
                fprintf(stderr,
                        "Error allocating memory for instance names: %s\n",
                        strerror(result));
            }
        }
        else
        {
            result = ENOENT;
        }

        cgutils_llist_free(&confs_list, &cgutils_configuration_delete);
    }
    else if (result != ENOENT)
    {
        fprintf(stderr,
                "Error parsing instances: %s",
                strerror(result));
    }

    return result;
}

static int tools_provider_stats_get_more_recent_shm_file(char const * prefix,
                                                         char ** out)
{
    static char const shm_dir[] = "/dev/shm";
    int result = 0;
    DIR * dirp = NULL;
    CGUTILS_ASSERT(prefix != NULL);
    CGUTILS_ASSERT(out != NULL);

    while(*prefix == '/')
    {
        prefix++;
    }

    result =  cgutils_file_opendir(shm_dir,
                                   &dirp);

    if (result == 0)
    {
        size_t const prefix_len = strlen(prefix);
        struct dirent dirent = (struct dirent) { 0 };
        struct dirent * dirent_p = &dirent;
        char * best = NULL;

        do
        {
            result = cgutils_file_readdir_r(dirp,
                                            &dirent,
                                            &dirent_p);

            if (result == 0 &&
                dirent_p != NULL)
            {
                if (strncmp(dirent.d_name, prefix, prefix_len) == 0)
                {
                    if (best == NULL ||
                        strcmp(dirent.d_name, best) > 0)
                    {
                        CGUTILS_FREE(best);
                        best = cgutils_strdup(dirent.d_name);

                        if (best == NULL)
                        {
                            result = ENOMEM;
                            fprintf(stderr,
                                    "Error allocating memory for file path: %s\n",
                                    strerror(result));
                        }
                    }
                }
            }
        }
        while (result == 0 &&
               dirent_p != NULL);

        if (result == 0)
        {
            if (best != NULL)
            {
                *out = best;
            }
            else
            {
                result = ENOENT;
            }
        }
        else
        {
            CGUTILS_FREE(best);
        }

        cgutils_file_closedir(dirp), dirp = NULL;
    }
    else
    {
        fprintf(stderr,
                "Error opening SHM directory %s: %s\n",
                shm_dir,
                strerror(result));
    }

    return result;
}

int tools_provider_stats_compute_monitor_info_path(cgutils_configuration const * const conf,
                                                   char ** const out)
{
    int result = 0;
    char * config_monitor_info_path = NULL;
    CGUTILS_ASSERT(conf != NULL);
    CGUTILS_ASSERT(out != NULL);

    result = cgutils_configuration_get_string(conf,
                                              "General/MonitorInformationsPath",
                                              &config_monitor_info_path);

    if (result == 0)
    {
        char * pid_file = NULL;

        result = cgutils_configuration_get_string(conf,
                                                  "General/PidFile",
                                                  &pid_file);

        if (result == 0)
        {
            pid_t pid = -1;

            result = cgutils_process_read_pid(pid_file,
                                              &pid);

            if (result == 0)
            {
                char * prefix = NULL;

                result = cgutils_asprintf(&prefix,
                                          "%s-%ld",
                                          config_monitor_info_path,
                                          (long) pid);

                if (result == 0)
                {
                    result = tools_provider_stats_get_more_recent_shm_file(prefix,
                                                                           out);

                    CGUTILS_FREE(prefix);
                }
                else
                {
                    fprintf(stderr,
                            "Error allocating memory: %s\n",
                            strerror(result));
                }
            }
            else if (result != ENOENT)
            {
                fprintf(stderr,
                        "Error reading PID from pid file %s: %s\n",
                        pid_file,
                        strerror(result));
            }

            CGUTILS_FREE(pid_file);
        }
        else
        {
            fprintf(stderr,
                    "Error getting PidFile value from the configuration file: %s\n",
                    strerror(result));
        }

        CGUTILS_FREE(config_monitor_info_path);
    }
    else
    {
        fprintf(stderr,
                "Error getting MonitorInformationsPath value from the configuration file: %s\n",
                strerror(result));
    }

    return result;
}
