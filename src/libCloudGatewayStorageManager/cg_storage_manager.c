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
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_htable.h>

#include "cgsm/cg_storage_manager_data.h"
#include "cgsm/cg_storage_manager.h"
#include "cgsm/cg_storage_connection.h"
#include "cgsm/cg_storage_filesystem.h"
#include "cgsm/cg_storage_instance.h"
#include "cgsm/cg_storage_listener.h"
#include "cgsm/cg_storage_provider.h"

static int cg_storage_manager_filesystems_load_all(cg_storage_manager_data * const data)
{
    assert(data != NULL);
    int result = 0;
    cgutils_llist * confs_list = NULL;
    cgutils_configuration * conf = cg_storage_manager_data_get_configuration(data);
    assert(conf != NULL);
    result = cgutils_configuration_get_all(conf,
                                           "FileSystems/FileSystem",
                                           &confs_list);

    if (result == 0)
    {
        assert(confs_list != NULL);
        assert(cgutils_llist_get_count(confs_list) > 0);

        cgutils_llist_elt * conf_elt = cgutils_llist_get_iterator(confs_list);

        while (result == 0 && conf_elt != NULL)
        {
            cgutils_configuration const * const filesystem_conf = cgutils_llist_elt_get_object(conf_elt);
            assert(filesystem_conf != NULL);
            cg_storage_filesystem * filesystem = NULL;

            result = cg_storage_filesystem_init(data,
                                                filesystem_conf,
                                                &filesystem);

            if (result == 0)
            {
                result = cg_storage_manager_data_add_filesystem(data,
                                                                filesystem);

                if (result != 0)
                {
                    if (result == EEXIST)
                    {
                        CGUTILS_ERROR("Error, there is at least two filesystems named %s in your configuration file.",
                                      cg_storage_filesystem_get_name(filesystem));
                    }
                    else
                    {
                        CGUTILS_ERROR("Error adding filesystem to list: %s", strerror(result));
                    }

                    cg_storage_filesystem_free(filesystem), filesystem = NULL;

                }
            }
            else
            {
                CGUTILS_ERROR("Error initializing filesystem: %s", strerror(result));
            }

            conf_elt = cgutils_llist_elt_get_next(conf_elt);
        }

        cgutils_llist_free(&confs_list, &cgutils_configuration_delete);
    }
    else if (result != ENOENT)
    {
        CGUTILS_ERROR("Error parsing filesystem: %s", strerror(result));
    }

    return result;
}

static int cg_storage_manager_providers_load_all(cg_storage_manager_data * const data)
{
    assert(data != NULL);
    int result = 0;
    cgutils_llist * confs_list = NULL;
    cgutils_configuration * conf = cg_storage_manager_data_get_configuration(data);
    assert(conf != NULL);
    result = cgutils_configuration_get_all(conf,
                                           "Providers/Provider",
                                           &confs_list);

    if (result == 0)
    {
        assert(confs_list != NULL);
        assert(cgutils_llist_get_count(confs_list) > 0);

        cgutils_llist_elt * conf_elt = cgutils_llist_get_iterator(confs_list);

        while (result == 0 && conf_elt != NULL)
        {
            cgutils_configuration const * const provider_conf = cgutils_llist_elt_get_object(conf_elt);
            assert(provider_conf != NULL);
            cg_storage_provider * provider = NULL;

            result = cg_storage_provider_init(data,
                                              provider_conf,
                                              &provider);

            if (result == 0)
            {
                result = cg_storage_manager_data_add_provider(data,
                                                              provider);

                if (result != 0)
                {
                    if (result == EEXIST)
                    {
                        CGUTILS_ERROR("Error, there is at least two providers named %s in your configuration file.",
                                      cg_storage_provider_get_name(provider));
                    }
                    else
                    {
                        CGUTILS_ERROR("Error adding provider to list: %s", strerror(result));
                    }

                    cg_storage_provider_free(provider), provider = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error initializing provider: %s", strerror(result));
            }

            conf_elt = cgutils_llist_elt_get_next(conf_elt);
        }

        cgutils_llist_free(&confs_list, &cgutils_configuration_delete);
    }
    else if (result != ENOENT)
    {
        CGUTILS_ERROR("Error parsing provider: %s", strerror(result));
    }
    else
    {
        result = 0;
    }

    return result;
}

static int cg_storage_manager_instances_load_all(cg_storage_manager_data * const data)
{
    assert(data != NULL);
    int result = 0;
    cgutils_llist * confs_list = NULL;
    cgutils_configuration * conf = cg_storage_manager_data_get_configuration(data);
    assert(conf != NULL);
    result = cgutils_configuration_get_all(conf,
                                           "Instances/Instance",
                                           &confs_list);

    if (result == 0)
    {
        assert(confs_list != NULL);
        assert(cgutils_llist_get_count(confs_list) > 0);

        cgutils_llist_elt * conf_elt = cgutils_llist_get_iterator(confs_list);
        size_t idx = 0;

        while (result == 0 && conf_elt != NULL)
        {
            cgutils_configuration const * const instance_conf = cgutils_llist_elt_get_object(conf_elt);
            assert(instance_conf != NULL);
            cg_storage_instance * instance = NULL;

            result = cg_storage_instance_init(data,
                                              idx,
                                              instance_conf,
                                              &instance);

            if (result == 0)
            {
                result = cg_storage_manager_data_add_instance(data,
                                                              instance);

                if (result != 0)
                {
                    if (result == EEXIST)
                    {
                        CGUTILS_ERROR("Error, there is at least two instances named %s in your configuration file.",
                                      cg_storage_instance_get_name(instance));
                    }
                    else
                    {
                        CGUTILS_ERROR("Error adding instance to list: %s", strerror(result));
                    }

                    cg_storage_instance_free(instance), instance = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error initializing instance: %s", strerror(result));
            }

            conf_elt = cgutils_llist_elt_get_next(conf_elt);
            idx++;
        }

        cgutils_llist_free(&confs_list, &cgutils_configuration_delete);
    }
    else if (result != ENOENT)
    {
        CGUTILS_ERROR("Error parsing instance: %s", strerror(result));
    }

    return result;
}

int cg_storage_manager_load_storage_provider_with_defaults(cg_storage_manager_data * const data,
                                                           char const * const name,
                                                           cg_storage_provider ** const out)
{
    int result = EINVAL;

    if (data != NULL && name != NULL && out != NULL)
    {
        result = cg_storage_provider_init_with_defaults(data,
                                                        name,
                                                        out);

        if (result == 0)
        {
            result = cg_storage_manager_data_add_provider(data,
                                                          *out);

            if (result != 0)
            {
                if (result == EEXIST)
                {
                    CGUTILS_ERROR("Error, there is at least two providers named %s in your configuration file.",
                                  cg_storage_provider_get_name(*out));
                }
                else
                {
                    CGUTILS_ERROR("Error adding provider to list: %s", strerror(result));
                }

                cg_storage_provider_free(*out), *out = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error initializing provider: %s", strerror(result));
        }
    }

    return result;
}

int cg_storage_manager_loop(cg_storage_manager_data * const data)
{
    assert(data != NULL);

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    int result = cgutils_event_dispatch(event_data);

    return result;
}

void cg_storage_manager_exit_loop(cg_storage_manager_data * const data)
{
    assert(data != NULL);

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    cgutils_event_exit_loop(event_data);
}

int cg_storage_manager_load_configuration(cg_storage_manager_data * const data,
                                          bool const load_instances,
                                          bool const load_filesystems)
{
    assert(data != NULL);

    int result = cg_storage_manager_providers_load_all(data);

    if (result == 0)
    {
        if (load_instances == true)
        {
            result = cg_storage_manager_instances_load_all(data);

            if (result == 0)
            {
                if (load_filesystems == true)
                {
                    result = cg_storage_manager_filesystems_load_all(data);

                    if (result != 0)
                    {
                        if (result == ENOENT)
                        {
                            CGUTILS_ERROR("No volume/filesystem configured.");
                        }
                        else
                        {
                            CGUTILS_ERROR("Error loading filesystems: %s", strerror(result));
                        }
                    }
                }
            }
            else
            {
                if (result == ENOENT)
                {
                    CGUTILS_ERROR("No storage/instance configured.");
                }
                else
                {
                    CGUTILS_ERROR("Error loading instances: %s", strerror(result));
                }
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Error loading providers: %s", strerror(result));
    }

    return result;
}

static int cg_storage_manager_setup_providers(cg_storage_manager_data * const data)
{
    int result = EINVAL;

    if (data != NULL)
    {
        cgutils_htable_iterator * it = NULL;
        result = cg_storage_manager_data_get_all_instances(data, &it);

        if (result == 0)
        {
            bool remaining = true;

            while (remaining == true)
            {
                cg_storage_instance * const instance = cgutils_htable_iterator_get_value(it);

                result = cg_storage_instance_setup_provider(instance);

                if (result != 0)
                {
                    assert(cgutils_htable_iterator_get_key(it) != NULL);
                    CGUTILS_ERROR("Error setting provider up on instance %s: %d",
                                  cgutils_htable_iterator_get_key(it),
                                  result);
                }

                remaining = cgutils_htable_iterator_next(it);
            }

            result = 0;

            cgutils_htable_iterator_free(it), it = NULL;
        }
        else if(result == ENOENT)
        {
            result = 0;
        }
        else
        {
            CGUTILS_ERROR("Error getting iterator on instances: %d", result);
        }
    }

    return result;
}

static int cg_storage_manager_setup_filesystems(cg_storage_manager_data * const data)
{
    int result = EINVAL;

    if (data != NULL)
    {
        cgutils_htable_iterator * it = NULL;
        result = cg_storage_manager_data_get_all_filesystems(data, &it);

        if (result == 0)
        {
            bool remaining = true;

            while (result == 0 && remaining == true)
            {
                cg_storage_filesystem * const fs = cgutils_htable_iterator_get_value(it);

                result = cg_storage_filesystem_setup(fs, data);

                if (result != 0)
                {
                    assert(cgutils_htable_iterator_get_key(it) != NULL);
                    CGUTILS_ERROR("Error setting fs up %s: %d", cgutils_htable_iterator_get_key(it), result);
                }

                remaining = cgutils_htable_iterator_next(it);
            }

            cgutils_htable_iterator_free(it), it = NULL;
        }
        else if(result == ENOENT)
        {
            result = 0;
        }
        else
        {
            CGUTILS_ERROR("Error getting iterator on filesystems: %d", result);
        }
    }

    return result;
}

static int cg_storage_manager_setup_instances(cg_storage_manager_data * const data)
{
    int result = EINVAL;

    if (data != NULL)
    {
        cgutils_htable_iterator * it = NULL;
        result = cg_storage_manager_data_get_all_instances(data, &it);

        if (result == 0)
        {
            bool remaining = true;

            while (result == 0 && remaining == true)
            {
                cg_storage_instance * const fs = cgutils_htable_iterator_get_value(it);

                result = cg_storage_instance_setup(fs, data);

                if (result != 0)
                {
                    assert(cgutils_htable_iterator_get_key(it) != NULL);
                    CGUTILS_ERROR("Error setting instance up %s: %d", cgutils_htable_iterator_get_key(it), result);
                }

                remaining = cgutils_htable_iterator_next(it);
            }

            cgutils_htable_iterator_free(it), it = NULL;
        }
        else if(result == ENOENT)
        {
            result = 0;
        }
        else
        {
            CGUTILS_ERROR("Error getting iterator on instances: %d", result);
        }
    }

    return result;
}

int cg_storage_manager_release_configuration(cg_storage_manager_data * const data)
{
    int result = EINVAL;

    if (data != NULL)
    {
        result = cg_storage_manager_data_configuration_finished(data);

        if (result != 0)
        {
            CGUTILS_ERROR("Error finishing data configuration: %d", result);
        }
    }

    return result;
}

int cg_storage_manager_setup(cg_storage_manager_data * const data,
                             bool const setup_providers)
{
    int result = EINVAL;

    if (data != NULL)
    {
        result = cg_storage_manager_data_setup(data);

        if (result == 0)
        {
            result = cg_storage_manager_setup_filesystems(data);

            if (result == 0)
            {
                result = cg_storage_manager_setup_instances(data);

                if (result == 0)
                {
                    if (setup_providers == true)
                    {
                        result = cg_storage_manager_setup_providers(data);

                        if (result == 0)
                        {
                            size_t const remaining = cg_storage_manager_data_provider_init_remaining(data);

                            if (remaining > 0)
                            {
                                cg_storage_manager_loop(data);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error setting providers up: %d", result);
                        }
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error setting instances up: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error setting filesystems up: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error in data setup: %d", result);
        }
    }

    return result;
}
