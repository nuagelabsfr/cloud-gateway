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

#include <cgmonitor/cg_monitor_data.h>

#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_shared_memory_segment.h>

typedef struct
{
    size_t instances_count;
    size_t values_set;
    cg_monitor_data_instance_status_data instances_data[];
} cg_monitor_data_shared;

struct cg_monitor_data
{
    cloudutils_shared_memory_segment_handler * handler;
    char * path;
    size_t instances_count;
    bool writable;
};

static size_t cg_monitor_data_get_shared_size(size_t const instances_count)
{
    size_t result = sizeof (cg_monitor_data_shared) +
        ( sizeof (cg_monitor_data_instance_status_data) * instances_count);
    return result;
}

static int cg_monitor_data_init(cloudutils_shared_memory_segment_handler * const handler,
                                char const * const path,
                                bool const writable,
                                size_t const instances_count,
                                cg_monitor_data ** const out)
{
    int result = 0;

    assert(handler != NULL);
    assert(path != NULL);
    assert(instances_count > 0);
    assert(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(*out);

    if (*out != NULL)
    {
        cg_monitor_data * this = *out;

        this->path = cgutils_strdup(path);

        if (this->path != NULL)
        {
            this->handler = handler;
            this->instances_count = instances_count;
            this->writable = writable;
        }
        else
        {
            result = ENOMEM;
        }

        if (result != 0)
        {
            CGUTILS_FREE(*out), *out = NULL;
        }
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static int cg_monitor_data_get_empty_shared(size_t const instances_count,
                                            cg_monitor_data_shared ** const out)
{
    int result = 0;
    CGUTILS_ASSERT(out != NULL);

    cg_monitor_data_shared * shared_zero = NULL;
    size_t const needed_size = cg_monitor_data_get_shared_size(instances_count);

    CGUTILS_MALLOC(shared_zero, 1, needed_size);

    if (shared_zero != NULL)
    {
        *shared_zero = (cg_monitor_data_shared) { 0 };

        for (size_t idx = 0;
             idx < instances_count;
             idx++)
        {
            (shared_zero->instances_data)[idx] = (cg_monitor_data_instance_status_data) { 0 };
            (shared_zero->instances_data)[idx].instance_index = idx;
        }

        shared_zero->instances_count = instances_count;
        shared_zero->values_set = 0;
        *out = shared_zero;
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

int cg_monitor_data_create(char const * const monitor_info_path,
                           size_t const instances_count,
                           cg_monitor_data ** const out)
{
    int result = EINVAL;

    if (monitor_info_path != NULL &&
        instances_count > 0 &&
        out != NULL)
    {
        size_t const needed_size = cg_monitor_data_get_shared_size(instances_count);
        cg_monitor_data_shared * shared_zero = NULL;

        result = cg_monitor_data_get_empty_shared(instances_count,
                                                  &shared_zero);

        if (result == 0)
        {
            cloudutils_shared_memory_segment_handler * handler =  NULL;

            result = cloudutils_shared_memory_segment_handler_create(monitor_info_path,
                                                                     needed_size,
                                                                     &handler);

            if (result == 0)
            {
                result = cloudutils_shared_memory_segment_handler_update(handler,
                                                                         shared_zero,
                                                                         needed_size);

                if (result == 0)
                {
                    result = cg_monitor_data_init(handler,
                                                  monitor_info_path,
                                                  true,
                                                  instances_count,
                                                  out);

                    if (result == 0)
                    {
                    }
                    else
                    {
                        CGUTILS_ERROR("Error in data init: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error updating shared memory: %d", result);
                }

                if (result != 0)
                {
                    cloudutils_shared_memory_segment_handler_destroy(handler);
                    cloudutils_shared_memory_segment_handler_detach(handler), handler = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error creating shared memory segment: %d", result);
            }

            CGUTILS_FREE(shared_zero);
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for shared memory segment: %d", result);
        }
    }

    return result;
}

int cg_monitor_data_destroy(cg_monitor_data * this)
{
    int result = 0;

    if (this != NULL)
    {
        if (this->handler != NULL)
        {
            result = cloudutils_shared_memory_segment_handler_destroy(this->handler);
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

void cg_monitor_data_free(cg_monitor_data * this)
{
    if (this != NULL)
    {
        if (this->handler != NULL)
        {
            cloudutils_shared_memory_segment_handler_detach(this->handler);
            this->handler = NULL;
        }

        CGUTILS_FREE(this->path);

        this->instances_count = 0;
        CGUTILS_FREE(this);
    }
}

int cg_monitor_data_update(cg_monitor_data * const this,
                           cg_monitor_data_instance_status_tab const * const new_values)
{
    int result = EINVAL;

    if (this != NULL &&
        this->writable == true &&
        new_values != NULL)
    {
        CGUTILS_ASSERT(this->handler != NULL);

        if (this->instances_count == new_values->instances_count)
        {
            size_t const shared_content_size = cg_monitor_data_get_shared_size(this->instances_count);
            cg_monitor_data_shared * new_shared_content = NULL;

            result = cg_monitor_data_get_empty_shared(this->instances_count,
                                                      &new_shared_content);

            if (result == 0)
            {

                for (size_t idx = 0;
                     idx < new_values->instances_count;
                     idx++)
                {
                    (new_shared_content->instances_data)[idx] = (new_values->instances_data)[idx];
                }

                new_shared_content->values_set = new_values->values_set;

                result = cloudutils_shared_memory_segment_handler_update(this->handler,
                                                                         new_shared_content,
                                                                         shared_content_size);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error updating shared data: %d", result);
                }

                CGUTILS_FREE(new_shared_content), new_shared_content = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error getting empty content: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Trying to update with different instances count, go away.");
        }
    }

    return result;
}

int cg_monitor_data_retrieve(cg_monitor_data * const this,
                             cg_monitor_data_instance_status_tab * const values)
{
    int result = EINVAL;

    if (this != NULL &&
        values != NULL)
    {
        if (this->instances_count == values->instances_count)
        {
            cg_monitor_data_shared * shared_content = NULL;

            result = cg_monitor_data_get_empty_shared(this->instances_count,
                                                      &shared_content);

            if (result == 0)
            {
                size_t const shared_content_size = cg_monitor_data_get_shared_size(this->instances_count);

                CGUTILS_ASSERT(shared_content != NULL);

                result = cloudutils_shared_memory_segment_handler_copy(this->handler,
                                                                       shared_content,
                                                                       shared_content_size);

                if (result == 0)
                {
                    for (size_t idx = 0;
                         idx < this->instances_count;
                         idx++)
                    {
                        (values->instances_data)[idx] = (shared_content->instances_data)[idx];
                    }

                    values->values_set = shared_content->values_set;
                }
                else
                {
                    CGUTILS_ERROR("Error retrieving shared content: %d", result);
                }

                CGUTILS_FREE(shared_content);
            }
            else
            {
                CGUTILS_ERROR("Error allocating memory for content: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Trying to retrieve with different instances count, go away.");
        }
    }
    else
    {
        CGUTILS_ERROR("EINVAL %p %p", this, values);
    }

    return result;
}

int cg_monitor_data_get(char const * const monitor_info_path,
                        bool const writable,
                        size_t const instances_count,
                        cg_monitor_data ** const out)
{
    int result = EINVAL;

    if (monitor_info_path != NULL &&
        instances_count > 0 &&
        out != NULL)
    {
        size_t const needed_size = cg_monitor_data_get_shared_size(instances_count);
        cloudutils_shared_memory_segment_handler * handler =  NULL;

        result = cloudutils_shared_memory_segment_handler_attach(monitor_info_path,
                                                                 true,
                                                                 needed_size,
                                                                 &handler);

        if (result == 0)
        {
            result = cg_monitor_data_init(handler,
                                          monitor_info_path,
                                          writable,
                                          instances_count,
                                          out);

            if (result == 0)
            {
                handler = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error in data init: %d", result);
            }

            if (result != 0)
            {
                cloudutils_shared_memory_segment_handler_detach(handler), handler = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error attaching shared memory: %d", result);
        }
    }

    return result;
}

int cg_monitor_data_set_readonly(cg_monitor_data * const this)
{
    int result = EINVAL;

    if (this != NULL)
    {
        if (this->writable == true)
        {
            size_t const needed_size = cg_monitor_data_get_shared_size(this->instances_count);

            assert(this->path != NULL);

            if (this->handler != NULL)
            {
                cloudutils_shared_memory_segment_handler_detach(this->handler);
                this->handler = NULL;
            }

            result = cloudutils_shared_memory_segment_handler_attach(this->path,
                                                                     false,
                                                                     needed_size,
                                                                     &(this->handler));

            if (result == 0)
            {
                this->writable = false;
            }
        }
        else
        {
            /* Already RO */
            result = 0;
        }
    }

    return result;
}

int cg_monitor_data_peek(char const * const monitor_info_path,
                         cg_monitor_data_instance_status_tab ** const copy)
{
    int result = EINVAL;

    if (monitor_info_path != NULL &&
        copy != NULL)
    {
        cg_monitor_data_shared * shared_content = NULL;

        result = cg_monitor_data_get_empty_shared(0,
                                                  &shared_content);

        if (result == 0)
        {
            size_t const shared_content_size = cg_monitor_data_get_shared_size(0);

            cloudutils_shared_memory_segment_handler * handler =  NULL;

            result = cloudutils_shared_memory_segment_handler_attach(monitor_info_path,
                                                                     true,
                                                                     shared_content_size,
                                                                     &handler);

            if (result == 0)
            {
                /* Copy only the instances_count and values_set part of the shared segment */
                result = cloudutils_shared_memory_segment_handler_copy(handler,
                                                                       shared_content,
                                                                       shared_content_size);

                if (result == 0)
                {
                    size_t const instances_count = shared_content->instances_count;

                    cg_monitor_data_instance_status_tab * status_tab = NULL;

                    CGUTILS_MALLOC(status_tab, 1, sizeof *(status_tab) + (sizeof *(status_tab->instances_data) * instances_count));

                    if (status_tab != NULL)
                    {
                        cg_monitor_data * this = NULL;

                        *status_tab = (cg_monitor_data_instance_status_tab) { 0 };
                        status_tab->instances_count = instances_count;

                        result = cg_monitor_data_get(monitor_info_path,
                                                     false,
                                                     instances_count,
                                                     &this);

                        if (result == 0)
                        {
                            result = cg_monitor_data_retrieve(this,
                                                              status_tab);

                            if (result == 0)
                            {
                                *copy = status_tab;
                                status_tab = NULL;
                            }
                            else
                            {
                                CGUTILS_ERROR("Error retrieving values: %d", result);
                            }

                            cg_monitor_data_free(this), this = NULL;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error attaching memory segment: %d", result);
                        }

                        CGUTILS_FREE(status_tab);
                    }
                    else
                    {
                        result = ENOMEM;
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error peeking at the segment: %d", result);
                }

                cloudutils_shared_memory_segment_handler_detach(handler), handler = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error attaching to the shared memory segment: %d", result);
            }

            CGUTILS_FREE(shared_content);
        }
        else
        {
            CGUTILS_ERROR("Error getting empty shared content: %d", result);
        }
    }

    return result;
}
