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

#include <unistd.h>

#include <cgsm/cg_storage_listener.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_event.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_network.h>

struct cg_storage_listener
{
    listener_callback * cb;
    void * cb_data;
    cg_storage_manager_data * data;
    cgutils_event * sock_event;
    struct addrinfo * binding;
    int backlog;
    int sock;
    bool bound;
};

static void cg_storage_listener_connection_cb(int sock,
                                              short flags,
                                              void * data)
{
    assert(sock >= 0);
    assert(data != NULL);

    (void) flags;

    cg_storage_listener * this = data;

    if (this->cb != NULL)
    {
        int connection_fd = -1;

        int result = cgutils_network_accept(sock, &connection_fd);

        if (result == 0)
        {
            (*(this->cb))(this->data, this, connection_fd, this->cb_data);
        }
        else
        {
            CGUTILS_ERROR("Error accepting connection: %d", result);

        }
    }
}


int cg_storage_listener_enable(cg_storage_listener * const this,
                               cg_storage_manager_data * const data,
                               listener_callback * cb,
                               void * const cb_data)
{

    int result = EINVAL;

    if (this != NULL && data != NULL && cb != NULL && cb_data != NULL)
    {
        cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
        assert(event_data);

        this->cb = cb;
        this->cb_data = cb_data;

        result = cgutils_event_create_fd_event(event_data,
                                               this->sock,
                                               &cg_storage_listener_connection_cb,
                                               this,
                                               CGUTILS_EVENT_READ|CGUTILS_EVENT_PERSIST,
                                               &(this->sock_event));

        if (result == 0)
        {
            result = cgutils_event_enable(this->sock_event, NULL);

            if (result != 0)
            {
                CGUTILS_ERROR("Error enabling event: %d", result);
                cgutils_event_free(this->sock_event), this->sock_event = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating event: %d", result);
        }
    }

    return result;
}

int cg_storage_listener_init(cg_storage_manager_data * const data,
                             cg_storage_listener ** out,
                             bool const immediate_bind,
                             int const backlog)
{
    int result = EINVAL;

    if (data != NULL && out != NULL)
    {
        char const * const unix_path = cg_storage_manager_data_get_communication_socket(data);
        result = 0;

        if (unix_path != NULL)
        {
            if (cgutils_file_exists(unix_path) == true)
            {
                result = cgutils_file_unlink(unix_path);

                if (result != 0)
                {
                    CGUTILS_ERROR("Unable to delete existing socket file %s: %d",
                                  unix_path,
                                  result);
                }
            }

            if (result == 0)
            {
                CGUTILS_ALLOCATE_STRUCT(*out);

                if (*out != NULL)
                {
                    struct addrinfo * binding = NULL;

                    result = cgutils_network_get_addrinfo_from_unix_path(unix_path,
                                                                         &binding);

                    if (result == 0)
                    {
                        (*out)->backlog = backlog;

                        if (immediate_bind == true)
                        {
                            result = cgutils_network_listen_on_socket(binding,
                                                                      /* no deferred accept on UNIX socket */
                                                                      0,
                                                                      true,
                                                                      (*out)->backlog,
                                                                      &((*out)->sock));

                            if (result == 0)
                            {
                                (*out)->bound = true;
                            }
                        }
                        else
                        {
                            result = cgutils_network_prepare_socket_for_listening(binding,
                                                                                  true,
                                                                                  &((*out)->sock));

                            (*out)->binding = binding, binding = NULL;
                        }

                        if (result == 0)
                        {
                            (*out)->data = data;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error listening on socket %s: %d",
                                          unix_path,
                                          result);
                        }

                        if (binding != NULL)
                        {
                            freeaddrinfo(binding), binding = NULL;
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Invalid communication path: %d", result);
                    }

                    if (result != 0)
                    {
                        cg_storage_listener_free(*out), *out = NULL;
                    }
                }
                else
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error allocating memory for listener: %d", result);
                }
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to get communication socket from configuration: %d", result);
        }
    }

    return result;
}

int cg_storage_listener_bind(cg_storage_listener * const this)
{
    int result = EINVAL;

    if (this != NULL &&
        this->bound == false)
    {
        CGUTILS_ASSERT(this->binding != NULL);

        result = cgutils_network_listen_on_prepared_socket(this->sock,
                                                           this->binding,
                                                           /* no deferred accept on UNIX socket */
                                                           0,
                                                           this->backlog);

        if (result == 0)
        {
            this->bound = true;
            freeaddrinfo(this->binding), this->binding = NULL;
        }
    }

    return result;
}

void cg_storage_listener_free(cg_storage_listener * this)
{
    if (this != NULL)
    {
        if (this->binding != NULL)
        {
            freeaddrinfo(this->binding), this->binding = NULL;
        }

        if (this->sock_event != NULL)
        {
            cgutils_event_free(this->sock_event), this->sock_event = NULL;
        }

        if (this->sock >= 0)
        {
            cgutils_file_close(this->sock), this->sock = -1;
        }

        this->backlog = -1;

        CGUTILS_FREE(this);
    }
}
