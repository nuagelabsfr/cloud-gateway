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
#include <string.h>
#include <time.h>

#include <cgsm/cg_storage_manager_data.h>

#include <cgsm/cg_storage_connection.h>
#include <cgsm/cg_storage_listener.h>
#include <cgsm/cg_storage_manager.h>

#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_process.h>

#include "cgStorageManagerServer.h"
#include "cgStorageManagerCommon.h"

#define CG_STORAGE_MANAGER_SERVER_LISTENING_RETRY_COUNT (5)
#define CG_STORAGE_MANAGER_SERVER_LISTENING_RETRY_DELAY_MS (10) /* 10 ms */

/* A value larger than /proc/sys/net/core/somaxconn will be silently
   truncated to it anyway on Linux > 2.4.25 */
#define CG_STORAGE_MANAGER_SERVER_BACKLOG (10000)

typedef struct
{
    cg_storage_manager_data * data;
    cg_storage_listener * listener;
    size_t active_connections;
    bool exiting;
} cg_storage_manager_server_data;

static cg_storage_manager_server_data * cg_storage_manager_server_get_data(void)
{
    static cg_storage_manager_server_data server_data =
        {
            .data = NULL,
            .listener = NULL,
            .active_connections = 0,
            .exiting = false
        };

    return &server_data;
}

static void cg_storage_manager_server_graceful_exit(int const sig,
                                                    void * const cb_data)
{
    cg_storage_manager_server_data * server_data = cb_data;
    assert(sig == CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG);
    assert(cb_data != NULL);
    assert(server_data->data != NULL);

    (void) sig;

    if (server_data->listener != NULL)
    {
        cg_storage_listener_free(server_data->listener), server_data->listener = NULL;
    }

    server_data->exiting = true;

    if (server_data->active_connections == 0)
    {
        cgutils_event_data * event_data = cg_storage_manager_data_get_event(server_data->data);
        assert(event_data != NULL);

        cgutils_event_exit_after_loop(event_data, NULL);
    }
}

static void cg_storage_manager_server_connection_end_cb(cg_storage_connection const * const conn,
                                                        void * const cb_data)
{
    cg_storage_manager_server_data * server_data = cb_data;
    CGUTILS_ASSERT(cb_data != NULL);
    CGUTILS_ASSERT(conn != NULL);

    (void) conn;

    assert(server_data->active_connections > 0);
    server_data->active_connections--;

    if (server_data->exiting == true &&
        server_data->active_connections == 0)
    {
        cgutils_event_data * event_data = cg_storage_manager_data_get_event(server_data->data);
        assert(event_data != NULL);

        cgutils_event_exit_after_loop(event_data, NULL);
    }
}

static void cg_storage_manager_server_listener_cb(cg_storage_manager_data * const data,
                                                  cg_storage_listener * const storage_listener,
                                                  int sock,
                                                  void * const cb_data)
{
    cg_storage_connection * conn = NULL;
    cg_storage_manager_server_data * server_data = cb_data;
    assert(data != NULL);
    assert(server_data != NULL);
    assert(storage_listener != NULL);
    assert(storage_listener == server_data->listener);
    assert(sock >= 0);

    (void) storage_listener;

    int result = cg_storage_connection_init(data,
                                            sock,
                                            &cg_storage_manager_server_connection_end_cb,
                                            server_data,
                                            &conn);

    if (result == 0)
    {
        server_data->active_connections++;

        result = cg_storage_connection_go(conn);

        if (result != 0)
        {
            cg_storage_connection_finish(conn);
        }
    }
    else
    {
        cgutils_file_close(sock), sock = -1;
    }
}

static int cg_storage_manager_server_handle_old_server(cg_storage_listener * const listener,
                                                       pid_t const old_server_pid)
{
    CGUTILS_ASSERT(listener != NULL);
    CGUTILS_ASSERT(old_server_pid != -1);

    int result = cgutils_process_signal(old_server_pid,
                                        CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG);

    if (result == 0)
    {
        /* nanosleep(CG_STORAGE_MANAGER_SERVER_LISTENING_RETRY_DELAY_MS); */
    }
    else
    {
        CGUTILS_ERROR("Error sending graceful exit signal (%d) to the old server process (%lld): %d",
                      CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG,
                      (long long) old_server_pid,
                      result);
    }

    /* Try to bind, even if signaling the previous server failed, as it may be because the process
       does not exist anymore. */

    result = EADDRINUSE;

    for (size_t count = CG_STORAGE_MANAGER_SERVER_LISTENING_RETRY_COUNT;
         count > 0 &&
             result == EADDRINUSE;
         count--)
    {
        result = cg_storage_listener_bind(listener);

        if (result != 0)
        {
            struct timespec const tsp =
                {
                    .tv_sec = 0,
                    .tv_nsec = CG_STORAGE_MANAGER_SERVER_LISTENING_RETRY_DELAY_MS * 1000 * 1000
                };

            CGUTILS_DEBUG("Bind failed with %d, will retry soon.",
                          result);

            count--;

            nanosleep(&tsp, NULL);
        }

    }

    if (result != 0)
    {
        CGUTILS_ERROR("Error while trying to bind: %d", result);
    }

    return result;
}

int cg_storage_manager_server_run(cg_storage_manager_data * const data,
                                  bool graceful,
                                  pid_t const old_server_pid)
{
    int result = 0;
    cg_storage_manager_server_data * server_data = cg_storage_manager_server_get_data();
    CGUTILS_ASSERT(server_data != NULL);
    CGUTILS_ASSERT(data != NULL);

    server_data->data = data;

    if (graceful == true &&
        old_server_pid == -1)
    {
        graceful = false;
    }

    result = cg_storage_listener_init(data,
                                      &(server_data->listener),
                                      graceful == true ? false : true,
                                      CG_STORAGE_MANAGER_SERVER_BACKLOG);

    if (result == 0)
    {
        CGUTILS_ASSERT(server_data->listener != NULL);

        result = cg_storage_manager_release_configuration(data);

        if (result == 0)
        {
            if (graceful == true)
            {
                result = cg_storage_manager_server_handle_old_server(server_data->listener,
                                                                     old_server_pid);
            }

            if (result == 0)
            {
                result = cg_storage_listener_enable(server_data->listener,
                                                    data,
                                                    &cg_storage_manager_server_listener_cb,
                                                    server_data);

                if (result == 0)
                {
                    result = cg_storage_manager_common_register_signal(data,
                                                                       CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG,
                                                                       &cg_storage_manager_server_graceful_exit,
                                                                       server_data);

                    if (result == 0)
                    {
                        result = cg_storage_manager_loop(data);

                        if (result != 0)
                        {
                            CGUTILS_ERROR("Exiting server loop with %d", result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error registering signal event: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error enabling listener: %s", strerror(result));
                }
            }
        }
        else
        {
            CGUTILS_ERROR("Error while releasing configuration: %d", result);
        }

        cg_storage_listener_free(server_data->listener), server_data->listener = NULL;
    }
    else
    {
        CGUTILS_ERROR("Error creating listener: %s", strerror(result));
    }

    return result;
}
