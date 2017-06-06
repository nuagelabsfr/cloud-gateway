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
#include <time.h>
#include <unistd.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_network.h>
#include <cloudutils/cloudutils_process.h>
#include <cloudutils/cloudutils_system.h>
#include <cloudutils/cloudutils_xml.h>

#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>

#include <cgmonitor/cg_monitor_data.h>

#include "cgStorageManagerCommon.h"

#include "cgStorageManagerCleaner.h"
#include "cgStorageManagerMonitor.h"
#include "cgStorageManagerServer.h"
#include "cgStorageManagerSyncer.h"

typedef enum
{
    cg_storage_manager_process_cleaner = 0,
    cg_storage_manager_process_monitor,
    cg_storage_manager_process_syncer,
    cg_storage_manager_process_server,

    cg_storage_manager_processes_count

} cg_storage_manager_process_type;

typedef struct
{
    char const * const name;
    char const * const proc_title;
    time_t next_respawn;
    pid_t pid;
    pid_t old_pid;
    bool enabled;
    cg_storage_manager_process_type type;
} cg_storage_manager_process;

typedef enum
{
    cg_storage_manager_master_init,
    cg_storage_manager_master_watching,
    cg_storage_manager_master_watching_waiting_respawning,
    cg_storage_manager_master_respawning,
    cg_storage_manager_master_exiting,
} cg_storage_manager_master_state;

static cg_storage_manager_data * global_data = NULL;
static cg_storage_manager_data * old_global_data = NULL;

static char const * configuration_file = NULL;

/* State of the master */
static cg_storage_manager_master_state master_state = cg_storage_manager_master_init;
static bool graceful_restart = false;

/* Timer used while waiting for a delay before respawning a child (child exiting too fast ). */
static cgutils_event * master_timer_event = NULL;

/* Pipe Of Death, used by the master to instruct children to exit. */
static int master_children_pipe[2];

/* Child's data */
static cgutils_event * child_pipe_event = NULL;
static bool child_exiting = false;

static cg_storage_manager_process cg_storage_manager_processes[] =
{
    { "cleaner", "cgStorageManager: Cleaner", (time_t) -1, (pid_t) -1, (pid_t) -1, true, cg_storage_manager_process_cleaner },
    { "monitor", "cgStorageManager: Monitor", (time_t) -1, (pid_t) -1, (pid_t) -1, true, cg_storage_manager_process_monitor },
    { "syncer", "cgStorageManager: Syncer",   (time_t) -1, (pid_t) -1, (pid_t) -1, true, cg_storage_manager_process_syncer },
    { "server", "cgStorageManager: Server",   (time_t) -1, (pid_t) -1, (pid_t) -1, true, cg_storage_manager_process_server },
};

COMPILER_STATIC_ASSERT(cg_storage_manager_processes_count == sizeof cg_storage_manager_processes / sizeof *cg_storage_manager_processes, "Enumerated processes does not match processes array size");

#define CG_STORAGE_MANAGER_MASTER_RESPAWN_INTERVAL (60)
#define MAXIMUM_NUMBER_OF_SIGNALS ((size_t) _NSIG)

static cgutils_event * signal_events[MAXIMUM_NUMBER_OF_SIGNALS];

static int cg_storage_manager_parse_opt(char const * const conf_file,
                                        cgutils_configuration ** const cg_conf)
{
    int result = EINVAL;

    if (conf_file != NULL && cg_conf != NULL)
    {
        result = cgutils_configuration_from_xml_file(conf_file,
                                                     cg_conf);

        if (result == 0)
        {
            assert(*cg_conf != NULL);
        }
    }

    return result;
}

static pid_t cg_storage_manager_get_old_child_pid(cg_storage_manager_process_type const type)
{
    assert(type < cg_storage_manager_processes_count);

    return cg_storage_manager_processes[type].old_pid;
}

static void cg_storage_manager_child_pipe_cb(int const fd,
                                             short const flags,
                                             void * const cb_data)
{
    cg_storage_manager_data * data = cb_data;
    assert(cb_data != NULL);
    assert(cb_data == global_data);
    assert(fd == master_children_pipe[0]);
    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    (void) flags;
    (void) fd;

    child_exiting = true;

    cgutils_event_exit_loop(event_data);
}

static int cg_storage_manager_master_notify_pipe(int const children_pipe[2])
{
    static char pipe_of_death[] = "K";
    static size_t pipe_of_death_len = sizeof pipe_of_death - 1;
    int result = 0;
    size_t sent = 0;
    assert(children_pipe != NULL);
    assert(children_pipe[1] >= 0);

    result = cgutils_network_send_data(children_pipe[1],
                                       true,
                                       pipe_of_death,
                                       pipe_of_death_len,
                                       &sent);

    if (result != 0)
    {
        CGUTILS_ERROR("Error sending pipe of death: %d", result);
    }

    return result;
}

static int cg_storage_manager_child_setup_master_pipe(cg_storage_manager_data * const data,
                                                      int master_pipe[2])
{
    int result = 0;
    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(data != NULL);
    assert(master_pipe != NULL);
    assert(master_pipe[0] >= 0);
    assert(event_data != NULL);

    if (master_children_pipe[1] >= 0)
    {
        cgutils_file_close(master_pipe[1]), master_pipe[1] = -1;
    }

    result = cgutils_event_create_fd_event(event_data,
                                           master_pipe[0],
                                           &cg_storage_manager_child_pipe_cb,
                                           data,
                                           CGUTILS_EVENT_READ,
                                           &child_pipe_event);

    if (result == 0)
    {
        assert(child_pipe_event != NULL);

        result = cgutils_event_enable(child_pipe_event,
                                      NULL);

        if (result != 0)
        {
            CGUTILS_ERROR("Error enabling child pipe event: %d", result);
            cgutils_event_free(child_pipe_event), child_pipe_event = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Error creating child pipe event: %d", result);
    }

    return result;
}

static int cg_storage_manager_setup_master_children_pipe(int children_pipe[2])
{
    int result = 0;
    assert(children_pipe != NULL);

    result = cgutils_file_pipe(children_pipe,
                               true);

    if (result != 0)
    {
        CGUTILS_ERROR("Error creating children pipe: %d", result);
    }

    return result;
}

static void cg_storage_manager_clean_master_children_pipe(int pipefd[2])
{
    if (child_pipe_event != NULL)
    {
        cgutils_event_free(child_pipe_event), child_pipe_event = NULL;
    }

    if (pipefd != NULL)
    {
        if (pipefd[0] >= 0)
        {
            cgutils_file_close(pipefd[0]), pipefd[0] = -1;
        }

        if (pipefd[1] >= 0)
        {
            cgutils_file_close(pipefd[1]), pipefd[1] = -1;
        }
    }
}

static void cg_storage_manager_child_signal_cb(int const sig,
                                               void * const cb_data)
{
    cg_storage_manager_data * data = cb_data;
    assert(sig >= 0);
    assert(cb_data != NULL);
    assert(cb_data == global_data);

    CGUTILS_TRACE("Got signal %d", sig);

    if (sig == SIGINT || sig == SIGTERM)
    {
        cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
        assert(event_data != NULL);

        child_exiting = true;

        cgutils_event_exit_loop(event_data);
    }
    else
    {
        /* Warn about other unhandled signals though. */
        CGUTILS_WARN("Signal not handled: %d", sig);
    }
}

static int cg_storage_manager_child_signal_init(cg_storage_manager_data * data)
{
    int result = 0;
    assert(data != NULL);

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    int const sigs[] = {
        SIGINT,
        SIGTERM
    };
    size_t const nb_sigs = sizeof sigs / sizeof *sigs;

    for (size_t idx = 0;
         result == 0 && idx < nb_sigs;
         idx++)
    {
        cgutils_event * sig_event = NULL;

        result = cgutils_event_create_signal_event(event_data,
                                                   sigs[idx],
                                                   &cg_storage_manager_child_signal_cb,
                                                   data,
                                                   &sig_event);

        if (result == 0)
        {
            assert(sig_event != NULL);

            result = cgutils_event_enable(sig_event, NULL);

            if (result == 0)
            {
                signal_events[sigs[idx]] = sig_event;
            }
            else
            {
                CGUTILS_ERROR("Error enabling signal %d handler: %d", sigs[idx], result);
            }

            if (result != 0)
            {
                cgutils_event_free(sig_event), sig_event = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating signal %d handler: %d", sigs[idx], result);
        }
    }

    return result;
}

static void cg_storage_manager_print_process_exit_status(pid_t const pid,
                                                         char const * const name,
                                                         int const status,
                                                         bool const exited,
                                                         bool const signaled)
{
    assert(name != NULL);

    if (exited == true)
    {
        CGUTILS_INFO("Process %s %lld has exited with status %d",
                     name,
                     (long long) pid,
                     status);
    }
    else if (signaled == true)
    {
        CGUTILS_ERROR("Process %s %lld has been terminated by signal %d",
                      name,
                      (long long) pid,
                      status);
    }
    else
    {
        CGUTILS_ERROR("Process %s %lld seems to have exited with status %d",
                      name,
                      (long long) pid,
                      status);
    }
}

#if 0
static int cg_storage_manager_waitpid(pid_t const pid,
                                      char const * const process_name)
{
    int status = 0;
    bool exited = false;
    bool signaled = false;

    int result = cgutils_process_waitpid(pid,
                                         &status,
                                         &exited,
                                         &signaled);

    if (result == 0)
    {
        cg_storage_manager_print_process_exit_status(pid,
                                                     process_name,
                                                     status,
                                                     exited,
                                                     signaled);
    }
    else
    {
        CGUTILS_ERROR("Error waiting for %s process %lld: %d",
                      process_name,
                      (long long) pid,
                      result);
    }

    return result;
}
#endif /* 0 */

static bool cg_storage_manager_in_background(cg_storage_manager_data const * const data)
{
    int result = false;
    CGUTILS_ASSERT(data != NULL);

    bool const nofork = getenv("CGSM_NOFORK") != NULL || cg_storage_manager_data_get_nofork(data) == true;
    bool const nodaemon = getenv("CGSM_NODAEMON") || cg_storage_manager_data_get_daemonize(data) == false;

    if (nofork == false &&
        nodaemon == false)
    {
        result = true;
    }

    return result;
}

static int cg_storage_manager_load_new_configuration(char const * const config_file,
                                                     cg_storage_manager_data ** const configuration)
{
    int result = 0;
    cgutils_configuration * config = NULL;
    assert(config_file != NULL);
    assert(configuration != NULL);

    result = cg_storage_manager_parse_opt(config_file, &config);

    if (result == 0)
    {
        result = cg_storage_manager_data_init(config,
                                              configuration);

        if (result == 0)
        {
            /* Parsing configuration */
            result = cg_storage_manager_load_configuration(*configuration,
                                                           true,
                                                           true);

            if (result == 0)
            {
                if (cg_storage_manager_in_background(*configuration) == true)
                {
                    char const * const log_file = cg_storage_manager_data_get_log_file(*configuration);

                    if (log_file != NULL)
                    {
                        cgutils_process_reopen_stderr(log_file);
                    }
                }
            }
            else
            {
                CGUTILS_ERROR("Error loading configuration: %d", result);
            }

            if (result != 0)
            {
                cg_storage_manager_data_free(*configuration), *configuration = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error in data init: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error parsing configuration: %d", result);
    }

    return result;
}

static void cg_storage_manager_cleanup(cg_storage_manager_data * data)
{
    for(size_t idx = 0; idx < MAXIMUM_NUMBER_OF_SIGNALS; idx++)
    {
        if (signal_events[idx] != NULL)
        {
            cgutils_event_free(signal_events[idx]), signal_events[idx] = NULL;
        }
    }

    cg_storage_manager_data_free(data);
}

static int cg_storage_manager_server(cg_storage_manager_data * const data,
                                     bool const graceful)
{
    assert(data != NULL);

    int result = cg_storage_manager_setup(data, true);

    if (result == 0)
    {
        result = cg_storage_manager_child_signal_init(data);

        if (result == 0)
        {
            result = cg_storage_manager_child_setup_master_pipe(data,
                                                                master_children_pipe);

            if (result == 0)
            {
                pid_t old_server_pid = -1;

                if (graceful == true)
                {
                    old_server_pid = cg_storage_manager_get_old_child_pid(cg_storage_manager_process_server);
                }

                result = cg_storage_manager_server_run(data,
                                                       graceful,
                                                       old_server_pid);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error in server run: %d", result);
                }

                cg_storage_manager_clean_master_children_pipe(master_children_pipe);
            }
            else
            {
                CGUTILS_ERROR("Error setting up pipe: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error setting signal handlers: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error in manager setup: %d", result);
    }

    cg_storage_manager_cleanup(data);

    return result;
}

static int cg_storage_manager_syncer(cg_storage_manager_data * const data,
                                     bool const graceful)
{
    assert(data != NULL);

    int result = cg_storage_manager_setup(data, true);

    if (result == 0)
    {
        result = cg_storage_manager_release_configuration(data);

        if (result == 0)
        {
            result = cg_storage_manager_child_signal_init(data);

            if (result == 0)
            {
                result = cg_storage_manager_child_setup_master_pipe(data,
                                                                    master_children_pipe);

                if (result == 0)
                {
                    result = cg_storage_manager_syncer_run(data,
                                                           graceful);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Exiting syncer loop with %d", result);
                    }

                    cg_storage_manager_clean_master_children_pipe(master_children_pipe);
                }
                else
                {
                    CGUTILS_ERROR("Error setting up pipe: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error setting signal handlers: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error releasing configuration: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error in manager setup: %d", result);
    }

    cg_storage_manager_cleanup(data);

    return result;
}

static int cg_storage_manager_monitor(cg_storage_manager_data * const data,
                                      bool const graceful)
{
    assert(data != NULL);

    int result = cg_storage_manager_setup(data, true);

    if (result == 0)
    {
        result = cg_storage_manager_release_configuration(data);

        if (result == 0)
        {
            result = cg_storage_manager_child_signal_init(data);

            if (result == 0)
            {
                result = cg_storage_manager_child_setup_master_pipe(data,
                                                                    master_children_pipe);

                if (result == 0)
                {
                    result = cg_storage_manager_monitor_run(data,
                                                            graceful);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Exiting monitor loop with %d", result);
                    }

                    cg_storage_manager_clean_master_children_pipe(master_children_pipe);
                }
                else
                {
                    CGUTILS_ERROR("Error setting up pipe: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error setting signal handlers: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error releasing configuration: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error in manager setup: %d", result);
    }

    cg_storage_manager_cleanup(data);

    return result;
}

static int cg_storage_manager_cleaner(cg_storage_manager_data * const data,
                                      bool const graceful)
{
    assert(data != NULL);

    int result = cg_storage_manager_setup(data, false);

    if (result == 0)
    {
        result = cg_storage_manager_release_configuration(data);

        if (result == 0)
        {
            result = cg_storage_manager_child_signal_init(data);

            if (result == 0)
            {
                result = cg_storage_manager_child_setup_master_pipe(data,
                                                                    master_children_pipe);

                if (result == 0)
                {
                    result = cg_storage_manager_cleaner_run(data,
                                                            graceful);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Exiting cleaner loop with %d", result);
                    }

                    cg_storage_manager_clean_master_children_pipe(master_children_pipe);
                }
                else
                {
                    CGUTILS_ERROR("Error setting up pipe: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error setting signal handlers: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error releasing configuration: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error in manager setup: %d", result);
    }

    cg_storage_manager_cleanup(data);

    return result;
}

static int cg_storage_manager_start_child(size_t const process_id,
                                          char * const argv0,
                                          bool const graceful,
                                          cg_storage_manager_data * const data)
{
    int result = 0;

    cg_storage_manager_processes[process_id].pid = getpid();

    cgutils_system_setproctitle(argv0,
                                cg_storage_manager_processes[process_id].proc_title);

    switch (process_id)
    {
    case cg_storage_manager_process_cleaner:
        result = cg_storage_manager_cleaner(data, graceful);
        break;
    case cg_storage_manager_process_monitor:
        result = cg_storage_manager_monitor(data, graceful);
        break;
    case cg_storage_manager_process_syncer:
        result = cg_storage_manager_syncer(data, graceful);
        break;
    case cg_storage_manager_process_server:
        result = cg_storage_manager_server(data, graceful);
        break;
    }

    return result;
}

static void cg_storage_manager_clean_inherited_env(cg_storage_manager_data * const data)
{
    /* clear timer, signals, and event_base */
    cgutils_crypto_atfork();

    if (master_timer_event != NULL)
    {
        cgutils_event_free(master_timer_event), master_timer_event = NULL;
    }

    for(size_t idx = 0; idx < MAXIMUM_NUMBER_OF_SIGNALS; idx++)
    {
        if (signal_events[idx] != NULL)
        {
            cgutils_event_free(signal_events[idx]), signal_events[idx] = NULL;
        }
    }

    cg_storage_manager_data_destroy_event(data);

    if (old_global_data != NULL)
    {
        cg_storage_manager_data_free(old_global_data), old_global_data = NULL;
    }
}

static void cg_storage_manager_master_do_respawn(char * const argv0,
                                                 cg_storage_manager_data * const data,
                                                 bool * const is_master)
{
    int result = 0;
    time_t const now = time(NULL);
    time_t next = -1;
    assert(data != NULL);

    for (size_t idx = 0;
         result == 0 &&
             idx < cg_storage_manager_processes_count &&
             *is_master == true;
         idx++)
    {
        if (cg_storage_manager_processes[idx].enabled == true &&
            cg_storage_manager_processes[idx].pid == -1)
        {
            if (cg_storage_manager_processes[idx].next_respawn <= now)
            {
                cg_storage_manager_processes[idx].pid = fork();

                if (cg_storage_manager_processes[idx].pid == 0)
                {
                    *is_master = false;

                    cg_storage_manager_clean_inherited_env(data);

                    result = cg_storage_manager_start_child(idx,
                                                            argv0,
                                                            graceful_restart,
                                                            data);

                }
                else if (cg_storage_manager_processes[idx].pid < 0)
                {
                    result = errno;
                }
                else
                {
                    cg_storage_manager_processes[idx].next_respawn = now +
                        CG_STORAGE_MANAGER_MASTER_RESPAWN_INTERVAL;
                }
            }
            else
            {
                CGUTILS_INFO("Process %s is respawning too fast, next respawn in %lld seconds.",
                             cg_storage_manager_processes[idx].name,
                             (long long int) (cg_storage_manager_processes[idx].next_respawn - now));

                if (next == -1)
                {
                    next = cg_storage_manager_processes[idx].next_respawn;
                }
                else if (next > cg_storage_manager_processes[idx].next_respawn)
                {
                    next = cg_storage_manager_processes[idx].next_respawn;
                }
            }
        }
    }

    if (*is_master == true)
    {
        graceful_restart = false;

        if (next == -1)
        {
            master_state = cg_storage_manager_master_watching;

            if (cgutils_event_is_enabled(master_timer_event) == true)
            {
                cgutils_event_disable(master_timer_event);
            }
        }
        else
        {
            struct timeval const tv =
                {
                    .tv_sec = next - now,
                    .tv_usec = 0,
                };
            assert(master_timer_event != NULL);

            result = cgutils_event_enable(master_timer_event, &tv);

            if (result != 0)
            {
                CGUTILS_ERROR("Error enabling master timer event: %d", result);
            }

            master_state = cg_storage_manager_master_watching_waiting_respawning;
        }
    }
}

static int cg_storage_manager_prefork_tasks(cg_storage_manager_data * const mg_data,
                                            bool const reload)
{
    int result = 0;
    CGUTILS_ASSERT(mg_data != NULL);

    if (reload == false)
    {
        result = cg_storage_manager_setup_master_children_pipe(master_children_pipe);
    }

    if (result == 0)
    {
        time_t const now = time(NULL);
        char * monitor_info_path = NULL;
        char const * const monitor_info_config_path = cg_storage_manager_data_get_monitor_informations_path(mg_data);
        assert(monitor_info_config_path != NULL);

        result = cgutils_asprintf(&monitor_info_path,
                                  "%s-%lld-%llu",
                                  monitor_info_config_path,
                                  (long long unsigned int) getpid(),
                                  (long long unsigned int) now);

        if (result == 0)
        {
            size_t const instances_count = cg_storage_manager_data_get_instances_count(mg_data);

            if (instances_count > 0)
            {
                cg_monitor_data * monitor_data = NULL;

                result = cg_monitor_data_create(monitor_info_path,
                                                instances_count,
                                                &monitor_data);

                if (result == 0)
                {
                    cg_storage_manager_data_set_monitor_data(mg_data, monitor_data);
                }
                else
                {
                    CGUTILS_ERROR("Error creating shared memory for monitor: %d", result);
                }
            }
            else
            {
                CGUTILS_WARN("No instances ? Oh, well.");
            }

            CGUTILS_FREE(monitor_info_path);
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for monitor info path: %d", result);
        }
    }
    else
    {
      CGUTILS_ERROR("Error setting up master child pipe: %d", result);
    }

    return result;
}

static void cg_storage_manager_master_timer_cb(void * cb_data)
{
    cg_storage_manager_data * data = cb_data;
    assert(cb_data != NULL);
    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    if (master_state == cg_storage_manager_master_watching_waiting_respawning)
    {
        master_state = cg_storage_manager_master_respawning;
    }

    cgutils_event_exit_loop(event_data);
}

static int cg_storage_manager_master_signal_init(cg_storage_manager_data * data);

static int cg_storage_manager_reset_local_events(cg_storage_manager_data * const data)
{
    int result = 0;
    assert(data != NULL);
    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    if (master_timer_event != NULL)
    {
        cgutils_event_free(master_timer_event), master_timer_event = NULL;
    }

    result = cgutils_event_create_timer_event(event_data,
                                              0,
                                              &cg_storage_manager_master_timer_cb,
                                              data,
                                              &master_timer_event);

    if (result == 0)
    {
        for(size_t idx = 0; idx < MAXIMUM_NUMBER_OF_SIGNALS; idx++)
        {
            if (signal_events[idx] != NULL)
            {
                cgutils_event_free(signal_events[idx]), signal_events[idx] = NULL;
            }
        }

        result = cg_storage_manager_master_signal_init(data);

        if (result == 0)
        {
        }
        else
        {
            CGUTILS_ERROR("Error in master signal init: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error creating timer event: %d", result);
    }

    return result;
}

static int cg_storage_manager_send_graceful_exit_signal_to_children(int const sig,
                                                                    bool const disable,
                                                                    bool const skip_server)
{
    int result = 0;
    time_t const now = time(NULL);

    for (size_t idx = 0;
         idx < cg_storage_manager_processes_count;
         idx++)
    {
        pid_t const pid = cg_storage_manager_processes[idx].pid;

        if (pid != -1)
        {
            if (disable == true)
            {
                cg_storage_manager_processes[idx].enabled = false;
            }
            else
            {
                cg_storage_manager_processes[idx].next_respawn = now;
            }

            if (skip_server == false ||
                cg_storage_manager_processes[idx].type != cg_storage_manager_process_server)
            {
                CGUTILS_TRACE("Sending signal %d to process %lld (%s)",
                              sig,
                              (long long) pid,
                              cg_storage_manager_processes[idx].name);

                result = cgutils_process_signal(pid, sig);

                if (result == 0)
                {
                    cg_storage_manager_processes[idx].old_pid = pid;
                    cg_storage_manager_processes[idx].pid = -1;
                }
                else
                {
                    CGUTILS_ERROR("Error sending signal %d to %s process %lld: %d",
                                  sig,
                                  cg_storage_manager_processes[idx].name,
                                  (long long) pid,
                                  result);
                }
            }
            else
            {
                /* For graceful restart, the old server process will be
                   signaled by the new one once it is ready. */
                cg_storage_manager_processes[idx].old_pid = pid;
                cg_storage_manager_processes[idx].pid = -1;
            }
        }
    }

    return result;
}

static void cg_storage_manager_reap_children(bool * const need_respawn)
{
    int result = 0;
    assert(need_respawn != NULL);
    *need_respawn = false;

    do
    {
        pid_t reaped = -1;
        int status = 0;
        bool signaled = false;
        bool exited = false;

        result = cgutils_process_reap(&reaped,
                                      WNOHANG,
                                      &status,
                                      &exited,
                                      &signaled);

        if (result == 0)
        {
            bool found = false;
            char const * process_name = "unknown";

            for (size_t idx = 0;
                 found == false &&
                     idx < cg_storage_manager_processes_count;
                 idx++)
            {
                pid_t const pid = cg_storage_manager_processes[idx].pid;
                pid_t const old_pid = cg_storage_manager_processes[idx].old_pid;

                if (pid == reaped ||
                    old_pid == reaped)
                {
                    found = true;
                    process_name = cg_storage_manager_processes[idx].name;

                    if (pid == reaped)
                    {
                        /* Current process */
                        cg_storage_manager_processes[idx].pid = (pid_t) -1;

                        if (cg_storage_manager_processes[idx].enabled == true)
                        {
                            *need_respawn = true;
                        }
                    }
                    else
                    {
                        cg_storage_manager_processes[idx].old_pid = (pid_t) -1;
                    }

                }
            }

            cg_storage_manager_print_process_exit_status(reaped,
                                                         process_name,
                                                         status,
                                                         exited,
                                                         signaled);
        }
        else if (result != ECHILD &&
                 result != ENOENT)
        {
            CGUTILS_ERROR("Error waiting for exited process: %d", result);
        }
    }
    while (result == 0);
}

static void cg_storage_manager_master_handle_old_global_data(void)
{
    bool all_old_processes_exited = true;

    for (size_t idx = 0;
         all_old_processes_exited == true &&
             idx < cg_storage_manager_processes_count;
         idx++)
    {
        if (cg_storage_manager_processes[idx].old_pid != (pid_t) -1)
        {
            all_old_processes_exited = false;
        }
    }

    if (all_old_processes_exited == true)
    {
        cg_monitor_data * monitor_data = cg_storage_manager_data_get_monitor_data(old_global_data);

        if (monitor_data != NULL)
        {
            int res = cg_monitor_data_destroy(monitor_data);

            if (res != 0)
            {
                CGUTILS_ERROR("Error destroying monitor data: %d", res);
            }
        }

        cg_storage_manager_data_free(old_global_data), old_global_data = NULL;
    }
}

static void cg_storage_manager_master_signal_cb(int sig,
                                                void * cb_data)
{
    int result = 0;
    cg_storage_manager_data * data = cb_data;
    bool all_exited = true;

    assert(sig >= 0);
    assert(cb_data != NULL);
    assert(cb_data == global_data);

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    CGUTILS_TRACE("Got signal %d", sig);

    if (sig == SIGINT || sig == SIGTERM)
    {
        /* Mark processes as exiting */
        for (size_t idx = 0;
             idx < cg_storage_manager_processes_count;
             idx++)
        {
            cg_storage_manager_processes[idx].enabled = false;
        }

        if (sig == SIGTERM)
        {
            CGUTILS_TRACE("Stopping children..");
            int res = cg_storage_manager_master_notify_pipe(master_children_pipe);

            if (res != 0)
            {
                CGUTILS_ERROR("Error notifying children on pipe: %d", res);
            }
        }

    }
    else if (sig == SIGCHLD)
    {
        bool need_respawn = false;

        cg_storage_manager_reap_children(&need_respawn);

        if (need_respawn == true)
        {
            master_state = cg_storage_manager_master_respawning;
            cgutils_event_exit_loop(event_data);
        }
    }
    else if (sig == CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG)
    {
        CGUTILS_TRACE("Gracefully exiting.");
        cg_storage_manager_send_graceful_exit_signal_to_children(sig, true, false);
    }
    else if (sig == CG_STORAGE_MANAGER_COMMON_RELOAD_CONFIG_SIG)
    {
        cg_storage_manager_data * new_configuration = NULL;

        graceful_restart = true;

        result = cg_storage_manager_load_new_configuration(configuration_file,
                                                           &new_configuration);

        if (result == 0)
        {
            result = cg_storage_manager_prefork_tasks(new_configuration, true);

            if (result == 0)
            {
                result = cg_storage_manager_data_setup_event(new_configuration);

                if (result == 0)
                {
                    /* reload local events */
                    result = cg_storage_manager_reset_local_events(new_configuration);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error resetting local events: %d", result);
                    }

                    /* signal old workers */
                    result = cg_storage_manager_send_graceful_exit_signal_to_children(CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG,
                                                                                      false,
                                                                                      true);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error gracefully stopping old workers: %d", result);
                    }

                    old_global_data = global_data;
                    global_data = new_configuration;
                    new_configuration = NULL;
                    event_data = cg_storage_manager_data_get_event(global_data);
                    assert(event_data != NULL);

                    /* start new workers */
                    master_state = cg_storage_manager_master_respawning;
                    cgutils_event_exit_loop(event_data);
                }
                else
                {
                    CGUTILS_ERROR("Error setting up event: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error performing prefork tasks: %d", result);
            }

            if (result != 0)
            {
                cg_storage_manager_data_free(new_configuration), new_configuration = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error loading new configuration: %d", result);
        }
    }
    else
    {
        CGUTILS_WARN("Signal not handled: %d", sig);
    }

    for (size_t idx = 0;
         all_exited == true &&
             idx < cg_storage_manager_processes_count;
         idx++)
    {
        if (cg_storage_manager_processes[idx].pid != (pid_t) -1 ||
            cg_storage_manager_processes[idx].old_pid != (pid_t) -1 ||
            cg_storage_manager_processes[idx].enabled == true)
        {
            all_exited = false;
        }
    }

    if (old_global_data != NULL)
    {
        cg_storage_manager_master_handle_old_global_data();
    }

    if (all_exited == true)
    {
        master_state = cg_storage_manager_master_exiting;
        cgutils_event_exit_loop(event_data);
    }
}

static int cg_storage_manager_master_signal_init(cg_storage_manager_data * data)
{
    int result = 0;
    assert(data != NULL);

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    int const sigs[] =
        {
            SIGINT,
            SIGTERM,
            SIGCHLD,
            CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG,
            CG_STORAGE_MANAGER_COMMON_RELOAD_CONFIG_SIG
        };

    size_t const nb_sigs = sizeof sigs / sizeof *sigs;

    for (size_t idx = 0;
         result == 0 && idx < nb_sigs;
         idx++)
    {
        cgutils_event * sig_event = NULL;

        result = cgutils_event_create_signal_event(event_data,
                                                   sigs[idx],
                                                   &cg_storage_manager_master_signal_cb,
                                                   data,
                                                   &sig_event);

        if (result == 0)
        {
            assert(sig_event != NULL);

            result = cgutils_event_enable(sig_event, NULL);

            if (result == 0)
            {
                signal_events[sigs[idx]] = sig_event;
            }
            else
            {
                CGUTILS_ERROR("Error enabling signal %d handler: %d",
                              sigs[idx],
                              result);
            }

            if (result != 0)
            {
                cgutils_event_free(sig_event), sig_event = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating signal %d handler: %d",
                          sigs[idx],
                          result);
        }
    }

    return result;
}

static int cg_storage_manager_master(char * const argv0,
                                     cg_storage_manager_data * data)
{
    bool is_master = true;
    assert(data != NULL);

    int result = cg_storage_manager_data_setup_event(data);

    if (result == 0)
    {
        cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
        assert(event_data != NULL);

        result = cgutils_event_create_timer_event(event_data,
                                                  0,
                                                  &cg_storage_manager_master_timer_cb,
                                                  data,
                                                  &master_timer_event);

        if (result == 0)
        {
            result = cg_storage_manager_master_signal_init(data);

            if (result == 0)
            {
                char const * pid_file = cg_storage_manager_data_get_pid_file(data);
                assert(pid_file != NULL);

                result = cgutils_process_write_pid(pid_file);

                if (result == 0)
                {
                    do
                    {
                        cgutils_event_dispatch(event_data);

                        if (data != global_data)
                        {
                            if (data == old_global_data)
                            {
                                /* disable old global event data */
                                cg_storage_manager_data_destroy_event(data);
                            }

                            data = global_data;
                            event_data = cg_storage_manager_data_get_event(data);
                            assert(event_data != NULL);
                        }

                        if (master_state == cg_storage_manager_master_respawning)
                        {
                            /* We were waiting for a timer in order to respawn a child. */
                            cg_storage_manager_master_do_respawn(argv0,
                                                                 data,
                                                                 &is_master);

                        }
                        else
                        {
                            /* We were waiting for a timer in order to check that all children
                               exited correctly. */
                            /*
                               Timer in order to force childs to exit:
                               - do we need it ?
                               => for graceful exit, well, that's graceful, so..
                               => for forced exit, well, we already wrote on the pipe, so what?
                             */
                        }
                    }
                    while (is_master == true &&
                           (master_state == cg_storage_manager_master_watching ||
                            master_state == cg_storage_manager_master_watching_waiting_respawning));

                    if (is_master == true)
                    {
                        pid_file = cg_storage_manager_data_get_pid_file(data);
                        assert(pid_file != NULL);

                        cgutils_file_unlink(pid_file);

                        cg_storage_manager_release_configuration(data);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error writing pid to %s: %d",
                                  pid_file,
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error setting signal handlers: %d", result);
            }

            if (master_timer_event != NULL)
            {
                cgutils_event_free(master_timer_event), master_timer_event = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating timer event: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error in storage manager event setup: %d", result);
    }

    if (is_master == true)
    {

        cg_monitor_data * monitor_data = cg_storage_manager_data_get_monitor_data(data);

        if (monitor_data != NULL)
        {
            int res = cg_monitor_data_destroy(monitor_data);

            if (res != 0)
            {
                CGUTILS_ERROR("Error destroying monitor data: %d", res);
            }
        }

        /* Otherwise, data has been freed in the child's role function */
        cg_storage_manager_cleanup(data);
    }

    return 0;
}

static int cg_storage_manager_daemonize(cg_storage_manager_data * data,
                                        bool * const master)
{
    int result = 0;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(master != NULL);

    if (cg_storage_manager_in_background(data) == true)
    {
        char const * const log_file = cg_storage_manager_data_get_log_file(data);
        result = cgutils_process_daemonize(log_file, master);

        if (result != 0 &&
            *master == true)
        {
            CGUTILS_ERROR("Error in daemonize: %d", result);
        }
    }
    else
    {
        *master = true;
    }

    return result;
}

static int cg_storage_manager_roles(char * const argv0,
                                    cg_storage_manager_data * data)
{
    int result = 0;
    assert(data != NULL);

    bool const nofork = getenv("CGSM_NOFORK") != NULL || cg_storage_manager_data_get_nofork(data) == true;

    if (nofork == true)
    {
        result = cg_storage_manager_server(data, false);
    }
    else
    {
        bool is_master = true;
        time_t const now = time(NULL);

        for (size_t idx = 0;
             result == 0 &&
                 idx < cg_storage_manager_processes_count &&
                 is_master == true;
             idx++)
        {
            if (cg_storage_manager_processes[idx].enabled == true)
            {
                cg_storage_manager_processes[idx].pid = fork();

                if (cg_storage_manager_processes[idx].pid == 0)
                {
                    is_master = false;

                    result = cg_storage_manager_start_child(idx,
                                                            argv0,
                                                            false,
                                                            data);
                }
                else if (cg_storage_manager_processes[idx].pid < 0)
                {
                    result = errno;
                }
                else
                {
                    cg_storage_manager_processes[idx].next_respawn = now +
                        CG_STORAGE_MANAGER_MASTER_RESPAWN_INTERVAL;
                }
            }
        }

        if (result == 0 &&
            is_master == true)
        {
            result = cg_storage_manager_master(argv0, data);
        }
    }

    return result;
}

int cg_storage_manager_common_register_signal(cg_storage_manager_data * const data,
                                              int const sig,
                                              cg_storage_manager_common_signal_cb * const signal_cb,
                                              void * const cb_data)
{
    int result = 0;
    assert(data != NULL);

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    cgutils_event * sig_event = NULL;

    result = cgutils_event_create_signal_event(event_data,
                                               sig,
                                               signal_cb,
                                               cb_data,
                                               &sig_event);

    if (result == 0)
    {
        assert(sig_event != NULL);

        result = cgutils_event_enable(sig_event, NULL);

        if (result == 0)
        {
            signal_events[sig] = sig_event;
        }
        else
        {
            CGUTILS_ERROR("Error enabling signal %d handler: %d", sig, result);
        }

        if (result != 0)
        {
            cgutils_event_free(sig_event), sig_event = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Error creating signal %d handler: %d", sig, result);
    }

    return result;
}

static int cg_storage_manager_init_all(void)
{
    int result = cgutils_crypto_init();

    if (result == 0)
    {
        result = cgutils_xml_init();

        if (result == 0)
        {
            result = cgutils_configuration_init();

            if (result == 0)
            {
                result = cgutils_http_init();
            }
        }
    }

    return result;
}

static void cg_storage_manager_destroy_all(void)
{
    cgutils_http_destroy();
    cgutils_configuration_destroy();
    cgutils_xml_destroy();
    cgutils_crypto_destroy();
}

int main(int argc, char ** argv)
{
    int result = EINVAL;
    assert(argv != NULL);
    assert(argv[0] != NULL);

    if (argc == 2)
    {
        setlocale(LC_TIME, "C");

        result = cg_storage_manager_init_all();

        if (result == 0)
        {
            cg_storage_manager_data * mg_data = NULL;
            /* Ignore SIGPIPE as writing to a closed socket is properly handled
               by checking the result of the send() / write() call. */
            signal(SIGPIPE, SIG_IGN);

            configuration_file = argv[1];

            result = cg_storage_manager_load_new_configuration(configuration_file,
                                                               &mg_data);

            if (result == 0)
            {
                bool master = false;
                global_data = mg_data;

                result = cg_storage_manager_daemonize(mg_data,
                                                      &master);

                if (result == 0 &&
                    master == true)
                {
                    result = cg_storage_manager_prefork_tasks(mg_data,
                                                              false);

                    if (result == 0)
                    {
                        result = cg_storage_manager_roles(argv[0], mg_data);
                        mg_data = NULL;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error in prefork tasks: %d", result);
                    }

                    cg_storage_manager_clean_master_children_pipe(master_children_pipe);
                }

                if ((result != 0 || master == false) &&
                    mg_data != NULL)
                {
                    cg_storage_manager_data_free(mg_data), mg_data = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error loading data configuration:  %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error in init all: %d", result);
        }

        cg_storage_manager_destroy_all();
    }
    else
    {
        CGUTILS_ERROR("Usage: %s <configuration file>", argv[0]);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
