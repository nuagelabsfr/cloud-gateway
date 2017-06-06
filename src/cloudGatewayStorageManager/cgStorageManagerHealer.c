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
#include <inttypes.h>
#include <time.h>

#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>

#include "cgStorageManagerHealer.h"
#include "cgStorageManagerCommon.h"

#define CG_STORAGE_MANAGER_HEALER_DELAY_DEFAULT (60)

#define CG_STORAGE_MANAGER_HEALER_DB_SLOTS_DEFAULT (10)

typedef struct
{
    cg_storage_manager_data * data;
    cgutils_event * timer_event;

    size_t remaining_db_slots;


    bool running;
    bool exiting;
} cg_storage_manager_healner_data;

static void cg_storage_manager_healer_graceful_exit(int const sig,
                                                    void * const cb_data)
{
    cg_storage_manager_healer_data * healer_data = cb_data;

    assert(sig == CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG);
    assert(cb_data != NULL);

    (void) sig;

    if (healer_data->exiting == false)
    {
        if (healer_data->timer_event != NULL)
        {
            cgutils_event_disable(healer_data->timer_event);
        }

        healer_data->exiting = true;

        if (healer_data->running == false)
        {
            cgutils_event_data * event_data = cg_storage_manager_data_get_event(healer_data->data);
            assert(event_data != NULL);
            cgutils_event_exit_after_loop(event_data, NULL);
        }
    }
}

static void cg_storage_manager_healer_timer_cb(void * cb_data)
{
    cg_storage_manager_healer_data * healer = cb_data;
    assert(cb_data != NULL);
    assert(healer->data != NULL);

    if (healer->running == false &&
        healer->remaining_db_slots > 0)
    {
        cg_storage_manager_data * data = healer->data;

        /* Locate orphan inode: (not linked to any entry or delayed_entry)
           - Every 12 hours or so
           - SELECT ino.fs_id, ino.inode_number FROM inodes AS ino
             LEFT OUTER JOIN entries AS ent ON (ent.fs_id = ino.fs_id AND ent.inode_number = ino.inode_number)
             LEFT OUTER JOIN delayed_expunge_entries AS dee ON (dee.fs_id = ino.fs_id AND dee.inode_number = ino.inode_number)
             WHERE ent.inode_number IS NULL AND dee.inode_number IS NULL
             ORDER BY ino.fs_id, ino.inode_number;
        */
        /* Locate missing inodes_instances:
           - Every 12 hours or so
           - In mirroring, for each instance associated with this FS:
             SELECT ino.fs_id, ino.inode_number FROM inodes AS ino
             LEFT OUTER JOIN inodes_instances_link AS iil ON (iil.fs_id = ino.fs_id AND iil.inode_number = ino.inode_number)
             LEFT OUTER JOIN inodes_instances AS ii ON (ii.inode_instance_id = iil.inode_instance_id AND ii.instance = $1)
             WHERE iil.inode_instance_id IS NULL
             ORDER BY ino.fs_id, ino.inode_number;
           - In striping mode,
             SELECT ino.fs_id, ino.inode_number FROM inodes AS ino
             LEFT OUTER JOIN inodes_instances_link AS iil ON (iil.fs_id = ino.fs_id AND iil.inode_number = ino.inode_number)
             LEFT OUTER JOIN inodes_instances AS ii ON (ii.inode_instance_id = iil.inode_instance_id)
             WHERE iil.inode_instance_id IS NULL
             ORDER BY ino.fs_id, ino.inode_number;
        */

        healer->running = true;

        healer->running = false;
    }
}

int cg_storage_manager_healer_run(cg_storage_manager_data * const data,
                                  bool const graceful)
{
    int result = 0;
    assert(data != NULL);

    cg_monitor_data * monitor_data = cg_storage_manager_data_get_monitor_data(data);

    if (monitor_data != NULL)
    {
        cg_monitor_data_free(monitor_data), monitor_data = NULL;
        cg_storage_manager_data_set_monitor_data(data, NULL);
    }

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    cg_storage_manager_healer_data * healer = NULL;

    (void) graceful;

    CGUTILS_ALLOCATE_STRUCT(healer);

    if (healer != NULL)
    {
        size_t healer_delay = cg_storage_manager_data_get_healer_delay(data);
        healer->data = data;
        healer->remaining_db_slots = cg_storage_manager_data_get_healer_db_slots(data);

        if (healer->remaining_db_slots == 0)
        {
            healer->remaining_db_slots = CG_STORAGE_MANAGER_HEALER_DB_SLOTS_DEFAULT;
        }

        if (healer_delay == 0)
        {
            healer_delay = CG_STORAGE_MANAGER_HEALER_DELAY_DEFAULT;
        }

        result = cgutils_event_create_timer_event(event_data,
                                                  CGUTILS_EVENT_PERSIST,
                                                  &cg_storage_manager_healer_timer_cb,
                                                  healer,
                                                  &(healer->timer_event));

        if (result == 0)
        {
            result = cg_storage_manager_common_register_signal(data,
                                                               CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG,
                                                               &cg_storage_manager_healer_graceful_exit,
                                                               healer);

            if (result == 0)
            {
                struct timeval tv =
                    {
                        .tv_sec = (time_t) healer_delay,
                        .tv_usec = 0
                    };

                result = cgutils_event_enable(healer->timer_event, &tv);

                if (result == 0)
                {
                    cg_storage_manager_loop(data);
                    cgutils_event_disable(healer->timer_event);
                }
                else
                {
                    CGUTILS_ERROR("Error enabling timer event: %d", result);
                }

                cgutils_event_free(healer->timer_event), healer->timer_event = NULL;
            }
            else
            {
                    CGUTILS_ERROR("Error registering signal event: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating timer event: %d", result);
        }

        CGUTILS_FREE(healer), healer = NULL;
    }
    else
    {
        result = ENOMEM;
        CGUTILS_ERROR("Error allocating memory for healer data: %d", result);
    }

    return result;
}
