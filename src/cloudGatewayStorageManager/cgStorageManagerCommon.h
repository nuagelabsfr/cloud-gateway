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

#ifndef CG_STORAGE_MANAGER_COMMON_H_
#define CG_STORAGE_MANAGER_COMMON_H_

#include <signal.h>

/* Signal sent from the user to the master process.
   This signal is *not* sent to the children, they are sent
   a graceful_exit signal and new children are started
   with an updated configuration. */
#define CG_STORAGE_MANAGER_COMMON_RELOAD_CONFIG_SIG SIGHUP

/* Signal sent from the user to the master, and from the
   master to its children. */
#define CG_STORAGE_MANAGER_COMMON_GRACEFUL_EXIT_SIG SIGUSR1

static inline char const * cg_storage_manager_common_get_version(void)
{
    static char const version[] =
#ifdef CG_COMPILE_VERSION
#define xstr(s) str(s)
#define str(s) #s
        xstr(CG_COMPILE_VERSION)
#undef str
#undef xstr
#else
        "Unknown"
#endif /* CG_COMPILE_VERSION */
        ;
    return version;
}

typedef void (cg_storage_manager_common_signal_cb)(int signal,
                                                   void * cb_data);

#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_manager.h>

int cg_storage_manager_common_register_signal(cg_storage_manager_data * data,
                                              int signal,
                                              cg_storage_manager_common_signal_cb * signal_cb,
                                              void * cb_data);

#endif /* CG_STORAGE_MANAGER_COMMON_H_ */
