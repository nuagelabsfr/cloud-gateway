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

#ifndef TOOLS_COMMON_H_
#define TOOLS_COMMON_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_crypto.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_http.h>
#include <cloudutils/cloudutils_process.h>
#include <cloudutils/cloudutils_xml.h>

static inline int cg_tools_init_all(void)
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

static inline void cg_tools_destroy_all(void)
{
    cgutils_http_destroy();
    cgutils_configuration_destroy();
    cgutils_xml_destroy();
    cgutils_crypto_destroy();
}

int cg_tools_handle_subprocess_exit(char const * process,
                                    int exec_result,
                                    int exit_code);

int cg_tools_handle_subprocess_reap(char const * process,
                                    pid_t pid,
                                    int exec_result,
                                    int exit_code);

int cg_tools_validate_mac_address(char const * mac_address);

int cg_tools_check_and_open_source_file(char const * path,
                                        int * fd,
                                        bool allow_root_owned_file);

int cg_tools_check_and_open_destination_file(char const * path,
                                             int * fd,
                                             bool strict_perms);

int cg_tools_validate_vlan(char const * vlan);

int cg_tools_set_env_for_suid(void);

#endif /* TOOLS_COMMON_H_ */
