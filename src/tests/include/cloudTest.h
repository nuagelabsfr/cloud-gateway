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

#ifndef CLOUD_TEST_H_
#define CLOUD_TEST_H_

#include <signal.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_crypto.h>
#include <cloudutils/cloudutils_http.h>
#include <cloudutils/cloudutils_xml.h>

#define PROJECT_DIR "/opt/cloudGW_build/repo"
#define TEST_BASE_DIR PROJECT_DIR "/src/tests/"
#define TEST_BUILD_DIR PROJECT_DIR "/build/"
#define TEST_STORAGE_FILTER_DIR TEST_BUILD_DIR "/cloudStorageFilters/lib/"

#define CONFIG_FILE TEST_BASE_DIR "CloudGatewayConfiguration.xml"
#define CONFIG_FILE_OSTACK_V2 TEST_BASE_DIR "CloudGatewayConfigurationOpenstackIdentityV2.xml"
#define CONFIG_FILE_PG TEST_BASE_DIR "configs/CloudGatewayConfigurationPG.xml"
#define CONFIG_FILE_MONGO TEST_BASE_DIR "configs/CloudGatewayConfigurationMongo.xml"

#define LOG(...)                                                        \
    do                                                                  \
    {                                                                   \
        cgutils_set_color(stderr, CLOUDUTILS_ANSI_COLOR_ATTR_DIM, CLOUDUTILS_ANSI_COLOR_RED, CLOUDUTILS_ANSI_COLOR_BLACK); \
        fprintf(stderr, "[%s(%d)] %s: ", __FILE__, __LINE__, __func__); \
        fprintf(stderr, __VA_ARGS__);                                   \
        fputs("\n", stderr);                                            \
        cgutils_set_color(stderr, CLOUDUTILS_ANSI_COLOR_ATTR_RESET, CLOUDUTILS_ANSI_COLOR_WHITE, CLOUDUTILS_ANSI_COLOR_BLACK); \
    }                                                                   \
    while(0)

#define TEST_ASSERT(condition, message)                                 \
    if ((condition) == false)                                           \
    {                                                                   \
        LOG("Assertion {%s} failed in %s: %s", #condition, __func__, (message) ); \
    }

static inline int cg_tests_init_all(void)
{
    /* Ignore SIGPIPE as writing to a closed socket is properly handled
       by checking the result of the send() / write() call. */
    signal(SIGPIPE, SIG_IGN);

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

static inline void cg_tests_destroy_all(void)
{
    cgutils_http_destroy();
    cgutils_configuration_destroy();
    cgutils_xml_destroy();
    cgutils_crypto_destroy();
}

#endif /* CLOUD_TEST_H_ */
