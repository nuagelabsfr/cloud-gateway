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

static inline char const * cg_tests_get_build_dir(void)
{
    static char const * const default_dir = ".";
    char const * result = getenv("CG_TESTS_BUILD_DIR");

    if (result == NULL)
    {
        result = default_dir;
    }

    return result;
}

static inline char const * cg_tests_get_temp_dir(void)
{
    static char const * const default_dir = "/tmp";
    char const * result = getenv("TMPDIR");

    if (result == NULL)
    {
        result = default_dir;
    }

    return result;
}

static inline char * cg_tests_get_configs_dir(void)
{
    char * result = NULL;
    char const * build_dir = cg_tests_get_build_dir();

    if (build_dir != NULL)
    {
        asprintf(&result, "%s/../src/tests/configs", build_dir);
    }

    return result;
}

static inline char * cg_tests_get_config_file(char const * const filename)
{
    char * result = NULL;
    char * configs_dir = cg_tests_get_configs_dir();

    if (configs_dir != NULL)
    {
        asprintf(&result, "%s/%s", configs_dir, filename);
        CGUTILS_FREE(configs_dir);
    }

    return result;
}

static inline char * cg_tests_get_temp_file(char const * const filename)
{
    char * result = NULL;
    char const * temp_dir = cg_tests_get_temp_dir();

    if (temp_dir != NULL)
    {
        asprintf(&result, "%s/%s", temp_dir, filename);
    }

    return result;
}

static inline char * cg_tests_get_storage_filter_dir(void)
{
    char * result = NULL;
    char const * build_dir = cg_tests_get_build_dir();

    if (build_dir != NULL)
    {
        asprintf(&result, "%s/%s", build_dir, "cloudStorageFilters/lib/");
    }

    return result;
}

static inline char * cg_tests_get_db_backends_dir(void)
{
    char * result = NULL;
    char const * build_dir = cg_tests_get_build_dir();

    if (build_dir != NULL)
    {
        asprintf(&result, "%s/%s", build_dir, "cloudDB/lib/");
    }

    return result;
}

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
