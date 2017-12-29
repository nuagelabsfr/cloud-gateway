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
#include <stdio.h>
#include <string.h>

#include "cloudTest.h"

#include <cgsm/cg_storage_manager.h>
#include <cgsm/cg_storage_filter.h>
#include <cloudutils/cloudutils_event.h>
#include <cloudutils/cloudutils_encoding.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_advanced_file_ops.h>

#define TEST_SMALL_FILE_REMOTE_ID "0xDEADBEEFSMALL"
#define TEST_HUGE_FILE_REMOTE_ID "0xDEADBEEFHUGE"
#define TEST_FILE_HASH_ALGO (cgutils_crypto_digest_algorithm_sha256)
#define TEST_FILE_DISK_HASH_ALGO (cgutils_crypto_digest_algorithm_sha256)
#define TEST_TEMPORARY_CONTAINER_NAME "cloudprovidertesttemporarycontainer"

#define SMALL_DATA_FILE "small.data"
#define HUGE_DATA_FILE "huge.data"

static cg_storage_manager_data * data = NULL;

static bool test_provider_create_container_done = false;
static bool test_provider_list_containers_done = false;
static bool test_provider_remove_container_done = false;
static bool test_provider_list_files_done = false;
static bool test_provider_put_small_file_done = false;
static bool test_provider_put_huge_file_done = false;
static bool test_provider_put_filtered_huge_file_done = false;
static bool test_provider_get_small_file_done = false;
static bool test_provider_get_huge_file_done = false;
static bool test_provider_get_filtered_huge_file_done = false;
static bool test_provider_delete_file_done = false;

static void * test_provider_small_file_hash = NULL;
static size_t test_provider_small_file_hash_size = 0;
static void * test_provider_small_file_disk_hash = NULL;
static size_t test_provider_small_file_disk_hash_size = 0;
static void * test_provider_huge_file_hash = NULL;
static size_t test_provider_huge_file_hash_size = 0;
static void * test_provider_huge_file_disk_hash = NULL;
static size_t test_provider_huge_file_disk_hash_size = 0;

static void test_provider_print_hashes(char const * const hash,
                                       size_t const hash_size,
                                       char const * const expected_hash,
                                       size_t const expected_hash_size)
{
    char * hash_hex = NULL;
    size_t hash_hex_size = 0;

    int result = cgutils_encoding_hex_sprint(hash,
                                             hash_size,
                                             &hash_hex,
                                             &hash_hex_size);

    TEST_ASSERT(result == 0,
                "Error converting hash to hex");

    if (result == 0)
    {
        char * expected_hash_hex = NULL;
        size_t expected_hash_hex_size = 0;

        result = cgutils_encoding_hex_sprint(expected_hash,
                                             expected_hash_size,
                                                             &expected_hash_hex,
                                             &expected_hash_hex_size);

        TEST_ASSERT(result == 0,
                    "Error converting hash to hex");

        if (result == 0)
        {
            CGUTILS_ERROR("Expected:\n %s[%zu]\n Got:\n%s[%zu]",
                          expected_hash_hex,
                          expected_hash_hex_size,
                          hash_hex,
                          hash_hex_size);

            CGUTILS_FREE(expected_hash_hex);
        }

        CGUTILS_FREE(hash_hex);
    }
}

static int test_provider_init(char const * const configuration_file)
{
    cgutils_configuration * cg_conf = NULL;

    int result = cgutils_configuration_from_xml_file(configuration_file,
                                                     &cg_conf);

    TEST_ASSERT(result == 0, "cgutils_configuration_from_xml_file");

    if (result == 0)
    {
        TEST_ASSERT(cg_conf != NULL, "cgutils_configuration_from_xml_file consistency");
        assert(cg_conf != NULL);

        result = cg_storage_manager_data_init(cg_conf, &data);

        TEST_ASSERT(result == 0, "cg_storage_manager_data_init");

        if (result == 0)
        {
            TEST_ASSERT(data != NULL, "cg_storage_manager_data_init consistency");

            result = cg_storage_manager_load_configuration(data,
                                                           true,
                                                           false);

            TEST_ASSERT(result == 0, "cg_storage_manager_load_configuration");

            if (result == 0)
            {
                result = cg_storage_manager_setup(data, true);

                TEST_ASSERT(result == 0, "cg_storage_manager_setup");
            }

            if (result != 0)
            {
                cg_storage_manager_data_free(data), data = NULL;
            }
        }
        else
        {
            cgutils_configuration_free(cg_conf), cg_conf = NULL;
        }
    }

    return result;
}

static int test_provider_create_container_cb(int const status,
                                             void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_create_container cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_create_container cb cb_data");

    TEST_ASSERT(test_provider_create_container_done == false,
                "cg_storage_instance_create_container boolean false");
    test_provider_create_container_done = true;

    cg_storage_manager_exit_loop(data);

    return 0;
}

static int test_provider_create_container(char const * const instance_name)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, instance_name, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        result = cg_storage_instance_create_container(instance,
                                                      TEST_TEMPORARY_CONTAINER_NAME,
                                                      &test_provider_create_container_cb,
                                                      data);

        TEST_ASSERT(result == 0 || result == ENOSYS, "cg_storage_instance_create_container");
    }

    return result;
}

static int test_provider_list_containers_cb(int const status,
                                            cgutils_llist * names,
                                            void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_list_containers cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_list_containers cb cb_data");
    TEST_ASSERT(names != NULL, "cg_storage_instance_list_containers cb names");

    TEST_ASSERT(test_provider_list_containers_done == false,
                "cg_storage_instance_list_containers boolean false");
    test_provider_list_containers_done = true;

    if (names != NULL)
    {
        bool found_temporary = false;

        for (cgutils_llist_elt * elt = cgutils_llist_get_first(names);
             found_temporary == false &&
                 elt != NULL;
             elt = cgutils_llist_elt_get_next(elt))
        {
            char const * const name = cgutils_llist_elt_get_object(elt);
            TEST_ASSERT(name != NULL, "objects returned by cg_storage_instance_list_containers are not NULL");

            if (name != NULL &&
                strcmp(name, TEST_TEMPORARY_CONTAINER_NAME) == 0)
            {
                found_temporary = true;
            }
        }

        TEST_ASSERT(found_temporary == true ||
                    test_provider_create_container_done == false,
                    "The temprary container "TEST_TEMPORARY_CONTAINER_NAME" should be in the list!");

        cgutils_llist_free(&names, &free);
    }

    cg_storage_manager_exit_loop(data);

    return 0;
}

static int test_provider_list_containers(char const * const instance_name)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, instance_name, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        result = cg_storage_instance_list_containers(instance,
                                                     &test_provider_list_containers_cb,
                                                     data);

        TEST_ASSERT(result == 0 || result == ENOSYS, "cg_storage_instance_list_containers");
    }

    return result;
}

static int test_provider_remove_container_cb(int const status,
                                             void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_remove_empty_container cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_remove_empty_container cb cb_data");

    TEST_ASSERT(test_provider_remove_container_done == false,
                "cg_storage_instance_remove_empty_container boolean false");
    test_provider_remove_container_done = true;

    cg_storage_manager_exit_loop(data);

    return 0;
}

static int test_provider_remove_container(char const * const instance_name)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, instance_name, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        result = cg_storage_instance_remove_empty_container(instance,
                                                            TEST_TEMPORARY_CONTAINER_NAME,
                                                            &test_provider_remove_container_cb,
                                                            data);

        TEST_ASSERT(result == 0 || result == ENOSYS, "cg_storage_instance_remove_empty_container");
    }

    return result;
}

static int test_provider_list_files_cb(int const status,
                                       cgutils_llist * names,
                                       void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_list_files cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_list_files cb cb_data");
    TEST_ASSERT(names != NULL, "cg_storage_instance_list_files cb names");

    TEST_ASSERT(test_provider_list_files_done == false,
                "cg_storage_instance_list_files boolean false");
    test_provider_list_files_done = true;

    if (names != NULL)
    {
        cgutils_set_color(stderr, CLOUDUTILS_ANSI_COLOR_ATTR_DIM, CLOUDUTILS_ANSI_COLOR_GREEN, CLOUDUTILS_ANSI_COLOR_BLACK);
        CGUTILS_DEBUG("Got %zu files", cgutils_llist_get_count(names));
        cgutils_set_color(stderr, CLOUDUTILS_ANSI_COLOR_ATTR_RESET, CLOUDUTILS_ANSI_COLOR_WHITE, CLOUDUTILS_ANSI_COLOR_BLACK);

        cgutils_llist_elt * elt = cgutils_llist_get_iterator(names);
        while (elt != NULL)
        {
/*            CGUTILS_DEBUG("Name is %s", (char *) cgutils_llist_elt_get_object(elt));*/
            elt = cgutils_llist_elt_get_next(elt);
        }

        cgutils_llist_free(&names, &free);
    }

    cg_storage_manager_exit_loop(data);

    return 0;
}

static int test_provider_list_files(char const * const instance_name)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, instance_name, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL,
                    "cg_storage_manager_data_get_instance consistency");

        result = cg_storage_instance_list_files(instance,
                                                &test_provider_list_files_cb,
                                                data);

        TEST_ASSERT(result == 0 || result == ENOSYS, "cg_storage_instance_list_files");
    }

    return result;
}

static int test_provider_put_small_file_cb(int const status,
                                           cg_storage_instance_infos * const infos,
                                           void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_put_file cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_put_file cb cb_data");

    TEST_ASSERT(test_provider_put_small_file_done == false,
                "cg_storage_instance_put_file boolean false");
    test_provider_put_small_file_done = true;

    if (status == 0)
    {
        CGUTILS_FREE(test_provider_small_file_hash);
        CGUTILS_FREE(test_provider_small_file_disk_hash);

        char * small_file_path = cg_tests_get_temp_file(SMALL_DATA_FILE);

        int result = cgutils_file_hash_sync(small_file_path,
                                            TEST_FILE_HASH_ALGO,
                                            &test_provider_small_file_hash,
                                            &test_provider_small_file_hash_size);

        TEST_ASSERT(result == 0, "cgutils_file_hash_sync");

        if (result == 0)
        {
            TEST_ASSERT(test_provider_small_file_hash != NULL,
                        "cgutils_file_hash_sync consistency");
            TEST_ASSERT(test_provider_small_file_hash_size > 0,
                        "cgutils_file_hash_sync consistency");
        }

        CGUTILS_FREE(small_file_path);
        TEST_ASSERT(infos != NULL, "test_provider_put_small_file_cb infos != NULL");

        if (infos != NULL)
        {
            TEST_ASSERT(infos->digest != NULL, "test_provider_put_small_file_cb infos->digest != NULL");

            test_provider_small_file_disk_hash = infos->digest;
            infos->digest = NULL;
            test_provider_small_file_disk_hash_size = infos->digest_size;
        }
    }

    if (cb_data != NULL)
    {
        int * fd = cb_data;
        cgutils_file_close(*fd), *fd = -1;
        CGUTILS_FREE(fd);
    }

    cg_storage_manager_exit_loop(data);

    return 0;
}

static int test_provider_put_small_file(char const * const instance_name)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, instance_name, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        int * fd = NULL;

        CGUTILS_MALLOC(fd, 1, sizeof *fd);

        if (fd != NULL)
        {
            char * small_file_path = cg_tests_get_temp_file(SMALL_DATA_FILE);
            *fd = -1;

            result = cgutils_file_open(small_file_path, O_RDONLY | O_NONBLOCK, 0, fd);

            TEST_ASSERT(result == 0, "cgutils_file_open");

            if (result == 0)
            {
                TEST_ASSERT(*fd > 0, "cgutils_file_open consistency");

                size_t file_size = 0;

                result = cgutils_file_get_size(*fd, &file_size);

                TEST_ASSERT(result == 0, "cgutils_file_get_size");

                if (result == 0)
                {
                    result = cg_storage_instance_put_file(instance,
                                                          TEST_SMALL_FILE_REMOTE_ID,
                                                          *fd,
                                                          file_size,
                                                          NULL,
                                                          TEST_FILE_DISK_HASH_ALGO,
                                                          &test_provider_put_small_file_cb,
                                                          fd);

                    TEST_ASSERT(result == 0, "cg_storage_instance_put_file");
                }

                if (result != 0)
                {
                    cgutils_file_close(*fd), *fd = -1;
                    CGUTILS_FREE(fd);

                }
            }

            CGUTILS_FREE(small_file_path);
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Allocation error: %d", result);
        }
    }

    return result;
}

static int test_provider_put_huge_file_cb(int const status,
                                          cg_storage_instance_infos * const infos,
                                          void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_put_file cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_put_file cb cb_data");

    TEST_ASSERT(test_provider_put_huge_file_done == false,
                "cg_storage_instance_put_file boolean false");
    test_provider_put_huge_file_done = true;

    if (status == 0)
    {
        CGUTILS_FREE(test_provider_huge_file_hash);
        CGUTILS_FREE(test_provider_huge_file_disk_hash);

        char * huge_file_path = cg_tests_get_temp_file(HUGE_DATA_FILE);

        int result = cgutils_file_hash_sync(huge_file_path,
                                            TEST_FILE_HASH_ALGO,
                                            &test_provider_huge_file_hash,
                                            &test_provider_huge_file_hash_size);

        TEST_ASSERT(result == 0, "cgutils_file_hash_sync");

        if (result == 0)
        {
            TEST_ASSERT(test_provider_huge_file_hash != NULL,
                        "cgutils_file_hash_sync consistency");
            TEST_ASSERT(test_provider_huge_file_hash_size > 0,
                        "cgutils_file_hash_sync consistency");
        }

        CGUTILS_FREE(huge_file_path);

        TEST_ASSERT(infos != NULL, "test_provider_put_huge_file_cb infos != NULL");

        if (infos != NULL)
        {
            TEST_ASSERT(infos->digest != NULL, "test_provider_put_huge_file_cb infos->digest != NULL");

            test_provider_huge_file_disk_hash = infos->digest;
            infos->digest = NULL;
            test_provider_huge_file_disk_hash_size = infos->digest_size;
        }
    }

    if (cb_data != NULL)
    {
        int * fd = cb_data;
        cgutils_file_close(*fd), *fd = -1;
        CGUTILS_FREE(fd);
    }

    cg_storage_manager_exit_loop(data);

    return 0;
}

static int test_provider_put_huge_file(char const * const instance_name)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, instance_name, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        int * fd = NULL;

        CGUTILS_MALLOC(fd, 1, sizeof *fd);

        if (fd != NULL)
        {
            *fd = -1;
            char * huge_file_path = cg_tests_get_temp_file(HUGE_DATA_FILE);

            result = cgutils_file_open(huge_file_path, O_RDONLY | O_NONBLOCK, 0, fd);

            TEST_ASSERT(result == 0, "cgutils_file_open");

            if (result == 0)
            {
                TEST_ASSERT(*fd > 0, "cgutils_file_open consistency");

                size_t file_size = 0;

                result = cgutils_file_get_size(*fd, &file_size);

                TEST_ASSERT(result == 0, "cgutils_file_get_size");

                if (result == 0)
                {
                    result = cg_storage_instance_put_file(instance,
                                                          TEST_HUGE_FILE_REMOTE_ID,
                                                          *fd,
                                                          file_size,
                                                          NULL,
                                                          TEST_FILE_DISK_HASH_ALGO,
                                                          &test_provider_put_huge_file_cb,
                                                          fd);

                    TEST_ASSERT(result == 0, "cg_storage_instance_put_file");
                }

                if (result != 0)
                {
                    cgutils_file_close(*fd), *fd = -1;
                    CGUTILS_FREE(fd);

                }
            }

            CGUTILS_FREE(huge_file_path);
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Allocation error: %d", result);
        }
    }

    return result;
}

static int test_provider_get_huge_file_cb(int const status,
                                          cg_storage_instance_infos * const infos,
                                          void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_get_file cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_get_file cb cb_data");

    TEST_ASSERT(test_provider_get_huge_file_done == false,
                "cg_storage_instance_get_huge_file boolean false");
    test_provider_get_huge_file_done = true;

    if (status == 0)
    {
        char * file_path = cg_tests_get_temp_file("test_provider_file_get.data");
        void * hash = NULL;
        size_t hash_size = 0;

        int result = cgutils_file_hash_sync(file_path,
                                            TEST_FILE_HASH_ALGO,
                                            &hash,
                                            &hash_size);

        TEST_ASSERT(result == 0, "cgutils_file_hash_sync");

        if (result == 0)
        {
            TEST_ASSERT(hash != NULL, "cgutils_file_hash_sync consistency");
            TEST_ASSERT(hash_size > 0, "cgutils_file_hash_sync consistency");

            TEST_ASSERT(test_provider_huge_file_hash != NULL,
                        "file should have been hashed previously");
            TEST_ASSERT(test_provider_huge_file_hash_size > 0,
                        "previous hash size is invalid");

            TEST_ASSERT(test_provider_huge_file_hash_size == hash_size,
                        "hash size does not match expected hash size");

            if (hash != NULL &&
                test_provider_huge_file_hash != NULL &&
                test_provider_huge_file_hash_size == hash_size)
            {
                result = memcmp(hash, test_provider_huge_file_hash, hash_size);

                TEST_ASSERT(result == 0,
                            "the current hash does not match the expected one");

                if (result != 0)
                {
                    test_provider_print_hashes(hash,
                                               hash_size,
                                               test_provider_huge_file_hash,
                                               test_provider_huge_file_hash_size);
                }
            }

            TEST_ASSERT(infos != NULL, "cg_storage_instance_get_huge_file infos");

            if (infos != NULL)
            {
                TEST_ASSERT(infos->digest != NULL, "cg_storage_instance_get_huge_file infos digest");

                if (infos->digest != NULL)
                {
                    TEST_ASSERT(test_provider_huge_file_disk_hash_size == infos->digest_size,
                                "hash size does not match expected hash size");

                    if (infos->digest != NULL &&
                        test_provider_huge_file_disk_hash != NULL &&
                        test_provider_huge_file_disk_hash_size == infos->digest_size)
                    {
                        result = memcmp(infos->digest, test_provider_huge_file_disk_hash, infos->digest_size);

                        TEST_ASSERT(result == 0,
                                    "the current hash does not match the expected one");

                        if (result != 0)
                        {
                            test_provider_print_hashes(infos->digest,
                                                       infos->digest_size,
                                                       test_provider_huge_file_disk_hash,
                                                       test_provider_huge_file_disk_hash_size);
                        }
                    }

                    CGUTILS_FREE(infos->digest);
                }
            }

            CGUTILS_FREE(hash);
        }

        CGUTILS_FREE(file_path);
    }

    if (cb_data != NULL)
    {
        int * fd = cb_data;
        cgutils_file_close(*fd), *fd = -1;
        CGUTILS_FREE(fd);
    }

    CGUTILS_FREE(test_provider_huge_file_hash);
    CGUTILS_FREE(test_provider_huge_file_disk_hash);

    cg_storage_manager_exit_loop(data);

    return 0;
}

static int test_provider_get_huge_file(char const * const instance_name)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, instance_name, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        int * fd = NULL;
        CGUTILS_MALLOC(fd, 1, sizeof *fd);

        if (fd != NULL)
        {
            char * file_path = cg_tests_get_temp_file("test_provider_file_get.data");
            *fd = -1;

            result = cgutils_file_open(file_path,
                                       O_WRONLY | O_NONBLOCK | O_CREAT | O_TRUNC,
                                       S_IRUSR | S_IWUSR,  fd);

            TEST_ASSERT(result == 0, "cgutils_file_open");

            if (result == 0)
            {
                TEST_ASSERT(*fd > 0, "cgutils_file_open consistency");

                result = cg_storage_instance_get_file(instance,
                                                      TEST_HUGE_FILE_REMOTE_ID,
                                                      *fd,
                                                      TEST_FILE_DISK_HASH_ALGO,
                                                      &test_provider_get_huge_file_cb,
                                                      fd);

                TEST_ASSERT(result == 0, "cg_storage_instance_get_file");

                if (result != 0)
                {
                    cgutils_file_close(*fd), *fd = -1;
                    CGUTILS_FREE(fd);
                }
            }

            CGUTILS_FREE(file_path);
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Allocation error: %d", result);
        }
    }

    return result;
}

static int test_provider_get_small_file_cb(int const status,
                                           cg_storage_instance_infos * const infos,
                                           void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_get_file cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_get_file cb cb_data");

    TEST_ASSERT(test_provider_get_small_file_done == false,
                "cg_storage_instance_get_file boolean false");
    test_provider_get_small_file_done = true;

    if (status == 0)
    {
        char * file_path = cg_tests_get_temp_file("test_provider_file_get.data");
        void * hash = NULL;
        size_t hash_size = 0;

        int result = cgutils_file_hash_sync(file_path,
                                            TEST_FILE_HASH_ALGO,
                                            &hash,
                                            &hash_size);

        TEST_ASSERT(result == 0, "cgutils_file_hash_sync");

        if (result == 0)
        {
            TEST_ASSERT(hash != NULL, "cgutils_file_hash_sync consistency");
            TEST_ASSERT(hash_size > 0, "cgutils_file_hash_sync consistency");

            TEST_ASSERT(test_provider_small_file_hash != NULL,
                        "file should have been hashed previously");
            TEST_ASSERT(test_provider_small_file_hash_size > 0,
                        "previous hash size is invalid");

            TEST_ASSERT(test_provider_small_file_hash_size == hash_size,
                        "hash size does not match expected hash size");

            if (hash != NULL &&
                test_provider_small_file_hash != NULL &&
                test_provider_small_file_hash_size == hash_size)
            {
                result = memcmp(hash, test_provider_small_file_hash, hash_size);

                TEST_ASSERT(result == 0,
                            "the current hash does not match the expected one");

                if (result != 0)
                {
                    test_provider_print_hashes(hash,
                                               hash_size,
                                               test_provider_huge_file_hash,
                                               test_provider_huge_file_hash_size);
                }
            }

            CGUTILS_FREE(hash);

            TEST_ASSERT(infos != NULL, "cg_storage_instance_get_small_file infos");

            if (infos != NULL)
            {
                TEST_ASSERT(infos->digest != NULL, "cg_storage_instance_get_small_file infos digest");

                if (infos->digest != NULL)
                {
                    TEST_ASSERT(test_provider_small_file_disk_hash_size == infos->digest_size,
                                "hash size does not match expected hash size");

                    if (infos->digest != NULL &&
                        test_provider_small_file_disk_hash != NULL &&
                        test_provider_small_file_disk_hash_size == infos->digest_size)
                    {
                        result = memcmp(infos->digest, test_provider_small_file_disk_hash, infos->digest_size);

                        TEST_ASSERT(result == 0,
                                    "the current hash does not match the expected one");

                    }

                    CGUTILS_FREE(infos->digest);
                }
            }
        }

        CGUTILS_FREE(file_path);
    }

    if (cb_data != NULL)
    {
        int * fd = cb_data;
        cgutils_file_close(*fd), *fd = -1;
        CGUTILS_FREE(fd);
    }

    CGUTILS_FREE(test_provider_small_file_hash);
    CGUTILS_FREE(test_provider_small_file_disk_hash);

    cg_storage_manager_exit_loop(data);

    return 0;
}

static int test_provider_get_small_file(char const * const instance_name)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, instance_name, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        int * fd = NULL;
        CGUTILS_MALLOC(fd, 1, sizeof *fd);

        if (fd != NULL)
        {
            char * file_path = cg_tests_get_temp_file("test_provider_file_get.data");
            *fd = -1;

            result = cgutils_file_open(file_path,
                                       O_WRONLY | O_NONBLOCK | O_CREAT | O_TRUNC,
                                       S_IRUSR | S_IWUSR,  fd);

            TEST_ASSERT(result == 0, "cgutils_file_open");

            if (result == 0)
            {
                TEST_ASSERT(*fd > 0, "cgutils_file_open consistency");

                result = cg_storage_instance_get_file(instance,
                                                      TEST_SMALL_FILE_REMOTE_ID,
                                                      *fd,
                                                      TEST_FILE_DISK_HASH_ALGO,
                                                      &test_provider_get_small_file_cb,
                                                      fd);

                TEST_ASSERT(result == 0, "cg_storage_instance_get_small_file");

                if (result != 0)
                {
                    cgutils_file_close(*fd), *fd = -1;
                    CGUTILS_FREE(fd);
                }
            }

            CGUTILS_FREE(file_path);
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Allocation error: %d", result);
        }
    }

    return result;
}

static int test_provider_delete_file_cb(int const status,
                                   void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_delete_file cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_delete_file cb cb_data");

    TEST_ASSERT(test_provider_delete_file_done == false, "cg_storage_instance_delete_file boolean false");
    test_provider_delete_file_done = true;

    cg_storage_manager_exit_loop(data);

    return 0;
}

static int test_provider_delete_file(char const * const instance_name,
                                     char const * const file_id)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, instance_name, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        result = cg_storage_instance_delete_file(instance,
                                                 file_id,
                                                 &test_provider_delete_file_cb,
                                                 &result);

        TEST_ASSERT(result == 0, "cg_storage_instance_delete_file");
    }

    return result;
}

static int test_provider_test_suite(char const * const instance_name)
{
    int result = 0;

    test_provider_create_container_done = false;
    test_provider_list_containers_done = false;
    test_provider_remove_container_done = false;
    test_provider_list_files_done = false;
    test_provider_put_small_file_done = false;
    test_provider_put_huge_file_done = false;
    test_provider_put_filtered_huge_file_done = false;
    test_provider_get_small_file_done = false;
    test_provider_get_huge_file_done = false;
    test_provider_get_filtered_huge_file_done = false;
    test_provider_delete_file_done = false;

    CGUTILS_DEBUG("- Creating container");

    result = test_provider_create_container(instance_name);

    if (result == 0)
    {
        cg_storage_manager_loop(data);
        TEST_ASSERT(test_provider_create_container_done == true,
                    "cg_storage_instance_create_container boolean true");
    }

    CGUTILS_DEBUG("- List containers");

    result = test_provider_list_containers(instance_name);

    if (result == 0)
    {
        cg_storage_manager_loop(data);
        TEST_ASSERT(test_provider_list_containers_done == true,
                    "cg_storage_instance_list_containers boolean true");
    }

    CGUTILS_DEBUG("- Remove containers");

    result = test_provider_remove_container(instance_name);

    if (result == 0)
    {
        cg_storage_manager_loop(data);
        TEST_ASSERT(test_provider_remove_container_done == true,
                    "cg_storage_instance_remove_container boolean true");
    }

    CGUTILS_DEBUG("- List files");

    result = test_provider_list_files(instance_name);

    if (result == 0)
    {
        cg_storage_manager_loop(data);
        TEST_ASSERT(test_provider_list_files_done == true,
                    "cg_storage_instance_list_files boolean true");
    }

    CGUTILS_DEBUG("- Putting small file");

    result = test_provider_put_small_file(instance_name);

    if (result == 0)
    {
        cg_storage_manager_loop(data);
        TEST_ASSERT(test_provider_put_small_file_done == true,
                    "cg_storage_instance_put_small_file boolean true");
    }

    char * file_path = cg_tests_get_temp_file("test_provider_file_get.data");
    cgutils_file_unlink(file_path);

    CGUTILS_DEBUG("- Getting small file");

    result = test_provider_get_small_file(instance_name);

    if (result == 0)
    {
        cg_storage_manager_loop(data);
        TEST_ASSERT(test_provider_get_small_file_done == true,
                    "cg_storage_instance_get_small_file boolean true");
    }

    test_provider_put_small_file_done = false;

    CGUTILS_DEBUG("- Overwriting small file");

    result = test_provider_put_small_file(instance_name);

    if (result == 0)
    {
        cg_storage_manager_loop(data);
        TEST_ASSERT(test_provider_put_small_file_done == true,
                    "cg_storage_instance_put_small_file boolean true");
    }

    CGUTILS_DEBUG("- Deleting small file");

    result = test_provider_delete_file(instance_name,
                                       TEST_SMALL_FILE_REMOTE_ID);

    if (result == 0)
    {
        /* this operation may be synchronous, for example in the POSIX provider */
        if (test_provider_delete_file_done == false)
        {
            cg_storage_manager_loop(data);
        }

        TEST_ASSERT(test_provider_delete_file_done == true,
                    "cg_storage_instance_delete_file boolean true");
    }

    CGUTILS_DEBUG("- Putting huge file");

    result = test_provider_put_huge_file(instance_name);

    if (result == 0)
    {
        cg_storage_manager_loop(data);
        TEST_ASSERT(test_provider_put_huge_file_done == true,
                    "cg_storage_instance_put_huge_file boolean true");
    }

    cgutils_file_unlink(file_path);

    CGUTILS_DEBUG("- Getting huge file");

    result = test_provider_get_huge_file(instance_name);

    if (result == 0)
    {
        cg_storage_manager_loop(data);
        TEST_ASSERT(test_provider_get_huge_file_done == true,
                    "cg_storage_instance_get_huge_file boolean true");
    }

    test_provider_put_huge_file_done = false;

    CGUTILS_DEBUG("- Overwriting huge file");

    result = test_provider_put_huge_file(instance_name);

    if (result == 0)
    {
        cg_storage_manager_loop(data);
        TEST_ASSERT(test_provider_put_huge_file_done == true,
                    "cg_storage_instance_put_huge_file boolean true");
    }

    test_provider_delete_file_done = false;

    CGUTILS_DEBUG("- Deleting huge file");

    result = test_provider_delete_file(instance_name,
                                       TEST_HUGE_FILE_REMOTE_ID);

    if (result == 0)
    {
        /* this operation may be synchronous, for example in the POSIX provider */
        if (test_provider_delete_file_done == false)
        {
            cg_storage_manager_loop(data);
        }

        TEST_ASSERT(test_provider_delete_file_done == true,
                    "cg_storage_instance_delete_file boolean true");
    }

    CGUTILS_FREE(test_provider_small_file_hash);
    CGUTILS_FREE(test_provider_small_file_disk_hash);
    CGUTILS_FREE(test_provider_huge_file_hash);
    CGUTILS_FREE(test_provider_huge_file_disk_hash);
    CGUTILS_FREE(file_path);

    return result;
}

int main(void)
{
    int result = cg_tests_init_all();
    bool localOnly = getenv("CG_TESTS_LOCAL_PROVIDERS_ONLY") != NULL;

    TEST_ASSERT(result == 0, "cgutils_init_all");

    if (result == 0)
    {
        struct
        {
            char * file;
            char const * const instance;
            bool remote;
        }
        providers[] =
            {
                { cg_tests_get_config_file("CloudGatewayConfiguration_posix_nofilters.xml"), "POSIXInstance1", false },
                { cg_tests_get_config_file("CloudGatewayConfiguration_posix_encryption.xml"), "POSIXInstance1", false },
                { cg_tests_get_config_file("CloudGatewayConfiguration_posix_compression.xml"), "POSIXInstance1", false },
                { cg_tests_get_config_file("CloudGatewayConfiguration_posix_compression_encryption.xml"), "POSIXInstance1", false },

                { cg_tests_get_config_file("CloudGatewayConfiguration_s3_nofilters.xml"), "AmazonInstance1", true },
                { cg_tests_get_config_file("CloudGatewayConfiguration_s3_encryption.xml"), "AmazonInstance1", true },

                { cg_tests_get_config_file("CloudGatewayConfiguration_openstackv1_nofilters.xml"), "OpenstackInstance1", true },
                { cg_tests_get_config_file("CloudGatewayConfiguration_openstackv2_nofilters.xml"), "OpenstackInstance1", true },
                { cg_tests_get_config_file("CloudGatewayConfiguration_openstackv2_encryption.xml"), "OpenstackInstance1", true },
                { cg_tests_get_config_file("CloudGatewayConfiguration_openstackv2_compression.xml"), "OpenstackInstance1", true },
                { cg_tests_get_config_file("CloudGatewayConfiguration_openstackv2_compression_encryption.xml"), "OpenstackInstance1", true },
            };
        size_t const providers_count = sizeof providers / sizeof *providers;

        for (size_t idx = 0;
             idx < providers_count;
             idx++)
        {
            if (providers[idx].file == NULL)
            {
                continue;
            }

            if (localOnly && providers[idx].remote == true)
            {
                continue;
            }

            cgutils_set_color(stderr, CLOUDUTILS_ANSI_COLOR_ATTR_DIM, CLOUDUTILS_ANSI_COLOR_CYAN, CLOUDUTILS_ANSI_COLOR_BLACK);
            CGUTILS_DEBUG("Testing %s : %s",
                          providers[idx].file,
                          providers[idx].instance);
            cgutils_set_color(stderr, CLOUDUTILS_ANSI_COLOR_ATTR_RESET, CLOUDUTILS_ANSI_COLOR_WHITE, CLOUDUTILS_ANSI_COLOR_BLACK);

            result = test_provider_init(providers[idx].file);

            if (result == 0)
            {
                test_provider_test_suite(providers[idx].instance);

                cg_storage_manager_data_free(data);
            }

            CGUTILS_FREE(providers[idx].file);
        }
    }

    cg_tests_destroy_all();

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
