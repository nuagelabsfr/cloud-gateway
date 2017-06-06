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
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_advanced_file_ops.h>

#define INSTANCE_NAME "AmazonInstance1"
#define TEST_SMALL_FILE_REMOTE_ID "0xDEADBEEFsmall"
#define TEST_HUGE_FILE_REMOTE_ID "0xDEADBEEFhuge"
#define TEST_SMALL_FILE_PATH PROJECT_DIR "/src/tests/config.xml"
#define TEST_HUGE_FILE_PATH "/data/random"
#define TEST_GET_SMALL_FILE_PATH "/tmp/test_amz_small_file_get.data"
#define TEST_GET_HUGE_FILE_PATH "/tmp/test_amz_huge_file_get.data"
#define TEST_FILE_HASH_ALGO (cgutils_crypto_digest_algorithm_sha256)

static cg_storage_manager_data * data = NULL;

static bool test_amz_list_containers_done = false;
static bool test_amz_list_files_done = false;
static bool test_amz_put_small_file_done = false;
static bool test_amz_put_huge_file_done = false;
static bool test_amz_get_small_file_done = false;
static bool test_amz_get_huge_file_done = false;
static bool test_amz_delete_small_file_done = false;
static bool test_amz_delete_huge_file_done = false;

static void * test_amz_small_file_hash = NULL;
static size_t test_amz_small_file_hash_size = 0;
static void * test_amz_huge_file_hash = NULL;
static size_t test_amz_huge_file_hash_size = 0;

static int test_amz_init(void)
{
    int result = cg_tests_init_all();

    TEST_ASSERT(result == 0, "cgutils_init_all");

    if (result == 0)
    {
        cgutils_configuration * cg_conf = NULL;

        result = cgutils_configuration_from_xml_file(CONFIG_FILE,
                                                     &cg_conf);

        CGUTILS_DEBUG("using %s", CONFIG_FILE);

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
    }

    return result;
}

static int test_amz_list_containers_cb(int const status,
                                       cgutils_llist * names,
                                       void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_list_containers cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_list_containers cb cb_data");
    TEST_ASSERT(names != NULL, "cg_storage_instance_list_containers cb names");

    TEST_ASSERT(test_amz_list_containers_done == false, "cg_storage_instance_list_containers boolean false");
    test_amz_list_containers_done = true;

    if (names != NULL)
    {
        cgutils_llist_free(&names, &free);
    }

    cg_storage_manager_exit_loop(data);

    return 0;
}

static int test_amz_containers(void)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, INSTANCE_NAME, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        result = cg_storage_instance_list_containers(instance,
                                                     &test_amz_list_containers_cb,
                                                     data);

        TEST_ASSERT(result == 0, "cg_storage_instance_list_containers");
    }

    return result;
}

static int test_amz_list_files_cb(int const status,
                                  cgutils_llist * names,
                                  void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_list_files cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_list_files cb cb_data");
    TEST_ASSERT(names != NULL, "cg_storage_instance_list_files cb names");

    TEST_ASSERT(test_amz_list_files_done == false, "cg_storage_instance_list_files boolean false");
    test_amz_list_files_done = true;

    if (names != NULL)
    {
        CGUTILS_DEBUG("Got %zu files", cgutils_llist_get_count(names));

        cgutils_llist_elt * elt = cgutils_llist_get_iterator(names);
        while (elt != NULL)
        {
            CGUTILS_DEBUG("Name is %s", (char *) cgutils_llist_elt_get_object(elt));
            elt = cgutils_llist_elt_get_next(elt);
        }

        cgutils_llist_free(&names, &free);
    }

    cg_storage_manager_exit_loop(data);

    return 0;
}

static int test_amz_list_files(void)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, INSTANCE_NAME, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        result = cg_storage_instance_list_files(instance,
                                                &test_amz_list_files_cb,
                                                data);

        TEST_ASSERT(result == 0, "cg_storage_instance_list_files");
    }

    return result;
}

static int test_amz_put_small_file_cb(int const status,
                                      cg_storage_instance_infos * const infos,
                                      void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_put_file cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_put_file cb cb_data");

    TEST_ASSERT(test_amz_put_small_file_done == false, "cg_storage_instance_put_file boolean false");
    test_amz_put_small_file_done = true;

    if (status == 0)
    {
        int result = cgutils_file_hash_sync(TEST_SMALL_FILE_PATH,
                                            TEST_FILE_HASH_ALGO,
                                            &test_amz_small_file_hash,
                                            &test_amz_small_file_hash_size);

        TEST_ASSERT(result == 0, "cgutils_file_hash_sync");

        if (result == 0)
        {
            TEST_ASSERT(test_amz_small_file_hash != NULL, "cgutils_file_hash_sync consistency");
            TEST_ASSERT(test_amz_small_file_hash_size > 0, "cgutils_file_hash_sync consistency");
        }

        if (infos != NULL &&
            infos->digest != NULL)
        {
            CGUTILS_FREE(infos->digest);
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

static int test_amz_put_small_file(void)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, INSTANCE_NAME, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        int * fd = NULL;

        CGUTILS_MALLOC(fd, 1, sizeof *fd);

        if (fd != NULL)
        {
            *fd = -1;

            result = cgutils_file_open(TEST_SMALL_FILE_PATH, O_RDONLY | O_NONBLOCK, 0, fd);

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
                                                          cgutils_crypto_digest_algorithm_none,
                                                          &test_amz_put_small_file_cb,
                                                          fd);

                    TEST_ASSERT(result == 0, "cg_storage_instance_put_file");
                }

                if (result != 0)
                {
                    cgutils_file_close(*fd), *fd = -1;
                    CGUTILS_FREE(fd);

                }
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Allocation error: %d", result);
        }
    }

    return result;
}

static int test_amz_put_huge_file_cb(int const status,
                                     cg_storage_instance_infos * const infos,
                                     void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_put_file cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_put_file cb cb_data");

    TEST_ASSERT(test_amz_put_huge_file_done == false, "cg_storage_instance_put_file boolean false");
    test_amz_put_huge_file_done = true;

    if (status == 0)
    {
        int result = cgutils_file_hash_sync(TEST_HUGE_FILE_PATH,
                                            TEST_FILE_HASH_ALGO,
                                            &test_amz_huge_file_hash,
                                            &test_amz_huge_file_hash_size);

        TEST_ASSERT(result == 0, "cgutils_file_hash_sync");

        if (result == 0)
        {
            TEST_ASSERT(test_amz_huge_file_hash != NULL, "cgutils_file_hash_sync consistency");
            TEST_ASSERT(test_amz_huge_file_hash_size > 0, "cgutils_file_hash_sync consistency");
        }

        if (infos != NULL &&
            infos->digest != NULL)
        {
            CGUTILS_FREE(infos->digest);
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

static int test_amz_put_huge_file(void)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, INSTANCE_NAME, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        int * fd = NULL;

        CGUTILS_MALLOC(fd, 1, sizeof *fd);

        if (fd != NULL)
        {
            *fd = -1;

            result = cgutils_file_open(TEST_HUGE_FILE_PATH, O_RDONLY | O_NONBLOCK, 0, fd);

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
                                                          cgutils_crypto_digest_algorithm_none,
                                                          &test_amz_put_huge_file_cb,
                                                          fd);

                    TEST_ASSERT(result == 0, "cg_storage_instance_put_file");
                }

                if (result != 0)
                {
                    cgutils_file_close(*fd), *fd = -1;
                    CGUTILS_FREE(fd);

                }
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Allocation error: %d", result);
        }
    }

    return result;
}

static int test_amz_get_small_file_cb(int const status,
                                      cg_storage_instance_infos * const infos,
                                      void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_get_small_file cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_get_small_file cb cb_data");

    TEST_ASSERT(test_amz_get_small_file_done == false,
                "cg_storage_instance_get_small_file boolean false");
    test_amz_get_small_file_done = true;

    if (status == 0)
    {
        void * hash = NULL;
        size_t hash_size = 0;

        int result = cgutils_file_hash_sync(TEST_GET_SMALL_FILE_PATH,
                                            TEST_FILE_HASH_ALGO,
                                            &hash,
                                            &hash_size);

        TEST_ASSERT(result == 0, "cgutils_file_hash_sync");

        if (result == 0)
        {
            TEST_ASSERT(hash != NULL, "cgutils_file_hash_sync consistency");
            TEST_ASSERT(hash_size > 0, "cgutils_file_hash_sync consistency");

            TEST_ASSERT(test_amz_small_file_hash != NULL, "file should have been hashed previously");
            TEST_ASSERT(test_amz_small_file_hash_size > 0, "previous hash size is invalid");

            TEST_ASSERT(test_amz_small_file_hash_size == hash_size,
                        "hash size does not match expected hash size");

            if (hash != NULL &&
                test_amz_small_file_hash != NULL &&
                test_amz_small_file_hash_size == hash_size)
            {
                result = memcmp(hash, test_amz_small_file_hash, hash_size);

                TEST_ASSERT(result == 0, "the current hash does not match the expected one");
            }

            CGUTILS_FREE(hash);
        }

        if (infos != NULL &&
            infos->digest != NULL)
        {
            CGUTILS_FREE(infos->digest);
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

static int test_amz_get_small_file(void)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, INSTANCE_NAME, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        int * fd = NULL;
        CGUTILS_MALLOC(fd, 1, sizeof *fd);

        if (fd != NULL)
        {
            *fd = -1;

            result = cgutils_file_open(TEST_GET_SMALL_FILE_PATH,
                                       O_WRONLY | O_NONBLOCK | O_CREAT | O_TRUNC,
                                       S_IRUSR | S_IWUSR,  fd);

            TEST_ASSERT(result == 0, "cgutils_file_open");

            if (result == 0)
            {
                TEST_ASSERT(*fd > 0, "cgutils_file_open consistency");

                result = cg_storage_instance_get_file(instance,
                                                      TEST_SMALL_FILE_REMOTE_ID,
                                                      *fd,
                                                      cgutils_crypto_digest_algorithm_none,
                                                      &test_amz_get_small_file_cb,
                                                      fd);

                TEST_ASSERT(result == 0, "cg_storage_instance_get_file");

                if (result != 0)
                {
                    cgutils_file_close(*fd), *fd = -1;
                    CGUTILS_FREE(fd);
                }
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Allocation error: %d", result);
        }
    }

    return result;
}

static int test_amz_get_huge_file_cb(int const status,
                                     cg_storage_instance_infos * const infos,
                                     void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_get_file cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_get_file cb cb_data");

    TEST_ASSERT(test_amz_get_huge_file_done == false,
                "cg_storage_instance_get_file boolean false");
    test_amz_get_huge_file_done = true;

    if (status == 0)
    {
        void * hash = NULL;
        size_t hash_size = 0;

        int result = cgutils_file_hash_sync(TEST_GET_HUGE_FILE_PATH,
                                            TEST_FILE_HASH_ALGO,
                                            &hash,
                                            &hash_size);

        TEST_ASSERT(result == 0, "cgutils_file_hash_sync");

        if (result == 0)
        {
            TEST_ASSERT(hash != NULL, "cgutils_file_hash_sync consistency");
            TEST_ASSERT(hash_size > 0, "cgutils_file_hash_sync consistency");

            TEST_ASSERT(test_amz_huge_file_hash != NULL, "file should have been hashed previously");
            TEST_ASSERT(test_amz_huge_file_hash_size > 0, "previous hash size is invalid");

            TEST_ASSERT(test_amz_huge_file_hash_size == hash_size, "hash size does not match expected hash size");

            if (hash != NULL && test_amz_huge_file_hash != NULL && test_amz_huge_file_hash_size == hash_size)
            {
                result = memcmp(hash, test_amz_huge_file_hash, hash_size);

                TEST_ASSERT(result == 0, "the current hash does not match the expected one");
            }

            CGUTILS_FREE(hash);
        }

        if (infos != NULL &&
            infos->digest != NULL)
        {
            CGUTILS_FREE(infos->digest);
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

static int test_amz_get_huge_file(void)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, INSTANCE_NAME, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        int * fd = NULL;
        CGUTILS_MALLOC(fd, 1, sizeof *fd);

        if (fd != NULL)
        {
            *fd = -1;

            result = cgutils_file_open(TEST_GET_HUGE_FILE_PATH,
                                       O_WRONLY | O_NONBLOCK | O_CREAT | O_TRUNC,
                                       S_IRUSR | S_IWUSR,  fd);

            TEST_ASSERT(result == 0, "cgutils_file_open");

            if (result == 0)
            {
                TEST_ASSERT(*fd > 0, "cgutils_file_open consistency");

                result = cg_storage_instance_get_file(instance,
                                                      TEST_HUGE_FILE_REMOTE_ID,
                                                      *fd,
                                                      cgutils_crypto_digest_algorithm_none,
                                                      &test_amz_get_huge_file_cb,
                                                      fd);

                TEST_ASSERT(result == 0, "cg_storage_instance_get_file");

                if (result != 0)
                {
                    cgutils_file_close(*fd), *fd = -1;
                    CGUTILS_FREE(fd);
                }
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Allocation error: %d", result);
        }
    }

    return result;
}

static int test_amz_delete_small_file_cb(int const status,
                                         void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_delete_small_file cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_delete_small_file cb cb_data");

    TEST_ASSERT(test_amz_delete_small_file_done == false,
                "cg_storage_instance_delete_small_file boolean false");
    test_amz_delete_small_file_done = true;

    cg_storage_manager_exit_loop(data);

    return 0;
}

static int test_amz_delete_small_file(void)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, INSTANCE_NAME, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        result = cg_storage_instance_delete_file(instance,
                                                 TEST_SMALL_FILE_REMOTE_ID,
                                                 &test_amz_delete_small_file_cb,
                                                 &result);

        TEST_ASSERT(result == 0, "cg_storage_instance_delete_file");
    }

    return result;
}

static int test_amz_delete_huge_file_cb(int const status,
                                        void * const cb_data)
{
    TEST_ASSERT(status == 0, "cg_storage_instance_delete_file cb status");
    TEST_ASSERT(cb_data != NULL, "cg_storage_instance_delete_file cb cb_data");

    TEST_ASSERT(test_amz_delete_huge_file_done == false,
                "cg_storage_instance_delete_file boolean false");
    test_amz_delete_huge_file_done = true;

    cg_storage_manager_exit_loop(data);

    return 0;
}

static int test_amz_delete_huge_file(void)
{
    cg_storage_instance * instance = NULL;
    int result = cg_storage_manager_data_get_instance(data, INSTANCE_NAME, &instance);

    TEST_ASSERT(result == 0, "cg_storage_manager_data_get_instance");

    if (result == 0)
    {
        TEST_ASSERT(instance != NULL, "cg_storage_manager_data_get_instance consistency");

        result = cg_storage_instance_delete_file(instance,
                                                 TEST_HUGE_FILE_REMOTE_ID,
                                                 &test_amz_delete_huge_file_cb,
                                                 &result);

        TEST_ASSERT(result == 0, "cg_storage_instance_delete_file");
    }

    return result;
}

int main(void)
{
    int result = test_amz_init();

    if (result == 0)
    {
        result = test_amz_containers();

        if (result == 0)
        {
            cg_storage_manager_loop(data);
            TEST_ASSERT(test_amz_list_containers_done == true, "cg_storage_instance_list_containers boolean true");
        }

        result = test_amz_list_files();

        if (result == 0)
        {
            cg_storage_manager_loop(data);
            TEST_ASSERT(test_amz_list_files_done == true, "cg_storage_instance_list_files boolean true");
        }

        result = test_amz_put_small_file();

        if (result == 0)
        {
            cg_storage_manager_loop(data);
            TEST_ASSERT(test_amz_put_small_file_done == true, "cg_storage_instance_put_file boolean true");
        }

        result = test_amz_put_huge_file();

        if (result == 0)
        {
            cg_storage_manager_loop(data);
            TEST_ASSERT(test_amz_put_huge_file_done == true, "cg_storage_instance_put_file boolean true");
        }

        result = cgutils_file_unlink(TEST_GET_SMALL_FILE_PATH);

        TEST_ASSERT(result == 0 || result == ENOENT, "cgutils_file_unlink(" TEST_GET_SMALL_FILE_PATH ")");

        result = test_amz_get_small_file();

        if (result == 0)
        {
            cg_storage_manager_loop(data);
            TEST_ASSERT(test_amz_get_small_file_done == true,
                        "cg_storage_instance_get_small_file boolean true");
        }

        result = cgutils_file_unlink(TEST_GET_HUGE_FILE_PATH);

        TEST_ASSERT(result == 0 || result == ENOENT, "cgutils_file_unlink(" TEST_GET_HUGE_FILE_PATH ")");

        result = test_amz_get_huge_file();

        if (result == 0)
        {
            cg_storage_manager_loop(data);
            TEST_ASSERT(test_amz_get_huge_file_done == true,
                        "cg_storage_instance_get_huge_file boolean true");
        }

        result = test_amz_delete_small_file();

        if (result == 0)
        {
            cg_storage_manager_loop(data);
            TEST_ASSERT(test_amz_delete_small_file_done == true,
                        "cg_storage_instance_delete_small_file boolean true");
        }

        result = test_amz_delete_huge_file();

        if (result == 0)
        {
            cg_storage_manager_loop(data);
            TEST_ASSERT(test_amz_delete_huge_file_done == true,
                        "cg_storage_instance_delete_huge_file boolean true");
        }

        cg_storage_manager_data_free(data);
    }

    cg_tests_destroy_all();

    if (test_amz_small_file_hash != NULL)
    {
        CGUTILS_FREE(test_amz_small_file_hash);
    }

    if (test_amz_huge_file_hash != NULL)
    {
        CGUTILS_FREE(test_amz_huge_file_hash);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
