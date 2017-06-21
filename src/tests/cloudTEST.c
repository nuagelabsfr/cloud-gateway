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
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_aio.h>
#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_crypto.h>
#include <cloudutils/cloudutils_encoding.h>
#include <cloudutils/cloudutils_event.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_advanced_file_ops.h>
#include <cloudutils/cloudutils_http.h>
#include <cloudutils/cloudutils_htable.h>
#include <cloudutils/cloudutils_network.h>
#include <cloudutils/cloudutils_process.h>
#include <cloudutils/cloudutils_rbtree.h>
#include <cloudutils/cloudutils_system.h>
#include <cloudutils/cloudutils_time_counter.h>
#include <cloudutils/cloudutils_xml.h>

#include <cgsm/cg_storage_filter.h>

#include "cloudTest.h"

#define TESTDIR "/tmp/cgutils_test_dir"
#define TESTFILE "/tmp/cgutils_test_dir/test_file"
#define AIO_TEST_FILE "/tmp/cgutils_test_aio_test_file"

#define TEST_STORAGE_FILTER_ENCRYPTION_CONFIG_FILE "storage_filter_encryption_config.xml"
#define TEST_STORAGE_FILTER_COMPRESSION_CONFIG_FILE "storage_filter_compression_config.xml"

static char const test_cgutils_encryption_in[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static size_t const test_cgutils_encryption_in_size = sizeof test_cgutils_encryption_in - 1;
static char const test_cgutils_compression_in[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static size_t const test_cgutils_compression_in_size = sizeof test_cgutils_compression_in - 1;

static int test_cgutils_init(void)
{
    int result = cg_tests_init_all();

    TEST_ASSERT(result == 0, "cg_tests_init_all");

    return result;
}

static int test_cgutils_storage_filter_decryption(char const * const in,
                                                  size_t const in_size)
{
    int result = 0;
    assert(in != NULL);

    char * config_file = cg_tests_get_config_file(TEST_STORAGE_FILTER_ENCRYPTION_CONFIG_FILE);
    cgutils_configuration * conf = NULL;

    result = cgutils_configuration_from_xml_file(config_file,
                                                 &conf);

    TEST_ASSERT(result == 0, "cgutils_configuration_from_xml_file");

    if (result == 0)
    {
        cg_storage_filter * filter = NULL;
        char * storage_filter_dir = cg_tests_get_storage_filter_dir();

        result = cg_storage_filter_init("encryption",
                                        storage_filter_dir,
                                        conf,
                                        &filter);

        TEST_ASSERT(result == 0, "cg_storage_filter_init");

        if (result == 0)
        {
            TEST_ASSERT(filter != NULL, "cg_storage_filter_init consistency");
            cg_storage_filter_ctx * ctx = NULL;

            result = cg_storage_filter_ctx_init(filter,
                                                cg_storage_filter_dec,
                                                &ctx);

            TEST_ASSERT(result == 0, "cg_storage_filter_ctx_init");

            if (result == 0)
            {
                TEST_ASSERT(ctx != NULL, "cg_storage_filter_ctx_init consistency");

                char * out = NULL;
                size_t out_size = 0;

                result = cg_storage_filter_do(ctx,
                                              in,
                                              in_size,
                                              &out,
                                              &out_size);

                TEST_ASSERT(result == 0, "cg_storage_filter_do");

                if (result == 0)
                {
                    char * finished = NULL;
                    size_t finished_size = 0;

                    TEST_ASSERT(out != NULL, "cg_storage_filter_do consistency");

                    result = cg_storage_filter_finish(ctx,
                                                      &finished,
                                                      &finished_size);

                    TEST_ASSERT(result == 0, "cg_storage_filter_finish");

                    if (result == 0)
                    {
                        char * final = NULL;
                        size_t final_size = out_size + finished_size;
                        CGUTILS_MALLOC(final, final_size + 1, 1);

                        if (final != NULL)
                        {
                            if (out != NULL &&
                                out_size > 0)
                            {
                                memcpy(final, out, out_size);
                            }

                            if (finished_size > 0)
                            {
                                assert(finished_size > 0);
                                memcpy(final + out_size, finished, finished_size);
                            }

                            TEST_ASSERT(final_size == test_cgutils_encryption_in_size,
                                        "decrypted size match original size");

                            if (final_size == test_cgutils_encryption_in_size)
                            {
                                result = memcmp(final, test_cgutils_encryption_in, final_size);

                                TEST_ASSERT(result == 0, "decrypted data match original data");
                            }

                            CGUTILS_FREE(final);
                        }
                        else
                        {
                            result = ENOMEM;
                            CGUTILS_ERROR("Error allocating memory for finished (%zu bytes)",
                                          final_size);
                        }

                        CGUTILS_FREE(finished);
                    }

                    CGUTILS_FREE(out);
                }

                cg_storage_filter_ctx_free(ctx), ctx = NULL;
            }

            cg_storage_filter_free(filter), filter = NULL;
        }

        CGUTILS_FREE(storage_filter_dir);
        cgutils_configuration_free(conf), conf = NULL;
    }

    CGUTILS_FREE(config_file);

    return result;
}

static int test_cgutils_storage_filter_encryption(char ** const final,
                                                  size_t * const final_size)
{
    int result = 0;
    assert(final != NULL);
    assert(final_size != NULL);

    char * config_file = cg_tests_get_config_file(TEST_STORAGE_FILTER_ENCRYPTION_CONFIG_FILE);
    cgutils_configuration * conf = NULL;

    result = cgutils_configuration_from_xml_file(config_file,
                                                 &conf);

    TEST_ASSERT(result == 0, "cgutils_configuration_from_xml_file");

    if (result == 0)
    {
        cg_storage_filter * filter = NULL;
        char * storage_filter_dir = cg_tests_get_storage_filter_dir();

        result = cg_storage_filter_init("encryption",
                                        storage_filter_dir,
                                        conf,
                                        &filter);

        TEST_ASSERT(result == 0, "cg_storage_filter_init");

        if (result == 0)
        {
            TEST_ASSERT(filter != NULL, "cg_storage_filter_init consistency");
            cg_storage_filter_ctx * ctx = NULL;

            result = cg_storage_filter_ctx_init(filter,
                                                cg_storage_filter_enc,
                                                &ctx);

            TEST_ASSERT(result == 0, "cg_storage_filter_ctx_init");

            if (result == 0)
            {
                TEST_ASSERT(ctx != NULL, "cg_storage_filter_ctx_init consistency");

                char * out = NULL;
                size_t out_size = 0;

                result = cg_storage_filter_do(ctx,
                                              test_cgutils_encryption_in,
                                              test_cgutils_encryption_in_size,
                                              &out,
                                              &out_size);

                TEST_ASSERT(result == 0, "cg_storage_filter_do");

                if (result == 0)
                {
                    char * finished = NULL;
                    size_t finished_size = 0;

                    TEST_ASSERT(out != NULL, "cg_storage_filter_do consistency");

                    result = cg_storage_filter_finish(ctx,
                                                      &finished,
                                                      &finished_size);

                    TEST_ASSERT(result == 0, "cg_storage_filter_finish");

                    if (result == 0)
                    {
                        *final_size = out_size + finished_size;
                        CGUTILS_MALLOC(*final, *final_size + 1, 1);

                        if (*final != NULL)
                        {
                            if (out_size > 0)
                            {
                                assert(out != NULL);
                                memcpy(*final, out, out_size);
                            }

                            if (finished_size > 0)
                            {
                                assert(finished_size > 0);
                                memcpy(*final + out_size, finished, finished_size);
                            }
                        }
                        else
                        {
                            result = ENOMEM;
                            CGUTILS_ERROR("Error allocating memory for finished (%zu bytes)",
                                          *final_size);
                        }

                        CGUTILS_FREE(finished);
                    }

                    CGUTILS_FREE(out);
                }

                cg_storage_filter_ctx_free(ctx), ctx = NULL;
            }

            cg_storage_filter_free(filter), filter = NULL;
        }

        CGUTILS_FREE(storage_filter_dir);
        cgutils_configuration_free(conf), conf = NULL;
    }

    CGUTILS_FREE(config_file);

    return result;
}

static int test_cgutils_storage_filter_decompression(char const * const in,
                                                     size_t const in_size)
{
    int result = 0;
    assert(in != NULL);

    char * config_file = cg_tests_get_config_file(TEST_STORAGE_FILTER_COMPRESSION_CONFIG_FILE);
    cgutils_configuration * conf = NULL;

    result = cgutils_configuration_from_xml_file(config_file,
                                                 &conf);

    TEST_ASSERT(result == 0, "cgutils_configuration_from_xml_file");

    if (result == 0)
    {
        cg_storage_filter * filter = NULL;
        char * storage_filter_dir = cg_tests_get_storage_filter_dir();

        result = cg_storage_filter_init("compression",
                                        storage_filter_dir,
                                        conf,
                                        &filter);

        TEST_ASSERT(result == 0, "cg_storage_filter_init");

        if (result == 0)
        {
            TEST_ASSERT(filter != NULL, "cg_storage_filter_init consistency");
            cg_storage_filter_ctx * ctx = NULL;

            result = cg_storage_filter_ctx_init(filter,
                                                cg_storage_filter_dec,
                                                &ctx);

            TEST_ASSERT(result == 0, "cg_storage_filter_ctx_init");

            if (result == 0)
            {
                TEST_ASSERT(ctx != NULL, "cg_storage_filter_ctx_init consistency");

                char * out = NULL;
                size_t out_size = 0;

                result = cg_storage_filter_do(ctx,
                                              in,
                                              in_size,
                                              &out,
                                              &out_size);

                TEST_ASSERT(result == 0, "cg_storage_filter_do");

                if (result == 0)
                {
                    char * finished = NULL;
                    size_t finished_size = 0;

                    TEST_ASSERT(out != NULL, "cg_storage_filter_do consistency");

                    result = cg_storage_filter_finish(ctx,
                                                      &finished,
                                                      &finished_size);

                    TEST_ASSERT(result == 0, "cg_storage_filter_finish");

                    if (result == 0)
                    {
                        char * final = NULL;
                        size_t final_size = out_size + finished_size;
                        CGUTILS_MALLOC(final, final_size + 1, 1);

                        if (final != NULL)
                        {
                            if (out != NULL &&
                                out_size > 0)
                            {
                                memcpy(final, out, out_size);
                            }

                            if (finished_size > 0)
                            {
                                assert(finished_size > 0);
                                memcpy(final + out_size, finished, finished_size);
                            }

                            TEST_ASSERT(final_size == test_cgutils_compression_in_size,
                                        "decompressed size match original size");

                            if (final_size == test_cgutils_compression_in_size)
                            {
                                result = memcmp(final, test_cgutils_compression_in, final_size);

                                TEST_ASSERT(result == 0, "decompressed data match original data");
                            }

                            CGUTILS_FREE(final);
                        }
                        else
                        {
                            result = ENOMEM;
                            CGUTILS_ERROR("Error allocating memory for finished (%zu bytes)",
                                          final_size);
                        }

                        CGUTILS_FREE(finished);
                    }

                    CGUTILS_FREE(out);
                }

                cg_storage_filter_ctx_free(ctx), ctx = NULL;
            }

            cg_storage_filter_free(filter), filter = NULL;
        }

        CGUTILS_FREE(storage_filter_dir);
        cgutils_configuration_free(conf), conf = NULL;
    }

    CGUTILS_FREE(config_file);

    return result;
}

static int test_cgutils_storage_filter_compression(char ** const final,
                                                   size_t * const final_size)
{
    int result = 0;
    assert(final != NULL);
    assert(final_size != NULL);

    char * config_file = cg_tests_get_config_file(TEST_STORAGE_FILTER_COMPRESSION_CONFIG_FILE);
    cgutils_configuration * conf = NULL;

    result = cgutils_configuration_from_xml_file(config_file,
                                                 &conf);

    TEST_ASSERT(result == 0, "cgutils_configuration_from_xml_file");

    if (result == 0)
    {
        cg_storage_filter * filter = NULL;
        char * storage_filter_dir = cg_tests_get_storage_filter_dir();

        result = cg_storage_filter_init("compression",
                                        storage_filter_dir,
                                        conf,
                                        &filter);

        TEST_ASSERT(result == 0, "cg_storage_filter_init");

        if (result == 0)
        {
            TEST_ASSERT(filter != NULL, "cg_storage_filter_init consistency");
            cg_storage_filter_ctx * ctx = NULL;

            result = cg_storage_filter_ctx_init(filter,
                                                cg_storage_filter_enc,
                                                &ctx);

            TEST_ASSERT(result == 0, "cg_storage_filter_ctx_init");

            if (result == 0)
            {
                TEST_ASSERT(ctx != NULL, "cg_storage_filter_ctx_init consistency");

                char * out = NULL;
                size_t out_size = 0;

                result = cg_storage_filter_do(ctx,
                                              test_cgutils_compression_in,
                                              test_cgutils_compression_in_size,
                                              &out,
                                              &out_size);

                TEST_ASSERT(result == 0, "cg_storage_filter_do");

                if (result == 0)
                {
                    char * finished = NULL;
                    size_t finished_size = 0;

                    TEST_ASSERT(out != NULL, "cg_storage_filter_do consistency");

                    result = cg_storage_filter_finish(ctx,
                                                      &finished,
                                                      &finished_size);

                    TEST_ASSERT(result == 0, "cg_storage_filter_finish");

                    if (result == 0)
                    {
                        *final_size = out_size + finished_size;
                        CGUTILS_MALLOC(*final, *final_size + 1, 1);

                        if (*final != NULL)
                        {
                            if (out_size > 0)
                            {
                                assert(out != NULL);
                                memcpy(*final, out, out_size);
                            }

                            if (finished_size > 0)
                            {
                                assert(finished_size > 0);
                                memcpy(*final + out_size, finished, finished_size);
                            }
                        }
                        else
                        {
                            result = ENOMEM;
                            CGUTILS_ERROR("Error allocating memory for finished (%zu bytes)",
                                          *final_size);
                        }

                        CGUTILS_FREE(finished);
                    }

                    CGUTILS_FREE(out);
                }

                cg_storage_filter_ctx_free(ctx), ctx = NULL;
            }

            cg_storage_filter_free(filter), filter = NULL;
        }

        CGUTILS_FREE(storage_filter_dir);
        cgutils_configuration_free(conf), conf = NULL;
    }

    CGUTILS_FREE(config_file);

    return result;
}

static int test_cgutils_crypto_cipher_enc(char const * const in,
                                          size_t const in_size,
                                          char const * const password,
                                          size_t const password_len,
                                          size_t const iteration_count,
                                          char const * const cipher_name,
                                          char const * const md_name,
                                          char const * const salt,
                                          size_t const salt_size,
                                          char ** const enc_out,
                                          size_t * const enc_out_size)

{
    assert(in != NULL);
    assert(password != NULL);
    assert(cipher_name != NULL);
    assert(md_name != NULL);
    assert(salt != NULL);
    assert(salt_size > 0);
    cgutils_crypto_cipher * cipher = NULL;

    int result = cgutils_crypto_cipher_init(cipher_name,
                                            &cipher);

    TEST_ASSERT(result == 0, "cgutils_crypto_cipher_init");

    if (result == 0)
    {
        cgutils_crypto_digest_algorithm const md = cgutils_crypto_digest_algorithm_from_str(md_name);

        TEST_ASSERT(md > cgutils_crypto_digest_algorithm_none &&
                    md < cgutils_crypto_digest_algorithm_max,
                    "cgutils_crypto_md_init");

        if (md > cgutils_crypto_digest_algorithm_none &&
            md < cgutils_crypto_digest_algorithm_max)
        {
            cgutils_crypto_cipher_ctx * cipher_ctx = NULL;

            result = cgutils_crypto_cipher_ctx_init_with_salt(cipher,
                                                              md,
                                                              password,
                                                              password_len,
                                                              iteration_count,
                                                              salt,
                                                              salt_size,
                                                              true,
                                                              &cipher_ctx);

            TEST_ASSERT(result == 0, "cgutils_crypto_cipher_ctx_init");

            if (result == 0)
            {
                TEST_ASSERT(cipher_ctx != NULL, "cgutils_crypto_cipher_ctx_init correctness");

                size_t final_size = 0;

                result = cgutils_crypto_cipher_get_final_size(cipher_ctx,
                                                              in_size,
                                                              &final_size);

                TEST_ASSERT(result == 0, "cgutils_crypto_cipher_get_final_size");

                if (result == 0 && final_size > 0)
                {
                    TEST_ASSERT(final_size > 0, "cgutils_crypto_cipher_get_final_size correctness");

                    CGUTILS_MALLOC(*enc_out, final_size, sizeof **enc_out);

                    TEST_ASSERT(*enc_out != NULL, "memory allocated");

                    if (*enc_out != NULL)
                    {
                        char * buffer = NULL;
                        size_t buffer_size = 0;

                        result = cgutils_crypto_cipher_ctx_update(cipher_ctx,
                                                                  in,
                                                                  in_size,
                                                                  &buffer,
                                                                  &buffer_size);

                        TEST_ASSERT(result == 0, "cgutils_crypto_cipher_ctx_update");

                        if (result == 0)
                        {
                            size_t out_pos = 0;

                            assert(buffer_size <= final_size);

                            memcpy(*enc_out, buffer, buffer_size);
                            out_pos += buffer_size;

                            CGUTILS_FREE(buffer);

                            result = cgutils_crypto_cipher_ctx_finish(cipher_ctx,
                                                                      &buffer,
                                                                      &buffer_size);

                            TEST_ASSERT(result == 0, "cgutils_crypto_cipher_ctx_finish");

                            if (result == 0)
                            {
                                assert(final_size - out_pos >= buffer_size);

                                if (buffer_size > 0)
                                {
                                    memcpy(*enc_out + out_pos, buffer, buffer_size);
                                    out_pos += buffer_size;
                                }
                                *enc_out_size = out_pos;

                                CGUTILS_FREE(buffer);
                            }
                        }

                        if (result != 0)
                        {
                            CGUTILS_FREE(*enc_out);
                        }
                    }
                    else
                    {
                        result = ENOMEM;
                    }
                }

                cgutils_crypto_cipher_ctx_free(cipher_ctx), cipher_ctx = NULL;
            }
        }
        else
        {
            result = ENOENT;
        }

        cgutils_crypto_cipher_free(cipher), cipher = NULL;
    }

    return result;
}

static int test_cgutils_crypto_cipher_dec(char const * const in,
                                          size_t const in_size,
                                          char const * const password,
                                          size_t const password_len,
                                          size_t const iteration_count,
                                          char const * const cipher_name,
                                          char const * const md_name,
                                          char const * const salt,
                                          size_t const salt_size,
                                          char ** const dec_out,
                                          size_t * const dec_out_size)
{
    assert(in != NULL);
    assert(password != NULL);
    assert(cipher_name != NULL);
    assert(md_name != NULL);
    assert(salt != NULL);
    assert(salt_size > 0);
    assert(dec_out != NULL);
    assert(dec_out_size != NULL);

    cgutils_crypto_cipher * cipher = NULL;

    int result = cgutils_crypto_cipher_init(cipher_name,
                                            &cipher);

    TEST_ASSERT(result == 0, "cgutils_crypto_cipher_init");

    if (result == 0)
    {
        cgutils_crypto_digest_algorithm const md = cgutils_crypto_digest_algorithm_from_str(md_name);

        TEST_ASSERT(md > cgutils_crypto_digest_algorithm_none &&
                    md < cgutils_crypto_digest_algorithm_max,
                    "cgutils_crypto_md_init");

        if (md > cgutils_crypto_digest_algorithm_none &&
            md < cgutils_crypto_digest_algorithm_max)
        {
            cgutils_crypto_cipher_ctx * cipher_ctx = NULL;

            result = cgutils_crypto_cipher_ctx_init_with_salt(cipher,
                                                              md,
                                                              password,
                                                              password_len,
                                                              iteration_count,
                                                              salt,
                                                              salt_size,
                                                              false,
                                                              &cipher_ctx);

            TEST_ASSERT(result == 0, "cgutils_crypto_cipher_ctx_init");

            if (result == 0)
            {
                TEST_ASSERT(cipher_ctx != NULL, "cgutils_crypto_cipher_ctx_init correctness");

                size_t final_size = 0;

                result = cgutils_crypto_cipher_get_final_size(cipher_ctx,
                                                              in_size,
                                                              &final_size);

                TEST_ASSERT(result == 0, "cgutils_crypto_cipher_get_final_size");

                if (result == 0 && final_size > 0)
                {
                    TEST_ASSERT(final_size > 0, "cgutils_crypto_cipher_get_final_size correctness");

                    CGUTILS_MALLOC(*dec_out, final_size, sizeof **dec_out);

                    TEST_ASSERT(*dec_out != NULL, "memory allocated");

                    if (*dec_out != NULL)
                    {
                        char * buffer = NULL;
                        size_t buffer_size = 0;

                        result = cgutils_crypto_cipher_ctx_update(cipher_ctx,
                                                                  in,
                                                                  in_size,
                                                                  &buffer,
                                                                  &buffer_size);

                        TEST_ASSERT(result == 0, "cgutils_crypto_cipher_ctx_update");

                        if (result == 0)
                        {
                            size_t out_pos = 0;

                            assert(buffer_size <= final_size);

                            memcpy(*dec_out, buffer, buffer_size);
                            out_pos += buffer_size;

                            CGUTILS_FREE(buffer);

                            result = cgutils_crypto_cipher_ctx_finish(cipher_ctx,
                                                                      &buffer,
                                                                      &buffer_size);

                            TEST_ASSERT(result == 0, "cgutils_crypto_cipher_ctx_finish");

                            if (result == 0)
                            {
                                assert(final_size - out_pos >= buffer_size);

                                if (buffer_size > 0)
                                {
                                    memcpy(*dec_out + out_pos, buffer, buffer_size);
                                    out_pos += buffer_size;
                                }
                                *dec_out_size = out_pos;

                                CGUTILS_FREE(buffer);
                            }
                            else
                            {
                                CGUTILS_ERROR("cgutils_crypto_cipher_ctx_finish failed with %d", result);
                            }
                        }

                        if (result != 0)
                        {
                            CGUTILS_FREE(*dec_out);
                        }
                    }
                    else
                    {
                        result = ENOMEM;
                    }
                }

                cgutils_crypto_cipher_ctx_free(cipher_ctx), cipher_ctx = NULL;
            }

        }
        else
        {
            result = ENOENT;
        }

        cgutils_crypto_cipher_free(cipher), cipher = NULL;
    }

    return result;
}

static int test_cgutils_crypto_cipher(void)
{
    char * salt = NULL;
    size_t salt_size = 0;

    int result = cgutils_crypto_get_pkcs5_random_salt(&salt,
                                                      &salt_size);

    TEST_ASSERT(result == 0, "cgutils_crypto_get_pkcs5_random_salt");

    if (result == 0)
    {
        static char const password[] = "test_cgutils_crypto_cipher_password";
        static size_t const password_len = sizeof password - 1;
        static char const in[] = "test_cgutils_crypto_cipher_text";
        static size_t const in_size = sizeof in - 1;
        static size_t iteration_count = 1;
        static char const * const cipher_name = "aes-128-ctr";
        static char const * const md_name = "md5";

        char * enc_out = NULL;
        size_t enc_out_size = 0;

        TEST_ASSERT(salt != NULL, "cgutils_crypto_get_pkcs5_random_salt correctness");
        TEST_ASSERT(salt_size > 0, "cgutils_crypto_get_pkcs5_random_salt correctness");

        result = test_cgutils_crypto_cipher_enc(in,
                                                in_size,
                                                password,
                                                password_len,
                                                iteration_count,
                                                cipher_name,
                                                md_name,
                                                salt,
                                                salt_size,
                                                &enc_out,
                                                &enc_out_size);

        TEST_ASSERT(result == 0, "test_cgutils_crypto_cipher_enc");

        if (result == 0)
        {
            char * dec_out = NULL;
            size_t dec_out_size = 0;

            TEST_ASSERT(enc_out != NULL, "test_cgutils_crypto_cipher_enc correctness");
            TEST_ASSERT(enc_out_size > 0, "test_cgutils_crypto_cipher_enc correctness");
            TEST_ASSERT(enc_out_size >= in_size, "test_cgutils_crypto_cipher_enc correctness");

            result = test_cgutils_crypto_cipher_dec(enc_out,
                                                    enc_out_size,
                                                    password,
                                                    password_len,
                                                    iteration_count,
                                                    cipher_name,
                                                    md_name,
                                                    salt,
                                                    salt_size,
                                                    &dec_out,
                                                    &dec_out_size);

            TEST_ASSERT(result == 0, "test_cgutils_crypto_cipher_dec");

            if (result == 0)
            {
                TEST_ASSERT(dec_out != NULL, "test_cgutils_crypto_cipher_dec correctness");
                TEST_ASSERT(dec_out_size > 0, "test_cgutils_crypto_cipher_dec correctness");
                TEST_ASSERT(dec_out_size == in_size, "test_cgutils_crypto_cipher_dec correctness");

                if (dec_out_size == in_size)
                {
                    if (dec_out != NULL)
                    {
                        int const res = memcmp(in, dec_out, in_size);
                        TEST_ASSERT(res == 0, "decoded matches initial string");
                    }
                }

                CGUTILS_FREE(dec_out);
            }

            CGUTILS_FREE(enc_out);
        }

        CGUTILS_FREE(salt);
    }

    return result;
}

static int test_cgutils_crypto(void)
{
    static char const in[] = "DATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    static size_t const in_size = sizeof(in) - 1;
    static char const salt[] = "SAAAAAALT";
    static size_t const salt_size = sizeof(salt) - 1;
    /* echo -n _in_ | openssl dgst -sha1 -hmac _salt_ */
    static char const hmac_expected_result[] = "17d7698be483ab699b6a4834b4ea42dec8487f01";
    static size_t const hmac_expected_result_size = sizeof hmac_expected_result;
    /* echo -n _in_ | openssl dgst -md5 */
    static char const hash_expected_result[] = "65100d5b5ebbb87979a5d3a86153c8ae";
    static size_t const hash_expected_result_size = sizeof hash_expected_result;
    void * buffer = NULL;
    size_t buffer_size = 0;

    int result = cgutils_crypto_hmac(salt,
                                     salt_size,
                                     in,
                                     in_size,
                                     cgutils_crypto_digest_algorithm_sha1,
                                     &buffer,
                                     &buffer_size);

    TEST_ASSERT(result == 0, "cgutils_crypto_hmac");

    if (result == 0)
    {
        TEST_ASSERT(buffer != NULL, "cgutils_crypto_hmac consistency");

        if (buffer != NULL)
        {
            char * hex_buffer = NULL;
            size_t hex_buffer_size = 0;

            result = cgutils_encoding_hex_sprint(buffer,
                                                 buffer_size,
                                                 &hex_buffer,
                                                 &hex_buffer_size);

            TEST_ASSERT(result == 0, "cgutils_crypto_hmac / cgutils_encoding_hex_print");
            if (result == 0)
            {
                TEST_ASSERT(hex_buffer_size == hmac_expected_result_size, "cgutils_crypto_hmac size correctness");

                if(hex_buffer_size == hmac_expected_result_size)
                {
                    result = memcmp(hex_buffer, hmac_expected_result, hmac_expected_result_size);
                    TEST_ASSERT(result == 0, "cgutils_crypto_hmac result correctness");
                }

                CGUTILS_FREE(hex_buffer);
            }

            CGUTILS_FREE(buffer);
        }
    }

    result = cgutils_crypto_hash(in,
                                 in_size,
                                 cgutils_crypto_digest_algorithm_md5,
                                 &buffer,
                                 &buffer_size);


    TEST_ASSERT(result == 0, "cgutils_crypto_hash");

    if (result == 0)
    {
        TEST_ASSERT(buffer != NULL, "cgutils_crypto_hash consistency");

        if (buffer != NULL)
        {
            char * hex_buffer = NULL;
            size_t hex_buffer_size = 0;

            result = cgutils_encoding_hex_sprint(buffer,
                                                 buffer_size,
                                                 &hex_buffer,
                                                 &hex_buffer_size);

            TEST_ASSERT(result == 0, "cgutils_crypto_hash / cgutils_encoding_hex_print");
            if (result == 0)
            {
                TEST_ASSERT(hex_buffer_size == hash_expected_result_size, "cgutils_crypto_hash size correctness");

                if(hex_buffer_size == hash_expected_result_size)
                {
                    result = memcmp(hex_buffer, hash_expected_result, hash_expected_result_size);
                    TEST_ASSERT(result == 0, "cgutils_crypto_hash result correctness");
                }

                CGUTILS_FREE(hex_buffer);
            }

            CGUTILS_FREE(buffer);
        }
    }

    if (result == 0)
    {
        result = test_cgutils_crypto_cipher();
        TEST_ASSERT(result == 0, "test_cgutils_crypto_cipher");
    }

    return result;
}

static int test_cgutils_encoding(void)
{
    static char const in[] = "DATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    static size_t const in_size = sizeof(in) - 1;
    void * buffer = NULL;
    size_t buffer_size = 0;

    int result = cgutils_encoding_base64_encode(in,
                                                in_size,
                                                &buffer,
                                                &buffer_size);

    TEST_ASSERT(result == 0, "cgutils_encoding_base64_encode");

    if (result == 0)
    {
        TEST_ASSERT(buffer != NULL, "cgutils_encoding_base64_encode consistency");

        if (buffer != NULL)
        {
            TEST_ASSERT(buffer_size > 0, "cgutils_encoding_base64_encode size consistency");

            if (buffer_size > 0)
            {
                void * buffer_decoded = NULL;
                size_t buffer_decoded_size = 0;

                result = cgutils_encoding_base64_decode(buffer,
                                                        buffer_size,
                                                        &buffer_decoded,
                                                        &buffer_decoded_size);

                TEST_ASSERT(result == 0, "cgutils_encoding_base64_decode");

                if (result == 0)
                {
                    TEST_ASSERT(buffer_decoded != NULL, "cgutils_encoding_base64_decode consistency");

                    if (buffer_decoded != NULL)
                    {
                        TEST_ASSERT(buffer_decoded_size == in_size, "cgutils_encoding_base64_decode size correctness");

                        if (buffer_decoded_size == in_size)
                        {
                            result = memcmp(in, buffer_decoded, in_size);

                            TEST_ASSERT(result == 0, "cgutils_encoding_base64_decode correctness");
                        }

                        CGUTILS_FREE(buffer_decoded);
                    }
                }
            }

            CGUTILS_FREE(buffer);
        }
    }

    return result;
}

static int test_cgutils_generic(void)
{
    unsigned int seed = (unsigned int) time(NULL);
    unsigned int const rnd = cgutils_get_random_number_r(&seed, INT_MAX);

    TEST_ASSERT(rnd <= INT_MAX, "cgutils_get_random_number");

    return 0;
}

static int test_cgutils_llist(void)
{
    cgutils_llist * list = NULL;

    int result = cgutils_llist_create(NULL);
    TEST_ASSERT(result == EINVAL, "cgutils_llist_create invalid");

    result = cgutils_llist_create(&list);
    TEST_ASSERT(result == 0, "cgutils_llist_create");

    if(result == 0)
    {
        cgutils_llist_elt * elt = cgutils_llist_get_iterator(NULL);

        TEST_ASSERT(elt == NULL, "cgutils_llist_get_iterator (invalid param) result");

        elt = cgutils_llist_get_iterator(list);

        TEST_ASSERT(elt == NULL, "cgutils_llist_get_iterator (list empty) result");

        result = cgutils_llist_insert(list, list);
        TEST_ASSERT(result == 0, "cgutils_llist_insert");

        result = cgutils_llist_insert(list, &result);
        TEST_ASSERT(result == 0, "cgutils_llist_insert of a second element");

        size_t count = cgutils_llist_get_count(list);

        TEST_ASSERT(count == 2, "cgutils_llist_get_count");

        elt = cgutils_llist_get_iterator(list);

        TEST_ASSERT(elt != NULL, "cgutils_llist_get_iterator result");

        if (elt != NULL)
        {
            cgutils_llist_elt * first_elt = elt;
            void const * obj = cgutils_llist_elt_get_object(elt);

            TEST_ASSERT(obj != NULL, "cgutils_llist_elt_get_object");

            TEST_ASSERT(obj == list, "cgutils_llist_elt_get_object consistency");

            elt = cgutils_llist_elt_get_next(elt);

            TEST_ASSERT(elt != NULL, "cgutils_llist_elt_get_next");

            obj = cgutils_llist_elt_get_object(elt);

            TEST_ASSERT(obj != NULL, "cgutils_llist_elt_get_object second");

            TEST_ASSERT(obj == &result, "cgutils_llist_elt_get_object consistency 2");

            elt = cgutils_llist_elt_get_previous(elt);

            TEST_ASSERT(elt != NULL, "cgutils_llist_elt_get_previous");

            TEST_ASSERT(elt == first_elt, "cgutils_llist_elt_get_previous consistency");

            obj = cgutils_llist_elt_get_object(elt);

            TEST_ASSERT(obj != NULL, "cgutils_llist_elt_get_object");

            TEST_ASSERT(obj == list, "cgutils_llist_elt_get_object consistency");

            result = cgutils_llist_remove(list, elt);

            TEST_ASSERT(result == 0, "cgutils_llist_remove");

            if (result == 0)
            {
                count = cgutils_llist_get_count(list);

                TEST_ASSERT(count == 1, "cgutils_llist_get_count");
            }

            result = cgutils_llist_remove_by_object(list, &result);

            TEST_ASSERT(result == 0, "cgutils_llist_remove_by_object");

            if (result == 0)
            {
                count = cgutils_llist_get_count(list);

                TEST_ASSERT(count == 0, "cgutils_llist_get_count");
            }
        }

        cgutils_llist_free(&list, NULL);
    }

    return result;
}

static int test_cgutils_htable(void)
{
    cgutils_htable * table = NULL;

    int result = cgutils_htable_easy_create(&table);
    TEST_ASSERT(result == 0, "cgutils_htable_easy_create");

    if(result == 0)
    {
        static char const key1[] = "hop";
        static char const key2[] = "hop2";
        static char const key3[] = "hop3";
        static char const key4[] = "hop4";

        result = cgutils_htable_insert(table, key1, table);
        TEST_ASSERT(result == 0, "cgutils_htable_insert");

        result = cgutils_htable_insert(table, key2, table);
        TEST_ASSERT(result == 0, "cgutils_htable_insert of a second key");

        result = cgutils_htable_insert(table, key1, table);
        TEST_ASSERT(result == EEXIST, "cgutils_htable_insert of an existing key");

        result = cgutils_htable_insert(table, key3, table);
        TEST_ASSERT(result == 0, "cgutils_htable_insert of a third key");

        void * hop = NULL;
        result = cgutils_htable_get(table, key1, &hop);
        TEST_ASSERT(result == 0, "cgutils_htable_get of first key");
        TEST_ASSERT(hop == table, "cgutils_htable_get of first key - consistency");

        TEST_ASSERT(cgutils_htable_lookup(table, key2) == true, "cgutils_htable_get of second key");
        TEST_ASSERT(cgutils_htable_lookup(table, key3) == true, "cgutils_htable_get of third key");
        TEST_ASSERT(cgutils_htable_lookup(table, key4) == false, "cgutils_htable_get of non existent key");;

        if (result == 0)
        {
            cgutils_htable_iterator * it = NULL;

            result = cgutils_htable_get_iterator(table,
                                                 &it);

            TEST_ASSERT(result == 0, "cgutils_htable_get_iterator result");

            if (result == 0)
            {
                TEST_ASSERT(it != NULL, "cgutils_htable_get_iterator - consistency");

                size_t table_size = 0;

                do
                {
                    void const * const value = cgutils_htable_iterator_get_value(it);

                    TEST_ASSERT(value != NULL, "cgutils_htable_iterator_get_value - result");
                    TEST_ASSERT(value == table, "cgutils_htable_iterator_get_value - consistency");

                    char const * const key = cgutils_htable_iterator_get_key(it);

                    TEST_ASSERT(key != NULL, "cgutils_htable_iterator_get_key - result");
                    table_size++;
                }
                while(cgutils_htable_iterator_next(it) == true);

                TEST_ASSERT(table_size == 3, "cgutils_table_iterator count");

                cgutils_htable_iterator_free(it), it = NULL;
            }
        }

        cgutils_htable_free(&table, NULL);
    }

    return result;
}

static int test_cgutils_rbtree_compare(void const * a,
                                       void const * b)
{
    TEST_ASSERT(a != NULL, "rbtree compare a != NULL");
    TEST_ASSERT(b != NULL, "rbtree compare b != NULL");

    if (a != NULL &&
        b != NULL)
    {
        return strcmp(a, b);
    }

    return 0;
}

static void test_cgutils_rbtree_key_delete(void * key)
{
    TEST_ASSERT(key != NULL, "rbtree key delete, key != NULL");
    (void) key;
}

static void test_cgutils_rbtree_value_delete(void * value)
{
    TEST_ASSERT(value != NULL, "rbtree value delete, value != NULL");
    (void) value;
}

static int test_cgutils_rbtree(void)
{
    cgutils_rbtree * tree = NULL;

    int result = cgutils_rbtree_init(&test_cgutils_rbtree_compare,
                                     &test_cgutils_rbtree_key_delete,
                                     &test_cgutils_rbtree_value_delete,
                                     &tree);
    TEST_ASSERT(result == 0, "cgutils_rbtree_init");

    if(result == 0)
    {
        result = cgutils_rbtree_insert(tree,  (void *) "hop",  (void *) "hop");
        TEST_ASSERT(result == 0, "cgutils_rbtree_insert");

        result = cgutils_rbtree_insert(tree,  (void *) "hop2",  (void *) "hop2");
        TEST_ASSERT(result == 0, "cgutils_rbtree_insert of a second key");

        result = cgutils_rbtree_insert(tree,  (void *) "hop3",  (void *) "hop3");
        TEST_ASSERT(result == 0, "cgutils_rbtree_insert of a third key");

        result = cgutils_rbtree_insert(tree,  (void *) "a",  (void *) "a");
        TEST_ASSERT(result == 0, "cgutils_rbtree_insert of a inferior key");

        result = cgutils_rbtree_insert(tree,  (void *) "hop",  (void *) "hop");
        TEST_ASSERT(result == EEXIST, "cgutils_rbtree_insert of an existing key");

        cgutils_rbtree_node * node = NULL;

        result = cgutils_rbtree_get(tree,
                                    "hop",
                                    &node);
        TEST_ASSERT(result == 0, "cgutils_rbtree_get of first key");

        if (result == 0)
        {
            TEST_ASSERT(node != NULL, "cgutils_rbtree_get of first key - consistency");

            if (node != NULL)
            {
                char const * value = cgutils_rbtree_node_get_value(node);
                TEST_ASSERT(value != NULL, "cgutils_rbtree_get of first key - consistency");

                if (value != NULL)
                {
                    TEST_ASSERT(strcmp(value, "hop") == 0, "cgutils_rbtree_get of first key - consistency");
                }
            }
        }

        result = cgutils_rbtree_get(tree,
                                    "hop2",
                                    &node);
        TEST_ASSERT(result == 0, "cgutils_rbtree_get of second key");

        if (result == 0)
        {
            TEST_ASSERT(node != NULL, "cgutils_rbtree_get of second key - consistency");

            if (node != NULL)
            {
                char const * value = cgutils_rbtree_node_get_value(node);
                TEST_ASSERT(value != NULL, "cgutils_rbtree_get of second key - consistency");

                if (value != NULL)
                {
                    TEST_ASSERT(strcmp(value, "hop2") == 0, "cgutils_rbtree_get of second key - consistency");
                }
            }
        }

        result = cgutils_rbtree_get(tree,
                                    "hop3",
                                    &node);
        TEST_ASSERT(result == 0, "cgutils_rbtree_get of third key");

        if (result == 0)
        {
            TEST_ASSERT(node != NULL, "cgutils_rbtree_get of third key - consistency");

            if (node != NULL)
            {
                char const * value = cgutils_rbtree_node_get_value(node);
                TEST_ASSERT(value != NULL, "cgutils_rbtree_get of third key - consistency");

                if (value != NULL)
                {
                    TEST_ASSERT(strcmp(value, "hop3") == 0, "cgutils_rbtree_get of third key - consistency");
                }

                result = cgutils_rbtree_remove(tree, node);
                TEST_ASSERT(result == 0, "cgutils_rbtree_remove");

                if (result == 0)
                {
                    result = cgutils_rbtree_get(tree,
                                                "hop3",
                                                &node);
                    TEST_ASSERT(result == ENOENT, "cgutils_rbtree_get of removed key");
                }
            }
        }

        result = cgutils_rbtree_get(tree,
                                    "a",
                                    &node);
        TEST_ASSERT(result == 0, "cgutils_rbtree_get of 'a' key");

        if (result == 0)
        {
            TEST_ASSERT(node != NULL, "cgutils_rbtree_get of 'a' key - consistency");

            if (node != NULL)
            {
                char const * value = cgutils_rbtree_node_get_value(node);
                TEST_ASSERT(value != NULL, "cgutils_rbtree_get of 'a' key - consistency");

                if (value != NULL)
                {
                    TEST_ASSERT(strcmp(value, "a") == 0, "cgutils_rbtree_get of 'a' key - consistency");
                }
            }
        }

        cgutils_rbtree_destroy(tree), tree = NULL;
    }

    return result;
}

static int test_cgutils_configuration(void)
{
    cgutils_configuration * config = NULL;
    char * config_file = cg_tests_get_config_file("dummy.xml");

    int result = cgutils_configuration_from_xml_file(config_file,
                                                     &config);

    TEST_ASSERT(result == 0, "cgutils_configuration_from_xml_file");

    if (result == 0)
    {
        TEST_ASSERT(config != NULL, "cgutils_htable_insert consistency");

        char * name = NULL;

        result = cgutils_configuration_get_string(config,
                                                  "NameNotExisting",
                                                  &name);

        TEST_ASSERT(result == ENOENT, "cgutils_configuration_get_string not existing");

        result = cgutils_configuration_get_string(config,
                                                  "Name",
                                                  &name);

        TEST_ASSERT(result == 0, "cgutils_configuration_get_string");

        if (result == 0)
        {
            TEST_ASSERT(name != NULL, "cgutils_configuration_get_string consistency");

            CGUTILS_FREE(name);
        }

        cgutils_configuration * specific_config = NULL;

        result = cgutils_configuration_from_path(config,
                                                 "Specific",
                                                 &specific_config);

        TEST_ASSERT(result == 0, "cgutils_configuration_from_path");

        if (result == 0)
        {
            TEST_ASSERT(specific_config != NULL, "cgutils_configuration_from_path consistency");

            bool secure = false;
            int64_t signed_integer = 0;
            uint64_t unsigned_integer = 0;

            result = cgutils_configuration_get_integer(specific_config,
                                                       "EndpointPort",
                                                       &signed_integer);

            TEST_ASSERT(result == 0, "cgutils_configuration_get_integer");

            if(result == 0)
            {
                TEST_ASSERT(signed_integer == 4242, "cgutils_configuration_get_integer consistency");
            }

            result = cgutils_configuration_get_unsigned_integer(specific_config,
                                                                "EndpointPort",
                                                                &unsigned_integer);

            TEST_ASSERT(result == 0, "cgutils_configuration_get_unsigned_integer");

            if(result == 0)
            {
                TEST_ASSERT(unsigned_integer == 4242, "cgutils_configuration_get_unsigned_integer consistency");
            }

            result = cgutils_configuration_get_boolean(specific_config,
                                                       "SecureTransaction",
                                                       &secure);

            TEST_ASSERT(result == 0, "cgutils_configuration_get_boolean");

            if(result == 0)
            {
                TEST_ASSERT(secure == true, "cgutils_configuration_get_boolean consistency");
            }


            cgutils_configuration_free(specific_config), specific_config = NULL;
        }

        cgutils_configuration_free(config), config = NULL;
    }

    CGUTILS_FREE(config_file);

    return result;
}

static int test_cgutils_file(void)
{
    int result = 0;
    char * config_file = cg_tests_get_config_file(TEST_STORAGE_FILTER_ENCRYPTION_CONFIG_FILE);

    TEST_ASSERT(cgutils_file_exists(config_file) == true, "cgutils_file_exists");

    if (cgutils_file_exists(TESTDIR) == true)
    {
        result = cgutils_file_rmdir(TESTDIR);
        TEST_ASSERT(result == 0, "cgutils_file_rmdir");
    }

    if (result == 0)
    {
        result = cgutils_file_mkdir(TESTDIR, S_IRWXU | S_IRWXG);
        TEST_ASSERT(result == 0, "cgutils_file_mkdir");

        if (result == 0)
        {
            result = cgutils_file_touch(TESTFILE, S_IRWXU | S_IRWXG);
            TEST_ASSERT(result == 0, "cgutils_file_touch");

            if (result == 0)
            {
                result = cgutils_file_rename(TESTFILE, TESTFILE ".2");
                TEST_ASSERT(result == 0, "cgutils_file_rename");

                if (result == 0)
                {
                    FILE * fd = fopen(TESTFILE ".2", "w");

                    if (fd != NULL)
                    {
                        result = cgutils_file_lock(fileno(fd), F_WRLCK);
                        TEST_ASSERT(result == 0, "cgutils_file_lock");

                        if (result == 0)
                        {
                            result = cgutils_file_unlock(fileno(fd));
                            TEST_ASSERT(result == 0, "cgutils_file_unlock");

                            if (result == 0)
                            {
                                char * dir = NULL;

                                result = cgutils_file_dirname("/there/is/no/bug",
                                                              &dir);

                                TEST_ASSERT(result == 0, "cgutils_file_dirname");

                                if (result == 0)
                                {
                                    TEST_ASSERT(dir != NULL, "cgutils_file_dirname consistency");

                                    if (dir != NULL)
                                    {
                                        result = strcmp(dir, "/there/is/no/");

                                        TEST_ASSERT(result == 0, "cgutils_file_dirname correctness");

                                        if (result == 0)
                                        {
                                            char * base = NULL;

                                            result = cgutils_file_basename("/there/is/no/bug", &base);

                                            TEST_ASSERT(result == 0, "cgutils_file_basename");
                                            if (result == 0)
                                            {
                                                TEST_ASSERT(base != NULL, "cgutils_file_basename consistency");

                                                if (base != NULL)
                                                {
                                                    result = strcmp(base, "bug");

                                                    TEST_ASSERT(result == 0, "cgutils_file_basename correctness");

                                                    CGUTILS_FREE(base);
                                                }
                                            }
                                        }

                                        CGUTILS_FREE(dir);
                                    }
                                }
                            }
                        }

                        fclose(fd), fd = NULL;
                    }

                    result = cgutils_file_unlink(TESTFILE ".2");
                    TEST_ASSERT(result == 0, "cgutils_file_unlink");
                }
                else
                {
                    result = cgutils_file_unlink(TESTFILE);
                    TEST_ASSERT(result == 0, "cgutils_file_unlink");
                }
            }

            result = cgutils_file_rmdir(TESTDIR);
            TEST_ASSERT(result == 0, "cgutils_file_rmdir");
        }
    }

    CGUTILS_FREE(config_file);

    return result;
}

static bool test_cgutils_advanced_file_ops_hash_done = false;

static void test_cgutils_advanced_file_ops_cb(int const status,
                                              void * hash,
                                              size_t hash_size,
                                              void * cb_data)
{
    int result = status;

    TEST_ASSERT(cb_data != NULL, "cgutils_file_hash cb_data");

    TEST_ASSERT(status == 0, "cgutils_file_hash result");
    TEST_ASSERT(hash != NULL, "cgutils_file_hash hash");
    TEST_ASSERT(hash_size > 0, "cgutils_file_hash hash size");

    if (result == 0)
    {
        /* openssl dgst -md5 AIO_TEST_FILE */
        static char const expected_hash[] = "11b7911a8936476fc51fabb6aebb6e6f";
        static size_t const expected_hash_size = sizeof expected_hash;

        char * hex_buffer = NULL;
        size_t hex_buffer_size = 0;

        result = cgutils_encoding_hex_sprint(hash,
                                             hash_size,
                                             &hex_buffer,
                                             &hex_buffer_size);

        TEST_ASSERT(result == 0, "cgutils_encoding_hex_sprint");

        if (result == 0)
        {
            TEST_ASSERT(hex_buffer_size == expected_hash_size, "cgutils_file_hash hash size");
            TEST_ASSERT(hex_buffer != NULL, "cgutils_file_hash hash");

            if (hex_buffer_size == expected_hash_size && hex_buffer != NULL)
            {
                result = memcmp(hex_buffer, expected_hash, expected_hash_size);
                TEST_ASSERT(result == 0, "cgutils_file_hash hash consistency");
            }

            CGUTILS_FREE(hex_buffer);
        }

        CGUTILS_FREE(hash);
    }

    test_cgutils_advanced_file_ops_hash_done = true;

    cgutils_event_data * event_data = cb_data;
    cgutils_event_exit_loop(event_data);
}

static int test_cgutils_advanced_file_ops(cgutils_event_data * const event_data)
{
    int result = 0;
    cgutils_aio * aio = NULL;
    assert(event_data != NULL);

    result = cgutils_aio_init(event_data, &aio);

    TEST_ASSERT(result == 0, "cgutils_aio_init");

    if (result == 0)
    {
        TEST_ASSERT(aio != NULL, "cgutils_aio_init consistency");

        result = cgutils_file_hash(aio,
                                   AIO_TEST_FILE,
                                   cgutils_crypto_digest_algorithm_md5,
                                   test_cgutils_advanced_file_ops_cb,
                                   event_data);

        TEST_ASSERT(result == 0, "cgutils_file_hash");

        cgutils_event_dispatch(event_data);

        TEST_ASSERT(test_cgutils_advanced_file_ops_hash_done == true, "cgutils_file_hash done");

        cgutils_aio_free(aio), aio = NULL;
    }


    return result;
}

static int test_cgutils_time_counter(void)
{
    cgutils_time_counter counter;
    int result = 0;

    cgutils_time_counter_init(&counter);
    cgutils_time_counter_start(&counter);
    sleep(2);
    cgutils_time_counter_stop(&counter);
    cgutils_time_counter_print(&counter);

    return result;
}

static int test_http_write_cb(cgutils_http_data * const http_data,
                              cgutils_http_request * const request,
                              void * const data,
                              size_t const data_size,
                              void * const cb_data)
{
    (void) http_data;
    (void) request;
    (void) data;
    (void) data_size;

    int64_t * const canary = cb_data;

    TEST_ASSERT(*canary == 0xdeadbeef ||
                *canary == 0xcafecafe, "test http write callback : data");

    return 0;
}

static int test_http_read_cb(cgutils_http_data * const http_data,
                             cgutils_http_request * const request,
                             void * const buffer,
                             size_t const buffer_size,
                             size_t  * const written,
                             bool * eof,
                             void * const cb_data)
{
    TEST_ASSERT(http_data != NULL, "test http response callback : data");
    TEST_ASSERT(request != NULL, "test http response callback : request");
    TEST_ASSERT(buffer != NULL, "test http response callback : buffer");
    TEST_ASSERT(cb_data != NULL, "test http response callback : cb_data");
    (void) http_data;
    (void) request;

    static bool done = false;

    if (done == false)
    {
        if (buffer != NULL)
        {
            char const hop[] = "aa&aaéé";

            *written = buffer_size > (sizeof hop -1) ? (sizeof hop -1) : buffer_size;
            memcpy(buffer, hop, *written);
        }

        done = true;
    }
    else
    {
        *eof = done;
        *written = 0;
    }

    return 0;
}

static int test_http_response_cb(cgutils_http_data * const data,
                                 cgutils_http_request * request,
                                 cgutils_http_response * response,
                                 void * const cb_data)
{
    TEST_ASSERT(data != NULL, "test http response callback : data");
    TEST_ASSERT(request != NULL, "test http response callback : request");
    TEST_ASSERT(response != NULL, "test http response callback : response");
    TEST_ASSERT(cb_data != NULL, "test http response callback : cb_data");

    uint16_t const status = cgutils_http_response_get_status(response);

    TEST_ASSERT(status == 200 ||
                status == 302 ||
                status == 413, "test http response callback : status code");

    if (status != 200 &&
        status != 302 &&
        status != 413)
    {
        LOG("Status is %"PRIu16, status);
    }

    TEST_ASSERT(cgutils_http_response_total_time(response) > 0, "cgutils_http_response_total_time");
    TEST_ASSERT(cgutils_http_response_namelookup_time(response) > 0, "cgutils_http_response_namelookup_time");
    TEST_ASSERT(cgutils_http_response_connect_time(response) > 0, "cgutils_http_response_connect_time");

    int64_t * const canary = cb_data;

    if (canary != NULL)
    {
        TEST_ASSERT(*canary == 0xdeadbeef || *canary == 0xcafecafe, "canary value is unexpected");
        *canary = 0xcafecafe;
    }

    cgutils_http_response_free(response), response = NULL;
    cgutils_http_request_free(request), request = NULL;


    return 0;
}

static int test_cgutils_http(cgutils_event_data * event_data,
                             void * canary,
                             cgutils_http_data ** http_data)
{
    int result = cgutils_http_data_init(event_data, NULL, http_data);
    TEST_ASSERT(result == 0, "cgutils_http_init");

    if (result == 0)
    {
        TEST_ASSERT(*http_data != NULL, "cgutils_http_init consistency");

        cgutils_http_callbacks const cbs = { .response_cb = &test_http_response_cb,
                                             .write_cb = &test_http_write_cb,
                                             .read_cb = &test_http_read_cb
        };
        cgutils_http_timeouts const timeouts = { .timeout = 10 };
        cgutils_http_request_options const options = { 0 };
        cgutils_http_request * http_request = NULL;

        result = cgutils_http_request_init(*http_data,
                                           "http://www.aquaray.fr/",
                                           CGUTILS_HTTP_METHOD_GET,
                                           NULL,
                                           &cbs,
                                           &timeouts,
                                           &options,
                                           canary,
                                           &http_request);
        TEST_ASSERT(result == 0, "cgutils_http_request_init");

        if (result == 0)
        {
            TEST_ASSERT(http_request != NULL, "cgutils_http_request_init consistency");

            result = cgutils_http_send(http_request);
            TEST_ASSERT(result == 0, "cgutils_http_send");

            if (result == 0)
            {
                cgutils_http_request * http_post_request = NULL;

                result = cgutils_http_request_init(*http_data,
                                                   "http://coredump.fr/",
                                                   CGUTILS_HTTP_METHOD_POST,
                                                   NULL,
                                                   &cbs,
                                                   &timeouts,
                                                   &options,
                                                   canary,
                                                   &http_post_request);
                TEST_ASSERT(result == 0, "cgutils_http_request_init POST");

                if (result == 0)
                {
                    TEST_ASSERT(http_post_request != NULL, "cgutils_http_request_init POST consistency");

                    result = cgutils_http_send(http_post_request);
                    TEST_ASSERT(result == 0, "cgutils_http_send POST");

                    if (result != 0)
                    {
                        cgutils_http_request_free(http_post_request), http_post_request = NULL;
                    }
                }
            }
            else
            {
                cgutils_http_request_free(http_request), http_request = NULL;
            }
        }
    }

    return result;
}

static char const test_cgutils_aio_write_buffer[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

static bool test_cgutils_aio_write_done = false;
static bool test_cgutils_aio_read_done = false;
static size_t test_cgutils_aio_read_completion = 0;

static int test_cgutils_aio_write_cb(int status,
                                     size_t const completion,
                                     void * cb_data)
{
    TEST_ASSERT(status == 0, "test_cgutils_aio_write_cb status");
    TEST_ASSERT(cb_data != NULL, "test_cgutils_aio_write_cb cb_data");

    test_cgutils_aio_write_done = true;

    TEST_ASSERT(completion == sizeof test_cgutils_aio_write_buffer - 1, "test_cgutils_aio_write_cb completion");

    cgutils_event_data * event_data = cb_data;
    cgutils_event_exit_loop(event_data);

    return 0;
}

static int test_cgutils_aio_read_cb(int status,
                                    size_t got,
                                    void * cb_data)
{
    TEST_ASSERT(status == 0, "test_cgutils_aio_write_cb status");
    TEST_ASSERT(cb_data != NULL, "test_cgutils_aio_write_cb cb_data");

    test_cgutils_aio_read_done = true;

    if (status != 0)
    {
        CGUTILS_ERROR("status is %d", status);
    }

    TEST_ASSERT(got == sizeof test_cgutils_aio_write_buffer - 1, "cgutils_aio_read size");
    test_cgutils_aio_read_completion = got;

    cgutils_event_data * event_data = cb_data;
    cgutils_event_exit_loop(event_data);

    return 0;
}

static int test_cgutils_aio(cgutils_event_data * const event_data)
{
    assert(event_data != NULL);

    cgutils_aio * aio = NULL;

    int result = cgutils_aio_init(event_data, &aio);

    TEST_ASSERT(result == 0, "cgutils_aio_init");

    if (result == 0)
    {
        TEST_ASSERT(aio != NULL, "cgutils_aio_init consistency");
        int write_fd = -1;

        result = cgutils_file_open(AIO_TEST_FILE, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR | S_IWUSR, &write_fd);

        TEST_ASSERT(result == 0, "cgutils_file_open");

        if (result == 0)
        {
            static size_t const write_buffer_size = sizeof test_cgutils_aio_write_buffer -1;
            int read_fd = -1;

            TEST_ASSERT(write_fd >= 0, "cgutils_file_open consistency");

            result = cgutils_aio_write(aio, write_fd,
                                       test_cgutils_aio_write_buffer,
                                       write_buffer_size,
                                       0,
                                       &test_cgutils_aio_write_cb,
                                       event_data);

            TEST_ASSERT(result == 0, "cgutils_aio_write");

            cgutils_event_dispatch(event_data);

            TEST_ASSERT(test_cgutils_aio_write_done == true, "cgutils_aio_write done");

            result = cgutils_file_open(AIO_TEST_FILE, O_RDONLY, 0, &read_fd);

            TEST_ASSERT(result == 0, "cgutils_file_open");

            if (result == 0)
            {
                static char read_buffer[4096];
                static size_t const read_buffer_size = sizeof read_buffer;

                TEST_ASSERT(read_fd >= 0, "cgutils_file_open consistency");
                result = cgutils_aio_read(aio,
                                          read_fd,
                                          read_buffer,
                                          read_buffer_size,
                                          0,
                                          &test_cgutils_aio_read_cb,
                                          event_data);

                TEST_ASSERT(result == 0, "cgutils_aio_read");

                cgutils_event_dispatch(event_data);

                TEST_ASSERT(test_cgutils_aio_read_done == true, "cgutils_aio_read done");

                if (test_cgutils_aio_read_completion == write_buffer_size)
                {
                    result = memcmp(read_buffer, test_cgutils_aio_write_buffer, write_buffer_size);

                    TEST_ASSERT(result == 0, "cgutils_aio_write / read consistency");
                }

                cgutils_file_close(read_fd), read_fd = -1;
            }

            cgutils_file_close(write_fd), write_fd = -1;
        }

        cgutils_aio_free(aio), aio = NULL;
    }

    return result;
}

static void test_cgutils_event_timer_cb(void * cb_data)
{
    (void) cb_data;
}

static int test_cgutils_event(cgutils_event_data ** event_data)
{
    int result = cgutils_event_init(event_data);
    TEST_ASSERT(result == 0, "cgutils_event_init");

    if (result == 0)
    {
        TEST_ASSERT(*event_data != NULL, "cgutils_event_init");
        cgutils_event * event = NULL;
        result = cgutils_event_create_timer_event(*event_data,
                                                  0,
                                                  &test_cgutils_event_timer_cb,
                                                  NULL,
                                                  &event);
        TEST_ASSERT(result == 0, "cgutils_event_create_timer_event");

        if (result == 0)
        {
            struct timeval timeout = { .tv_sec = 10 };

            TEST_ASSERT(event != NULL, "cgutils_event_create_timer_event");

            result = cgutils_event_enable(event, &timeout);

            TEST_ASSERT(result == 0, "cgutils_event_enable");

            if (result == 0)
            {
                bool pending = false;

                result = cgutils_event_pending(event, 0, &pending);

                TEST_ASSERT(result == 0, "cgutils_event_pending");
                TEST_ASSERT(pending == true, "cgutils_event_pending consistency");

                result = cgutils_event_disable(event);

                TEST_ASSERT(result == 0, "cgutils_event_disable");

                if (result == 0)
                {
                    result = cgutils_event_pending(event, 0, &pending);
                    TEST_ASSERT(result == 0, "cgutils_event_pending");
                    TEST_ASSERT(pending == false, "cgutils_event_pending consistency");
                }
            }

            cgutils_event_free(event), event = NULL;
        }

        result = cgutils_event_clear(*event_data);

        TEST_ASSERT(result == 0, "cgutils_event_clear");
    }

    return result;
}

static int test_cgutils_network(void)
{
    struct addrinfo * addr = NULL;

    int result = cgutils_network_get_addr_storage("::1",
                                                  "54242",
                                                  "TCP",
                                                  &addr);

    TEST_ASSERT(result == 0, "cgutils_network_get_addr_storage");

    if (result == 0)
    {
        TEST_ASSERT(addr != NULL, "cgutils_network_get_addr_storage consistency");

        int sock = -1;

        result = cgutils_network_listen_on_socket(addr,
                                                  10,
                                                  SOMAXCONN,
                                                  true,
                                                  &sock);

        TEST_ASSERT(result == 0, "cgutils_network_listen_on_socket");

        if (result == 0)
        {
            TEST_ASSERT(sock >= 0, "cgutils_network_listen_on_socket consistency");

            cgutils_file_close(sock), sock = 1;
        }

        freeaddrinfo(addr), addr = NULL;
    }

    return result;
}

static int test_cgutils_system(void)
{
    cgutils_vector * itfs = NULL;

    int result = cgutils_system_network_get_all_interfaces(&itfs);

    TEST_ASSERT(result == 0, "cgutils_system_network_get_all_interfaces");

    if (result == 0)
    {
        TEST_ASSERT(itfs != NULL, "cgutils_system_network_get_all_interfaces consistency");

        if (itfs != NULL)
        {
            size_t const interfaces_count = cgutils_vector_count(itfs);

            for (size_t idx = 0;
                 idx < interfaces_count;
                 idx++)
            {
                cgutils_system_network_interface const * itf = NULL;

                result = cgutils_vector_get(itfs,
                                            idx,
                                            (void ** )&itf);
                TEST_ASSERT(result == 0, "cgutils_vector_get");

                if (result == 0)
                {
                    assert(itf != NULL);
                    char const * const name = cgutils_system_network_interface_get_name(itf);
                    TEST_ASSERT(name != NULL, "cgutils_system_network_interface_get_name");
                }
            }

            cgutils_vector_deep_free(&itfs, &cgutils_system_network_interface_delete);
        }
    }

    cgutils_llist * addrs = NULL;

    result = cgutils_system_network_get_all_addresses(&addrs);

    TEST_ASSERT(result == 0, "cgutils_system_network_get_all_addresses");

    if (result == 0)
    {
        TEST_ASSERT(addrs != NULL, "cgutils_system_network_get_all_addresses consistency");

        if (addrs != NULL)
        {
            for (cgutils_llist_elt * it = cgutils_llist_get_first(addrs);
                 it != NULL;
                 it = cgutils_llist_elt_get_next(it))
            {
                cgutils_system_network_address const * const addr = cgutils_llist_elt_get_object(it);
                assert(addr != NULL);
                char const * const itf_name = cgutils_system_network_address_get_interface_name(addr);
                char const * const address = cgutils_system_network_address_get_addr(addr);
                char const * const mask = cgutils_system_network_address_get_mask(addr);

                TEST_ASSERT(itf_name != NULL, "cgutils_system_network_address_get_interface_name");
                TEST_ASSERT(mask != NULL, "cgutils_system_network_address_get_mask");
                TEST_ASSERT(address != NULL, "cgutils_system_network_address_get_addr");
            }

            cgutils_llist_free(&addrs, &cgutils_system_network_address_delete);
        }
    }

    cgutils_system_uname_info * uinfo = NULL;

    result = cgutils_system_get_uname_info(&uinfo);

    TEST_ASSERT(result == 0, "cgutils_system_get_uname_info");

    if (result == 0)
    {
        TEST_ASSERT(uinfo != NULL, "cgutils_system_get_uname_info consistency");

        if (uinfo != NULL)
        {
            char const * const sysname = cgutils_system_uname_get_sysname(uinfo);
            TEST_ASSERT(sysname != NULL, "cgutils_system_uname_get_sysname");
            char const * const nodename = cgutils_system_uname_get_nodename(uinfo);
            TEST_ASSERT(nodename != NULL, "cgutils_system_uname_get_nodename");
            char const * const release = cgutils_system_uname_get_release(uinfo);
            TEST_ASSERT(release != NULL, "cgutils_system_uname_get_release");
            char const * const version = cgutils_system_uname_get_version(uinfo);
            TEST_ASSERT(version != NULL, "cgutils_system_uname_get_version");
            char const * const machine = cgutils_system_uname_get_machine(uinfo);
            TEST_ASSERT(machine != NULL, "cgutils_system_uname_get_machine");

            cgutils_system_uname_info_free(uinfo), uinfo = NULL;
        }
    }

    char * str = NULL;
    size_t str_len = 0;

    result = cgutils_system_get_cpuinfo(&str,
                                        &str_len);

    TEST_ASSERT(result == 0, "cgutils_system_get_cpuinfo");

    if (result == 0)
    {
        TEST_ASSERT(str != NULL, "cgutils_system_get_cpuinfo consistency");

        if (str != NULL)
        {
            CGUTILS_FREE(str);
        }

        str_len = 0;
    }

    result = cgutils_system_get_meminfo(&str,
                                        &str_len);

    TEST_ASSERT(result == 0, "cgutils_system_get_meminfo");

    if (result == 0)
    {
        TEST_ASSERT(str != NULL, "cgutils_system_get_meminfo consistency");

        if (str != NULL)
        {
            CGUTILS_FREE(str);
        }

        str_len = 0;
    }

    cgutils_vector * vector = NULL;

    result = cgutils_system_network_get_interfaces_stats(&vector);

    TEST_ASSERT(result == 0, "cgutils_system_network_get_interfaces_stats");

    if (result == 0)
    {
        TEST_ASSERT(vector != NULL, "cgutils_system_network_get_interfaces_stats consistency");
        cgutils_vector_deep_free(&vector, &free);
    }

    cgutils_system_cpu_stats stats = (cgutils_system_cpu_stats) { 0 } ;

    result = cgutils_system_get_cpu_stats(&stats);

    TEST_ASSERT(result == 0, "cgutils_system_get_cpu_stats");

    cgutils_system_memory_stats memstats = (cgutils_system_memory_stats) { 0 } ;

    result = cgutils_system_get_memory_stats(&memstats);

    TEST_ASSERT(result == 0, "cgutils_system_get_memory_stats");

    return result;
}

static int test_cgutils_xml(void)
{
    static char const date1[] = "2013-04-18T23:49:44.023Z";
    static char const date2[] = "2013-04-19T01:49:44.023+02:00";
    static char const date3[] = "2013-04-18T11:04:44.023-12:45";
    time_t date1_time = -1;
    time_t date2_time = -1;
    time_t date3_time = -1;

    int result = cgutils_xml_time_from_str(date1,
                                           &date1_time);

    TEST_ASSERT(result == 0, "cgutils_xml_time_from_str");

    if (result == 0)
    {
        TEST_ASSERT(date1_time != (time_t) -1, "cgutils_xml_time_from_str consistency");

        result = cgutils_xml_time_from_str(date2,
                                           &date2_time);

        TEST_ASSERT(result == 0, "cgutils_xml_time_from_str with timezone");

        if (result == 0)
        {
            TEST_ASSERT(date1_time == date2_time, "cgutils_xml_time_from_str same date with different timezones");

            result = cgutils_xml_time_from_str(date3,
                                               &date3_time);

            TEST_ASSERT(result == 0, "cgutils_xml_time_from_str with negative timezone");

            if (result == 0)
            {
                TEST_ASSERT(date2_time == date3_time, "cgutils_xml_time_from_str same date with different timezones");
            }
        }
    }

    return result;
}

typedef struct
{
    pid_t child;
    cgutils_event_data * event_data;
    bool signaled;
} test_cgutils_process_data;

static void test_cgutils_sig_chld_cb(int const sig,
                                     void * const cb_data)
{
    assert(sig == SIGCHLD);
    assert(cb_data != NULL);

    test_cgutils_process_data * data = cb_data;
    pid_t reaped_pid = -1;
    int status = 0;
    bool exited = false;
    bool signaled = false;

    int result = cgutils_process_reap(&reaped_pid,
                                      WNOHANG,
                                      &status,
                                      &exited,
                                      &signaled);

    (void) sig;

    TEST_ASSERT(result == 0, "cgutils_process_reap");

    if (result == 0)
    {
        TEST_ASSERT(status == 0, "cgutils_process_reap status");
        TEST_ASSERT(exited == true, "cgutils_process_reap exited");
        TEST_ASSERT(signaled == false, "cgutils_process_reap signaled");
        TEST_ASSERT(data->child == reaped_pid, "cgutils_process_reap pid");
    }

    TEST_ASSERT(data->signaled == false, "test_cgutils_sig_chld_cb first call");
    data->signaled = true;
    cgutils_event_exit_loop(data->event_data);
}

static int test_cgutils_process(cgutils_event_data * const event_data)
{
    int result = 0;
    assert(event_data != NULL);
    test_cgutils_process_data process_data =
        {
            .child = -1,
            .event_data = event_data,
            .signaled = false
        };

    process_data.child = fork();

    TEST_ASSERT(process_data.child >= 0, "fork");

    if (process_data.child == 0)
    {
        cgutils_event_clear(event_data);
        cgutils_event_destroy(event_data);
        sleep(1);
        cg_tests_destroy_all();
        fclose(stdin);
        fclose(stdout);
        fclose(stderr);
        exit(0);
    }
    else if (process_data.child > 0)
    {
        cgutils_event * sig_event = NULL;
        result = cgutils_event_create_signal_event(event_data,
                                                   SIGCHLD,
                                                   &test_cgutils_sig_chld_cb,
                                                   &process_data,
                                                   &sig_event);

        TEST_ASSERT(result == 0, "cgutils_event_create_signal_event");

        if (result == 0)
        {
            TEST_ASSERT(sig_event != NULL, "cgutils_event_create_signal_event consistency");


            result = cgutils_event_enable(sig_event, NULL);

            TEST_ASSERT(result == 0, "cgutils_event_enable");

            if (result == 0)
            {
                cgutils_event_dispatch(event_data);

                TEST_ASSERT(process_data.signaled == true, "test_cgutils_sig_chld_cb called");

                result = cgutils_event_disable(sig_event);

                TEST_ASSERT(result == 0, "cgutils_event_disable");
            }

            cgutils_event_free(sig_event), sig_event = NULL;
        }
    }

    return result;
}

int main(void)
{
    cgutils_event_data * event_data = NULL;
    int64_t canary = 0xdeadbeef;
    int result = 0;
    char * encrypted = NULL;
    size_t encrypted_size = 0;
    char * compressed = NULL;
    size_t compressed_size = 0;

    /* cgutils crypto init OpenSSL, and should be tested first for this reason */

    result = test_cgutils_init();

    if (result == 0)
    {
        result = test_cgutils_generic();

        TEST_ASSERT(result == 0, "test_cgutils_generic");

        result = test_cgutils_encoding();

        TEST_ASSERT(result == 0, "test_cgutils_encoding");

        result = test_cgutils_crypto();

        TEST_ASSERT(result == 0, "test_cgutils_crypto");

        result = test_cgutils_llist();

        TEST_ASSERT(result == 0, "test_cgutils_llist");

        result = test_cgutils_htable();

        TEST_ASSERT(result == 0, "test_cgutils_htable");

        result = test_cgutils_file();

        TEST_ASSERT(result == 0, "test_cgutils_file");

        result = test_cgutils_configuration();

        TEST_ASSERT(result == 0, "test_cgutils_configuration");

        result = test_cgutils_time_counter();

        TEST_ASSERT(result == 0, "test_cgutils_time_counter");

        result = test_cgutils_network();

        TEST_ASSERT(result == 0, "test_cgutils_network");

        result = test_cgutils_system();

        TEST_ASSERT(result == 0, "test_cgutils_system");

        result = test_cgutils_xml();

        TEST_ASSERT(result == 0, "test_cgutils_xml");

        result = test_cgutils_rbtree();

        TEST_ASSERT(result == 0, "test_cgutils_rbtree");

        result = test_cgutils_storage_filter_encryption(&encrypted,
                                                        &encrypted_size);

        TEST_ASSERT(result == 0, "test_cgutils_storage_filter_encryption");

        if (result == 0)
        {
            result = test_cgutils_storage_filter_decryption(encrypted,
                                                            encrypted_size);

            TEST_ASSERT(result == 0, "test_cgutils_storage_filter_decryption");

            CGUTILS_FREE(encrypted);
        }

        result = test_cgutils_storage_filter_compression(&compressed,
                                                         &compressed_size);

        TEST_ASSERT(result == 0, "test_cgutils_storage_filter_compression");

        if (result == 0)
        {
            cgutils_set_color(stderr, CLOUDUTILS_ANSI_COLOR_ATTR_DIM, CLOUDUTILS_ANSI_COLOR_GREEN, CLOUDUTILS_ANSI_COLOR_BLACK);
            CGUTILS_DEBUG("Compressed size is %zu, was %zu",
                          compressed_size,
                          test_cgutils_compression_in_size);
            cgutils_set_color(stderr, CLOUDUTILS_ANSI_COLOR_ATTR_RESET, CLOUDUTILS_ANSI_COLOR_WHITE, CLOUDUTILS_ANSI_COLOR_BLACK);
            result = test_cgutils_storage_filter_decompression(compressed,
                                                               compressed_size);

            TEST_ASSERT(result == 0, "test_cgutils_storage_filter_decompression");

            CGUTILS_FREE(compressed);
        }

        result = test_cgutils_event(&event_data);

        TEST_ASSERT(result == 0, "test_cgutils_event");

        if (result == 0)
        {
            cgutils_http_data * http_data = NULL;
            result = test_cgutils_http(event_data, &canary, &http_data);

            if (result == 0)
            {
                cgutils_event_dispatch(event_data);
                TEST_ASSERT(canary == 0xcafecafe, "test http response callback executed");
                cgutils_http_data_free(http_data), http_data = NULL;
            }

            result = test_cgutils_aio(event_data);

            TEST_ASSERT(result == 0, "test_cgutils_aio");

            result = test_cgutils_process(event_data);

            TEST_ASSERT(result == 0, "test_cgutils_process");

            result = test_cgutils_advanced_file_ops(event_data);

            TEST_ASSERT(result == 0, "test_cgutils_advanced_file_ops");

            cgutils_event_destroy(event_data);
        }

        cg_tests_destroy_all();
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
