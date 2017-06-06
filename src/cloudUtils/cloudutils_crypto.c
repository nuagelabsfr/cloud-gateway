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
#include <strings.h>

#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "cloudutils/cloudutils.h"
#include "cloudutils/cloudutils_crypto.h"
#include "cloudutils/cloudutils_file.h"

int cgutils_crypto_init(void)
{
    /* As does libcurl:
       OPENSSL_config(NULL); is "strongly recommended" to use but unfortunately
       that function makes an exit() call on wrongly formatted config files
       which makes it hard to use in some situations. OPENSSL_config() itself
       calls CONF_modules_load_file() and we use that instead and we ignore
       its return code! */

    OPENSSL_load_builtin_modules();
    ENGINE_load_builtin_engines();

    (void)CONF_modules_load_file(NULL, NULL,
                                 CONF_MFLAGS_DEFAULT_SECTION|
                                 CONF_MFLAGS_IGNORE_MISSING_FILE);

    ERR_load_crypto_strings();

#define DIGEST(str, value)                      \
    EVP_add_digest(EVP_ ## value());
#include "cloudutils/cloudutils_crypto_digests.itm"
#undef DIGEST

#define CIPHER(str, value)                      \
    EVP_add_cipher(EVP_ ## value());
#include "cloudutils_crypto_ciphers.itm"
#undef CIPHER

    ENGINE_register_all_complete();

    return 0;
}

void cgutils_crypto_atfork(void)
{
    /* Reseed the random number generator, otherwise
       all children may end up with the same random data.
    */

    RAND_poll();
}

void cgutils_crypto_destroy(void)
{
    ERR_remove_state(0);
    ERR_free_strings();

    ENGINE_cleanup();
    EVP_cleanup();

    CONF_modules_finish();
    CONF_modules_free();
    CONF_modules_unload(1);

    CRYPTO_cleanup_all_ex_data();
}

cgutils_crypto_digest_algorithm cgutils_crypto_digest_algorithm_from_str(char const * const digest_str)
{
    cgutils_crypto_digest_algorithm result = cgutils_crypto_digest_algorithm_none;

    if (COMPILER_LIKELY(digest_str != NULL))
    {
        static struct
        {
            char const * const name;
            cgutils_crypto_digest_algorithm value;
        }
        const digests[] =
            {
#define DIGEST(name, value) { name, cgutils_crypto_digest_algorithm_ ## value } ,
#include "cloudutils/cloudutils_crypto_digests.itm"
#undef DIGEST
            };
        static size_t const digests_count = sizeof digests / sizeof *digests;

        for (size_t idx = 0;
             idx < digests_count &&
                 result == cgutils_crypto_digest_algorithm_none;
             idx++)
        {
            if (strcasecmp(digest_str,
                           digests[idx].name) == 0)
            {
                result = digests[idx].value;
            }
        }
    }

    return result;
}

static EVP_MD const * cgutils_crypto_get_digest(cgutils_crypto_digest_algorithm const algo)
{
    EVP_MD const * result = NULL;

    switch (algo)
    {
    case cgutils_crypto_digest_algorithm_none:
    case cgutils_crypto_digest_algorithm_max:
        result = NULL;
        break;
#define DIGEST(name, value)                                     \
        case cgutils_crypto_digest_algorithm_ ## value:         \
            result = EVP_ ## value();                           \
                break;
#include "cloudutils/cloudutils_crypto_digests.itm"
#undef DIGEST
    }

    return result;
}

int cgutils_crypto_hmac(void const * const salt,
                        size_t const salt_size,
                        void const * const data,
                        size_t const data_size,
                        cgutils_crypto_digest_algorithm const algorithm,
                        void ** const out,
                        size_t * const out_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(salt != NULL &&
                        data != NULL &&
                        algorithm > cgutils_crypto_digest_algorithm_none &&
                        algorithm < cgutils_crypto_digest_algorithm_max &&
                        out != NULL))
    {
        EVP_MD const * const md_algo = cgutils_crypto_get_digest(algorithm);

        if (COMPILER_LIKELY(md_algo != NULL))
        {
            CGUTILS_MALLOC(*out, EVP_MAX_MD_SIZE, 1);

            if (COMPILER_LIKELY(*out != NULL))
            {
                if (salt_size <= INT_MAX && data_size <= INT_MAX)
                {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
                    HMAC_CTX * ctx = HMAC_CTX_new();

                    if (COMPILER_LIKELY(ctx != NULL))
                    {
                        int res = HMAC_Init_ex(ctx, salt, (int) salt_size, md_algo, NULL);

                        if (COMPILER_LIKELY(res == 1))
                        {
                            res = HMAC_Update(ctx, data, data_size);

                            if (COMPILER_LIKELY(res == 1))
                            {
                                unsigned int temp_out_size = EVP_MAX_MD_SIZE;

                                res = HMAC_Final(ctx, *out, &temp_out_size);

                                if (COMPILER_LIKELY(res == 1 &&
                                                    temp_out_size > 0))
                                {
                                  *out_size = temp_out_size;
                                  result = 0;
                                }
                            }
                        }

                        HMAC_CTX_free(ctx), ctx = NULL;
                    }
                    else
                    {
                        result = ENOMEM;
                    }
#else /* (OPENSSL_VERSION_NUMBER >= 0x10100000L) */
                    HMAC_CTX ctx;
                    HMAC_CTX_init(&ctx);

                    result = EIO;

                    int res = 1;

#if (OPENSSL_VERSION_NUMBER >= 0x10000000L)
                    res =
#endif
                        HMAC_Init(&ctx, salt, (int) salt_size, md_algo);

                    if (COMPILER_LIKELY(res == 1))
                    {
#if (OPENSSL_VERSION_NUMBER >= 0x10000000L)
                        res =
#endif
                            HMAC_Update(&ctx, data, data_size);

                        if (COMPILER_LIKELY(res == 1))
                        {
                            unsigned int temp_out_size = EVP_MAX_MD_SIZE;

#if (OPENSSL_VERSION_NUMBER >= 0x10000000L)
                            res =
#endif
                                HMAC_Final(&ctx, *out, &temp_out_size);

                            if (COMPILER_LIKELY(res == 1 &&
                                                temp_out_size > 0))
                            {
                                *out_size = temp_out_size;
                                result = 0;
                            }
                        }
                    }

                    HMAC_CTX_cleanup(&ctx);
#endif /* (OPENSSL_VERSION_NUMBER >= 0x10100000L) */
                }
                else
                {
                    result = E2BIG;
                }

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_FREE(*out);
                }
            }
            else
            {
                result = ENOMEM;
            }
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}

struct cgutils_crypto_hash_context
{
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    EVP_MD_CTX * ctx;
#else
    EVP_MD_CTX ctx;
#endif
};

void cgutils_crypto_hash_context_free(cgutils_crypto_hash_context * context)
{
    if (COMPILER_LIKELY(context != NULL))
    {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        EVP_MD_CTX_reset(context->ctx);
        EVP_MD_CTX_free(context->ctx);
#else
        EVP_MD_CTX_cleanup(&(context->ctx));
#endif
        CGUTILS_FREE(context);
    }
}

int cgutils_crypto_hash_context_finish(cgutils_crypto_hash_context * const context,
                                       void ** const out,
                                       size_t * const out_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(context != NULL && out != NULL && out_size != NULL))
    {
        result = ENOMEM;

        CGUTILS_MALLOC(*out, EVP_MAX_MD_SIZE, 1);

        if (COMPILER_LIKELY(*out != NULL))
        {
            unsigned int temp_out_size = EVP_MAX_MD_SIZE;
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
            int res = EVP_DigestFinal(context->ctx, *out, &temp_out_size);
#else
            int res = EVP_DigestFinal(&(context->ctx), *out, &temp_out_size);
#endif

            if (COMPILER_LIKELY(res == 1 &&
                                temp_out_size > 0))
            {
                *out_size = temp_out_size;
                result = 0;
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_FREE(*out);
            }
        }
    }

    return result;
}

int cgutils_crypto_hash_context_update(cgutils_crypto_hash_context * const context,
                                       void const * const data,
                                       size_t const data_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(context != NULL && data != NULL))
    {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        int res = EVP_DigestUpdate(context->ctx, data, data_size);
#else
        int res = EVP_DigestUpdate(&(context->ctx), data, data_size);
#endif

        if (COMPILER_LIKELY(res == 1))
        {
            result = 0;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_crypto_hash_context_init(cgutils_crypto_digest_algorithm const algorithm,
                                     cgutils_crypto_hash_context ** const out)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(algorithm > cgutils_crypto_digest_algorithm_none &&
                        algorithm < cgutils_crypto_digest_algorithm_max &&
                        out != NULL))
    {
        EVP_MD const * const md_algo = cgutils_crypto_get_digest(algorithm);

        result = ENOMEM;

        if (COMPILER_LIKELY(md_algo != NULL))
        {
            CGUTILS_ALLOCATE_STRUCT(*out);

            if (COMPILER_LIKELY(*out != NULL))
            {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
                (*out)->ctx = EVP_MD_CTX_new();

                if ((*out)->ctx != NULL)
                {
                    int res = EVP_DigestInit((*out)->ctx, md_algo);

                    if (COMPILER_LIKELY(res == 1))
                    {
                      result = 0;
                    }
                }
#else
                int res = EVP_DigestInit(&((*out)->ctx), md_algo);

                if (COMPILER_LIKELY(res == 1))
                {
                    result = 0;
                }
#endif
                if (COMPILER_UNLIKELY(result != 0))
                {
                    cgutils_crypto_hash_context_free(*out), *out = NULL;
                }
            }
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}

int cgutils_crypto_hash(void const * const data,
                        size_t const data_size,
                        cgutils_crypto_digest_algorithm const algorithm,
                        void ** const out,
                        size_t * const out_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(data != NULL &&
                        algorithm > cgutils_crypto_digest_algorithm_none &&
                        algorithm < cgutils_crypto_digest_algorithm_max &&
                        out != NULL))
    {
        EVP_MD const * const md_algo = cgutils_crypto_get_digest(algorithm);

        if (COMPILER_LIKELY(md_algo != NULL))
        {
            CGUTILS_MALLOC(*out, EVP_MAX_MD_SIZE, 1);

            if (COMPILER_LIKELY(*out != NULL))
            {
                if (COMPILER_LIKELY(data_size <= INT_MAX))
                {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
                    EVP_MD_CTX * ctx = EVP_MD_CTX_new();
                    if (COMPILER_LIKELY(ctx != NULL))
                    {
                        result = EIO;

                        int res = EVP_DigestInit(ctx, md_algo);

                        if (COMPILER_LIKELY(res == 1))
                        {
                            res = EVP_DigestUpdate(ctx, data, data_size);

                            if (COMPILER_LIKELY(res == 1))
                            {
                                unsigned int temp_out_size = EVP_MAX_MD_SIZE;

                                res = EVP_DigestFinal(ctx, *out, &temp_out_size);

                                if (COMPILER_LIKELY(res == 1 &&
                                                    temp_out_size > 0))
                                {
                                  *out_size = temp_out_size;
                                  result = 0;
                                }
                            }
                        }

                        EVP_MD_CTX_free(ctx), ctx = NULL;
                    }
                    else
                    {
                        result = ENOMEM;
                    }
#else
                    EVP_MD_CTX ctx;
                    result = EIO;

                    int res = EVP_DigestInit(&ctx, md_algo);

                    if (COMPILER_LIKELY(res == 1))
                    {
                        res = EVP_DigestUpdate(&ctx, data, data_size);

                        if (COMPILER_LIKELY(res == 1))
                        {
                            unsigned int temp_out_size = EVP_MAX_MD_SIZE;

                            res = EVP_DigestFinal(&ctx, *out, &temp_out_size);

                            if (COMPILER_LIKELY(res == 1 &&
                                                temp_out_size > 0))
                            {
                                *out_size = temp_out_size;
                                result = 0;
                            }
                        }
                    }

                    EVP_MD_CTX_cleanup(&ctx);
#endif
                }
                else
                {
                    result = E2BIG;
                }

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_FREE(*out);
                }
            }
            else
            {
                result = ENOMEM;
            }
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}

struct cgutils_crypto_cipher
{
    EVP_CIPHER const * cipher;
};

int cgutils_crypto_cipher_init(char const * const name,
                               cgutils_crypto_cipher ** const out)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(name != NULL && out != NULL))
    {
        EVP_CIPHER const * const cipher = EVP_get_cipherbyname(name);

        if (COMPILER_LIKELY(cipher != NULL))
        {
            CGUTILS_ALLOCATE_STRUCT(*out);

            if (COMPILER_LIKELY(*out != NULL))
            {
                result = 0;
                (*out)->cipher = cipher;
            }
            else
            {
                result = ENOMEM;
            }
        }
        else
        {
            result = ENOENT;
        }
    }

    return result;
}

void cgutils_crypto_cipher_free(cgutils_crypto_cipher * cipher)
{
    if (COMPILER_LIKELY(cipher != NULL))
    {
        cipher->cipher = NULL;
        CGUTILS_FREE(cipher);
    }
}

int cgutils_crypto_get_random_bytes(char * const out,
                                    size_t const out_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(out != NULL && out_size <= INT_MAX))
    {
        result = RAND_bytes((unsigned char *) out, (int) out_size);

        if (COMPILER_LIKELY(result == 1))
        {
            result = 0;
        }
        else
        {
            result = EIO;
        }
    }

    return result;
}

int cgutils_crypto_get_pseudo_random_bytes(char * const out,
                                           size_t const out_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(out != NULL && out_size <= INT_MAX))
    {
        result = RAND_pseudo_bytes((unsigned char *) out, (int) out_size);

        if (COMPILER_LIKELY(result == 1))
        {
            result = 0;
        }
        else if (result != 0)
        {
            result = EIO;
        }
    }

    return result;
}

struct cgutils_crypto_cipher_ctx
{
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    EVP_CIPHER_CTX * ctx;
#else
    EVP_CIPHER_CTX ctx;
#endif
    EVP_CIPHER const * cipher;
    EVP_MD * md;
    char * salt;
    size_t salt_size;
    size_t block_size;
    bool crypt;
};

size_t cgutils_crypto_get_pkcs5_salt_len(void)
{
    COMPILER_STATIC_ASSERT(PKCS5_SALT_LEN > 0 && PKCS5_SALT_LEN < INT_MAX,
                           "PKCS5_SALT_LEN value is not valid");

    size_t result = PKCS5_SALT_LEN;

    return result;
}

int cgutils_crypto_get_pkcs5_random_salt(char ** const out,
                                         size_t * const out_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(out != NULL && out_size != NULL))
    {
        *out_size = cgutils_crypto_get_pkcs5_salt_len();
        CGUTILS_MALLOC(*out, *out_size + 1, sizeof **out);

        if (COMPILER_LIKELY(*out != NULL))
        {
            assert(*out_size <= INT_MAX);

            result = cgutils_crypto_get_random_bytes(*out, *out_size);

            if (COMPILER_LIKELY(result == 0))
            {
                (*out)[*out_size] = '\0';
            }
            else
            {
                CGUTILS_FREE(*out);
            }
        }
        else
        {
            result = ENOMEM;
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            *out_size = 0;
        }
    }

    return result;
}

static int cgutils_crypto_cipher_get_iv_and_key_from_password(cgutils_crypto_cipher const * const cipher,
                                                              cgutils_crypto_digest_algorithm const md_algo,
                                                              char const * const salt,
                                                              char const * const password,
                                                              size_t const password_len,
                                                              size_t const key_iteration_count,
                                                              unsigned char ** const key,
                                                              unsigned char ** const iv)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(cipher != NULL &&
                        md_algo > cgutils_crypto_digest_algorithm_none &&
                        md_algo < cgutils_crypto_digest_algorithm_max &&
                        salt != NULL &&
                        password != NULL &&
                        password_len <= INT_MAX &&
                        key_iteration_count <= INT_MAX &&
                        key != NULL &&
                        iv != NULL))
    {
        EVP_MD const * const md = cgutils_crypto_get_digest(md_algo);

        if (COMPILER_LIKELY(md != NULL))
        {
            CGUTILS_MALLOC(*iv, EVP_MAX_IV_LENGTH, sizeof **iv);

            if (COMPILER_LIKELY(*iv != NULL))
            {
                CGUTILS_MALLOC(*key, EVP_MAX_KEY_LENGTH, sizeof **key);

                if (COMPILER_LIKELY(*key != NULL))
                {
                    /* EVP_BytesToKey returns the number of bytes of the generated key */
                    result = EVP_BytesToKey(cipher->cipher,
                                            md,
                                            (unsigned char *) salt,
                                            (unsigned char *) password,
                                            (int) password_len,
                                            (int) key_iteration_count,
                                            *key,
                                            *iv);

                    if (COMPILER_LIKELY(result > 0))
                    {
                        result = 0;
                    }
                    else
                    {
                        result = EIO;
                    }

                    if (COMPILER_UNLIKELY(result != 0))
                    {
                        CGUTILS_FREE(*key);
                    }
                }
                else
                {
                    result = ENOMEM;
                }

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_FREE(*iv);
                }
            }
            else
            {
                result = ENOMEM;
            }
        }
    }

    return result;
}

int cgutils_crypto_cipher_get_final_size(cgutils_crypto_cipher_ctx const * const ctx,
                                         size_t const data_size,
                                         size_t * const final_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(ctx != NULL && final_size != NULL))
    {
        result = 0;

        long unsigned const mode = EVP_CIPHER_mode(ctx->cipher);

        if (mode == EVP_CIPH_CBC_MODE ||
            mode == EVP_CIPH_ECB_MODE)
        {
            /* Padding */
            size_t remaining = data_size % ctx->block_size;

            *final_size = data_size + ctx->block_size - remaining;
        }
        else
        {
            /* No padding */
            *final_size = data_size;
        }
    }

    return result;
}

size_t cgutils_crypto_cipher_ctx_get_max_input_for_buffer(cgutils_crypto_cipher_ctx const * const ctx,
                                                          size_t const buffer_size)
{
    size_t result = 0;

    if (COMPILER_LIKELY(ctx != NULL && buffer_size > 0))
    {
        long unsigned const mode = EVP_CIPHER_mode(ctx->cipher);

        if (mode == EVP_CIPH_CBC_MODE ||
            mode == EVP_CIPH_ECB_MODE)
        {
            /* Padding */

            if (buffer_size > ctx->block_size)
            {
                result = buffer_size - ctx->block_size;
            }
            else
            {
                result = 0;
            }
        }
        else
        {
            /* No padding */
            result = buffer_size;
        }
    }

    return result;
}

size_t cgutils_crypto_cipher_ctx_buffer_size_for_input(cgutils_crypto_cipher_ctx const * const ctx,
                                                       size_t const input_size)
{
    size_t result = 0;

    if (COMPILER_LIKELY(ctx != NULL))
    {
        result = input_size + ctx->block_size;
    }

    return result;
}

static int cgutils_crypto_cipher_ctx_init_internal(cgutils_crypto_cipher const * const cipher,
                                                   cgutils_crypto_digest_algorithm const md_algo,
                                                   char const * const password,
                                                   size_t const password_len,
                                                   size_t const key_iteration_count,
                                                   bool const crypt,
                                                   char * salt,
                                                   size_t const salt_size,
                                                   cgutils_crypto_cipher_ctx ** const out)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(cipher != NULL &&
                        md_algo > cgutils_crypto_digest_algorithm_none &&
                        md_algo < cgutils_crypto_digest_algorithm_max &&
                        password != NULL &&
                        salt != NULL &&
                        out != NULL))
    {
        CGUTILS_ALLOCATE_STRUCT(*out);

        if (COMPILER_LIKELY(*out != NULL))
        {
            cgutils_crypto_cipher_ctx * this = *out;
            unsigned char * key = NULL;
            unsigned char * iv = NULL;
            this->salt = salt;
            salt = NULL;
            this->salt_size = salt_size;
            this->cipher = cipher->cipher;
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
            this->ctx = EVP_CIPHER_CTX_new();
            if (this->ctx != NULL)
            {
#endif

                result = cgutils_crypto_cipher_get_iv_and_key_from_password(cipher,
                                                                            md_algo,
                                                                            this->salt,
                                                                            password,
                                                                            password_len,
                                                                            key_iteration_count,
                                                                            &key,
                                                                            &iv);

                if (COMPILER_LIKELY(result == 0))
                {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
                    result = EVP_CipherInit(this->ctx,
                                            cipher->cipher,
                                            key,
                                            iv,
                                            crypt == true ? 1 : 0);
#else
                    result = EVP_CipherInit(&(this->ctx),
                                            cipher->cipher,
                                            key,
                                            iv,
                                            crypt == true ? 1 : 0);
#endif

                    if (COMPILER_LIKELY(result == 1))
                    {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
                        int const block_size = EVP_CIPHER_CTX_block_size(this->ctx);
#else
                        int const block_size = EVP_CIPHER_CTX_block_size(&(this->ctx));
#endif
                        assert(block_size >= 0);
                        this->block_size = (size_t) block_size;
                        result = 0;
                    }

                    CGUTILS_FREE(key);
                    CGUTILS_FREE(iv);
                }
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
            }
            else
            {
                result = ENOMEM;
            }
#endif
            if (COMPILER_UNLIKELY(result != 0))
            {
                cgutils_crypto_cipher_ctx_free(this), this = NULL;
                *out = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    if (COMPILER_UNLIKELY(result != 0 && salt != NULL))
    {
        CGUTILS_FREE(salt);
    }

    return result;
}

int cgutils_crypto_cipher_ctx_init_with_salt(cgutils_crypto_cipher const * const cipher,
                                             cgutils_crypto_digest_algorithm const md_algo,
                                             char const * const password,
                                             size_t const password_len,
                                             size_t const key_iteration_count,
                                             char const * const salt,
                                             size_t const salt_size,
                                             bool const crypt,
                                             cgutils_crypto_cipher_ctx ** const out)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(cipher != NULL &&
                        md_algo > cgutils_crypto_digest_algorithm_none &&
                        md_algo < cgutils_crypto_digest_algorithm_max &&
                        password != NULL &&
                        salt != NULL &&
                        out != NULL))
    {
        char * salt_allocated = cgutils_strndup(salt, salt_size);

        if (COMPILER_LIKELY(salt_allocated != NULL))
        {
            result = cgutils_crypto_cipher_ctx_init_internal(cipher,
                                                             md_algo,
                                                             password,
                                                             password_len,
                                                             key_iteration_count,
                                                             crypt,
                                                             salt_allocated,
                                                             salt_size,
                                                             out);
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_crypto_cipher_ctx_init(cgutils_crypto_cipher const * const cipher,
                                   cgutils_crypto_digest_algorithm const md_algo,
                                   char const * const password,
                                   size_t const password_len,
                                   size_t const key_iteration_count,
                                   bool const crypt,
                                   cgutils_crypto_cipher_ctx ** const out)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(cipher != NULL &&
                        md_algo > cgutils_crypto_digest_algorithm_none &&
                        md_algo < cgutils_crypto_digest_algorithm_max &&
                        password != NULL &&
                        out != NULL))
    {
        char * salt = NULL;
        size_t salt_size = 0;

        result = cgutils_crypto_get_pkcs5_random_salt(&salt,
                                                      &salt_size);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgutils_crypto_cipher_ctx_init_internal(cipher,
                                                             md_algo,
                                                             password,
                                                             password_len,
                                                             key_iteration_count,
                                                             crypt,
                                                             salt,
                                                             salt_size,
                                                             out);

        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_crypto_cipher_ctx_update(cgutils_crypto_cipher_ctx * const ctx,
                                     char const * const in,
                                     size_t const in_size,
                                     char ** const out,
                                     size_t * const out_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(ctx != NULL && in != NULL && in_size <= INT_MAX && out != NULL && out_size != NULL))
    {
        /* in_size + ctx->block_size - 1 is enough for encryption, but
           in_size + ctx->block_size is needed for decryption.
           Learned the hard way. */
        size_t const max_out_size = in_size + ctx->block_size;

        if (COMPILER_LIKELY(max_out_size <= INT_MAX))
        {
            CGUTILS_MALLOC(*out, max_out_size, sizeof **out);

            if (COMPILER_LIKELY(*out != NULL))
            {
                int temp_out_size = (int) max_out_size;

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
                int res = EVP_CipherUpdate(ctx->ctx,
#else
                int res = EVP_CipherUpdate(&(ctx->ctx),
#endif
                                           (unsigned char *) *out,
                                           &temp_out_size,
                                           (unsigned char const *) in,
                                           (int) in_size);

                if (COMPILER_LIKELY(res == 1 &&
                                    temp_out_size >= 0))
                {
                    result = 0;
                    *out_size = (size_t) temp_out_size;
                }
                else
                {
                    result = EIO;
                }

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_FREE(*out);
                    *out_size = 0;
                }
            }
            else
            {
                result = ENOMEM;
            }
        }
        else
        {
            result = E2BIG;
        }
    }

    return result;
}

int cgutils_crypto_cipher_ctx_finish(cgutils_crypto_cipher_ctx * const ctx,
                                     char ** const out,
                                     size_t * const out_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(ctx != NULL && out != NULL && out_size != NULL))
    {
        CGUTILS_MALLOC(*out, ctx->block_size, sizeof **out);

        if (COMPILER_LIKELY(*out != NULL))
        {
            assert(ctx->block_size <= INT_MAX);
            *out_size = ctx->block_size;
            int temp_size = (int) *out_size;

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
            result = EVP_CipherFinal(ctx->ctx,
#else
            result = EVP_CipherFinal(&(ctx->ctx),
#endif
                                     (unsigned char *) *out,
                                     &temp_size);

            if (COMPILER_LIKELY(result == 1 &&
                                temp_size >= 0))
            {
                *out_size = (size_t) temp_size;

                if (*out_size == 0)
                {
                    CGUTILS_FREE(*out);
                }

                result = 0;
            }
            else
            {
                CGUTILS_ERROR("EVP_CipherFinal failed with %d", result);
                result = EIO;
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_FREE(*out);
                *out_size = 0;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}


void cgutils_crypto_cipher_ctx_free(cgutils_crypto_cipher_ctx * ctx)
{
    if (COMPILER_LIKELY(ctx != NULL))
    {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        EVP_CIPHER_CTX_free(ctx->ctx), ctx->ctx = NULL;
#else
        EVP_CIPHER_CTX_cleanup(&(ctx->ctx));
#endif

        if (ctx->salt != NULL)
        {
            CGUTILS_FREE(ctx->salt);
        }

        ctx->salt_size = 0;
        ctx->block_size = 0;
        ctx->cipher = NULL;
        ctx->md = NULL;

        CGUTILS_FREE(ctx);
    }
}

struct cgutils_crypto_signature_context
{
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    EVP_MD_CTX * ctx;
#else
    EVP_MD_CTX ctx;
#endif
    cgutils_crypto_signature_action action;
};

typedef enum
{
    cgutils_crypto_pkey_type_public,
    cgutils_crypto_pkey_type_private
} cgutils_crypto_pkey_type;

struct cgutils_crypto_pkey
{
    EVP_PKEY * pkey;
    cgutils_crypto_pkey_type type;
};

size_t cgutils_crypto_pkey_get_size(cgutils_crypto_pkey const * const pkey)
{
    size_t result = 0;

    if (pkey != NULL && pkey->pkey != NULL)
    {
        result = (size_t) EVP_PKEY_size(pkey->pkey);
    }

    return result;
}

char const * cgutils_crypto_pkey_get_algo_str(cgutils_crypto_pkey const * const pkey)
{
    char const * result = NULL;

    if (pkey != NULL && pkey->pkey != NULL)
    {
        int const algo = EVP_PKEY_id(pkey->pkey);
        switch(algo)
        {
        case EVP_PKEY_RSA:
        case EVP_PKEY_RSA2:
            result = "RSA";
            break;
        case EVP_PKEY_DSA:
        case EVP_PKEY_DSA1:
        case EVP_PKEY_DSA2:
        case EVP_PKEY_DSA3:
        case EVP_PKEY_DSA4:
            result = "DSA";
            break;
        case EVP_PKEY_DH:
            result = "Diffie Hellman";
            break;
        };
    }

    return result;
}

void cgutils_crypto_pkey_print_infos(cgutils_crypto_pkey const * const pkey)
{
    if (pkey != NULL && pkey->pkey != NULL)
    {
        int const algo = EVP_PKEY_id(pkey->pkey);
        char const * algo_str = cgutils_crypto_pkey_get_algo_str(pkey);

        CGUTILS_INFO("PKEY type: %s",
                     pkey->type == cgutils_crypto_pkey_type_public ?
                     "Public" : "Private");

        if (algo_str != NULL)
        {
            CGUTILS_INFO("PKEY algo: %s", algo_str);
        }
        else
        {
            CGUTILS_INFO("PKEY algo is unknown, numeric type %d", algo);
        }

        CGUTILS_INFO("PKEY size: %zu", cgutils_crypto_pkey_get_size(pkey));
    }
    else
    {
        CGUTILS_INFO("NULL PKEY");
    }
}

int cgutils_crypto_public_key_init(char const * const file,
                                   cgutils_crypto_pkey ** const out)
{
    int result = EINVAL;

    if (file != NULL && out != NULL)
    {
        FILE * fp = NULL;

        result = cgutils_file_fopen(file,
                                    "rb",
                                    &fp);

        if (result == 0)
        {
            EVP_PKEY * pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

            if (pkey != NULL)
            {
                CGUTILS_ALLOCATE_STRUCT(*out);

                if (*out != NULL)
                {
                    (*out)->pkey = pkey;
                    (*out)->type = cgutils_crypto_pkey_type_public;
                    pkey = NULL;
                }
                else
                {
                    EVP_PKEY_free(pkey), pkey = NULL;
                    result = ENOMEM;
                }
            }
            else
            {
                result = EIO;
            }

            cgutils_file_fclose(fp), fp = NULL;
        }
    }

    return result;
}

int cgutils_crypto_private_key_init(char const * const file,
                                    cgutils_crypto_pkey ** const out)
{
    int result = EINVAL;

    if (file != NULL && out != NULL)
    {
        FILE * fp = NULL;

        result = cgutils_file_fopen(file,
                                    "rb",
                                    &fp);

        if (result == 0)
        {
            EVP_PKEY * pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);

            if (pkey != NULL)
            {
                CGUTILS_ALLOCATE_STRUCT(*out);

                if (*out != NULL)
                {
                    (*out)->pkey = pkey;
                    (*out)->type = cgutils_crypto_pkey_type_private;
                    pkey = NULL;
                }
                else
                {
                    EVP_PKEY_free(pkey), pkey = NULL;
                    result = ENOMEM;
                }
            }
            else
            {
                result = EIO;
            }

            cgutils_file_fclose(fp), fp = NULL;
        }
    }

    return result;
}

void cgutils_crypto_pkey_free(cgutils_crypto_pkey * pkey)
{
    if (pkey != NULL)
    {
        if (pkey->pkey != NULL)
        {
            EVP_PKEY_free(pkey->pkey), pkey->pkey = NULL;
        }

        CGUTILS_FREE(pkey);
    }
}

void cgutils_crypto_signature_context_free(cgutils_crypto_signature_context * context)
{
    if (context != NULL)
    {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        EVP_MD_CTX_free(context->ctx), context->ctx = NULL;
#else
        EVP_MD_CTX_cleanup(&(context->ctx));
#endif
        CGUTILS_FREE(context);
    }
}

int cgutils_crypto_signature_context_verify_final(cgutils_crypto_signature_context * const context,
                                                  char const * const signature,
                                                  size_t const signature_len,
                                                  cgutils_crypto_pkey const * const pkey,
                                                  bool * const valid)
{
    int result = EINVAL;

    if (context != NULL &&
        context->action == cgutils_crypto_signature_action_verify &&
        signature != NULL &&
        signature_len > 0 &&
        signature_len <= UINT_MAX &&
        pkey != NULL &&
        pkey->type == cgutils_crypto_pkey_type_public &&
        valid != NULL)
    {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        result = EVP_VerifyFinal(context->ctx,
                                 (unsigned char *) signature,
                                 (unsigned int) signature_len,
                                 pkey->pkey);
#else
        result = EVP_VerifyFinal(&(context->ctx),
                                 (unsigned char *) signature,
                                 (unsigned int) signature_len,
                                 pkey->pkey);
#endif
        if (result == 1)
        {
            result = 0;
            *valid = true;
        }
        else
        {
            result = 0;
            *valid = false;
        }
    }

    return result;
}

int cgutils_crypto_signature_context_sign_final(cgutils_crypto_signature_context * const context,
                                                char ** const signature,
                                                size_t * const signature_len,
                                                cgutils_crypto_pkey const * const pkey)
{
    int result = EINVAL;

    if (context != NULL && context->action == cgutils_crypto_signature_action_sign &&
        signature != NULL &&
        signature_len != NULL &&
        pkey != NULL && pkey->type == cgutils_crypto_pkey_type_private)
    {
        int const key_size = EVP_PKEY_size(pkey->pkey);

        if (key_size > 0)
        {
            CGUTILS_MALLOC(*signature, (size_t) key_size, sizeof **signature);

            if (*signature != NULL)
            {
                unsigned int written = (unsigned int) key_size;

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
                result = EVP_SignFinal(context->ctx,
                                       (unsigned char *) *signature,
                                       &written,
                                       pkey->pkey);
#else
                result = EVP_SignFinal(&(context->ctx),
                                       (unsigned char *) *signature,
                                       &written,
                                       pkey->pkey);
#endif

                if (result == 1)
                {
                    result = 0;
                    *signature_len = (size_t) written;
                }
                else
                {
                    result = EIO;
                }

                if (result != 0)
                {
                    CGUTILS_FREE(*signature);
                    *signature_len = 0;
                }
            }
            else
            {
                result = ENOMEM;
            }
        }
    }

    return result;
}

int cgutils_crypto_signature_context_update(cgutils_crypto_signature_context * const context,
                                            void const * const data,
                                            size_t const data_size)
{
    int result = EINVAL;

    if (context != NULL && data != NULL && data_size <= UINT_MAX)
    {
        int res = 0;

        if (context->action == cgutils_crypto_signature_action_verify)
        {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
            res = EVP_VerifyUpdate(context->ctx, data, data_size);
#else
            res = EVP_VerifyUpdate(&(context->ctx), data, data_size);
#endif
        }
        else
        {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
            res = EVP_SignUpdate(context->ctx, data, data_size);
#else
            res = EVP_SignUpdate(&(context->ctx), data, data_size);
#endif
        }

        if (res == 1)
        {
            result = 0;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_crypto_signature_context_init(cgutils_crypto_digest_algorithm const algo,
                                          cgutils_crypto_signature_action const action,
                                          cgutils_crypto_signature_context ** const out)
{
    int result = EINVAL;

    if (algo > cgutils_crypto_digest_algorithm_none &&
        algo < cgutils_crypto_digest_algorithm_max &&
        out != NULL)
    {
        EVP_MD const * const md_algo = cgutils_crypto_get_digest(algo);

        if (md_algo != NULL)
        {
            CGUTILS_ALLOCATE_STRUCT(*out);

            if (*out != NULL)
            {
                int res = 0;

                if (action == cgutils_crypto_signature_action_verify)
                {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
                    (*out)->ctx = EVP_MD_CTX_new();

                    if ((*out)->ctx != NULL)
                    {
                        res = EVP_VerifyInit((*out)->ctx, md_algo);
                    }
                    else
                    {
                        result = ENOMEM;
                    }
#else
                    res = EVP_VerifyInit(&((*out)->ctx), md_algo);
#endif
                }
                else
                {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
                    (*out)->ctx = EVP_MD_CTX_new();

                    if ((*out)->ctx != NULL)
                    {
                        res = EVP_SignInit((*out)->ctx, md_algo);
                    }
                    else
                    {
                        result = ENOMEM;
                    }
#else
                    res = EVP_SignInit(&((*out)->ctx), md_algo);
#endif
                }

                if (res == 1)
                {
                    (*out)->action = action;
                    result = 0;
                }

                if (result != 0)
                {
                    cgutils_crypto_signature_context_free(*out), *out = NULL;
                }
            }
            else
            {
                result = ENOMEM;
            }
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}
