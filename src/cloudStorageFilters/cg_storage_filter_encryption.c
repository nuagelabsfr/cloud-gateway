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
#include <string.h>

#include <cgsm/cg_storage_filter_backend.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_crypto.h>

typedef struct
{
    cgutils_crypto_cipher * cipher;
    cgutils_crypto_digest_algorithm md;
    char * password;
    size_t key_iteration_count;
    size_t password_len;
} cg_storage_filter_encryption_data;

typedef struct
{
    cg_storage_filter_encryption_data * data;
    cgutils_crypto_cipher_ctx * ctx;
    char * salt;
    size_t salt_size;
    size_t got_salt_size;
    cg_storage_filter_mode mode;
    bool salt_sent;
} cg_storage_filter_encryption_ctx;

static void cg_storage_filter_encryption_free(void * data)
{
    if (data != NULL)
    {
        cg_storage_filter_encryption_data * this = data;

        if (this->cipher != NULL)
        {
            cgutils_crypto_cipher_free(this->cipher), this->cipher = NULL;
        }

        if (this->password != NULL)
        {
            CGUTILS_FREE(this->password);
        }

        this->key_iteration_count = 0;
        this->password_len = 0;

        CGUTILS_FREE(this);
    }
}

static int cg_storage_filter_encryption_cipher_init(char const * const cipher_name,
                                                    cgutils_crypto_cipher ** const cipher)
{
    static char const * const allowed_ciphers[] =
        {
#define CIPHER(str) str,
#include "cg_storage_filter_encryption_ciphers.itm"
#undef CIPHER
        };
    static size_t const allowed_ciphers_count = sizeof allowed_ciphers / sizeof *allowed_ciphers;

    int result = ENOENT;

    assert(cipher_name != NULL);
    assert(cipher != NULL);

    for (size_t idx = 0;
         result == ENOENT &&
             idx < allowed_ciphers_count;
         idx++)
    {
        if (strcmp(cipher_name, allowed_ciphers[idx]) == 0)
        {
            result = 0;
        }
    }

    if (result == 0)
    {
        result = cgutils_crypto_cipher_init(cipher_name,
                                            cipher);
    }
    else
    {
        CGUTILS_ERROR("Error, requested cipher %s does not exist or is not allowed. "
                      "Only strong, CBC and CTR ciphers are supported. Full list available in the documentation.",
                      cipher_name);
    }

    return result;
}

static int cg_storage_filter_encryption_init(cgutils_configuration const * const specifics,
                                             void ** const data)
{
    int result = EINVAL;

    if (specifics != NULL && data != NULL)
    {
        char * cipher_name = NULL;
        char * digest_name = NULL;
        char * password = NULL;
        uint64_t key_iteration_count = 0;

        result = 0;

#define STRING_PARAMETER(storage, path, required)                       \
        if (result == 0)                                                \
        {                                                               \
            result = cgutils_configuration_get_string(specifics,        \
                                                      path,             \
                                                      &(storage));      \
            if (result == ENOENT && required == false)                  \
            {                                                           \
                result = 0;                                             \
                storage = NULL;                                         \
            }                                                           \
            else if (result != 0)                                       \
            {                                                           \
                CGUTILS_ERROR("Required parameter [%s] not found.",     \
                              path);                                    \
            }                                                           \
        }
#define UNSIGNED_INTEGER_PARAMETER(storage, path, required)             \
        if (result == 0)                                                \
        {                                                               \
            result = cgutils_configuration_get_unsigned_integer(specifics, \
                                                                path,   \
                                                                &(storage)); \
            if (result == ENOENT && required == false)                  \
            {                                                           \
                result = 0;                                             \
            }                                                           \
            else if (result != 0)                                       \
            {                                                           \
                CGUTILS_ERROR("Required parameter [%s] not found.",     \
                              path);                                    \
            }                                                           \
        }
#include "cg_storage_filter_encryption_parameters.itm"
#undef UNSIGNED_INTEGER_PARAMETER
#undef STRING_PARAMETER

        if (result == 0)
        {
            cgutils_crypto_cipher * cipher = NULL;

            result = cg_storage_filter_encryption_cipher_init(cipher_name,
                                                              &cipher);

            if (result == 0)
            {
                cgutils_crypto_digest_algorithm md = cgutils_crypto_digest_algorithm_from_str(digest_name);

                if (md != cgutils_crypto_digest_algorithm_none)
                {
                    cg_storage_filter_encryption_data * this = NULL;

                    CGUTILS_ALLOCATE_STRUCT(this);

                    if (this != NULL)
                    {
                        this->cipher = cipher;
                        cipher = NULL;
                        this->md = md;
                        this->password = password;
                        password = NULL;
                        this->password_len = strlen(this->password);
                        this->key_iteration_count = key_iteration_count;

                        *data = this;
                    }
                    else
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Error allocating memory for encryption filter data: %d",
                                      result);
                    }

                }
                else
                {
                    result = ENOENT;
                    CGUTILS_ERROR("Error loading message digest %s: %d",
                                  digest_name,
                                  result);
                }

                if (result != 0 && cipher != NULL)
                {
                    cgutils_crypto_cipher_free(cipher), cipher = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error loading message cipher %s: %d",
                              cipher_name,
                              result);
            }
        }

        if (cipher_name != NULL)
        {
            CGUTILS_FREE(cipher_name);
        }

        if (digest_name != NULL)
        {
            CGUTILS_FREE(digest_name);
        }

        if (password != NULL)
        {
                CGUTILS_FREE(password);
        }
    }

    return result;
}

static int cg_storage_filter_encryption_context_init(void * const data,
                                                     cg_storage_filter_mode const mode,
                                                     void ** const ctx_out)
{
    int result = EINVAL;

    if (data != NULL && ctx_out != NULL)
    {
        cg_storage_filter_encryption_data * const this = data;
        char * salt = NULL;
        size_t salt_size = 0;
        size_t got_salt_size = 0;
        cgutils_crypto_cipher_ctx * cipher_ctx = NULL;

        result = 0;

        if (mode == cg_storage_filter_enc)
        {
            result = cgutils_crypto_get_pkcs5_random_salt(&salt,
                                                          &salt_size);

            if (result == 0)
            {
                got_salt_size = salt_size;

                result = cgutils_crypto_cipher_ctx_init_with_salt(this->cipher,
                                                                  this->md,
                                                                  this->password,
                                                                  this->password_len,
                                                                  this->key_iteration_count,
                                                                  salt,
                                                                  salt_size,
                                                                  true,
                                                                  &cipher_ctx);

                if (result == 0)
                {
                    assert(cipher_ctx != NULL);
                }
                else
                {
                    CGUTILS_ERROR("Error getting a crypto cipher ctx: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting a salt: %d", result);
            }
        }
        else
        {
            salt_size = cgutils_crypto_get_pkcs5_salt_len();

            CGUTILS_MALLOC(salt, salt_size, sizeof *salt);

            if (salt == NULL)
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for salt: %d", result);
            }
        }

        if (result == 0)
        {
            cg_storage_filter_encryption_ctx * ctx = NULL;

            CGUTILS_ALLOCATE_STRUCT(ctx);

            if (ctx != NULL)
            {
                ctx->data = this;
                ctx->ctx = cipher_ctx;
                cipher_ctx = NULL;
                ctx->salt = salt;
                salt = NULL;
                ctx->salt_size = salt_size;
                ctx->got_salt_size = got_salt_size;
                ctx->mode = mode;

                *ctx_out = ctx;
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for storage filter encryption ctx: %d",
                              result);
            }
        }

        if (result != 0)
        {
            if (cipher_ctx != NULL)
            {
                cgutils_crypto_cipher_ctx_free(cipher_ctx), cipher_ctx = NULL;
            }

            if (salt != NULL)
            {
                CGUTILS_FREE(salt);
                salt_size = 0;
            }
        }
    }

    return result;
}

static void cg_storage_filter_encryption_context_free(void * ctx)
{
    if (ctx != NULL)
    {
        cg_storage_filter_encryption_ctx * this = ctx;

        if (this->ctx != NULL)
        {
            cgutils_crypto_cipher_ctx_free(this->ctx), this->ctx = NULL;
        }

        if (this->salt != NULL)
        {
            CGUTILS_FREE(this->salt);
        }

        this->data = NULL;
        this->salt_size = 0;
        this->got_salt_size = 0;

        CGUTILS_FREE(this);
    }
}

static int cg_storage_filter_encryption_context_finish(void * const ctx,
                                                       char ** const out,
                                                       size_t * const out_size)
{
    int result = EINVAL;

    if (ctx != NULL && out != NULL && out_size != NULL)
    {
        cg_storage_filter_encryption_ctx * this = ctx;

        if (this->ctx != NULL)
        {
            result = cgutils_crypto_cipher_ctx_finish(this->ctx, out, out_size);
        }
        else
        {
            *out_size = 0;
            *out = NULL;
            result = 0;
        }
    }
    else
    {
        CGUTILS_ERROR("Called with %p, %p, %p", ctx, out, out_size);
    }

    return result;
}

static int cg_storage_filter_encryption_context_do(void * const ctx,
                                                   char const * in,
                                                   size_t in_size,
                                                   char ** const out,
                                                   size_t * const out_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(ctx != NULL && in != NULL && out != NULL && out_size != NULL))
    {
        cg_storage_filter_encryption_ctx * this = ctx;
        size_t const total_salt_size = this->salt_size;

        result = 0;

        if (COMPILER_UNLIKELY(this->mode == cg_storage_filter_dec &&
                              this->got_salt_size < total_salt_size))
        {
            /* We need to read more of the salt */
            size_t const need = total_salt_size - this->got_salt_size;
            size_t got = in_size > need ? need : in_size;
            assert(this->salt != NULL);

            memcpy(this->salt + this->got_salt_size,
                   in,
                   got);
            this->got_salt_size += got;
            in += got;
            in_size -= got;

            if (this->got_salt_size == this->salt_size)
            {
                result = cgutils_crypto_cipher_ctx_init_with_salt(this->data->cipher,
                                                                  this->data->md,
                                                                  this->data->password,
                                                                  this->data->password_len,
                                                                  this->data->key_iteration_count,
                                                                  this->salt,
                                                                  this->salt_size,
                                                                  false,
                                                                  &(this->ctx));

                if (COMPILER_LIKELY(result == 0))
                {
                    assert(this->ctx != NULL);
                }
                else
                {
                    CGUTILS_ERROR("Error getting a crypto cipher ctx: %d", result);
                }
            }
        }

        if (COMPILER_LIKELY(result == 0 &&
                            in_size > 0))
        {
            assert(this->ctx != NULL);

            result = cgutils_crypto_cipher_ctx_update(this->ctx,
                                                      in,
                                                      in_size,
                                                      out,
                                                      out_size);

            if (COMPILER_LIKELY(result == 0))
            {
                if (COMPILER_UNLIKELY(this->mode == cg_storage_filter_enc &&
                                      this->salt_sent == false))
                {
                    assert(SIZE_MAX - this->salt_size >= *out_size);

                    char * new_out = NULL;
                    size_t const new_out_size = *out_size + this->salt_size;

                    CGUTILS_MALLOC(new_out, new_out_size, sizeof *new_out);

                    if (COMPILER_LIKELY(new_out != NULL))
                    {
                        memcpy(new_out, this->salt, this->salt_size);
                        memcpy(new_out + this->salt_size, *out, *out_size);
                        CGUTILS_FREE(*out);
                        *out = new_out;
                        new_out = NULL;
                        *out_size = new_out_size;
                        this->salt_sent = true;
                    }
                    else
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Error allocating memory for salt+output: %d", result);
                    }
                }
            }
            else
            {
                CGUTILS_ERROR("Error doing cipher ctx update: %d", result);
            }
        }

        if (COMPILER_UNLIKELY(result != 0 && *out != NULL))
        {
            CGUTILS_FREE(*out);
            *out_size = 0;
        }
    }

    return result;
}

static size_t cg_storage_filter_encryption_max_input_for_buffer(void * const ctx,
                                                                size_t const buffer_size)
{
    size_t result = 0;

    if (ctx != NULL && buffer_size > 0)
    {
        cg_storage_filter_encryption_ctx * this = ctx;

        result = cgutils_crypto_cipher_ctx_get_max_input_for_buffer(this->ctx,
                                                                    buffer_size);

        if (this->mode == cg_storage_filter_enc && this->salt_sent == false)
        {
            if (result > this->salt_size)
            {
                result -= this->salt_size;
            }
            else
            {
                result = 0;
            }
        }
    }

    return result;
}

static int cg_storage_filter_encryption_get_max_final_size(void * const ctx,
                                                           size_t const in_size,
                                                           size_t * const out_size)
{
    int result = EINVAL;

    if (ctx != NULL)
    {
        cg_storage_filter_encryption_ctx * this = ctx;

        result = cgutils_crypto_cipher_get_final_size(this->ctx,
                                                      in_size,
                                                      out_size);

        if (this->mode == cg_storage_filter_enc &&
            this->salt_sent == false)
        {
            *out_size += this->salt_size;
        }
    }

    return result;
}

static cg_storage_filter_type cg_storage_filter_encryption_get_type(void const * const data)
{
    (void) data;

    return cg_storage_filter_type_encryption;
}

COMPILER_BLOCK_VISIBILITY_DEFAULT

extern cg_storage_filter_ops const cg_storage_filter_encryption_ops;

cg_storage_filter_ops const cg_storage_filter_encryption_ops =
{
    .init = &cg_storage_filter_encryption_init,
    .get_type = &cg_storage_filter_encryption_get_type,
    .init_context = &cg_storage_filter_encryption_context_init,
    .do_filter = &cg_storage_filter_encryption_context_do,
    .max_input_for_buffer = &cg_storage_filter_encryption_max_input_for_buffer,
    .get_max_final_size = &cg_storage_filter_encryption_get_max_final_size,
    .finish = &cg_storage_filter_encryption_context_finish,
    .free_context = &cg_storage_filter_encryption_context_free,
    .free = &cg_storage_filter_encryption_free,
    .predictable_output_size = true,
};

COMPILER_BLOCK_VISIBILITY_END
