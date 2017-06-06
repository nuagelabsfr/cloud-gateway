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
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <openssl/bio.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "cloudutils/cloudutils.h"
#include "cloudutils/cloudutils_encoding.h"

static int cgutils_fill_buffer_from_BUF_MEM(BUF_MEM * const buff,
                                            void ** const buffer,
                                            size_t * const buffer_size)
{
    assert(buff != NULL);
    assert(buffer != NULL);
    assert(buffer_size != NULL);

    size_t const buff_len = buff->length;

    int result = 0;

    if (COMPILER_LIKELY(buff_len > 0))
    {
        *buffer_size = buff_len;
        CGUTILS_MALLOC(*buffer, *buffer_size + 1, 1);

        if (COMPILER_LIKELY(*buffer != NULL))
        {
            memcpy(*buffer, buff->data, *buffer_size);
            (*(char**)buffer)[*buffer_size] = '\0';
            result = 0;
        }
        else
        {
            result = ENOMEM;
        }
    }
    else
    {
        result = EIO;
    }

    return result;
}

static int cgutils_fill_buffer_from_mem_bio(BIO * const bio,
                                            void ** const buffer,
                                            size_t * const buffer_size)
{
    assert(bio != NULL);
    assert(buffer != NULL);
    assert(buffer_size != NULL);

    int result = 0;
    BUF_MEM * tmp_buff = NULL;

    BIO_get_mem_ptr(bio, &tmp_buff);

    if (COMPILER_LIKELY(tmp_buff != NULL))
    {
        result = cgutils_fill_buffer_from_BUF_MEM(tmp_buff,
                                                  buffer,
                                                  buffer_size);
    }
    else
    {
        result = EIO;
    }

    return result;
}

static int cgutils_fill_buffer_from_bio(BIO * const bio,
                                        void ** const buffer,
                                        size_t * const buffer_size)
{
    assert(bio != NULL);
    assert(buffer != NULL);
    assert(buffer_size != NULL);

    int result = 0;
    BUF_MEM * buf = BUF_MEM_new();

    if (COMPILER_LIKELY(buf != NULL))
    {
        int res = 0;
        size_t pos = 0;

        do
        {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
            size_t grow = BUF_MEM_grow(buf, buf->max + BUFSIZ);
#else
            int grow = BUF_MEM_grow(buf, buf->max + BUFSIZ);
#endif

            if (COMPILER_LIKELY(grow > 0))
            {
                res = BIO_read(bio, &(buf->data[pos]), BUFSIZ);

                if (COMPILER_LIKELY(res > 0))
                {
                    pos += (size_t) res;
                }
            }
            else
            {
                result = ENOMEM;
            }
        }
        while (res > 0 && result == 0);

        if (COMPILER_LIKELY(result == 0))
        {
            buf->length = pos;
            result = cgutils_fill_buffer_from_BUF_MEM(buf, buffer, buffer_size);
        }

        BUF_MEM_free(buf), buf = NULL;
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

int cgutils_encoding_base64_encode(void const * const data,
                                   size_t const data_size,
                                   void ** const out,
                                   size_t * const out_size)
{
    int result = 0;

    if (COMPILER_LIKELY(data != NULL &&
                        out != NULL &&
                        out_size != NULL &&
                        data_size < INT_MAX))
    {
        BIO * memory_bio = BIO_new(BIO_s_mem());

        if (COMPILER_LIKELY(memory_bio != NULL))
        {
            BIO * b64_bio = BIO_new(BIO_f_base64());

            if (COMPILER_LIKELY(b64_bio != NULL))
            {
                BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

                if (COMPILER_LIKELY(BIO_push(b64_bio, memory_bio) != NULL))
                {
                    int res = BIO_write(b64_bio, data, (int)data_size);

                    if (COMPILER_LIKELY(res == (int)data_size))
                    {
                        res = BIO_flush(b64_bio);

                        if (COMPILER_LIKELY(res == 1))
                        {
                            result = cgutils_fill_buffer_from_mem_bio(b64_bio,
                                                                      out,
                                                                      out_size);

                            if (COMPILER_LIKELY(result == 0))
                            {
                                /* OpenSSL encoding adds a '\n' at the end of encoded data,
                                 but not with the NO_NL option set. */
                                /* (*out_size)--;
                                ((char *) *out)[*out_size] = '\0'; */
                            }
                        }
                        else
                        {
                            result = EIO;
                        }
                    }
                    else
                    {
                        result = EIO;
                    }
                }
                else
                {
                    result = ENOMEM;
                }

                BIO_free(b64_bio);
                b64_bio = NULL;
            }
            else
            {
                result = ENOMEM;
            }

            BIO_free(memory_bio), memory_bio = NULL;
        }
        else
        {
            result = ENOMEM;
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgutils_encoding_base64_decode(void const * const data,
                                   size_t const data_size,
                                   void ** const out,
                                   size_t * const out_size)
{
    int result = 0;

    if (COMPILER_LIKELY(data != NULL &&
                        out != NULL &&
                        out_size != NULL &&
                        data_size < INT_MAX))
    {
        BIO * memory_in_bio = BIO_new_mem_buf((void*)data, (int)data_size);

        if (COMPILER_LIKELY(memory_in_bio != NULL))
        {
            BIO * b64_bio = BIO_new(BIO_f_base64());

            if (COMPILER_LIKELY(b64_bio != NULL))
            {
                BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

                if (COMPILER_LIKELY(BIO_push(b64_bio, memory_in_bio) != NULL))
                {
                    int res = BIO_flush(memory_in_bio);

                    if (COMPILER_LIKELY(res == 1))
                    {
                        result = cgutils_fill_buffer_from_bio(b64_bio, out, out_size);
                    }
                    else
                    {
                        result = EIO;
                    }
                }
                else
                {
                    result = ENOMEM;
                }

                BIO_free(b64_bio), b64_bio = NULL;
            }
            else
            {
                result = ENOMEM;
            }

            BIO_free(memory_in_bio), memory_in_bio = NULL;
        }
        else
        {
            result = ENOMEM;
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgutils_encoding_hex_sprint(void const * const data,
                               size_t const data_size,
                               char ** const out,
                               size_t * const out_size)
{
    int result = EINVAL;

    if (data != NULL && out != NULL && out_size != NULL && data_size < (SIZE_MAX / 2))
    {
        *out_size = data_size * 2 + 1;
        CGUTILS_MALLOC(*out, *out_size, 1);

        if (*out != NULL)
        {
            result = 0;
            for(size_t idx = 0; idx < data_size; idx++)
            {
                sprintf(&((*out)[idx*2]), "%02x", *((uint8_t *)data + idx));
            }
            (*out)[data_size*2] = '\0';
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}
