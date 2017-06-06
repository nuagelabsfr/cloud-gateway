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

#ifndef CLOUD_UTILS_CRYPTO_H_
#define CLOUD_UTILS_CRYPTO_H_

/* contains crypto functions */

/* _init should be called before initializing any other library
   which may use OpenSSL.
   _destroy after calling destructor for all libraries which
   may use OpenSSL.
*/

typedef struct cgutils_crypto_hash_context cgutils_crypto_hash_context;
typedef struct cgutils_crypto_cipher cgutils_crypto_cipher;
typedef struct cgutils_crypto_md cgutils_crypto_md;
typedef struct cgutils_crypto_pkey cgutils_crypto_pkey;
typedef struct cgutils_crypto_cipher_ctx cgutils_crypto_cipher_ctx;
typedef struct cgutils_crypto_signature_context cgutils_crypto_signature_context;

typedef enum
{
    cgutils_crypto_signature_action_verify,
    cgutils_crypto_signature_action_sign,
} cgutils_crypto_signature_action;

typedef enum
{
    cgutils_crypto_digest_algorithm_none = 0,
#define DIGEST(name, value) cgutils_crypto_digest_algorithm_ ## value,
#include <cloudutils/cloudutils_crypto_digests.itm>
#undef DIGEST
    cgutils_crypto_digest_algorithm_max
} cgutils_crypto_digest_algorithm;

#include <stdbool.h>
#include <stddef.h>

#include <cloudutils/cloudutils_compiler_specifics.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_crypto_init(void);
void cgutils_crypto_atfork(void);
void cgutils_crypto_destroy(void);

cgutils_crypto_digest_algorithm cgutils_crypto_digest_algorithm_from_str(char const *);

int cgutils_crypto_hmac(void const * salt,
                        size_t salt_size,
                        void const * data,
                        size_t data_size,
                        cgutils_crypto_digest_algorithm algorithm,
                        void ** out,
                        size_t * out_size);

int cgutils_crypto_hash(void const * data,
                        size_t data_size,
                        cgutils_crypto_digest_algorithm algorithm,
                        void ** out,
                        size_t * out_size);

void cgutils_crypto_hash_context_free(cgutils_crypto_hash_context * context);

int cgutils_crypto_hash_context_finish(cgutils_crypto_hash_context * context,
                                       void ** out,
                                       size_t * out_size);

int cgutils_crypto_hash_context_update(cgutils_crypto_hash_context * context,
                                       void const * data,
                                       size_t data_size);

int cgutils_crypto_hash_context_init(cgutils_crypto_digest_algorithm algorithm,
                                     cgutils_crypto_hash_context ** out);

int cgutils_crypto_get_random_bytes(char * out,
                                    size_t out_size);

int cgutils_crypto_get_pseudo_random_bytes(char * out,
                                           size_t out_size);

int cgutils_crypto_get_pkcs5_random_salt(char ** out,
                                         size_t * out_size);

size_t cgutils_crypto_get_pkcs5_salt_len(void) COMPILER_CONST_FUNCTION;

int cgutils_crypto_cipher_init(char const * name,
                               cgutils_crypto_cipher ** out);
void cgutils_crypto_cipher_free(cgutils_crypto_cipher * md);

int cgutils_crypto_cipher_ctx_init(cgutils_crypto_cipher const * cipher,
                                   cgutils_crypto_digest_algorithm md_algo,
                                   char const * password,
                                   size_t password_len,
                                   size_t key_iteration_count,
                                   bool crypt,
                                   cgutils_crypto_cipher_ctx ** out);

int cgutils_crypto_cipher_ctx_init_with_salt(cgutils_crypto_cipher const * cipher,
                                             cgutils_crypto_digest_algorithm md_algo,
                                             char const * password,
                                             size_t password_len,
                                             size_t key_iteration_count,
                                             char const * salt,
                                             size_t salt_size,
                                             bool crypt,
                                             cgutils_crypto_cipher_ctx ** out);

int cgutils_crypto_cipher_ctx_update(cgutils_crypto_cipher_ctx * ctx,
                                     char const * in,
                                     size_t in_size,
                                     char ** out,
                                     size_t * out_size);

void cgutils_crypto_cipher_ctx_free(cgutils_crypto_cipher_ctx * ctx);

int cgutils_crypto_cipher_get_final_size(cgutils_crypto_cipher_ctx const * ctx,
                                         size_t data_size,
                                         size_t * final_size);

size_t cgutils_crypto_cipher_ctx_get_max_input_for_buffer(cgutils_crypto_cipher_ctx const * ctx,
                                                          size_t buffer_size) COMPILER_PURE_FUNCTION;

size_t cgutils_crypto_cipher_ctx_buffer_size_for_input(cgutils_crypto_cipher_ctx const * ctx,
                                                       size_t input_size) COMPILER_PURE_FUNCTION;

int cgutils_crypto_cipher_ctx_finish(cgutils_crypto_cipher_ctx * ctx,
                                     char ** out,
                                     size_t * out_size);

int cgutils_crypto_public_key_init(char const * file,
                                   cgutils_crypto_pkey ** out);

int cgutils_crypto_private_key_init(char const * file,
                                    cgutils_crypto_pkey ** out);

size_t cgutils_crypto_pkey_get_size(cgutils_crypto_pkey const * pkey);

char const * cgutils_crypto_pkey_get_algo_str(cgutils_crypto_pkey const * pkey);

void const * cgutils_crypto_pkey_get_bytes(cgutils_crypto_pkey const * pkey);

void cgutils_crypto_pkey_print_infos(cgutils_crypto_pkey const * pkey);
void cgutils_crypto_pkey_free(cgutils_crypto_pkey * pkey);

void cgutils_crypto_signature_context_free(cgutils_crypto_signature_context * context);

int cgutils_crypto_signature_context_verify_final(cgutils_crypto_signature_context * context,
                                                  char const * signature,
                                                  size_t signature_len,
                                                  cgutils_crypto_pkey const * pubkey,
                                                  bool * valid);

int cgutils_crypto_signature_context_sign_final(cgutils_crypto_signature_context * context,
                                                  char ** signature,
                                                  size_t * signature_len,
                                                  cgutils_crypto_pkey const * privkey);

int cgutils_crypto_signature_context_update(cgutils_crypto_signature_context * context,
                                            void const * data,
                                            size_t data_size);

int cgutils_crypto_signature_context_init(cgutils_crypto_digest_algorithm md_algo,
                                          cgutils_crypto_signature_action action,
                                          cgutils_crypto_signature_context ** out);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_CRYPTO_H_ */
