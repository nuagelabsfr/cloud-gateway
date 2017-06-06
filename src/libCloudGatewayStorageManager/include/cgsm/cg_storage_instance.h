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

#ifndef CLOUD_GATEWAY_STORAGE_INSTANCE_H_
#define CLOUD_GATEWAY_STORAGE_INSTANCE_H_

typedef struct cg_storage_instance cg_storage_instance;

typedef enum
{
#define STATUS(value) cg_storage_instance_status_ ## value,
#include <cgsm/cg_storage_instance_status.itm>
#undef STATUS
    cg_storage_instance_status_count
} cg_storage_instance_status;

#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_crypto.h>

typedef struct
{
    void * digest;
    size_t digest_size;
    cgutils_crypto_digest_algorithm algo;
    /* The following values are only relevant for a PUT operation */
    bool compressed;
    bool encrypted;
} cg_storage_instance_infos;

typedef struct
{
    uint64_t objects_count;
    uint64_t bytes_count;
} cg_storage_instance_container_stats;

typedef int (cg_storage_instance_status_cb)(int status,
                                            void * cb_data);

typedef int (cg_storage_instance_get_status_cb)(int status,
                                                cg_storage_instance_infos * infos,
                                                void * cb_data);

typedef int (cg_storage_instance_put_status_cb)(int status,
                                                cg_storage_instance_infos * infos,
                                                void * cb_data);

typedef int (cg_storage_instance_list_cb)(int status,
                                          cgutils_llist * list,
                                          void * cb_data);

typedef int (cg_storage_instance_container_stats_cb)(int status,
                                                     cg_storage_instance_container_stats const * stats,
                                                     void * cb_data);

#include <cgsm/cg_storage_manager_data.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

char const * cg_storage_instance_status_to_str(cg_storage_instance_status status) COMPILER_CONST_FUNCTION;

int cg_storage_instance_init(cg_storage_manager_data * data,
                             size_t index,
                             cgutils_configuration const * instance_conf,
                             cg_storage_instance ** instance);

void cg_storage_instance_free(cg_storage_instance * );

static inline void cg_storage_instance_delete(void * data)
{
    cg_storage_instance_free(data);
}

char const * cg_storage_instance_get_name(cg_storage_instance const * instance) COMPILER_PURE_FUNCTION;
uint64_t cg_storage_instance_get_id(cg_storage_instance const * instance) COMPILER_PURE_FUNCTION;

int cg_storage_instance_create_container(cg_storage_instance * this,
                                         char const * container_name,
                                         cg_storage_instance_status_cb * cb,
                                         void * cb_data);

int cg_storage_instance_remove_empty_container(cg_storage_instance * this,
                                               char const * container_name,
                                               cg_storage_instance_status_cb * cb,
                                               void * cb_data);

int cg_storage_instance_list_containers(cg_storage_instance * this,
                                        cg_storage_instance_list_cb * cb,
                                        void * cb_data);

int cg_storage_instance_get_container_stats(cg_storage_instance * this,
                                            char const * container_name,
                                            cg_storage_instance_container_stats_cb * cb,
                                            void * cb_data);

int cg_storage_instance_list_files(cg_storage_instance * this,
                                   cg_storage_instance_list_cb * cb,
                                   void * cb_data);

int cg_storage_instance_get_file(cg_storage_instance * this,
                                 char const * id,
                                 int fd,
                                 cgutils_crypto_digest_algorithm digest_to_compute,
                                 cg_storage_instance_get_status_cb * cb,
                                 void * cb_data);

int cg_storage_instance_put_file(cg_storage_instance * this,
                                 char const * id,
                                 int fd,
                                 size_t file_size,
                                 /* list of cg_storage_provider_meta_data * */
                                 cgutils_llist * metadata,
                                 cgutils_crypto_digest_algorithm digest_to_compute,
                                 cg_storage_instance_put_status_cb * cb,
                                 void * cb_data);

int cg_storage_instance_delete_file(cg_storage_instance * this,
                                    char const * id,
                                    cg_storage_instance_status_cb * cb,
                                    void * cb_data);

int cg_storage_instance_get_object_id(cg_storage_instance * this,
                                      char const * object_id,
                                      char ** object_id_in_instance);

int cg_storage_instance_setup_provider(cg_storage_instance * this);

int cg_storage_instance_setup(cg_storage_instance * this,
                              cg_storage_manager_data * data);

size_t cg_storage_instance_get_index(cg_storage_instance const * this) COMPILER_PURE_FUNCTION;

char const * cg_storage_instance_get_provider_name(cg_storage_instance const * this) COMPILER_PURE_FUNCTION;

bool cg_storage_instance_support_variable_input_size(cg_storage_instance const * this) COMPILER_PURE_FUNCTION;

bool cg_storage_instance_use_encryption(cg_storage_instance const * const this) COMPILER_PURE_FUNCTION;
bool cg_storage_instance_use_compression(cg_storage_instance const * const this) COMPILER_PURE_FUNCTION;

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_STORAGE_INSTANCE_H_ */
