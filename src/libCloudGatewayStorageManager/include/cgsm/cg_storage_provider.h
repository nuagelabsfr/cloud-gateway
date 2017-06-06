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

#ifndef CLOUD_GATEWAY_STORAGE_PROVIDER_H_
#define CLOUD_GATEWAY_STORAGE_PROVIDER_H_

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_http.h>

typedef struct cg_storage_provider cg_storage_provider;

typedef struct
{
    bool chunked_upload;
    bool object_hashing;
} cg_storage_provider_capabilities;

typedef struct
{
    char * key;
    char * value;
} cg_storage_provider_metadata;

#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_instance.h>

int cg_storage_provider_init(cg_storage_manager_data * data,
                             cgutils_configuration const * config,
                             cg_storage_provider ** out);

int cg_storage_provider_init_with_defaults(cg_storage_manager_data * data,
                                           char const * name,
                                           cg_storage_provider ** out);

void cg_storage_provider_free(cg_storage_provider *);

static inline void cg_storage_provider_delete(void * provider)
{
    cg_storage_provider_free(provider);
}

char const * cg_storage_provider_get_name(cg_storage_provider const *) COMPILER_PURE_FUNCTION;

int cg_storage_provider_parse_specific_config(cg_storage_provider const * provider,
                                              cgutils_configuration * provider_specific,
                                              void ** data);

void cg_storage_provider_clear_specific_config(cg_storage_provider const * provider,
                                               void * const);

int cg_storage_provider_create_container(cg_storage_provider * this,
                                         void * instance_specifics,
                                         char const * container_name,
                                         cg_storage_instance_status_cb * cb,
                                         void * cb_data);

int cg_storage_provider_remove_empty_container(cg_storage_provider * this,
                                               void * instance_specifics,
                                               char const * container_name,
                                               cg_storage_instance_status_cb * cb,
                                               void * cb_data);

int cg_storage_provider_list_containers(cg_storage_provider * this,
                                        void * instance_specifics,
                                        cg_storage_instance_list_cb * cb,
                                        void * cb_data);

int cg_storage_provider_get_container_stats(cg_storage_provider * this,
                                            void * instance_specifics,
                                            char const * container_name,
                                            cg_storage_instance_container_stats_cb * cb,
                                            void * cb_data);

int cg_storage_provider_list_files(cg_storage_provider * this,
                                   void * instance_specifics,
                                   cg_storage_instance_list_cb * cb,
                                   void * cb_data);

int cg_storage_provider_get_file(cg_storage_provider * this,
                                 void * instance_specifics,
                                 char const * id,
                                 int fd,
                                 /* list of cg_storage_filter * */
                                 cgutils_llist * filters_list,
                                 cgutils_crypto_digest_algorithm digest_to_compute,
                                 cg_storage_instance_get_status_cb * cb,
                                 void * cb_data);

int cg_storage_provider_put_file(cg_storage_provider * this,
                                 void * instance_specifics,
                                 char const * id,
                                 int fd,
                                 size_t file_size,
                                 /* list of cg_storage_filter * */
                                 cgutils_llist * filters_list,
                                 /* list of cg_storage_provider_meta_data * */
                                 cgutils_llist * metadata,
                                 cgutils_crypto_digest_algorithm digest_to_compute,
                                 cg_storage_instance_put_status_cb * cb,
                                 void * cb_data);

int cg_storage_provider_delete_file(cg_storage_provider * this,
                                    void * instance_specifics,
                                    char const * id,
                                    cg_storage_instance_status_cb * cb,
                                    void * cb_data);

int cg_storage_provider_setup(cg_storage_provider * this,
                              void * instance_specifics);

cg_storage_provider_capabilities const * cg_storage_provider_get_capabilities(cg_storage_provider const * this) COMPILER_PURE_FUNCTION;


int cg_storage_provider_metadata_add(cgutils_llist * list,
                                     char const * key,
                                     char const * value);

void cg_storage_provider_metadata_free(cg_storage_provider_metadata * this);

static inline void cg_storage_provider_metadata_delete(void * this)
{
    cg_storage_provider_metadata_free(this);
}

#endif /* CLOUD_GATEWAY_STORAGE_PROVIDER_H_ */
