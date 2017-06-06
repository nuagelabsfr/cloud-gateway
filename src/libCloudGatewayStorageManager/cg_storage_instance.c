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

#include <cloudutils/cloudutils_crypto.h>
#include <cloudutils/cloudutils_encoding.h>

#include <cgsm/cg_storage_instance.h>
#include <cgsm/cg_storage_manager.h>
#include <cgsm/cg_storage_filter.h>

#define CG_STORAGE_INSTANCE_RANDOM_BYTES_IN_ID_SIZE (8)
#define CG_STORAGE_INSTANCE_HASH_ALGO_FOR_ID (cgutils_crypto_digest_algorithm_sha256)

struct cg_storage_instance
{
    char * name;
    cg_storage_provider * provider;
    void * provider_specific_config;
    cgutils_event_data * event_data;
    /* LList of cg_storage_filter * */
    cgutils_llist * filters;
    size_t index;
    uint64_t id;
    bool use_compression;
    bool use_encryption;
};

char const * cg_storage_instance_status_to_str(cg_storage_instance_status const status)
{
    static char const * const str[] =
        {
#define STATUS(value) #value,
#include <cgsm/cg_storage_instance_status.itm>
#undef STATUS
        };
    static size_t const count = sizeof str / sizeof *str;
    char const * result = NULL;

    if (status < count)
    {
        result = str[status];
    }

    return result;
}

static int cg_storage_instance_add_filters(cg_storage_manager_data * const data,
                                           cgutils_configuration const * const conf,
                                           cg_storage_instance * const this)
{
    cgutils_llist * configs = NULL;
    assert(data != NULL);
    assert(conf != NULL);
    assert(this != NULL);

    int result = cgutils_configuration_get_all(conf, "Filters/Filter",
                                              &configs);

    if (result == 0)
    {
        size_t const configs_count = cgutils_llist_get_count(configs);

        if (configs_count > 0)
        {
            char const * const filters_path = cg_storage_manager_data_get_storage_filters_path(data);
            cgutils_llist_elt * filter_elt = cgutils_llist_get_iterator(configs);

            assert(filters_path != NULL);

            while(filter_elt != NULL && result == 0)
            {
                cgutils_configuration * filter_conf = cgutils_llist_elt_get_object(filter_elt);
                assert(filter_conf != NULL);

                bool enabled = false;

                result = cgutils_configuration_get_boolean(filter_conf, "./Enabled", &enabled);

                if (result == 0)
                {
                    if (enabled)
                    {
                        char * filter_type = NULL;

                        result = cgutils_configuration_get_string(filter_conf, "./Type", &filter_type);

                        if (result == 0)
                        {
                            cgutils_configuration * filter_specifics = NULL;

                            result = cgutils_configuration_from_path(filter_conf,
                                                                     "./Specifics",
                                                                     &filter_specifics);

                            if (result == 0)
                            {
                                cg_storage_filter * filter = NULL;

                                result = cg_storage_filter_init(filter_type,
                                                                filters_path,
                                                                filter_specifics,
                                                                &filter);
                                if (result == 0)
                                {
                                    assert(filter != NULL);

                                    /* Check if the filter can predict its output size, or if
                                       we support chunked uploading.
                                       Otherwise, we have a problem and this filter will not be used with
                                       this instance.
                                    */

                                    if (cg_storage_filter_support_predictable_output_size(filter) == true ||
                                        cg_storage_instance_support_variable_input_size(this) == true)
                                    {
                                        result = cgutils_llist_insert(this->filters,
                                                                      filter);

                                        if (result == 0)
                                        {
                                            if (strcasecmp(filter_type, "Encryption") == 0)
                                            {
                                                cg_storage_manager_data_set_encryption_in_use(data);
                                                this->use_encryption = true;
                                            }
                                            else if (strcasecmp(filter_type, "Compression") == 0)
                                            {
                                                cg_storage_manager_data_set_compression_in_use(data);
                                                this->use_compression = true;
                                            }
                                        }
                                        else
                                        {
                                            cg_storage_filter_free(filter), filter = NULL;
                                            CGUTILS_ERROR("Error inserting filter in list: %d", result);
                                        }
                                    }
                                    else
                                    {
                                        CGUTILS_WARN("Instance %s does not support variable input size, "
                                                     "and therefore is not compatible with the %s filter, whose "
                                                     "output size is not predictable. The %s filter will be disabled "
                                                     "for this instance.",
                                                     cg_storage_instance_get_name(this),
                                                     filter_type,
                                                     filter_type);
                                        cg_storage_filter_free(filter), filter = NULL;

                                    }
                                }
                                else
                                {
                                    CGUTILS_ERROR("Unable to load filter %s for instance %s: %d",
                                                  filter_type,
                                                  cg_storage_instance_get_name(this),
                                                  result);
                                }

                                cgutils_configuration_free(filter_specifics), filter_specifics = NULL;
                            }
                            else
                            {
                                CGUTILS_ERROR("Unable to get specifics for filter %s for instance %s: %d",
                                              filter_type,
                                              cg_storage_instance_get_name(this),
                                              result);
                            }

                            CGUTILS_FREE(filter_type);
                        }
                        else
                        {
                            CGUTILS_ERROR("Unable to get filter type for instance %s: %d",
                                          cg_storage_instance_get_name(this),
                                          result);
                        }
                    }
                }
                else if (result == ENOENT)
                {
                    result = 0;
                }

                filter_elt = cgutils_llist_elt_get_next(filter_elt);
            }
        }

        cgutils_llist_free(&configs, &cgutils_configuration_delete);
    }
    else if (result == ENOENT)
    {
        result = 0;
    }

    return result;
}

static int cg_storage_instance_create(cgutils_configuration * const provider_specific,
                                      char * name,
                                      cg_storage_provider * const provider,
                                      cg_storage_instance ** const instance)
{
    int result = 0;
    assert(provider_specific != NULL);
    assert(name != NULL);
    assert(provider != NULL);
    assert(instance != NULL);

    CGUTILS_ALLOCATE_STRUCT(*instance);

    if (*instance != NULL)
    {
        (*instance)->name = name;
        (*instance)->provider = provider;

        result = cg_storage_provider_parse_specific_config(provider,
                                                           provider_specific,
                                                           &((*instance)->provider_specific_config));

        if (result != 0)
        {
            CGUTILS_ERROR("Error parsing specific configuration for instance %s: %d", name, result);
        }

        if (result != 0)
        {
            cg_storage_instance_free(*instance), *instance = NULL;
        }
    }
    else
    {
        result = ENOMEM;
        CGUTILS_FREE(name);
    }

    return result;
}

int cg_storage_instance_init(cg_storage_manager_data * const data,
                             size_t const idx,
                             cgutils_configuration const * const instance_conf,
                             cg_storage_instance ** const instance)
{
    int result = EINVAL;

    if (data != NULL && instance_conf != NULL && instance != NULL)
    {
        char * name = NULL;

        result = cgutils_configuration_get_string(instance_conf, "Name", &name);

        if (result == 0)
        {
            assert(name != NULL);

            char * provider = NULL;

            result = cgutils_configuration_get_string(instance_conf, "Provider", &provider);

            if (result == 0)
            {
                assert(provider != NULL);

                cg_storage_provider * provider_obj = NULL;

                result = cg_storage_manager_data_get_provider(data, provider, &provider_obj);

                if (result == ENOENT)
                {
                    result = cg_storage_manager_load_storage_provider_with_defaults(data,
                                                                                    provider,
                                                                                    &provider_obj);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Unable to load provider %s: %d", provider, result);
                    }
                }

                if (result == 0)
                {
                    cgutils_configuration * provider_specific = NULL;

                    assert(provider_obj != NULL);

                    result = cgutils_configuration_from_path(instance_conf,
                                                             "Specifics",
                                                             &provider_specific);

                    if (result == 0)
                    {
                        assert(provider_specific != NULL);

                        result = cg_storage_instance_create(provider_specific,
                                                            name,
                                                            provider_obj,
                                                            instance);

                        name = NULL;

                        if (result == 0)
                        {
                            (*instance)->index = idx;
                            (*instance)->event_data = cg_storage_manager_data_get_event(data);

                            result = cgutils_llist_create(&((*instance)->filters));

                            if (result == 0)
                            {
                                result = cg_storage_instance_add_filters(data, instance_conf, *instance);

                                if (result == 0)
                                {
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error loading storage filters: %d", result);
                                }
                            }
                            else
                            {
                                CGUTILS_ERROR("Error creating storage filters list: %d", result);
                            }
                        }

                        cgutils_configuration_free(provider_specific), provider_specific = NULL;

                    }
                    else
                    {
                        CGUTILS_ERROR("Unable to get provider specific configuration for instance %s: %d", name, result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Unable to get provider %s for instance %s: %d", provider, name, result);
                }

                CGUTILS_FREE(provider);
            }

            if (result != 0 && name != NULL)
            {
                CGUTILS_FREE(name);
            }
        }
    }

    return result;
}

void cg_storage_instance_free(cg_storage_instance * instance)
{
    if (instance != NULL)
    {
        if (instance->filters != NULL)
        {
            cgutils_llist_free(&(instance->filters), &cg_storage_filter_delete);
        }

        if (instance->provider != NULL && instance->provider_specific_config != NULL)
        {
            cg_storage_provider_clear_specific_config(instance->provider,
                                                      instance->provider_specific_config),
            instance->provider_specific_config = NULL;
            instance->provider = NULL;
        }

        if (instance->name != NULL)
        {
            CGUTILS_FREE(instance->name);
        }

        CGUTILS_FREE(instance);
    }
}

char const * cg_storage_instance_get_name(cg_storage_instance const * const instance)
{
    char const * result = NULL;

    if (instance != NULL)
    {
        result = instance->name;
    }

    return result;
}

uint64_t cg_storage_instance_get_id(cg_storage_instance const * const instance)
{
    uint64_t result = 0;

    if (instance != NULL)
    {
        result = instance->id;
    }

    return result;
}

int cg_storage_instance_create_container(cg_storage_instance * const this,
                                         char const * const container_name,
                                         cg_storage_instance_status_cb * const cb,
                                         void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL &&
        container_name != NULL &&
        cb != NULL &&
        cb_data != NULL)
    {
        assert(this->provider != NULL);

        result = cg_storage_provider_create_container(this->provider,
                                                      this->provider_specific_config,
                                                      container_name,
                                                      cb,
                                                      cb_data);
    }

    return result;
}

int cg_storage_instance_remove_empty_container(cg_storage_instance * const this,
                                               char const * const container_name,
                                               cg_storage_instance_status_cb * const cb,
                                               void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL &&
        container_name != NULL &&
        cb != NULL &&
        cb_data != NULL)
    {
        assert(this->provider != NULL);

        result = cg_storage_provider_remove_empty_container(this->provider,
                                                            this->provider_specific_config,
                                                            container_name,
                                                            cb,
                                                            cb_data);
    }

    return result;
}

int cg_storage_instance_list_containers(cg_storage_instance * const this,
                                        cg_storage_instance_list_cb * const cb,
                                        void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL && cb != NULL && cb_data != NULL)
    {
        assert(this->provider != NULL);

        result = cg_storage_provider_list_containers(this->provider, this->provider_specific_config, cb, cb_data);
    }

    return result;
}

int cg_storage_instance_get_container_stats(cg_storage_instance * const this,
                                            char const * const container_name,
                                            cg_storage_instance_container_stats_cb * const cb,
                                            void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL &&
        cb != NULL &&
        cb_data != NULL)
    {
        CGUTILS_ASSERT(this->provider != NULL);

        result = cg_storage_provider_get_container_stats(this->provider,
                                                         this->provider_specific_config,
                                                         container_name,
                                                         cb,
                                                         cb_data);
    }

    return result;
}

int cg_storage_instance_list_files(cg_storage_instance * const this,
                                   cg_storage_instance_list_cb * const cb,
                                   void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL && cb != NULL && cb_data != NULL)
    {
        assert(this->provider != NULL);

        result = cg_storage_provider_list_files(this->provider, this->provider_specific_config, cb, cb_data);
    }

    return result;
}

int cg_storage_instance_get_file(cg_storage_instance * const this,
                                 char const * const id,
                                 int fd,
                                 cgutils_crypto_digest_algorithm const digest_to_compute,
                                 cg_storage_instance_get_status_cb * const cb,
                                 void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL && id != NULL && fd >= 0 && cb != NULL)
    {
        assert(this->provider != NULL);
        result = cg_storage_provider_get_file(this->provider,
                                              this->provider_specific_config,
                                              id,
                                              fd,
                                              this->filters,
                                              digest_to_compute,
                                              cb, cb_data);

        if (result == EACCES)
        {
            CGUTILS_ERROR("Authentication error for file id %s: %d", id, result);
        }
        else if (result != 0)
        {
            CGUTILS_ERROR("Error while calling get file: %d", result);
        }
    }

    return result;
}

int cg_storage_instance_put_file(cg_storage_instance * const this,
                                 char const * const id,
                                 int const fd,
                                 size_t const file_size,
                                 cgutils_llist * const metadata,
                                 cgutils_crypto_digest_algorithm const digest_to_compute,
                                 cg_storage_instance_put_status_cb * const cb,
                                 void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL && id != NULL && fd >= 0 && cb != NULL)
    {
        assert(this->provider != NULL);

        result = cg_storage_provider_put_file(this->provider,
                                              this->provider_specific_config,
                                              id,
                                              fd,
                                              file_size,
                                              this->filters,
                                              metadata,
                                              digest_to_compute,
                                              cb, cb_data);

        if (result == EACCES)
        {
            CGUTILS_ERROR("Authentication error for file id %s: %d", id, result);
        }
        else if (result != 0)
        {
            CGUTILS_ERROR("Error while calling put file (%s): %d", id, result);
        }
    }

    return result;
}

int cg_storage_instance_delete_file(cg_storage_instance * const this,
                                    char const * const id,
                                    cg_storage_instance_status_cb * const cb,
                                    void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL && id != NULL && cb != NULL)
    {
        assert(this->provider != NULL);

        result = cg_storage_provider_delete_file(this->provider, this->provider_specific_config,
                                              id,
                                              cb, cb_data);

        if (result == EACCES)
        {
            CGUTILS_ERROR("Authentication error for file id %s: %d", id, result);
        }
        else if (result != 0)
        {
            CGUTILS_ERROR("Error while calling delete file: %d", result);
        }
    }

    return result;
}

int cg_storage_instance_get_object_id(cg_storage_instance * this,
                                      char const * object_key,
                                      char ** object_id_in_instance)
{
    int result = EINVAL;

    if (this != NULL && object_key != NULL && object_id_in_instance != NULL)
    {
        char random_bytes[CG_STORAGE_INSTANCE_RANDOM_BYTES_IN_ID_SIZE];
        size_t const random_bytes_size = sizeof random_bytes / sizeof *random_bytes;

        result = cgutils_crypto_get_pseudo_random_bytes(random_bytes,
                                                        random_bytes_size);

        if (result == 0)
        {
            cgutils_crypto_hash_context * ctx = NULL;
            struct timeval tv = (struct timeval) { 0 };

            gettimeofday(&tv, NULL);

            result = cgutils_crypto_hash_context_init(CG_STORAGE_INSTANCE_HASH_ALGO_FOR_ID,
                                                      &ctx);

            if (result == 0)
            {
                result = cgutils_crypto_hash_context_update(ctx,
                                                            object_key,
                                                            strlen(object_key));

                if (result != 0)
                {
                    CGUTILS_ERROR("Error updating hash context with object key: %d", result);
                }

                if (result == 0)
                {
                    result = cgutils_crypto_hash_context_update(ctx,
                                                                this->name,
                                                                strlen(this->name));

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error updating hash context with instance name: %d", result);
                    }
                }

                if (result == 0)
                {
                    result = cgutils_crypto_hash_context_update(ctx,
                                                                &(tv.tv_sec),
                                                                sizeof (tv.tv_sec));

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error updating hash context with sec timestamp : %d", result);
                    }
                }

                if (result == 0)
                {
                    result = cgutils_crypto_hash_context_update(ctx,
                                                                &(tv.tv_usec),
                                                                sizeof (tv.tv_usec));

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error updating hash context with usec timestamp : %d", result);
                    }
                }

                if (result == 0)
                {
                    result = cgutils_crypto_hash_context_update(ctx,
                                                                random_bytes,
                                                                random_bytes_size);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error updating hash context with random bytes : %d", result);
                    }

                }

                if (result == 0)
                {
                    void * hash = NULL;
                    size_t hash_size = 0;

                    result = cgutils_crypto_hash_context_finish(ctx,
                                                                &hash,
                                                                &hash_size);

                    if (result == 0)
                    {
                        void * b64 = NULL;
                        size_t b64_size = 0;

                        result = cgutils_encoding_base64_encode(hash,
                                                                hash_size,
                                                                &b64,
                                                                &b64_size);

                        if (result == 0)
                        {
                            char * ptr = b64;

                            for(size_t idx = 0; idx < (b64_size - 1); idx++)
                            {
                                if (COMPILER_UNLIKELY(ptr[idx] == '+' ||
                                                      ptr[idx] == '/'))
                                {
                                    ptr[idx] = '-';
                                }
                            }

                            ptr[b64_size - 1] = '\0';

                            *object_id_in_instance = ptr;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error encoding hash into base64: %d", result);
                        }

                        CGUTILS_FREE(hash);
                    }
                    else
                    {
                        CGUTILS_ERROR("Error finishing hash context: %d", result);
                    }
                }

                cgutils_crypto_hash_context_free(ctx), ctx = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error creating hash context: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error getting random bytes: %d", result);
        }
    }

    return result;
}

int cg_storage_instance_setup_provider(cg_storage_instance * const this)
{
    int result = EINVAL;

    if (this != NULL)
    {
        assert(this->provider != NULL);
        result = cg_storage_provider_setup(this->provider, this->provider_specific_config);

        if (result != 0)
        {
            CGUTILS_ERROR("Error setting provider up: %d", result);
        }
    }

    return result;
}

int cg_storage_instance_setup(cg_storage_instance * const this,
                              cg_storage_manager_data * const data)
{
    int result = EINVAL;

    if (this != NULL && data != NULL)
    {
        cgdb_data * db = cg_storage_manager_data_get_db(data);

        if (db != NULL)
        {
            result = cgdb_sync_get_instance_id(db,
                                               this->name,
                                               &this->id);

            if (result != 0)
            {
                CGUTILS_ERROR("Error looking for the instance id for %s in the database: %d",
                              this->name,
                              result);
            }
        }
    }

    return result;
}

size_t cg_storage_instance_get_index(cg_storage_instance const * const this)
{
    size_t result = 0;

    if (this != NULL)
    {
        result = this->index;
    }

    return result;
}

char const * cg_storage_instance_get_provider_name(cg_storage_instance const * const this)
{
    char const * result = NULL;

    if (this != NULL && this->provider != NULL)
    {
        result = cg_storage_provider_get_name(this->provider);
    }

    return result;
}

bool cg_storage_instance_support_variable_input_size(cg_storage_instance const * const this)
{
    bool result = false;

    if (this != NULL && this->provider != NULL)
    {
        cg_storage_provider_capabilities const * capabilities = cg_storage_provider_get_capabilities(this->provider);

        if (capabilities != NULL)
        {
            result = capabilities->chunked_upload;
        }
    }

    return result;
}

bool cg_storage_instance_use_encryption(cg_storage_instance const * const this)
{
    bool result = false;

    if (this != NULL)
    {
        result = this->use_encryption;
    }

    return result;
}

bool cg_storage_instance_use_compression(cg_storage_instance const * const this)
{
    bool result = false;

    if (this != NULL)
    {
        result = this->use_compression;
    }

    return result;
}
