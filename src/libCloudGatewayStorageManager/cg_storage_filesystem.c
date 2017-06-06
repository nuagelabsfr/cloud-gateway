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
#include <inttypes.h>
#include <stdint.h>
#include <strings.h>
#include <string.h>
#include <time.h>

#include <cgsm/cg_storage_cache.h>
#include <cgsm/cg_storage_filesystem.h>
#include <cgsm/cg_storage_filesystem_db.h>
#include <cgsm/cg_storage_filesystem_common.h>

#include <cloudutils/cloudutils_crypto.h>
#include <cloudutils/cloudutils_encoding.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_system.h>

#include <cgdb/cgdb.h>

#define CG_STORAGE_FILESYSTEM_DEFAULT_IO_BLOCK_SIZE (4096)
#define CG_STORAGE_FILESYSTEM_DEFAULT_INODE_DIGEST (cgutils_crypto_digest_algorithm_sha256)

char const * cg_storage_filesystem_state_to_str(cg_storage_filesystem_handler_state const state)
{
    static char const * const states_str[] =
        {
#define STATE(name) #name,
#include "cgsm/cg_storage_filesystem_states.h"
#undef STATE
        };
   static size_t const states_str_count = sizeof states_str / sizeof *states_str;

   char const * result = NULL;

   if (state < states_str_count)
   {
       result = states_str[state];
   }

   return result;
}

static int cg_storage_filesystem_type_from_str(char const * const str,
                                               cg_storage_filesystem_type * const type)
{
    assert(str != NULL);
    assert(type != NULL);

    static struct
    {
        char const * const str;
        cg_storage_filesystem_type const type;
    } const types[] =
          {
#define TYPE(type, str) { str, type},
#include <cgsm/cg_st_filesystem_type.itm>
#undef TYPE
          };
    static size_t const types_count = sizeof types / sizeof *types;
    int result = ENOENT;

    for(size_t idx = 0; result == ENOENT && idx < types_count; idx++)
    {
        if (strcasecmp(str, types[idx].str) == 0)
        {
            *type = types[idx].type;
            result = 0;
        }
    }

    return result;
}

static int cg_storage_filesystem_add_instances(cg_storage_manager_data * const data,
                                               cgutils_configuration const * const fs_conf,
                                               cg_storage_filesystem * const fs)
{
    cgutils_llist * configs = NULL;
    assert(data != NULL);
    assert(fs_conf != NULL);
    assert(fs != NULL);

    int result = cgutils_configuration_get_all(fs_conf, "Instances/Instance",
                                              &configs);

    if (result == 0)
    {
        size_t const configs_count = cgutils_llist_get_count(configs);

        if (configs_count > 0)
        {
            CGUTILS_MALLOC(fs->instances, configs_count, sizeof *(fs->instances));

            if (fs->instances != NULL)
            {
                fs->instances_count = 0;

                cgutils_llist_elt * inst_elt = cgutils_llist_get_iterator(configs);

                while(inst_elt != NULL &&
                      result == 0)
                {
                    cgutils_configuration * inst_conf = cgutils_llist_elt_get_object(inst_elt);
                    assert(inst_conf != NULL);

                    char * instance_name = NULL;

                    result = cgutils_configuration_get_string(inst_conf,
                                                              ".",
                                                              &instance_name);

                    if (result == 0)
                    {
                        assert(instance_name != NULL);
                        cg_storage_instance * inst = NULL;

                        result = cg_storage_manager_data_get_instance(data,
                                                                      instance_name,
                                                                      &inst);

                        if (result == 0)
                        {
                            if (fs->instances_count == 0 ||
                                fs->type != cg_storage_filesystem_type_single)
                            {
                                size_t const inst_pos = fs->instances_count;
                                assert(inst != NULL);

                                fs->instances[inst_pos].instance = inst;
                                fs->instances[inst_pos].status = (cg_monitor_data_instance_status_data) { 0 };
                                fs->instances_count++;
                            }
                            else
                            {
                                CGUTILS_WARN("More than one instance has been configured for a Single filesystem. "
                                             "Skipping instance named %s.", instance_name);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Unable to find instance %s for filesystem %s: %d",
                                          instance_name,
                                          fs->name,
                                      result);
                        }

                        CGUTILS_FREE(instance_name);
                    }
                    else if (result == ENOENT)
                    {
                        result = 0;
                    }

                    inst_elt = cgutils_llist_elt_get_next(inst_elt);
                }
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for instances: %d", result);
            }
        }
        else
        {
            CGUTILS_WARN("No instance associated to filesystem %s, probably not what you want.",
                         fs->name);
        }

        cgutils_llist_free(&configs, &cgutils_configuration_delete);
    }
    else if (result == ENOENT)
    {
        CGUTILS_WARN("No instance associated to filesystem %s, probably not what you want.",
                     fs->name);
        result = 0;
    }

    return result;
}

static int cg_storage_filesystem_create(cg_storage_manager_data * const data,
                                        cgutils_configuration const * const filesystem_conf,
                                        char * name,
                                        char * cache_dir,
                                        cg_storage_filesystem_type const type,
                                        cg_storage_filesystem ** const filesystem)
{
    int result = 0;
    assert(data != NULL);
    assert(filesystem_conf);
    assert(name != NULL);
    assert(cache_dir != NULL);
    assert(filesystem != NULL);

    CGUTILS_ALLOCATE_STRUCT(*filesystem);

    if (*filesystem != NULL)
    {
        (*filesystem)->name = name;
        (*filesystem)->cache_dir = cache_dir;
        (*filesystem)->type = type;
        (*filesystem)->data = data;
        (*filesystem)->seed = (unsigned int) time(NULL);
        cache_dir = NULL;
        name = NULL;

        result = cg_storage_filesystem_add_instances(data, filesystem_conf, *filesystem);

        if (result == 0)
        {
            result = cg_storage_cache_init(*filesystem,
                                           (*filesystem)->cache_dir,
                                           &((*filesystem)->cache));

            if (result == 0)
            {
                if (type == cg_storage_filesystem_type_mirroring)
                {
                    cg_storage_manager_data_set_mirroring_in_use(data);
                }
                else if (type == cg_storage_filesystem_type_striping)
                {
                    cg_storage_manager_data_set_striping_in_use(data);
                }
            }
            else
            {
                CGUTILS_ERROR("Error in cache init: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error loading instances: %d", result);
        }

        if (result != 0)
        {
            cg_storage_filesystem_free(*filesystem), *filesystem = NULL;
        }
    }
    else
    {
        result = ENOMEM;
    }

    if (result != 0)
    {
        CGUTILS_FREE(name);
        CGUTILS_FREE(cache_dir);
    }

    return result;
}

int cg_storage_filesystem_setup(cg_storage_filesystem * const this,
                                cg_storage_manager_data * const data)
{
    int result = EINVAL;

    if (this != NULL && data != NULL)
    {
        cgdb_data * db = cg_storage_manager_data_get_db(data);

        if (db != NULL)
        {
            result = cgdb_sync_get_filesystem_id(db,
                                                 this->name,
                                                 &this->id);

            if (result == 0)
            {
                this->db = db;
            }
            else
            {
                CGUTILS_ERROR("Error looking for the filesystem's id for %s in the database: %d",
                              this->name,
                              result);
            }
        }
    }

    return result;
}

static void cg_storage_filesystem_compute_optimal_io_block_size(cg_storage_filesystem * const this)
{
    uint32_t page_size = 0;

    int result = cgutils_system_get_page_size(&page_size);

    if (result == 0 && page_size > 0)
    {
        this->io_block_size = page_size;
    }
    else
    {
        this->io_block_size = CG_STORAGE_FILESYSTEM_DEFAULT_IO_BLOCK_SIZE;
    }
}

int cg_storage_filesystem_init(cg_storage_manager_data * const data,
                               cgutils_configuration const * const filesystem_conf,
                               cg_storage_filesystem ** const filesystem)
{
    int result = EINVAL;

    if (data != NULL && filesystem_conf != NULL && filesystem != NULL)
    {
        char * id = NULL;

        result = cgutils_configuration_get_string(filesystem_conf,
                                                  "Id",
                                                  &id);

        if (result == 0)
        {
            assert(id != NULL);

            char * type_str = NULL;

            result = cgutils_configuration_get_string(filesystem_conf,
                                                      "Type",
                                                      &type_str);

            if (result == 0 ||
                result == ENOENT)
            {
                cg_storage_filesystem_type type = cg_storage_filesystem_type_single;

                if (result == 0)
                {
                    assert(type_str != NULL);

                    result = cg_storage_filesystem_type_from_str(type_str,
                                                                 &type);
                }
                else
                {
                    type_str = NULL;
                    result = 0;
                }

                if (result == 0)
                {
                    char * cache_dir = NULL;

                    result = cgutils_configuration_get_string(filesystem_conf, "CacheRoot", &cache_dir);

                    if (result == 0)
                    {
                        uint64_t full_threshold = 0;

                        result = cgutils_configuration_get_unsigned_integer(filesystem_conf,
                                                                            "FullThreshold",
                                                                            &full_threshold);

                        if (result == 0)
                        {
                            if (full_threshold <= 100)
                            {
                                result = cg_storage_filesystem_create(data,
                                                                      filesystem_conf,
                                                                      id,
                                                                      cache_dir,
                                                                      type,
                                                                      filesystem);

                                id = NULL;
                                cache_dir = NULL;

                                if (result == 0)
                                {
                                    uint64_t clean_min_file_size = 0;
                                    uint64_t clean_max_access_offset = 0;
                                    uint64_t delayed_expunge = 0;
                                    uint64_t io_block_size = 0;
                                    char * digest_algo_str = NULL;
                                    bool auto_expunge;

                                    (*filesystem)->full_threshold = (uint8_t) full_threshold;

                                    int res = cgutils_configuration_get_unsigned_integer(filesystem_conf,
                                                                                         "CleanMinFileSize",
                                                                                         &clean_min_file_size);

                                    if (res == 0)
                                    {
                                        (*filesystem)->clean_min_file_size = clean_min_file_size;
                                    }
                                    else if (res == E2BIG)
                                    {
                                        CGUTILS_WARN("More than one 'CleanMinFileSize' value specified for FS %s, using the default.", id);
                                    }
                                    else if (res != ENOENT)
                                    {
                                        CGUTILS_WARN("Error retrieving the 'CleanMinFileSize' value for FS %s, using the default.", id);
                                    }

                                    res = cgutils_configuration_get_unsigned_integer(filesystem_conf,
                                                                                     "CleanMaxAccessOffset",
                                                                                     &clean_max_access_offset);

                                    if (res == 0)
                                    {
                                        (*filesystem)->clean_max_access_offset = clean_max_access_offset;
                                    }
                                    else if (res == E2BIG)
                                    {
                                        CGUTILS_WARN("More than one 'CleanMaxAccessOffset' value specified for FS %s, using the default.", id);
                                    }
                                    else if (res != ENOENT)
                                    {
                                        CGUTILS_WARN("Error retrieving the 'CleanMaxAccessOffset' value for FS %s, using the default.", id);
                                    }

                                    res = cgutils_configuration_get_unsigned_integer(filesystem_conf,
                                                                                     "DelayedExpunge",
                                                                                     &delayed_expunge);

                                    if (res == 0)
                                    {
                                        (*filesystem)->delayed_expunge = delayed_expunge;
                                    }
                                    else if (res == E2BIG)
                                    {
                                        CGUTILS_WARN("More than one 'DelayedExpunge' value specified for FS %s, using the default.", id);
                                    }
                                    else if (res != ENOENT)
                                    {
                                        CGUTILS_WARN("Error retrieving the 'DelayedExpunge' value for FS %s, using the default.", id);
                                    }


                                    res = cgutils_configuration_get_boolean(filesystem_conf,
                                                                            "AutoExpunge",
                                                                            &auto_expunge);

                                    if (res == 0)
                                    {
                                        (*filesystem)->auto_expunge = auto_expunge;
                                    }
                                    else if (res == E2BIG)
                                    {
                                        CGUTILS_WARN("More than one 'AutoExpunge' value specified for FS %s, using the default.", id);
                                    }
                                    else if (res != ENOENT)
                                    {
                                        CGUTILS_WARN("Error retrieving the 'AutoExpunge' value for FS %s, using the default.", id);
                                    }

                                    res = cgutils_configuration_get_unsigned_integer(filesystem_conf,
                                                                                     "IOBlockSize",
                                                                                     &io_block_size);

                                    if (res == 0)
                                    {
                                        if (io_block_size <= UINT32_MAX)
                                        {
                                            (*filesystem)->io_block_size = (uint32_t) io_block_size;
                                        }
                                        else
                                        {
                                            res = E2BIG;
                                            CGUTILS_WARN("Invalid filesystem IOBlockSize parameter, skipping.");
                                        }
                                    }
                                    else if (res == E2BIG)
                                    {
                                        CGUTILS_WARN("More than one 'IOBlockSize' value specified for FS %s, using the default.", id);
                                    }
                                    else if (res != ENOENT)
                                    {
                                        CGUTILS_WARN("Error retrieving the 'IOBlockSize' value for FS %s, using the default.", id);
                                    }

                                    if (res != 0)
                                    {
                                        cg_storage_filesystem_compute_optimal_io_block_size(*filesystem);
                                    }

                                    res = cgutils_configuration_get_string(filesystem_conf,
                                                                           "InodeDigestAlgorithm",
                                                                           &digest_algo_str);

                                    if (res == 0)
                                    {
                                        (*filesystem)->digest_algorithm = cgutils_crypto_digest_algorithm_from_str(digest_algo_str);

                                        if ((*filesystem)->digest_algorithm == cgutils_crypto_digest_algorithm_none &&
                                            strcasecmp(digest_algo_str, "none") != 0)
                                        {
                                            CGUTILS_WARN("Invalid digest algorithm specified withInodeDigestAlgorithm, skipping.");
                                            (*filesystem)->digest_algorithm = CG_STORAGE_FILESYSTEM_DEFAULT_INODE_DIGEST;
                                        }
                                    }
                                    else
                                    {
                                        (*filesystem)->digest_algorithm = CG_STORAGE_FILESYSTEM_DEFAULT_INODE_DIGEST;
                                    }
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error in filesystem init: %d", result);
                                }
                            }
                            else
                            {
                                result = EINVAL;
                                CGUTILS_ERROR("Invalid threshold for fileystem %s (%" PRIu64 "): %d", id, full_threshold, result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Unable to get filesystem %s threshold: %d", id, result);
                        }

                        CGUTILS_FREE(cache_dir);
                    }
                    else
                    {
                        CGUTILS_ERROR("Unable to get filesystem %s CacheRoot: %d", id, result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Unknown type %s for filesystem %s: %d", type_str, id, result);
                }

                CGUTILS_FREE(type_str);
            }
            else
            {
                CGUTILS_ERROR("Unable to retrieve type for filesystem %s: %d", id, result);
            }

            if (id != NULL)
            {
                CGUTILS_FREE(id);
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to retrieve id for filesystem: %d", result);
        }
    }

    return result;
}

void cg_storage_filesystem_free(cg_storage_filesystem * fs)
{
    if (fs != NULL)
    {
        if (fs->name != NULL)
        {
            CGUTILS_FREE(fs->name);
        }

        if (fs->cache != NULL)
        {
            cg_storage_cache_free(fs->cache), fs->cache = NULL;
        }

        if (fs->cache_dir != NULL)
        {
            CGUTILS_FREE(fs->cache_dir);
        }

        if (fs->instances != NULL)
        {
            CGUTILS_FREE(fs->instances);
        }

        if (fs->pending_transfers != NULL)
        {
            cgutils_rbtree_destroy(fs->pending_transfers), fs->pending_transfers = NULL;
        }

        fs->id = 0;

        CGUTILS_FREE(fs);
    }
}

char const * cg_storage_filesystem_get_name(cg_storage_filesystem const * const filesystem)
{
    char const * result = NULL;

    if (filesystem != NULL)
    {
        result = filesystem->name;
    }

    return result;
}

uint64_t cg_storage_filesystem_get_id(cg_storage_filesystem const * const filesystem)
{
    uint64_t result = 0;

    if (filesystem != NULL)
    {
        result = filesystem->id;
    }

    return result;
}

int cg_storage_filesystem_check_cache(cg_storage_filesystem const * const this,
                                      bool * const full)
{
    int result = EINVAL;

    if (this != NULL && full != NULL)
    {
        uint64_t total = 0;
        uint64_t ufree = 0;
        uint64_t non_priv_free = 0;

        result = cg_storage_cache_get_usage(this->cache,
                                            &total,
                                            &ufree,
                                            &non_priv_free);

        if (result == 0)
        {
            uint64_t const threshold = (total / 100) * this->full_threshold;

            if (threshold >= non_priv_free)
            {
                *full = true;
            }
            else
            {
                *full = false;
            }
        }
        else if (result != ENOENT)
        {
            CGUTILS_ERROR("Error in cg_storage_cache_get_usage: %d", result);
        }
    }

    return result;
}

uint64_t cg_storage_filesystem_get_clean_max_access_offset(cg_storage_filesystem const * const fs)
{
    uint64_t result = 0;

    if (fs != NULL)
    {
        result = fs->clean_max_access_offset;
    }

    return result;
}

uint64_t cg_storage_filesystem_get_clean_min_file_size(cg_storage_filesystem const * const fs)
{
    uint64_t result = 0;

    if (fs != NULL)
    {
        result = fs->clean_min_file_size;
    }

    return result;
}

uint32_t cg_storage_filesystem_get_io_block_size(cg_storage_filesystem const * const fs)
{
    uint32_t result = 0;

    if (fs != NULL)
    {
        result = fs->io_block_size;
    }

    return result;
}

cg_storage_filesystem_type cg_storage_filesystem_get_type(cg_storage_filesystem const * const this)
{
    cg_storage_filesystem_type result = 0;

    if (this != NULL)
    {
        result = this->type;
    }

    return result;
}

bool cg_storage_filesystem_has_auto_expunge(cg_storage_filesystem const * const this)
{
    bool result = false;

    if (this != NULL)
    {
        result = this->auto_expunge;
    }

    return result;
}
