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
#include <string.h>

#include <cgsm/cg_storage_cache.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_crypto.h>
#include <cloudutils/cloudutils_encoding.h>

#define CG_STORAGE_CACHE_HASH (cgutils_crypto_digest_algorithm_sha256)
#define CG_STORAGE_CACHE_ARBO_DEPTH_LEGACY 8
#define CG_STORAGE_CACHE_ARBO_DEPTH 3
#define CG_STORAGE_CACHE_TEMPORARY_SUFFIX "-XXXXXX"

struct cg_storage_cache
{
    cg_storage_filesystem * fs;
    char * cache_root;
    size_t cache_root_len;
};

int cg_storage_cache_init(cg_storage_filesystem * const fs,
                          char const * const cache_root,
                          cg_storage_cache ** const cache)
{
    int result = EINVAL;

    if (fs != NULL &&
        cache_root != NULL &&
        cache != NULL)
    {
        CGUTILS_ALLOCATE_STRUCT(*cache);

        if (*cache != NULL)
        {
            (*cache)->cache_root = cgutils_strdup(cache_root);

            if ((*cache)->cache_root != NULL)
            {
                result = 0;
                (*cache)->cache_root_len = strlen(cache_root);
                (*cache)->fs = fs;
            }
            else
            {
                result = ENOMEM;
            }

            if (result != 0)
            {
                cg_storage_cache_free(*cache), *cache = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

void cg_storage_cache_free(cg_storage_cache * this)
{
    if (this != NULL)
    {
        CGUTILS_FREE(this->cache_root);

        this->cache_root_len = 0;
        this->fs = NULL;

        CGUTILS_FREE(this);
    }
}

/*
   Check that the entry in cache has not been updated since the last sync,
   ie if the metadata is the same as what we have in DB.
*/
int cg_storage_cache_check_expungeable_stats(cg_storage_cache * const cache,
                                             struct stat const * const st,
                                             char const * const path_in_cache,
                                             bool * const valid)
{
    int result = EINVAL;

    if (cache != NULL &&
        st != NULL &&
        path_in_cache != NULL &&
        valid != NULL)
    {
        struct stat cache_st;
        *valid = false;

        result = cgutils_file_stat(path_in_cache, &cache_st);

        if (result == 0)
        {
            if (st->st_size == cache_st.st_size &&
                st->st_mtime >= cache_st.st_mtime)
            {
                *valid = true;
            }
        }
        else
        {
            if (result == ENOENT)
            {
                result = 0;
            }
        }
    }

    return result;
}

/*
   Check that the entry in cache is at least as fresh as we expect from the
   database metadata.
*/
int cg_storage_cache_check_freshness_stats(cg_storage_cache const * const cache,
                                           struct stat const * const st,
                                           char const * const path_in_cache,
                                           bool * const valid)
{
    int result = EINVAL;

    if (cache != NULL &&
        st != NULL &&
        path_in_cache != NULL &&
        valid != NULL)
    {
        struct stat cache_st;
        *valid = false;

        result = cgutils_file_stat(path_in_cache, &cache_st);

        if (result == 0)
        {
            /* Don't check size, it may not have been updated in DB yet
               if the file has not been released.
               if (db_st.st_size == cache_st.st_size)

            */
            if (st->st_mtime <= cache_st.st_mtime)
            {
                *valid = true;
            }
        }
        else
        {
            if (result == ENOENT)
            {
                result = 0;
            }
        }
    }

    return result;
}

int cg_storage_cache_check_freshness(cg_storage_cache const * const cache,
                                     cg_storage_object const * object,
                                     char const * const path_in_cache,
                                     bool * const valid)
{
    int result = EINVAL;

    if (cache != NULL &&
        object != NULL &&
        path_in_cache != NULL &&
        valid != NULL)
    {
        struct stat db_st = (struct stat) { 0 };

        result = cg_storage_object_get_stat(object, &db_st);

        if (result == 0)
        {
            result = cg_storage_cache_check_freshness_stats(cache,
                                                            &db_st,
                                                            path_in_cache,
                                                            valid);
        }
    }

    return result;
}

/* hash[] = base64(CG_STORAGE_CACHE_HASH(<fs id>_<inode number>))
   Cache File := cache_root/hash[0]/.../hash[x]/hash
*/
int cg_storage_cache_get_existing_path(cg_storage_cache const * const this,
                                       uint64_t const inode_number,
                                       bool const creation,
                                       char ** const cache_path,
                                       size_t * const cache_path_len)
{
    int result = EINVAL;

    if (this != NULL &&
        cache_path != NULL &&
        cache_path_len != NULL)
    {
        char * canonical = NULL;

        result = cgutils_asprintf(&canonical,
                                  "%"PRIu64"_%"PRIu64,
                                  cg_storage_filesystem_get_id(this->fs),
                                  inode_number);

        if (result == 0)
        {
            size_t const canonical_len = strlen(canonical);
            void * hashname = NULL;
            size_t hashname_size = 0;

            result = cgutils_crypto_hash(canonical,
                                         canonical_len,
                                         CG_STORAGE_CACHE_HASH,
                                         &hashname,
                                         &hashname_size);

            if (result == 0)
            {
                void * basename_str = NULL;
                size_t basename_str_size = 0;

                result = cgutils_encoding_base64_encode(hashname,
                                                        hashname_size,
                                                        &basename_str,
                                                        &basename_str_size);

                if (result == 0)
                {
                    result = cgutils_file_compute_hashed_path(this->cache_root,
                                                              this->cache_root_len,
                                                              basename_str,
                                                              basename_str_size,
                                                              CG_STORAGE_CACHE_ARBO_DEPTH,
                                                              cache_path,
                                                              cache_path_len);

                    if (result == 0)
                    {
                        if (creation == false)
                        {
                            /* If we are looking for an existing file and
                               it does not exists, check whether it exists
                               at its legacy location/ */

                            struct stat st = (struct stat) { 0 };

                            result = cgutils_file_stat(*cache_path,
                                                       &st);

                            if (result != 0)
                            {
                                char * legacy_cache_path = NULL;
                                size_t legacy_cache_path_len = 0;

                                result = cgutils_file_compute_hashed_path(this->cache_root,
                                                                          this->cache_root_len,
                                                                          basename_str,
                                                                          basename_str_size,
                                                                          CG_STORAGE_CACHE_ARBO_DEPTH_LEGACY,
                                                                          &legacy_cache_path,
                                                                          &legacy_cache_path_len);

                                if (result == 0)
                                {
                                    st = (struct stat) { 0 };

                                    result = cgutils_file_stat(legacy_cache_path,
                                                               &st);

                                    if (result == 0)
                                    {
                                        CGUTILS_FREE(*cache_path);
                                        *cache_path_len = 0;
                                        *cache_path = legacy_cache_path;
                                        *cache_path_len = legacy_cache_path_len;
                                        legacy_cache_path = NULL;
                                        legacy_cache_path_len = 0;
                                    }
                                    else
                                    {
                                        result = 0;
                                    }

                                    CGUTILS_FREE(legacy_cache_path);
                                    legacy_cache_path_len = 0;
                                }
                            }
                        }

                        if (result != 0)
                        {
                            CGUTILS_FREE(*cache_path);
                            *cache_path_len = 0;
                        }
                    }

                    CGUTILS_FREE(basename_str);
                }
                else
                {
                    CGUTILS_ERROR("Error getting canonical hash base64 value: %d", result);
                }

                CGUTILS_FREE(hashname);
            }
            else
            {
                CGUTILS_ERROR("Error getting canonical hash value: %d", result);
            }

            CGUTILS_FREE(canonical);
        }
        else
        {
            CGUTILS_ERROR("Error allocating memory for cache canonical name: %d", result);
        }
    }

    return result;
}

static int cg_storage_cache_create_path(char * const real_path,
                                        size_t const real_path_len)
{
    CGUTILS_ASSERT(real_path != NULL);

    int result = 0;

    for (size_t idx = 0;
         result == 0 &&
             idx < real_path_len;
         idx++)
    {
        if (COMPILER_UNLIKELY(idx > 0 &&
                              real_path[idx] == '/'))
        {
            real_path[idx] = '\0';
            result = cgutils_file_mkdir(real_path,
                                        S_IRUSR | S_IWUSR | S_IXUSR);

            if (result != 0)
            {
                if (result == EEXIST)
                {
                    result = 0;
                }
                else
                {
                    CGUTILS_ERROR("Error creating directory %s: %d", real_path, result);
                }
            }

            real_path[idx] = '/';
        }
    }

    return result;
}

int cg_storage_cache_create_file(cg_storage_cache * const this,
                                 uint64_t const inode_number,
                                 char ** const out_path,
                                 int * const fd)
{
    int result = EINVAL;

    if (this != NULL &&
        out_path != NULL &&
        fd != NULL)
    {
        char * cache_path = NULL;
        size_t cache_path_len = 0;

        result = cg_storage_cache_get_existing_path(this,
                                                    inode_number,
                                                    true,
                                                    &cache_path,
                                                    &cache_path_len);

        if (result == 0)
        {
            result = cg_storage_cache_create_path(cache_path,
                                                  cache_path_len);

            if (result == 0)
            {
                result = cgutils_file_open(cache_path,
                                           O_CLOEXEC | O_CREAT | O_EXCL,
                                           S_IRUSR | S_IWUSR,
                                           fd);

                if (result == 0)
                {
                    *out_path = cache_path, cache_path = NULL;
                }
                else if (result != EEXIST)
                {
                    CGUTILS_ERROR("Error opening file %s (fs %s, inode %"PRIu64"): %d",
                                  cache_path,
                                  cg_storage_filesystem_get_name(this->fs),
                                  inode_number,
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error creating path %s for FS %s and inode %"PRIu64": %d",
                              cache_path,
                              cg_storage_filesystem_get_name(this->fs),
                              inode_number,
                              result);
            }

            if (cache_path)
            {
                CGUTILS_FREE(cache_path);
            }
        }
        else
        {
            CGUTILS_ERROR("Error computing path for inode %"PRIu64", FS %s: %d",
                          inode_number,
                          cg_storage_filesystem_get_name(this->fs),
                          result);
        }
    }

    return result;
}

int cg_storage_cache_unlink_file(cg_storage_cache * const this,
                                 uint64_t const inode_number)
{
    int result = EINVAL;

    if (this != NULL)
    {
        char * cache_path = NULL;
        size_t cache_path_len = 0;

        result = cg_storage_cache_get_existing_path(this,
                                                    inode_number,
                                                    false,
                                                    &cache_path,
                                                    &cache_path_len);

        if (result == 0)
        {
            result = cgutils_file_unlink(cache_path);

            if (result != 0)
            {
                if (result != ENOENT)
                {
                    CGUTILS_ERROR("Error removing cache file (%s): %d",
                                  cache_path,
                                  result);
                }
                else
                {
                    result = 0;
                }
            }

            CGUTILS_FREE(cache_path);
        }
        else
        {
            CGUTILS_ERROR("Error getting path (%s, %"PRIu64"): %d",
                          this->cache_root,
                          inode_number,
                          result);
        }
    }

    return result;
}

int cg_storage_cache_get_temporary_path(cg_storage_cache * const this,
                                        uint64_t const inode_number,
                                        char ** const cache_path,
                                        size_t * const cache_path_len,
                                        int * const fd)
{
    int result = EINVAL;

    if (this != NULL &&
        cache_path != NULL &&
        cache_path_len != NULL &&
        fd != NULL)
    {
        char * final_path = NULL;
        size_t final_path_len = 0;

        result = cg_storage_cache_get_existing_path(this,
                                                    inode_number,
                                                    false,
                                                    &final_path,
                                                    &final_path_len);

        if (result == 0)
        {
            CGUTILS_ASSERT(final_path != NULL);

            result = cg_storage_cache_create_path(final_path,
                                                  final_path_len);

            if (result == 0)
            {
                static char const temporary_suffix[] = CG_STORAGE_CACHE_TEMPORARY_SUFFIX;
                static size_t const temporary_suffix_len = sizeof temporary_suffix - 1;
                char * temporary_path = NULL;
                size_t const temporary_path_len = final_path_len + temporary_suffix_len;

                CGUTILS_MALLOC(temporary_path, temporary_path_len + 1, 1);

                if (temporary_path != NULL)
                {
                    memcpy(temporary_path, final_path, final_path_len);
                    memcpy(temporary_path + final_path_len, CG_STORAGE_CACHE_TEMPORARY_SUFFIX, temporary_suffix_len);
                    temporary_path[final_path_len + temporary_suffix_len] = '\0';

                    result = cgutils_file_mkstemp(temporary_path,
                                                  fd);

                    if (result == 0)
                    {
                        assert(*fd != -1);

                        *cache_path = temporary_path;
                        *cache_path_len = temporary_path_len;
                        temporary_path = NULL;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating temorary cache file %s for FS %s and inode %"PRIu64": %d",
                                      temporary_path,
                                      cg_storage_filesystem_get_name(this->fs),
                                      inode_number,
                                      result);
                    }

                    if (result != 0)
                    {
                        CGUTILS_FREE(temporary_path);
                    }
                }
                else
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error allocating memory for temporary path: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error creating path %s for FS %s and inode %"PRIu64": %d",
                              final_path,
                              cg_storage_filesystem_get_name(this->fs),
                              inode_number,
                              result);
            }

            CGUTILS_FREE(final_path);
        }
        else
        {
            CGUTILS_ERROR("Error computing path for inode %"PRIu64", FS %s: %d",
                          inode_number,
                          cg_storage_filesystem_get_name(this->fs),
                          result);
        }
    }

    return result;
}

int cg_storage_cache_move_temporary_to_final(cg_storage_cache * const this,
                                             uint64_t const inode_number,
                                             char const * const temporary_path,
                                             char ** const final_path)
{
    int result = EINVAL;

    if (this != NULL &&
        temporary_path != NULL &&
        final_path != NULL)
    {
        size_t final_path_len = 0;

        result = cg_storage_cache_get_existing_path(this,
                                                    inode_number,
                                                    false,
                                                    final_path,
                                                    &final_path_len);

        if (result == 0)
        {
            result = cgutils_file_rename(temporary_path, *final_path);

            if (result != 0)
            {
                CGUTILS_ERROR("Error renaming temporary cache file '%s' to '%s': %d",
                              temporary_path, *final_path, result);
                CGUTILS_FREE(*final_path);
            }

        }
        else
        {
            CGUTILS_ERROR("Error computing path for inode %"PRIu64", FS %s: %d",
                          inode_number,
                          cg_storage_filesystem_get_name(this->fs),
                          result);
        }

    }

    return result;
}


int cg_storage_cache_truncate(cg_storage_cache * const this,
                              uint64_t const inode_number,
                              off_t const offset)
{
    int result = EINVAL;

    if (this != NULL)
    {
        char * final_path = NULL;
        size_t final_path_len = 0;

        result = cg_storage_cache_get_existing_path(this,
                                                    inode_number,
                                                    false,
                                                    &final_path,
                                                    &final_path_len);

        if (result == 0)
        {
            result = cgutils_file_truncate(final_path, offset);

            if (result != 0)
            {
                CGUTILS_ERROR("Error truncating file %s: %d",
                              final_path,
                              result);
            }

            CGUTILS_FREE(final_path);
        }
        else
        {
            CGUTILS_ERROR("Error computing path for inode %"PRIu64", FS %s: %d",
                          inode_number,
                          cg_storage_filesystem_get_name(this->fs),
                          result);
        }
    }
    else
    {
        CGUTILS_DEBUG("EINVAL");
    }

    return result;
}

int cg_storage_cache_utimens(cg_storage_cache * const this,
                             uint64_t const inode_number,
                             struct timespec const ts[2])
{
    int result = EINVAL;

    if (this != NULL)
    {
        char * final_path = NULL;
        size_t final_path_len = 0;

        result = cg_storage_cache_get_existing_path(this,
                                                    inode_number,
                                                    false,
                                                    &final_path,
                                                    &final_path_len);

        if (result == 0)
        {
            result = cgutils_file_utimens(final_path, ts);

            if (result != 0 &&
                result != ENOENT)
            {
                CGUTILS_ERROR("Error updating time on file %s: %d",
                              final_path,
                              result);
            }

            CGUTILS_FREE(final_path);
        }
        else
        {
            CGUTILS_ERROR("Error computing path for inode %"PRIu64", FS %s: %d",
                          inode_number,
                          cg_storage_filesystem_get_name(this->fs),
                          result);
        }
    }
    else
    {
        CGUTILS_DEBUG("EINVAL");
    }

    return result;
}

int cg_storage_cache_get_usage(cg_storage_cache const * const this,
                               uint64_t * const total,
                               uint64_t * const ufree,
                               uint64_t * const non_priv_free)
{
    int result = EINVAL;

    if (this != NULL && total != NULL && ufree != NULL && non_priv_free != NULL)
    {
        result = cgutils_file_get_fs_usage(this->cache_root,
                                           total,
                                           ufree,
                                           non_priv_free);

        if (result != 0)
        {
            if (result == ENOENT)
            {
                CGUTILS_DEBUG("The cache directory %s does not exists: %d",
                              this->cache_root,
                              result);
            }
            else
            {
                CGUTILS_ERROR("Error in cgutils_file_get_fs_usage(%s): %d",
                              this->cache_root,
                              result);
            }
        }
    }

    return result;
}

int cg_storage_cache_refresh_stats_from_cache_if_needed(struct stat * const st,
                                                        char const * const path_in_cache)
{
    int result = EINVAL;

    if (st != NULL &&
        path_in_cache != NULL)
    {
        struct stat cache_st;

        result = cgutils_file_stat(path_in_cache, &cache_st);

        if (result == 0)
        {
            if (st->st_mtime <= cache_st.st_mtime)
            {
                st->st_size = cache_st.st_size;
                st->st_atime = cache_st.st_atime;
                st->st_mtime = cache_st.st_mtime;
            }
        }
        else
        {
            if (result == ENOENT)
            {
                result = 0;
            }
        }

    }

    return result;
}

int cg_storage_cache_refresh_db_stats(cg_storage_cache const * const this,
                                      cgdb_entry * const entry)
{
    int result = EINVAL;

    if (this != NULL &&
        entry != NULL)
    {
        result = 0;

        if (COMPILER_UNLIKELY(entry->inode.dirty_writers > 0))
        {
            /* Check if the cache is more recent, it may occur if the file is dirty */
            char * path_in_cache = NULL;
            size_t path_in_cache_len = 0;

            result = cg_storage_cache_get_existing_path(this,
                                                        entry->inode.inode_number,
                                                        false,
                                                        &path_in_cache,
                                                        &path_in_cache_len);

            if (result == 0)
            {
                bool cache_ok = false;

                result = cg_storage_cache_check_freshness_stats(this,
                                                                &entry->inode.st,
                                                                path_in_cache,
                                                                &cache_ok);

                if (result == 0)
                {
                    if (cache_ok == true)
                    {
                        cg_storage_cache_refresh_stats_from_cache_if_needed(&entry->inode.st,
                                                                            path_in_cache);
                    }
                }
                else if (result != ENOENT)
                {
                    CGUTILS_WARN("Error checking cache validity for inode %"PRIu64" on fs %s: %d",
                                 entry->inode.inode_number,
                                 cg_storage_filesystem_get_name(this->fs),
                                 result);
                }

                CGUTILS_FREE(path_in_cache);
            }
            else
            {
                CGUTILS_WARN("Error getting path in cache for inode %"PRIu64" on fs %s: %d",
                             entry->inode.inode_number,
                             cg_storage_filesystem_get_name(this->fs),
                             result);
            }
        }
    }

    return result;
}
