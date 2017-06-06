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
#include <limits.h>
#include <stdbool.h>
#include <string.h>

#include <cgdb/cgdb.h>
#include <cgdb/cgdb_utils.h>
#include "cgdb_utils_internal.h"

struct cgdb_row
{
    cgdb_field * fields;
    size_t fields_count;
};

static int cgdb_set_operator_field_internal(cgdb_field * const this,
                                            char const * const name,
                                            size_t const name_len,
                                            cgdb_field_value_type const type,
                                            cgdb_field_operator_type const operator_type)
{
    assert(this != NULL);
    assert(name != NULL);

    int result = 0;

    this->name = name;

    this->name_len = name_len;
    this->operator_type = operator_type;
    this->value_type = type;

    return result;
}

void cgdb_param_array_init(cgdb_param params[],
                           size_t const count)
{
    for (size_t idx = 0;
         idx < count;
         idx++)
    {
        params[idx].value = NULL;
        params[idx].type = CGDB_FIELD_VALUE_TYPE_NULL;
    }
}

void cgdb_param_set_uint64(cgdb_param params[],
                           size_t * const position,
                           uint64_t const * const value)
{
    params[*position].value = value;
    params[*position].type = CGDB_FIELD_VALUE_TYPE_UINT64;
    (*position)++;
}

void cgdb_param_set_int64(cgdb_param params[],
                          size_t * const position,
                          int64_t const * const value)
{
    params[*position].value = value;
    params[*position].type = CGDB_FIELD_VALUE_TYPE_INT64;
    (*position)++;
}

void cgdb_param_set_int32(cgdb_param params[],
                          size_t * const position,
                          int32_t const * const value)
{
    params[*position].value = value;
    params[*position].type = CGDB_FIELD_VALUE_TYPE_INT32;
    (*position)++;
}

void cgdb_param_set_uint16(cgdb_param params[],
                           size_t * const position,
                           uint16_t const * const value)
{
    params[*position].value = value;
    params[*position].type = CGDB_FIELD_VALUE_TYPE_UINT16;
    (*position)++;
}

void cgdb_param_set_boolean(cgdb_param params[],
                            size_t * const position,
                            bool const * const value)
{
    params[*position].value = value;
    params[*position].type = CGDB_FIELD_VALUE_TYPE_BOOLEAN;
    (*position)++;
}

void cgdb_param_set_string(cgdb_param params[],
                           size_t * const position,
                           char const * const value)
{
    params[*position].value = value;
    params[*position].type = CGDB_FIELD_VALUE_TYPE_STRING;
    (*position)++;
}

void cgdb_param_set_immutable_string(cgdb_param params[],
                                     size_t * const position,
                                     char const * const value)
{
    params[*position].value = value;
    params[*position].type = CGDB_FIELD_VALUE_TYPE_IMMUTABLE_STRING;
    (*position)++;
}

void cgdb_param_set_null(cgdb_param params[],
                         size_t * const position)
{
    params[*position].value = NULL;
    params[*position].type = CGDB_FIELD_VALUE_TYPE_NULL;
    (*position)++;
}

int cgdb_get_inode_from_row(cgdb_row const * const row,
                            cgdb_inode ** const out)
{
    int result = EINVAL;

    CGUTILS_ASSERT(row != NULL);
    CGUTILS_ASSERT(out != NULL);
    uint64_t inode_number = 0;
    uint64_t uid = 0;
    uint64_t gid = 0;
    uint64_t mode = 0;
    uint64_t size = 0;
    uint64_t atime = 0;
    uint64_t ctime = 0;
    uint64_t mtime = 0;
    uint64_t last_usage = 0;
    uint64_t last_modification = 0;
    uint64_t nlink = 0;
    uint64_t dirty_writers = 0;
    bool in_cache = false;
    char * digest = NULL;
    uint16_t digest_type = 0;

    result = 0;

#define GET(type, name, optional)                                       \
    if (COMPILER_LIKELY(result == 0))                                   \
    {                                                                   \
        result = cgdb_row_get_field_value_as_ ## type(row, #name, &name); \
        if (result == ENOENT && optional == true)                       \
        {                                                               \
            result = 0;                                                 \
        }                                                               \
        else if (COMPILER_UNLIKELY(result != 0))                        \
        {                                                               \
            CGUTILS_ERROR("Error getting field '%s': %d", #name, result); \
        }                                                               \
    }
GET(uint64, inode_number, false)
GET(uint64, uid, false)
GET(uint64, gid, false)
GET(uint64, mode, false)
GET(uint64, size, false)
GET(uint64, atime, false)
GET(uint64, ctime, false)
GET(uint64, mtime, false)
GET(uint64, last_usage, false)
GET(uint64, last_modification, false)
GET(uint64, nlink, false)
GET(uint64, dirty_writers, false)
GET(boolean, in_cache, false)
GET(string, digest, true)
GET(uint16, digest_type, true)
#undef GET

    if (COMPILER_LIKELY(result == 0))
    {
        cgdb_inode * inode = NULL;

        CGUTILS_ALLOCATE_STRUCT(inode);

        if (COMPILER_LIKELY(inode != NULL))
        {
            inode->inode_number = inode_number;
            inode->st.st_uid = (uid_t) uid;
            inode->st.st_gid = (gid_t) gid;
            inode->st.st_mode = (mode_t) mode;
            inode->st.st_nlink = (nlink_t) nlink;
            COMPILER_STATIC_ASSERT(sizeof(ino_t) <= sizeof(uint64_t),
                                   "The size of the ino_t type should be <= the size of uint64_t");
            inode->st.st_ino = (ino_t) inode_number;
            inode->last_usage = last_usage;
            inode->last_modification = last_modification;
            inode->dirty_writers = dirty_writers;
            inode->in_cache = in_cache;
            inode->digest = digest;
            inode->digest_type = (uint8_t) digest_type;

            if (digest != NULL)
            {
                inode->digest_size = strlen(digest);
            }

            inode->st.st_size = (size <= LONG_MAX) ? (long) size : 0;
            inode->st.st_atime = (atime <= LONG_MAX) ? (long) atime : 0;
            inode->st.st_ctime = (ctime <= LONG_MAX) ? (long) ctime : 0;
            inode->st.st_mtime = (mtime <= LONG_MAX) ? (long) mtime : 0;

            *out = inode;
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for inode: %d",
                          result);
        }
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_FREE(digest);
    }

    return result;
}

int cgdb_get_entry_from_row(cgdb_row const * const row,
                            cgdb_entry ** const out)
{
    int result = EINVAL;

    CGUTILS_ASSERT(row != NULL);
    CGUTILS_ASSERT(out != NULL);
    uint64_t entry_id = 0;
    uint64_t fs_id = 0;
    uint16_t type = 0;
    char * name = NULL;
    char * link_to = NULL;
    uint64_t inode_number = 0;
    uint64_t uid = 0;
    uint64_t gid = 0;
    uint64_t mode = 0;
    uint64_t size = 0;
    uint64_t atime = 0;
    uint64_t ctime = 0;
    uint64_t mtime = 0;
    uint64_t last_usage = 0;
    uint64_t last_modification = 0;
    uint64_t nlink = 0;
    uint64_t dirty_writers = 0;
    bool in_cache = false;
    char * digest = NULL;
    uint16_t digest_type = 0;

    result = 0;

#define GET(type, name, idx, optional)                                  \
    if (COMPILER_LIKELY(result == 0))                                   \
    {                                                                   \
        result = cgdb_row_get_field_value_as_ ## type ## _by_idx(row, idx, &name); \
        if (result == ENOENT && optional == true)                       \
        {                                                               \
            result = 0;                                                 \
        }                                                               \
        else if (COMPILER_UNLIKELY(result != 0))                        \
        {                                                               \
            CGUTILS_ERROR("Error getting field '%s': %d", #name, result); \
        }                                                               \
    }
GET(uint64, entry_id, 1, false)
GET(uint64, fs_id, 2, false)
GET(uint16, type, 3, false)
GET(string, name, 4, false)
GET(string, link_to, 5, false)
GET(uint64, inode_number, 6, false)
GET(uint64, uid, 7, false)
GET(uint64, gid, 8, false)
GET(uint64, mode, 9, false)
GET(uint64, size, 10, false)
GET(uint64, atime, 11, false)
GET(uint64, ctime, 12, false)
GET(uint64, mtime, 13, false)
GET(uint64, last_usage, 14, false)
GET(uint64, last_modification, 15, false)
GET(uint64, nlink, 16, false)
GET(uint64, dirty_writers, 17, false)
GET(boolean, in_cache, 18, false)
GET(string, digest, 19, true)
GET(uint16, digest_type, 20, true)
#undef GET

    if (COMPILER_LIKELY(result == 0))
    {
        cgdb_entry * entry = NULL;

        CGUTILS_ALLOCATE_STRUCT(entry);

        if (COMPILER_LIKELY(entry != NULL))
        {
            entry->name = name;
            entry->link_to = link_to;
            entry->entry_id = entry_id;
            entry->fs_id = fs_id;
            entry->type = type;

            entry->inode.inode_number = inode_number;
            entry->inode.st.st_uid = (uid_t) uid;
            entry->inode.st.st_gid = (gid_t) gid;
            entry->inode.st.st_mode = (mode_t) mode;
            entry->inode.st.st_nlink = (nlink_t) nlink;
            COMPILER_STATIC_ASSERT(sizeof(ino_t) <= sizeof(uint64_t),
                                   "The size of the ino_t type should be <= the size of uint64_t");
            entry->inode.st.st_ino = (ino_t) inode_number;
            entry->inode.last_usage = last_usage;
            entry->inode.last_modification = last_modification;
            entry->inode.dirty_writers = dirty_writers;
            entry->inode.in_cache = in_cache;
            entry->inode.digest = digest;
            entry->inode.digest_type = (uint8_t) digest_type;

            if (digest != NULL)
            {
                entry->inode.digest_size = strlen(digest);
            }

            entry->inode.st.st_size = (size <= LONG_MAX) ? (long) size : 0;
            entry->inode.st.st_atime = (atime <= LONG_MAX) ? (long) atime : 0;
            entry->inode.st.st_ctime = (ctime <= LONG_MAX) ? (long) ctime : 0;
            entry->inode.st.st_mtime = (mtime <= LONG_MAX) ? (long) mtime : 0;

            *out = entry;
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for entry: %d", result);
        }

    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_FREE(name);
        CGUTILS_FREE(link_to);
        CGUTILS_FREE(digest);
    }

    return result;
}

int cgdb_get_delayed_expunge_entry_from_row(cgdb_row const * const row,
                                            cgdb_delayed_expunge_entry ** const out)
{
    int result = EINVAL;

    if (row != NULL &&
        out != NULL)
    {
        char * full_path = NULL;
        uint64_t fs_id = 0;
        uint64_t inode_number = 0;
        uint64_t delete_after = 0;
        uint64_t deletion_time = 0;
        uint64_t uid = 0;
        uint64_t gid = 0;
        uint64_t mode = 0;
        uint64_t size = 0;
        uint64_t atime = 0;
        uint64_t ctime = 0;
        uint64_t mtime = 0;
        uint64_t nlink = 0;
        bool in_cache = false;

        result = 0;

#define GET(type, name, optional)                                       \
        if (result == 0)                                                \
        {                                                               \
            result = cgdb_row_get_field_value_as_ ## type(row, #name, &name); \
            if (result == ENOENT && optional == true)               \
            {                                                           \
                result = 0;                                             \
            }                                                           \
            else if (result != 0)                                       \
            {                                                           \
                CGUTILS_ERROR("Error getting field '%s': %d", #name, result); \
            }                                                           \
        }
GET(string, full_path, false)
GET(uint64, fs_id, false)
GET(uint64, inode_number, false)
GET(uint64, delete_after, false)
GET(uint64, deletion_time, false)
GET(uint64, uid, false)
GET(uint64, gid, false)
GET(uint64, mode, false)
GET(uint64, size, false)
GET(uint64, atime, false)
GET(uint64, ctime, false)
GET(uint64, mtime, false)
GET(uint64, nlink, false)
GET(boolean, in_cache, false)
#undef GET

        if (result == 0)
        {
            cgdb_delayed_expunge_entry * delayed_entry = NULL;

            CGUTILS_ALLOCATE_STRUCT(delayed_entry);

            if (delayed_entry != NULL)
            {
                cgdb_entry * entry = &(delayed_entry->entry);

                entry->name = NULL;
                entry->link_to = NULL;
                entry->entry_id = 0;
                entry->fs_id = fs_id;
                entry->type = CGDB_OBJECT_TYPE_FILE;

                entry->inode.inode_number = inode_number;
                entry->inode.st.st_uid = (uid_t) uid;
                entry->inode.st.st_gid = (gid_t) gid;
                entry->inode.st.st_mode = (mode_t) mode;
                entry->inode.st.st_nlink = (nlink_t) nlink;
                COMPILER_STATIC_ASSERT(sizeof(ino_t) <= sizeof(uint64_t),
                                       "The size of the ino_t type should be <= the size of uint64_t");
                entry->inode.st.st_ino = (ino_t) inode_number;
                entry->inode.st.st_size = (size <= LONG_MAX) ? (long) size : 0;
                entry->inode.st.st_atime = (atime <= LONG_MAX) ? (long) atime : 0;
                entry->inode.st.st_ctime = (ctime <= LONG_MAX) ? (long) ctime : 0;
                entry->inode.st.st_mtime = (mtime <= LONG_MAX) ? (long) mtime : 0;

                entry->inode.dirty_writers = 0;
                entry->inode.in_cache = in_cache;
                entry->inode.digest = NULL;
                entry->inode.digest_type = 0;

                delayed_entry->full_path = full_path;

                delayed_entry->delete_after = delete_after;
                delayed_entry->deletion_time = deletion_time;

                *out = delayed_entry;
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for entry: %d", result);
            }

        }

        if (result != 0)
        {
            CGUTILS_FREE(full_path);
        }
    }

    return result;
}

int cgdb_get_inode_instance_from_row(cgdb_row const * const row,
                                     cgdb_inode_instance ** const out)
{
    assert(row != NULL);
    assert(out != NULL);

    int result = 0;

    uint64_t upload_time = 0;
    uint64_t inode_mtime = 0;
    uint64_t inode_last_modification = 0;
    uint64_t inode_size = 0;
    uint64_t instance_id = 0;
    uint64_t inode_number = 0;
    uint64_t inode_dirty_writers = 0;
    char * id_in_instance = NULL;
    uint64_t fs_id = 0;
    bool uploading = false;
    bool deleting = false;
    uint8_t status = 0;
    uint8_t inode_digest_type = 0;

#define GET(type, name, optional)                                       \
    if (result == 0)                                                    \
    {                                                                   \
        result = cgdb_row_get_field_value_as_ ## type(row, #name, &name); \
        if (result == ENOENT && optional == true)                       \
        {                                                               \
            result = 0;                                                 \
        }                                                               \
        else if (result != 0)                                           \
        {                                                               \
            CGUTILS_ERROR("Error getting field %s: %d", #name, result); \
        }                                                               \
    }
GET(uint64, instance_id, false)
GET(uint64, inode_number, false)
GET(uint64, upload_time, false)
GET(uint64, inode_mtime, true)
GET(uint64, inode_last_modification, true)
GET(uint64, inode_size, true)
GET(uint64, inode_dirty_writers, true)
GET(string, id_in_instance, false)
GET(uint64, fs_id, false)
GET(boolean, uploading, false)
GET(boolean, deleting, false)
GET(uint8, status, false)
GET(uint8, inode_digest_type, true)
#undef GET

    if (result == 0)
    {
        CGUTILS_ALLOCATE_STRUCT(*out);

        if (*out != NULL)
        {
            cgdb_inode_instance * this = *out;
            this->upload_time = upload_time;
            this->inode_mtime = inode_mtime;
            this->inode_last_modification = inode_last_modification;
            this->instance_id = instance_id;
            this->inode_number = inode_number;
            this->id_in_instance = id_in_instance;
            this->inode_dirty_writers = inode_dirty_writers;
            this->inode_size = (size_t) inode_size;
            this->inode_digest_type = inode_digest_type;
            this->fs_id = fs_id;
            this->status = status;
            this->uploading = uploading;
            this->deleting = deleting;
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating object: %d", result);
        }
    }

    if (result != 0)
    {
        CGUTILS_FREE(id_in_instance);
    }

    return result;
}

int cgdb_field_set_string(cgdb_field * const this,
                          char const * const name,
                          size_t const name_len,
                          char const * const value)
{
    int result = EINVAL;

    if (CGUTILS_COMPILER_LIKELY(this != NULL &&
                                name != NULL &&
                                value != NULL))
    {
        char * value_str = cgutils_strdup(value);

        if (CGUTILS_COMPILER_LIKELY(value_str != NULL))
        {
            result = cgdb_set_operator_field_internal(this,
                                                      name,
                                                      name_len,
                                                      CGDB_FIELD_VALUE_TYPE_STRING,
                                                      CGDB_FIELD_OPERATOR_EQUAL);

            if (CGUTILS_COMPILER_LIKELY(result == 0))
            {
                this->value_str = value_str;
            }
            else
            {
                CGUTILS_FREE(value_str);
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgdb_field_set_null(cgdb_field * const this,
                        char const * const name,
                        size_t const name_len)
{
    int result = EINVAL;

    if (this != NULL &&
        name != NULL)
    {
        result = cgdb_set_operator_field_internal(this,
                                                  name,
                                                  name_len,
                                                  CGDB_FIELD_VALUE_TYPE_NULL,
                                                  CGDB_FIELD_OPERATOR_EQUAL);

    }

    return result;
}

int cgdb_field_set_uint64(cgdb_field * const  this,
                          char const * const name,
                          size_t const name_len,
                          uint64_t const value)
{
    int result = EINVAL;

    if (CGUTILS_COMPILER_LIKELY(this != NULL &&
                                name != NULL))
    {
        result = cgdb_set_operator_field_internal(this,
                                                  name,
                                                  name_len,
                                                  CGDB_FIELD_VALUE_TYPE_UINT64,
                                                  CGDB_FIELD_OPERATOR_EQUAL);

        if (CGUTILS_COMPILER_LIKELY(result == 0))
        {
            this->value_uint64 = value;
        }
    }

    return result;
}

int cgdb_field_set_uint16(cgdb_field * const this,
                          char const * const name,
                          size_t const name_len,
                          uint16_t const value)
{
    int result = EINVAL;

    if (this != NULL &&
        name != NULL)
    {
        result = cgdb_set_operator_field_internal(this,
                                                  name,
                                                  name_len,
                                                  CGDB_FIELD_VALUE_TYPE_UINT16,
                                                  CGDB_FIELD_OPERATOR_EQUAL);

        if (CGUTILS_COMPILER_LIKELY(result == 0))
        {
            this->value_uint16 = value;
        }
    }

    return result;
}

int cgdb_field_set_boolean(cgdb_field * const this,
                           char const * const name,
                           size_t const name_len,
                           bool const value)
{
    int result = EINVAL;

    if (this != NULL &&
        name != NULL)
    {
        result = cgdb_set_operator_field_internal(this,
                                                  name,
                                                  name_len,
                                                  CGDB_FIELD_VALUE_TYPE_BOOLEAN,
                                                  CGDB_FIELD_OPERATOR_EQUAL);
        if (CGUTILS_COMPILER_LIKELY(result == 0))
        {
            this->value_bool = value;
        }
    }

    return result;
}

int cgdb_field_set_int32(cgdb_field * const this,
                         char const * const name,
                         size_t const name_len,
                         int32_t const value)
{
    int result = EINVAL;

    if (this != NULL &&
        name != NULL)
    {
        result = cgdb_set_operator_field_internal(this,
                                                  name,
                                                  name_len,
                                                  CGDB_FIELD_VALUE_TYPE_INT32,
                                                  CGDB_FIELD_OPERATOR_EQUAL);

        if (CGUTILS_COMPILER_LIKELY(result == 0))
        {
            this->value_int32 = value;
        }
    }

    return result;
}

int cgdb_field_set_int64(cgdb_field * const this,
                         char const * const name,
                         size_t const name_len,
                         int64_t const value)
{
    int result = EINVAL;

    if (this != NULL &&
        name != NULL)
    {
        result = cgdb_set_operator_field_internal(this,
                                                  name,
                                                  name_len,
                                                  CGDB_FIELD_VALUE_TYPE_INT64,
                                                  CGDB_FIELD_OPERATOR_EQUAL);

        if (CGUTILS_COMPILER_LIKELY(result == 0))
        {
            this->value_int64 = value;
        }
    }

    return result;
}

void cgdb_field_clean(cgdb_field * this)
{
    if (COMPILER_LIKELY(this != NULL))
    {
        if (this->value_type == CGDB_FIELD_VALUE_TYPE_STRING ||
            this->value_type == CGDB_FIELD_VALUE_TYPE_FIELD)
        {
            CGUTILS_FREE(this->value_str);
        }

        this->value_type = CGDB_FIELD_VALUE_TYPE_NULL;
        this->name_len = 0;
    }
}

void cgdb_field_free(cgdb_field * this)
{
    if (this != NULL)
    {
        cgdb_field_clean(this);

        CGUTILS_FREE(this);
    }
}

int cgdb_row_init(cgdb_row ** const row,
                  size_t fields_count)
{
    int result = EINVAL;

    if (CGUTILS_COMPILER_LIKELY(row != NULL &&
                                fields_count > 0))
    {
        result = ENOMEM;

        CGUTILS_ALLOCATE_STRUCT(*row);

        if (CGUTILS_COMPILER_LIKELY(*row != NULL))
        {
            CGUTILS_MALLOC((*row)->fields, fields_count, sizeof *((*row)->fields));

            if (CGUTILS_COMPILER_LIKELY((*row)->fields != NULL))
            {
                for (size_t idx = 0;
                     idx < fields_count;
                     idx++)
                {
                    (*row)->fields[idx] = (cgdb_field) { 0 };
                }

                result = 0;

                (*row)->fields_count = fields_count;
            }

            if (CGUTILS_COMPILER_UNLIKELY(result != 0))
            {
                cgdb_row_free(*row), *row = NULL;
            }
        }
    }

    return result;
}

int cgdb_row_get_field_by_name(cgdb_row const * const row,
                               char const * const field_name,
                               cgdb_field ** const field)
{
    int result = EINVAL;

    if (CGUTILS_COMPILER_LIKELY(row != NULL &&
                                field_name != NULL &&
                                field != NULL))
    {
        size_t const fields_count = row->fields_count;
        size_t const field_name_len = strlen(field_name);
        result = ENOENT;

        for (size_t idx = 0;
             result == ENOENT &&
                 idx < fields_count;
             idx++)
        {
            cgdb_field * current = &(row->fields[idx]);
            CGUTILS_ASSERT(current != NULL);

            if (field_name_len == current->name_len &&
                strcmp(current->name, field_name) == 0)
            {
                result = 0;
                *field = current;
            }
        }
    }

    return result;
}

int cgdb_row_get_field_by_idx(cgdb_row const * const row,
                              size_t const idx,
                              cgdb_field ** const field)
{
    int result = 0;
    CGUTILS_ASSERT(row != NULL);
    CGUTILS_ASSERT(field != NULL);

    if (COMPILER_LIKELY(idx < row->fields_count))
    {
        *field = &(row->fields[idx]);
    }
    else
    {
        result = ENOENT;
    }

    return result;
}

int cgdb_row_get_field_value_as_string(cgdb_row const * const row,
                                       char const * const field_name,
                                       char ** const value)
{
    int result = 0;

    if (COMPILER_LIKELY(row != NULL &&
                        field_name != NULL &&
                        value != NULL))
    {
        cgdb_field * field = NULL;

        result = cgdb_row_get_field_by_name(row, field_name, &field);

        if (COMPILER_LIKELY(result == 0))
        {
            if (COMPILER_LIKELY(field->value_type == CGDB_FIELD_VALUE_TYPE_STRING))
            {
                *value = cgutils_strdup(field->value_str);

                if (COMPILER_UNLIKELY(*value == NULL))
                {
                    result = ENOMEM;
                }
            }
            else
            {
                result = EINVAL;
            }
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgdb_row_get_field_value_as_string_by_idx(cgdb_row const * const row,
                                              size_t const idx,
                                              char ** const value)
{
    int result = 0;

    if (COMPILER_LIKELY(row != NULL &&
                        value != NULL))
    {
        cgdb_field * field = NULL;

        result = cgdb_row_get_field_by_idx(row,
                                           idx,
                                           &field);

        if (COMPILER_LIKELY(result == 0))
        {
            if (COMPILER_LIKELY(field->value_type == CGDB_FIELD_VALUE_TYPE_STRING))
            {
                *value = cgutils_strdup(field->value_str);

                if (COMPILER_UNLIKELY(*value == NULL))
                {
                    result = ENOMEM;
                }
            }
            else
            {
                result = EINVAL;
            }
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgdb_row_get_field_value_as_boolean(cgdb_row const * const row,
                                        char const * const field_name,
                                        bool * const value)
{
    int result = EINVAL;

    if (row != NULL && field_name != NULL && value != NULL)
    {
        cgdb_field * field = NULL;

        result = cgdb_row_get_field_by_name(row, field_name, &field);

        if (result == 0)
        {
            if (field->value_type == CGDB_FIELD_VALUE_TYPE_BOOLEAN)
            {
                *value = field->value_bool;
            }
            else
            {
                result = EINVAL;
            }
        }
    }

    return result;
}

int cgdb_row_get_field_value_as_boolean_by_idx(cgdb_row const * const row,
                                               size_t const idx,
                                               bool * const value)
{
    int result = 0;

    if (COMPILER_LIKELY(row != NULL &&
                        value != NULL))
    {
        cgdb_field * field = NULL;

        result = cgdb_row_get_field_by_idx(row,
                                           idx,
                                           &field);

        if (COMPILER_LIKELY(result == 0))
        {
            if (COMPILER_LIKELY(field->value_type == CGDB_FIELD_VALUE_TYPE_BOOLEAN))
            {
                *value = field->value_bool;
            }
            else
            {
                result = EINVAL;
            }
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgdb_row_get_field_value_as_uint8(cgdb_row const * const row,
                                      char const * const field_name,
                                      uint8_t * const value)
{
    int result = EINVAL;

    if (row != NULL && field_name != NULL && value != NULL)
    {
        cgdb_field * field = NULL;

        result = cgdb_row_get_field_by_name(row, field_name, &field);

        if (result == 0)
        {
            if (field->value_type == CGDB_FIELD_VALUE_TYPE_UINT16)
            {
                uint16_t const tmp = field->value_uint16;

                if (tmp <= UINT8_MAX)
                {
                    *value = (uint8_t) tmp;
                }
                else
                {
                    CGUTILS_WARN("Trying to get field %s value as a type %d, but it is really a %d type",
                                 field_name, CGDB_FIELD_VALUE_TYPE_UINT16, field->value_type);
                    result = EINVAL;
                }
            }
            else
            {
                result = EINVAL;
            }
        }
    }

    return result;
}

int cgdb_row_get_field_value_as_uint16(cgdb_row const * const row,
                                       char const * const field_name,
                                       uint16_t * const value)
{
    int result = EINVAL;

    if (row != NULL && field_name != NULL && value != NULL)
    {
        cgdb_field * field = NULL;

        result = cgdb_row_get_field_by_name(row, field_name, &field);

        if (result == 0)
        {
            if (field->value_type == CGDB_FIELD_VALUE_TYPE_UINT16)
            {
                *value = field->value_uint16;
            }
            else
            {
                CGUTILS_WARN("Trying to get field %s value as a type %d, but it is really a %d type",
                             field_name, CGDB_FIELD_VALUE_TYPE_UINT16, field->value_type);
                result = EINVAL;
            }
        }
    }

    return result;
}

int cgdb_row_get_field_value_as_uint16_by_idx(cgdb_row const * const row,
                                              size_t const idx,
                                              uint16_t * const value)
{
    int result = 0;

    if (COMPILER_LIKELY(row != NULL &&
                        value != NULL))
    {
        cgdb_field * field = NULL;

        result = cgdb_row_get_field_by_idx(row,
                                           idx,
                                           &field);

        if (COMPILER_LIKELY(result == 0))
        {
            if (COMPILER_LIKELY(field->value_type == CGDB_FIELD_VALUE_TYPE_UINT16))
            {
                *value = field->value_uint16;
            }
            else
            {
                CGUTILS_WARN("Trying to get field %zu value as a type %d, but it is really a %d type",
                             idx,
                             CGDB_FIELD_VALUE_TYPE_UINT16,
                             field->value_type);
                result = EINVAL;
            }
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgdb_row_get_field_value_as_uint64(cgdb_row const * const row,
                                       char const * const field_name,
                                       uint64_t * const value)
{
    int result = EINVAL;

    if (row != NULL && field_name != NULL && value != NULL)
    {
        cgdb_field * field = NULL;

        result = cgdb_row_get_field_by_name(row, field_name, &field);

        if (result == 0)
        {
            if (field->value_type == CGDB_FIELD_VALUE_TYPE_UINT64)
            {
                *value = field->value_uint64;
            }
            else
            {
                CGUTILS_WARN("Trying to get field %s value as a type %d, but it is really a %d type",
                             field_name, CGDB_FIELD_VALUE_TYPE_UINT64, field->value_type);

                result = EINVAL;
            }
        }
    }

    return result;
}

int cgdb_row_get_field_value_as_uint64_by_idx(cgdb_row const * const row,
                                              size_t const idx,
                                              uint64_t * const value)
{
    int result = 0;

    if (COMPILER_LIKELY(row != NULL &&
                        value != NULL))
    {
        cgdb_field * field = NULL;

        result = cgdb_row_get_field_by_idx(row,
                                           idx,
                                           &field);

        if (COMPILER_LIKELY(result == 0))
        {
            if (COMPILER_LIKELY(field->value_type == CGDB_FIELD_VALUE_TYPE_UINT64))
            {
                *value = field->value_uint64;
            }
            else
            {
                CGUTILS_WARN("Trying to get field %zu value as a type %d, but it is really a %d type",
                             idx,
                             CGDB_FIELD_VALUE_TYPE_UINT64,
                             field->value_type);

                result = EINVAL;
            }
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}


void cgdb_row_free(cgdb_row * this)
{
    if (COMPILER_LIKELY(this != NULL))
    {
        if (COMPILER_LIKELY(this->fields != NULL))
        {
            for (size_t idx = 0;
                 idx < this->fields_count;
                 idx++)
            {
                cgdb_field_clean(&(this->fields[idx]));
            }

            CGUTILS_FREE(this->fields);
        }

        CGUTILS_FREE(this);
    }
}

bool cgdb_limit_is_valid(cgdb_limit_type const type)
{
    bool result = false;

    if (type != CGDB_LIMIT_NONE &&
        type >= 0 &&
        type <= UINT32_MAX)
    {
        result = true;
    }

    return result;
}

bool cgdb_skip_is_valid(cgdb_skip_type const type)
{
    bool result = false;

    if (type != CGDB_SKIP_NONE &&
        type >= 0 &&
        type <= UINT32_MAX)
    {
        result = true;
    }

    return result;
}
