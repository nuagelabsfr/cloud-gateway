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

#include "cloudutils/cloudutils.h"
#include "cloudutils/cloudutils_json_reader.h"
#include "cloudutils/cloudutils_file.h"

#include <json-c/json_object.h>
#include <json-c/json.h>

#define JSON_READER_BUFFER_SIZE (4096)

struct cgutils_json_reader
{
    struct json_object * object;
    cgutils_json_reader * parent;
    size_t refs_count;
};

static int cgutils_json_reader_from_object(struct json_object * object,
                                           cgutils_json_reader ** const out)
{
    int result = 0;
    cgutils_json_reader * this = NULL;
    CGUTILS_ASSERT(object != NULL);
    CGUTILS_ASSERT(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(this);

    if (this != NULL)
    {
        this->object = object;
        this->refs_count = 0;
        *out = this;
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

int cgutils_json_reader_from_buffer(char const * const data,
                                    size_t const data_size,
                                    cgutils_json_reader ** const out)
{
    int result = EINVAL;

    if (data != NULL &&
        data_size > 0 &&
        out != NULL &&
        data_size <= INT_MAX)
    {
        struct json_tokener * tokener = json_tokener_new();

        if (tokener != NULL)
        {
            struct json_object * object = json_tokener_parse_ex(tokener,
                                                                data,
                                                                (int) data_size);

            if (object != NULL)
            {
                result = cgutils_json_reader_from_object(object,
                                                         out);

                if (result != 0)
                {
                    json_object_put(object), object = NULL;
                }
            }
            else
            {
                enum json_tokener_error const error = json_tokener_get_error(tokener);
                CGUTILS_ERROR("Error parsing JSON: %s",
                              json_tokener_error_desc(error));
                result = EIO;
            }

            json_tokener_free(tokener), tokener = NULL;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_json_reader_from_file(char const * const file,
                                  cgutils_json_reader ** const out)
{
    int result = EINVAL;

    if (file != NULL &&
        out != NULL)
    {
        int fd = -1;

        result = cgutils_file_open(file,
                                   O_RDONLY,
                                   0,
                                   &fd);

        if (result == 0)
        {
            struct json_tokener * tokener = json_tokener_new();

            if (tokener != NULL)
            {
                struct json_object * object = NULL;
                char buffer[JSON_READER_BUFFER_SIZE];
                size_t const buffer_size = sizeof buffer;
                size_t got = 0;
                bool finished = false;

                result = cgutils_file_read(fd,
                                           buffer,
                                           buffer_size,
                                           &got);

                while(result == 0 &&
                      got > 0 &&
                      finished == false)
                {
                    CGUTILS_ASSERT((size_t) got <= buffer_size);
                    CGUTILS_ASSERT(buffer_size <= INT_MAX);

                    object = json_tokener_parse_ex(tokener,
                                                   buffer,
                                                   (int) got);

                    if (object == NULL)
                    {
                        enum json_tokener_error const error = json_tokener_get_error(tokener);

                        if (error == json_tokener_continue)
                        {
                            /* ok, we need to read more. */
                        }
                        else
                        {
                            CGUTILS_ERROR("Error parsing JSON: %s\n",
                                          json_tokener_error_desc(error));
                            result = EINVAL;
                        }
                    }
                    else
                    {
                        finished = true;
                    }

                    if (finished == false)
                    {
                        result = cgutils_file_read(fd,
                                                   buffer,
                                                   buffer_size,
                                                   &got);
                    }
                }

                if (result == 0)
                {
                    if (finished == true)
                    {
                        CGUTILS_ASSERT(object != NULL);

                        result = cgutils_json_reader_from_object(object,
                                                                 out);
                    }
                    else
                    {
                        CGUTILS_ASSERT(got == 0);
                        result = EINVAL;
                    }
                }

                json_tokener_free(tokener), tokener = NULL;
            }
            else
            {
                result = ENOMEM;
            }

            cgutils_file_close(fd), fd = -1;
        }
    }

    return result;
}

int cgutils_json_reader_from_key(cgutils_json_reader * const reader,
                                 char const * const key,
                                 cgutils_json_reader ** const out)
{
    int result = EINVAL;

    if (reader != NULL &&
        key != NULL &&
        out != NULL)
    {
        struct json_object * sub = NULL;

        CGUTILS_ASSERT(reader->object != NULL);

        json_bool const found = json_object_object_get_ex(reader->object,
                                                          key,
                                                          &sub);

        if (found == true)
        {
            result = cgutils_json_reader_from_object(sub,
                                                     out);

            if (result == 0)
            {
                (*out)->parent = reader;
                reader->refs_count++;
            }
        }
        else
        {
            result = ENOENT;
        }
    }

    return result;
}

int cgutils_json_reader_get_all(cgutils_json_reader * const reader,
                                char const * const key,
                                cgutils_llist ** const confs_list)
{
    int result = EINVAL;

    if (reader != NULL &&
        key != NULL &&
        confs_list != NULL)
    {
        struct json_object * list = NULL;
        CGUTILS_ASSERT(reader->object != NULL);

        json_bool const found = json_object_object_get_ex(reader->object,
                                                          key,
                                                          &list);

        if (found == true)
        {
            if (json_object_get_type(list) == json_type_array)
            {
                size_t count = 0;
                size_t const len = json_object_array_length(list);

                if (len > 0)
                {
                    result = cgutils_llist_create(confs_list);

                    if (result == 0)
                    {
                        for(size_t idx = 0;
                            result == 0 &&
                                idx < len;
                            idx++)
                        {
                            struct json_object * obj = json_object_array_get_idx(list,
                                                                                 idx);

                            if (obj != NULL)
                            {
                                cgutils_json_reader * new_reader = NULL;

                                result = cgutils_json_reader_from_object(obj,
                                                                         &new_reader);

                                if (result == 0)
                                {
                                    CGUTILS_ASSERT(new_reader != NULL);

                                    result = cgutils_llist_insert(*confs_list,
                                                                  new_reader);

                                    if (result == 0)
                                    {
                                        count++;
                                        reader->refs_count++;
                                        new_reader->parent = reader;
                                    }
                                    else
                                    {
                                        cgutils_json_reader_free(new_reader), new_reader = NULL;
                                    }
                                }
                            }
                        }

                        if (result != 0)
                        {
                            cgutils_llist_free(confs_list, &cgutils_json_reader_delete);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating list: %d",
                                      result);
                    }
                }
                else
                {
                    result = ENOENT;
                }
            }
            else
            {
                result = ENOENT;
            }
        }
        else
        {
            result = ENOENT;
        }
    }

    return result;
}

int cgutils_json_reader_get_string(cgutils_json_reader const * const reader,
                                   char const * const key,
                                   char ** const out)
{
    int result = 0;

    if (reader != NULL &&
        key != NULL &&
        out != NULL)
    {
        struct json_object * value_obj = NULL;

        CGUTILS_ASSERT(reader->object != NULL);

        json_bool const found = json_object_object_get_ex(reader->object,
                                                          key,
                                                          &value_obj);

        if (found == true)
        {
            char const * const temp = json_object_get_string(value_obj);

            if (temp != NULL)
            {
                *out = cgutils_strdup(temp);

                if (*out == NULL)
                {
                    result = ENOMEM;
                }
            }
            else
            {
                result = ENOENT;
            }
        }
        else
        {
            result = ENOENT;
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgutils_json_reader_get_boolean(cgutils_json_reader const * reader,
                                    char const * const key,
                                    bool * const out)
{
    int result = 0;

    if (reader != NULL &&
        key != NULL &&
        out != NULL)
    {
        struct json_object * value_obj = NULL;

        CGUTILS_ASSERT(reader->object != NULL);

        json_bool const found = json_object_object_get_ex(reader->object,
                                                          key,
                                                          &value_obj);

        if (found == true)
        {
            *out = json_object_get_boolean(value_obj);
        }
        else
        {
            result = ENOENT;
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}


int cgutils_json_reader_get_unsigned_integer(cgutils_json_reader const * const reader,
                                             char const * const key,
                                            uint64_t * const out)
{
    int result = 0;

    if (reader != NULL &&
        key != NULL &&
        out != NULL)
    {
        struct json_object * value_obj = NULL;

        CGUTILS_ASSERT(reader->object != NULL);

        json_bool const found = json_object_object_get_ex(reader->object,
                                                          key,
                                                          &value_obj);

        if (found == true)
        {
            int64_t const temp = json_object_get_int64(value_obj);

            if (temp >= 0)
            {
                *out = (uint64_t) temp;
            }
            else
            {
                result = ERANGE;
            }
        }
        else
        {
            result = ENOENT;
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgutils_json_reader_get_integer(cgutils_json_reader const * const reader,
                                    char const * const key,
                                    int64_t * const out)
{
    int result = 0;

    if (reader != NULL &&
        key != NULL &&
        out != NULL)
    {
        struct json_object * value_obj = NULL;

        CGUTILS_ASSERT(reader->object != NULL);

        json_bool const found = json_object_object_get_ex(reader->object,
                                                          key,
                                                          &value_obj);

        if (found == true)
        {
            *out = json_object_get_int64(value_obj);
        }
        else
        {
            result = ENOENT;
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

void cgutils_json_reader_free(cgutils_json_reader * reader)
{
    if (reader != NULL)
    {
        if (reader->refs_count == 0)
        {
            if (reader->parent != NULL)
            {
                cgutils_json_reader_free(reader->parent), reader->parent = NULL;
            }
            else if (reader->object != NULL)
            {
                /* only the root object should be put away */
                json_object_put(reader->object);
            }

            reader->object = NULL;
            CGUTILS_FREE(reader);
        }
        else
        {
            reader->refs_count--;
        }
    }
}

void cgutils_json_reader_delete(void * reader)
{
    cgutils_json_reader_free(reader);
}
