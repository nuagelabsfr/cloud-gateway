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
#include <inttypes.h>
#include <string.h>
#include <strings.h>

#include <json-c/json_object.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_json_writer.h>

struct cgutils_json_writer
{
    cgutils_json_writer_element * root_elt;
};

struct cgutils_json_writer_element
{
    cgutils_json_writer * doc;
    struct json_object * object;
};

static int cgutils_json_writer_new_element_internal(cgutils_json_writer_element * const parent,
                                                    struct json_object * const object,
                                                    cgutils_json_writer_element ** out)
{
    int result = 0;
    CGUTILS_ASSERT(out != NULL);
    CGUTILS_ASSERT(object != NULL);

    CGUTILS_ALLOCATE_STRUCT(*out);

    if (*out != NULL)
    {
        (*out)->object = object;

        if (parent != NULL)
        {
            (*out)->doc = parent->doc;
        }
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

int cgutils_json_writer_new(cgutils_json_writer ** const writer)
{
    int result = EINVAL;

    if (writer != NULL)
    {
        result = ENOMEM;

        struct json_object * object = json_object_new_object();

        if (object != NULL)
        {
            cgutils_json_writer_element * elt = NULL;

            CGUTILS_ALLOCATE_STRUCT(elt);

            if (elt != NULL)
            {
                elt->object = object;
                object = NULL;

                CGUTILS_ALLOCATE_STRUCT(*writer);

                if (*writer != NULL)
                {
                    elt->doc = *writer;

                    (*writer)->root_elt = elt;
                    elt = NULL;

                    result = 0;
                }

                if (elt != NULL)
                {
                    cgutils_json_writer_element_release(elt), elt = NULL;
                }
            }

            if (object != NULL)
            {
                json_object_put(object), object = NULL;
            }
        }
    }

    return result;
}

cgutils_json_writer_element * cgutils_json_writer_get_root(cgutils_json_writer const * const writer)
{
    cgutils_json_writer_element * result = NULL;

    if (writer != NULL)
    {
        result = writer->root_elt;
    }

    return result;
}

int cgutils_json_writer_new_element(cgutils_json_writer_element ** elt)
{
    int result = EINVAL;

    if (elt != NULL)
    {
        struct json_object * obj = json_object_new_object();

        if (obj != NULL)
        {
            result = cgutils_json_writer_new_element_internal(NULL,
                                                              obj,
                                                              elt);

            if (result != 0)
            {
                json_object_put(obj), obj = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_json_writer_add_element_to_list(cgutils_json_writer_element * const parent,
                                            cgutils_json_writer_element * const child)
{
    int result = EINVAL;

    if (parent != NULL &&
        child != NULL)
    {
        result = json_object_array_add(parent->object,
                                       child->object);

        if (result == 0)
        {
            child->doc = parent->doc;
        }
    }

    return result;
}

int cgutils_json_writer_element_add_list_child(cgutils_json_writer_element * const parent,
                                               char const * const name,
                                               cgutils_json_writer_element ** const child)
{
    int result = EINVAL;

    if (parent != NULL &&
        name != NULL &&
        child != NULL)
    {
        struct json_object * child_object = json_object_new_array();

        if (child_object != NULL)
        {
            result = cgutils_json_writer_new_element_internal(parent,
                                                              child_object,
                                                              child);
            if (result == 0)
            {
                json_object_object_add(parent->object,
                                       name,
                                       child_object);
            }
            else
            {
                result = ENOMEM;
            }

            if (result != 0)
            {
                json_object_put(child_object), child_object = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}


int cgutils_json_writer_element_add_child(cgutils_json_writer_element * const parent,
                                          char const * const name,
                                          cgutils_json_writer_element ** const child)
{
    int result = EINVAL;

    if (parent != NULL &&
        name != NULL &&
        child != NULL)
    {
        struct json_object * child_object = json_object_new_object();

        if (child_object != NULL)
        {
            result = cgutils_json_writer_new_element_internal(parent,
                                                              child_object,
                                                              child);
            if (result == 0)
            {
                json_object_object_add(parent->object,
                                       name,
                                       child_object);

                result = 0;
            }

            if (result != 0)
            {
                json_object_put(child_object), child_object = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_json_writer_element_add_string_prop(cgutils_json_writer_element * const elt,
                                                char const * const prop_name,
                                                char const * const prop_value)
{
    int result = EINVAL;

    if (elt != NULL &&
        prop_name != NULL)
    {
        struct json_object * prop_value_str = json_object_new_string(prop_value);

        if (prop_value_str != NULL)
        {
            json_object_object_add(elt->object, prop_name, prop_value_str);

            result = 0;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_json_writer_element_add_uint64_prop(cgutils_json_writer_element * const elt,
                                                char const * const prop_name,
                                                uint64_t const prop_value)
{
    int result = EINVAL;

    if (elt != NULL &&
        prop_name != NULL &&
        prop_value < INT64_MAX)
    {
        struct json_object * prop_value_obj = json_object_new_int64((int64_t) prop_value);

        if (prop_value_obj != NULL)
        {
            json_object_object_add(elt->object, prop_name, prop_value_obj);

            result = 0;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_json_writer_element_add_boolean_prop(cgutils_json_writer_element * const elt,
                                                 char const * const prop_name,
                                                 bool const prop_value)
{
    int result = EINVAL;

    if (elt != NULL &&
        prop_name != NULL)
    {
        struct json_object * prop_value_obj = json_object_new_boolean(prop_value);

        if (prop_value_obj != NULL)
        {
            json_object_object_add(elt->object, prop_name, prop_value_obj);

            result = 0;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}


void cgutils_json_writer_element_free(cgutils_json_writer_element * element)

{
    if (element != NULL)
    {
        element->doc = NULL;
        CGUTILS_FREE(element);
    }
}

void cgutils_json_writer_element_release(cgutils_json_writer_element * element)
{
    if (element != NULL)
    {
        /* Don't release the root,
           it may leave a dangling pointer at the parent */
        if (element->doc == NULL ||
            element->doc->root_elt != element)
        {
            cgutils_json_writer_element_free(element);
        }
    }
}

int cgutils_json_writer_get_output(cgutils_json_writer const * const writer,
                                   char ** const out,
                                   size_t * const size)
{
    int result = EINVAL;

    if (writer != NULL &&
        out != NULL &&
        size != NULL)
    {
        char const * const str = json_object_get_string(writer->root_elt->object);

        if (str != NULL)
        {
            *out = cgutils_strdup(str);

            if (*out != NULL)
            {
                *size = strlen(*out);
                result = 0;
            }
            else
            {
                result = ENOMEM;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

void cgutils_json_writer_free(cgutils_json_writer * writer)
{
    if (writer != NULL)
    {
        if (writer->root_elt != NULL)
        {
            json_object_put(writer->root_elt->object), writer->root_elt->object = NULL;
            cgutils_json_writer_element_free(writer->root_elt);
            writer->root_elt = NULL;
        }

        CGUTILS_FREE(writer);
    }
}

void cgutils_json_writer_delete(void * writer)
{
    cgutils_json_writer_free(writer);
}
