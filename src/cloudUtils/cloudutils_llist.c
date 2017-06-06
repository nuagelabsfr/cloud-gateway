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

#include <cloudutils/cloudutils_llist.h>

struct cgutils_llist_elt
{
    struct cgutils_llist_elt * prev;
    struct cgutils_llist_elt * next;
    void * object;
};

struct cgutils_llist
{
    cgutils_llist_elt * head;
    size_t count;
};

size_t cgutils_llist_get_count(cgutils_llist const * const list)
{
    size_t result = 0;

    if (COMPILER_LIKELY(list != NULL))
    {
        result = list->count;
    }

    return result;
}

cgutils_llist_elt * cgutils_llist_get_first(cgutils_llist * const list)
{
    cgutils_llist_elt * result = NULL;

    if (COMPILER_LIKELY(list != NULL && list->head != NULL))
    {
        result = list->head->next;
    }

    return result;
}

cgutils_llist_elt * cgutils_llist_get_last(cgutils_llist * const list)
{
    cgutils_llist_elt * result = NULL;

    if (COMPILER_LIKELY(list != NULL && list->head != NULL))
    {
        result = list->head->prev;
    }

    return result;
}

cgutils_llist_elt * cgutils_llist_elt_get_next(cgutils_llist_elt * const elt)
{
    cgutils_llist_elt * result = NULL;

    if (COMPILER_LIKELY(elt != NULL))
    {
        result = elt->next;

        if (COMPILER_UNLIKELY(result != NULL && result->object == NULL))
        {
            result = NULL;
        }
    }

    return result;
}

cgutils_llist_elt * cgutils_llist_elt_get_previous(cgutils_llist_elt * const elt)
{
    cgutils_llist_elt * result = NULL;

    if (COMPILER_LIKELY(elt != NULL))
    {
        result = elt->prev;

        if (COMPILER_UNLIKELY(result != NULL && result->object == NULL))
        {
            result = NULL;
        }
    }

    return result;
}

void * cgutils_llist_elt_get_object(cgutils_llist_elt * const elt)
{
    void * result = NULL;

    if (COMPILER_LIKELY(elt != NULL))
    {
        result = elt->object;
    }

    return result;
}

int cgutils_llist_create(cgutils_llist ** const list)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(list != NULL))
    {
        CGUTILS_ALLOCATE_STRUCT(*list);

        if (COMPILER_LIKELY(*list != NULL))
        {
            (*list)->count = 0;
            CGUTILS_ALLOCATE_STRUCT((*list)->head);

            if (COMPILER_LIKELY((*list)->head != NULL))
            {
                result = 0;
            }
            else
            {
                result = errno;
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_FREE(*list);
            }
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

void cgutils_llist_free(cgutils_llist ** const list ,
                       void (*object_cleaner)(void *))
{
    if (COMPILER_LIKELY(list != NULL && *list != NULL))
    {
        if (COMPILER_LIKELY((*list)->count > 0))
        {
            cgutils_llist_elt * elt = (*list)->head->next;

            while(COMPILER_LIKELY(elt != NULL && elt->object != NULL))
            {
                assert(elt != (*list)->head);
                cgutils_llist_elt * next = elt->next;

                if (COMPILER_LIKELY(elt->object != NULL &&
                                    object_cleaner != NULL))
                {
                    (*object_cleaner)(elt->object), elt->object = NULL;
                }

                CGUTILS_FREE(elt);
                elt = next;
            }
        }

        CGUTILS_FREE((*list)->head);
        CGUTILS_FREE(*list);
    }
}

int cgutils_llist_insert(cgutils_llist * const list,
                         void * const object)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(list != NULL && object != NULL))
    {
        assert(list->head != NULL);

        cgutils_llist_elt * elt = NULL;
        CGUTILS_ALLOCATE_STRUCT(elt);

        if (COMPILER_LIKELY(elt != NULL))
        {
            result = 0;
            elt->object = object;
            elt->next = list->head;
            elt->prev = list->head->prev;

            if (list->head->prev != NULL)
            {
                assert(list->head->prev->next == list->head);

                list->head->prev->next = elt;
            }
            else
            {
                list->head->next = elt;
            }

            list->head->prev = elt;
            list->count++;
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_llist_remove(cgutils_llist * const list,
                         cgutils_llist_elt * elt)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(list != NULL && elt != NULL && list->count > 0))
    {
        result = 0;

        if (list->head->next == elt)
        {
            if (elt->next != list->head)
            {
                list->head->next = elt->next;
            }
            else
            {
                list->head->next = NULL;
            }
        }

        if (list->head->prev == elt)
        {
            if (elt->prev != list->head)
            {
                list->head->prev = elt->prev;
            }
            else
            {
                list->head->prev = NULL;
            }
        }

        if (elt->next != NULL)
        {
            elt->next->prev = elt->prev;
        }

        if (elt->prev != NULL)
        {
            elt->prev->next = elt->next;
        }

        list->count--;

        CGUTILS_FREE(elt);
    }

    return result;
}

int cgutils_llist_elt_get_by_object(cgutils_llist * const list,
                                    void const * const object,
                                    cgutils_llist_elt ** const out)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(list != NULL && object != NULL && out != NULL))
    {
        cgutils_llist_elt * elt = cgutils_llist_get_iterator(list);
        bool found = false;
        result = 0;

        while(result == 0 && found == false && elt != NULL)
        {
            if (COMPILER_UNLIKELY(cgutils_llist_elt_get_object(elt) == object))
            {
                found = true;

                *out = elt;
            }
            else
            {
                elt = cgutils_llist_elt_get_next(elt);
            }
        }

        if (COMPILER_UNLIKELY(result == 0 && found == false))
        {
            result = ENOENT;
        }
    }

    return result;
}


int cgutils_llist_remove_by_object(cgutils_llist * const list,
                                   void const * const object)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(list != NULL && object != NULL))
    {
        cgutils_llist_elt * elt = NULL;

        result = cgutils_llist_elt_get_by_object(list, object, &elt);

        if (COMPILER_LIKELY(result == 0))
        {
            assert(elt != NULL);

            result = cgutils_llist_remove(list, elt);
        }
    }

    return result;
}

int cgutils_llist_merge(cgutils_llist * list_in,
                        cgutils_llist * list_to_add)
{
    int result = EINVAL;

    if (list_in != NULL && list_to_add != NULL)
    {
        size_t list_to_add_count = cgutils_llist_get_count(list_to_add);
        size_t list_to_in_count = cgutils_llist_get_count(list_in);

        result = 0;

        if (list_to_add_count > 0)
        {
            if (list_to_in_count > 0)
            {
                list_to_add->head->next->prev = list_in->head->prev;
                list_in->head->prev->next = list_to_add->head->next;

                list_to_add->head->prev->next = list_in->head;
                list_in->head->prev = list_to_add->head->prev;
            }
            else
            {
                /* Nothing in the dest list */
                list_in->head->next = list_to_add->head->next;
                list_in->head->prev = list_to_add->head->prev;
                list_in->head->next->prev = list_in->head;
                list_in->head->prev->next = list_in->head;
            }
        }

        list_to_add->head->next = NULL;
        list_to_add->head->prev = NULL;
        list_to_add->count = 0;
        list_in->count += list_to_add_count;
    }

    return result;
}
