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
#include <cloudutils/cloudutils_pool.h>

struct cgutils_pool
{
    cgutils_pool_releaser * releaser;
    cgutils_llist * elts;
    size_t pool_size;
    size_t count;
    bool warn_on_full;
    bool warn_on_empty;
};

int cgutils_pool_init(size_t const pool_size,
                      cgutils_pool_releaser * const releaser,
                      bool const warn_on_full,
                      bool const warn_on_empty,
                      cgutils_pool ** const out)
{
    int result = EINVAL;

    if (pool_size > 0 && out != NULL)
    {
        result = ENOMEM;

        CGUTILS_ALLOCATE_STRUCT(*out);

        if (*out != NULL)
        {
            cgutils_pool * this = *out;

            result = cgutils_llist_create(&(this->elts));

            if (result == 0)
            {
                this->releaser = releaser;
                this->pool_size = pool_size;
                this->count = 0;
                this->warn_on_full = warn_on_full;
                this->warn_on_empty = warn_on_empty;
            }

            if (result != 0)
            {
                cgutils_pool_free(this);
                this = NULL;
                *out = NULL;
            }
        }
    }

    return result;
}

int cgutils_pool_get(cgutils_pool * const this,
                     void ** const object)
{
    int result = EINVAL;

    if (this != NULL && object != NULL)
    {
        if (this->count > 0)
        {
            assert(this->elts != NULL);

            cgutils_llist_elt * elt = cgutils_llist_get_iterator(this->elts);
            assert(elt != NULL);

            *object = cgutils_llist_elt_get_object(elt);
            assert(*object != NULL);

            cgutils_llist_remove(this->elts, elt);
            (this->count)--;
            elt = NULL;
            result = 0;
        }
        else
        {
            result = ENOENT;

            if (this->warn_on_empty)
            {
                CGUTILS_DEBUG("Element needed but pool is empty");
            }
        }
    }

    return result;
}


int cgutils_pool_add(cgutils_pool * const this,
                     void * object)
{
    int result = EINVAL;

    if (this != NULL && object != NULL)
    {
        result = 0;

        if (this->count < this->pool_size)
        {
            result = cgutils_llist_insert(this->elts, object);

            if (result == 0)
            {
                (this->count)++;
            }
        }
        else
        {
            this->releaser(object), object = NULL;
            if (this->warn_on_full)
            {
                CGUTILS_DEBUG("Element added but pool is full");
            }
        }
    }

    return result;
}

void cgutils_pool_free(cgutils_pool * this)
{
    if (this != NULL)
    {
        if (this->elts != NULL)
        {
            cgutils_llist_free(&(this->elts), this->releaser);
        }

        this->releaser = NULL;
        this->pool_size = 0;
        this->count = 0;
        this->warn_on_full = false;
        this->warn_on_empty = false;

        CGUTILS_FREE(this);
    }
}
