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

#include <errno.h>
#include <stdlib.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_vector.h>

struct cgutils_vector
{
    void ** elements;
    size_t size;
    size_t count;
};

int cgutils_vector_init(size_t const initial_size,
                        cgutils_vector ** const vector)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(vector != NULL))
    {
        CGUTILS_ALLOCATE_STRUCT(*vector);

        if (COMPILER_LIKELY(*vector != NULL))
        {
            cgutils_vector * this = *vector;
            result = 0;
            this->count = 0;
            this->size = initial_size;

            if (initial_size == 0)
            {
                this->elements = NULL;
            }
            else
            {
                CGUTILS_MALLOC(this->elements, sizeof *(this->elements), initial_size);

                if (COMPILER_UNLIKELY(this->elements == NULL))
                {
                    result = ENOMEM;
                }
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                cgutils_vector_free(this), this = NULL;
                *vector = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_vector_add(cgutils_vector * const this,
                       void * const element)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(this != NULL &&
                        element != NULL))
    {
        result = 0;

        if (this->size <= this->count)
        {
            void * newptr = NULL;

            CGUTILS_REALLOC(newptr, this->elements, sizeof *(this->elements), this->size * 2);

            if (COMPILER_LIKELY(newptr != NULL))
            {
                this->elements = newptr;
                this->size = this->size * 2;
            }
            else
            {
                result = ENOMEM;
            }
        }

        if (COMPILER_LIKELY(result == 0))
        {
            this->elements[this->count] = element;
            this->count++;
        }
    }

    return result;
}

int cgutils_vector_get(cgutils_vector const * const this,
                       size_t const position,
                       void ** const element)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(this != NULL &&
                        element != NULL))
    {
        if (COMPILER_LIKELY(position < this->count))
        {
            result = 0;
            *element = this->elements[position];
        }
        else
        {
            result = ENOENT;
        }
    }

    return result;
}

int cgutils_vector_set(cgutils_vector * const this,
                       size_t const position,
                       void * const value)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(this != NULL &&
                        position < this->count))
    {
        result = 0;
        this->elements[position] = value;
    }

    return result;
}

size_t cgutils_vector_count(cgutils_vector const * const this)
{
    size_t result = 0;

    if (COMPILER_LIKELY(this != NULL))
    {
        result = this->count;
    }

    return result;
}

void cgutils_vector_free(cgutils_vector * this)
{
    if (this != NULL)
    {
        if (this->elements != NULL)
        {
            CGUTILS_FREE(this->elements);
        }

        CGUTILS_FREE(this);
    }
}

void cgutils_vector_deep_free(cgutils_vector ** this,
                              void (*freer)(void *))
{
    if (this != NULL &&
        *this != NULL)
    {
        size_t const count = (*this)->count;

        if (freer != NULL &&
            (*this)->elements != NULL &&
            count > 0)
        {
            for (size_t idx = 0;
                 idx < count;
                 idx++)
            {
                (*freer)((*this)->elements[idx]), (*this)->elements[idx] = NULL;
            }
        }

        cgutils_vector_free(*this), *this = NULL;
    }
}
