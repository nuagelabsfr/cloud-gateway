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
#include <stdint.h>
#include <string.h>

#include <cloudutils/cloudutils_htable.h>

typedef struct cgutils_htable_elt cgutils_htable_elt;

struct cgutils_htable_elt
{
    char const * key;
    void * object;
    cgutils_htable_elt * next;
};

struct cgutils_htable
{
    cgutils_htable_elt ** table;
    size_t size;
    size_t count;
};

struct cgutils_htable_iterator
{
    cgutils_htable * htable;
    cgutils_htable_elt * elt;
    size_t table_idx;
    bool eof;
};

int cgutils_htable_get_iterator(cgutils_htable * const htable,
                                cgutils_htable_iterator ** out)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(htable != NULL && out != NULL))
    {
        result = ENOMEM;
        CGUTILS_ALLOCATE_STRUCT(*out);

        if (COMPILER_LIKELY(*out != NULL))
        {
            (*out)->htable = htable;
            (*out)->eof = false;
            (*out)->elt = NULL;

            size_t idx = 0;

            for (idx = 0;
                 idx < htable->size;
                 idx++)
            {
                if (COMPILER_LIKELY(htable->table[idx] != NULL))
                {
                    (*out)->elt = htable->table[idx];
                    break;
                }
            }

            if (COMPILER_LIKELY((*out)->elt != NULL))
            {
                result = 0;
                (*out)->table_idx = idx;
            }
            else
            {
                result = ENOENT;
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                cgutils_htable_iterator_free(*out), *out = NULL;
            }
        }
    }

    return result;
}

void * cgutils_htable_iterator_get_value(cgutils_htable_iterator const * const it)
{
    void * result = NULL;

    if (COMPILER_LIKELY(it != NULL))
    {
        assert(it->elt != NULL);

        result = it->elt->object;
    }

    return result;
}

char const * cgutils_htable_iterator_get_key(cgutils_htable_iterator const * const it)
{
    char const * result = NULL;

    if (COMPILER_LIKELY(it != NULL))
    {
        assert(it->elt != NULL);

        result = it->elt->key;
    }

    return result;
}

void cgutils_htable_iterator_free(cgutils_htable_iterator * it)
{
    if (it != NULL)
    {
        it->htable = NULL;
        it->table_idx = 0;
        it->elt = NULL;
        CGUTILS_FREE(it);
    }
}

bool cgutils_htable_iterator_next(cgutils_htable_iterator * const iterator)
{
    bool result = false;

    if (COMPILER_LIKELY(iterator != NULL))
    {
        assert(iterator->htable != NULL);
        assert(iterator->elt != NULL);
        assert(iterator->table_idx < iterator->htable->size);

        iterator->elt = iterator->elt->next;

        if (iterator->elt == NULL)
        {
            iterator->table_idx++;

            for (;
                 iterator->elt == NULL &&
                     iterator->table_idx < iterator->htable->size;
                 iterator->table_idx++)
            {
                if (COMPILER_LIKELY(iterator->htable->table[iterator->table_idx] != NULL))
                {
                    iterator->elt = iterator->htable->table[iterator->table_idx];
                }
            }

            if (COMPILER_LIKELY(iterator->elt != NULL))
            {
                iterator->table_idx--;
            }
        }

        if (COMPILER_LIKELY(iterator->elt != NULL))
        {
            result = true;
        }
    }

    return result;
}

/* This is a slightly modified version of an ELF hash.
   Almost as efficient as a Jenkins hash, but a lot easier */
static COMPILER_PURE_FUNCTION size_t cgutils_htable_hash(char const * key,
                                                         size_t const size)
{
    size_t val = 0;

    while (*key != '\0')
    {
        size_t skey = (size_t)*key;
        size_t tmp;

        val = (val << 4) + skey;

        if ((tmp = (val & 0xf0000000)))
        {
            val ^= tmp >> 24;
            val ^= tmp;
        }

        key++;
    }

    return val % size;
}

static void cgutils_htable_elt_free(cgutils_htable_elt ** const elt,
                                    void (*object_cleaner)(void *))
{
    if (elt != NULL)
    {
        if (*elt != NULL)
        {
            (*elt)->key = NULL;

            if (object_cleaner != NULL && (*elt)->object != NULL)
            {
                (*object_cleaner)((*elt)->object);
            }

            CGUTILS_FREE(*elt);
        }
    }
}

static int cgutils_htable_internal_get_elt(cgutils_htable const * const table,
                                           char const * const key,
                                           cgutils_htable_elt ** const out)
{
    assert(table != NULL);
    assert(key != NULL);
    assert(out != NULL);

    int result = ENOENT;

    size_t const offset = cgutils_htable_hash(key, table->size);

    cgutils_htable_elt * elt = table->table[offset];

    while(COMPILER_LIKELY(elt != NULL &&
                          result == ENOENT))
    {
        assert(elt->key != NULL);

        if (COMPILER_UNLIKELY(strcmp(elt->key, key) == 0))
        {
            result = 0;
            *out = elt;
        }
        else
        {
            elt = elt->next;
        }
    }

    return result;
}

int cgutils_htable_remove(cgutils_htable * const table,
                          char const * const key)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(table != NULL &&
                        key != NULL))
    {
        result = ENOENT;

        if (COMPILER_LIKELY(table->count > 0))
        {
            size_t const offset = cgutils_htable_hash(key, table->size);

            cgutils_htable_elt * elt = table->table[offset];
            cgutils_htable_elt ** prev = &(table->table[offset]);

            while(COMPILER_LIKELY(elt != NULL &&
                                  result == ENOENT))
            {
                assert(elt->key != NULL);

                if (COMPILER_UNLIKELY(strcmp(elt->key, key) == 0))
                {
                    result = 0;
                }
                else
                {
                    prev = &(elt->next);
                    elt = elt->next;
                }
            }

            if (COMPILER_LIKELY(result == 0))
            {
                *prev = elt->next;
                cgutils_htable_elt_free(&elt, NULL);
                table->count--;
            }
        }
    }

    return result;
}

int cgutils_htable_create(cgutils_htable ** const table,
                          size_t const table_size)
{
    int result = EINVAL;

    if (table != NULL &&
        table_size > 0 &&
        (table_size < (SIZE_MAX / sizeof *((*table)->table))))
    {
        cgutils_htable * this = NULL;

        CGUTILS_ALLOCATE_STRUCT(this);

        if (this != NULL)
        {
            CGUTILS_MALLOC(this->table,
                           table_size,
                           sizeof *((*table)->table));

            if (this->table != NULL)
            {
                result = 0;

                this->size = table_size;
                this->count = 0;

                for(size_t idx = 0;
                    idx < table_size &&
                        result == 0;
                    idx++)
                {
                    this->table[idx] = NULL;
                }
            }

            if (result == 0)
            {
                *table = this, this = NULL;
            }
            else
            {
                CGUTILS_FREE(this);
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

#define CGUTILS_HASH_DEFAULT_TABLE_SIZE 8

int cgutils_htable_easy_create(cgutils_htable ** const table)
{
    return cgutils_htable_create(table, CGUTILS_HASH_DEFAULT_TABLE_SIZE);
}

int cgutils_htable_insert(cgutils_htable * const table,
                          char const * const key,
                          void * const object)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(table != NULL &&
                        key != NULL &&
                        object != NULL))
    {
        size_t const offset = cgutils_htable_hash(key,
                                                  table->size);

        cgutils_htable_elt * elt = table->table[offset];
        cgutils_htable_elt ** prev = &(table->table[offset]);

        result = 0;

        while(COMPILER_LIKELY(elt != NULL &&
                              result == 0))
        {
            assert(elt->key != NULL);

            if (COMPILER_UNLIKELY(strcmp(elt->key, key) == 0))
            {
                result = EEXIST;
            }
            else
            {
                prev = &(elt->next);
                elt = elt->next;
            }
        }

        if (COMPILER_LIKELY(result == 0))
        {
            cgutils_htable_elt * new_elt = NULL;
            CGUTILS_ALLOCATE_STRUCT(new_elt);

            if (COMPILER_LIKELY(new_elt != NULL))
            {
                new_elt->key = key;
                new_elt->object = object;
                *prev = new_elt;
                table->count++;
                result = 0;
            }
            else
            {
                result = ENOMEM;
            }
        }
    }

    return result;
}

bool cgutils_htable_lookup(cgutils_htable const * const table,
                           char const * const key)
{
    bool result = false;

    if (COMPILER_LIKELY(table != NULL &&
                        key != NULL &&
                        table->count > 0))
    {
        cgutils_htable_elt * elt = NULL;

        int res = cgutils_htable_internal_get_elt(table,
                                                  key,
                                                  &elt);

        if (COMPILER_LIKELY(res == 0))
        {
            result = true;
        }
    }

    return result;
}

int cgutils_htable_get(cgutils_htable const * table,
                       char const * key,
                       void ** object)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(table != NULL &&
                        key != NULL &&
                        object != NULL))
    {
        if (COMPILER_LIKELY(table->count > 0))
        {
            cgutils_htable_elt * elt = NULL;

            result = cgutils_htable_internal_get_elt(table,
                                                     key,
                                                     &elt);

            if (COMPILER_LIKELY(result == 0))
            {
                assert(elt != NULL);
                assert(elt->key != NULL);
                assert(elt->object != NULL);
                *object = elt->object;
            }
        }
        else
        {
            result = ENOENT;
        }
    }

    return result;
}

void cgutils_htable_free(cgutils_htable ** const table,
                         void (*object_cleaner)(void *))
{
    if (table != NULL && *table != NULL)
    {
        if ((*table)->table != NULL)
        {
            for (size_t idx = 0; idx < (*table)->size; idx++)
            {
                cgutils_htable_elt * elt = (*table)->table[idx];

                while(elt != NULL)
                {
                    cgutils_htable_elt * next = elt->next;
                    cgutils_htable_elt_free(&elt, object_cleaner);
                    elt = next;
                }
            }

            CGUTILS_FREE((*table)->table);
        }

        CGUTILS_FREE(*table);
    }
}

size_t cgutils_htable_get_count(cgutils_htable const * const table)
{
    size_t result = 0;

    if (COMPILER_LIKELY(table != NULL))
    {
        result = table->count;
    }

    return result;
}

size_t cgutils_htable_iterator_get_table_count(cgutils_htable_iterator const * const it)
{
    size_t result = 0;

    if (COMPILER_LIKELY(it != NULL &&
                        it->htable != NULL))
    {
        result = it->htable->count;
    }

    return result;
}
