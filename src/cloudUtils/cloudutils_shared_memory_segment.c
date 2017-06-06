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
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <cloudutils/cloudutils_shared_memory_segment.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_file.h>

typedef struct
{
    pthread_rwlock_t lock;
    size_t data_size;
    char data[];
} cloudutils_shared_memory_segment;

struct cloudutils_shared_memory_segment_handler
{
    char * path;
    cloudutils_shared_memory_segment * segment;
    size_t segment_size;
};

static size_t cloudutils_shared_memory_segment_handler_compute_size(size_t const segment_size)
{
    return sizeof(cloudutils_shared_memory_segment) + segment_size;
}

static void cloudutils_shared_memory_segment_handler_free(cloudutils_shared_memory_segment_handler * this)
{
    if (this != NULL)
    {
        if (this->segment != NULL)
        {
            int res = munmap(this->segment, this->segment_size);

            if (res != 0)
            {
                res = errno;

                CGUTILS_ERROR("Error unmapping segment %s: %d",
                              this->path != NULL ? this->path : "NULL",
                              res);
            }

            this->segment = NULL;
        }

        this->segment_size = 0;

        CGUTILS_FREE(this->path);
        CGUTILS_FREE(this);
    }
}

static int cloudutils_shared_memory_segment_handler_init(char const * const path,
                                                         cloudutils_shared_memory_segment * const segment,
                                                         size_t const segment_size,
                                                         cloudutils_shared_memory_segment_handler ** out)
{
    int result = 0;

    CGUTILS_ASSERT(path != NULL);
    CGUTILS_ASSERT(segment != NULL);
    CGUTILS_ASSERT(segment_size > 0);
    CGUTILS_ASSERT(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(*out);

    if (*out != NULL)
    {
        (*out)->path = cgutils_strdup(path);

        if ((*out)->path != NULL)
        {
            (*out)->segment = segment;
            (*out)->segment_size = segment_size;
        }
        else
        {
            result = ENOMEM;
        }

        if (result != 0)
        {
            cloudutils_shared_memory_segment_handler_free(*out), *out = NULL;
        }
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static int cloudutils_shared_memory_segment_map(char const * const path,
                                                bool const writable,
                                                size_t const data_size,
                                                bool const creation,
                                                cloudutils_shared_memory_segment ** segment,
                                                size_t * segment_size)
{
    int result = 0;
    int flags = O_RDWR;
    CGUTILS_ASSERT(path != NULL);
    CGUTILS_ASSERT(data_size > 0);
    CGUTILS_ASSERT(segment != NULL);
    CGUTILS_ASSERT(segment_size != NULL);

    if (creation == true)
    {
        flags |= O_CREAT | O_TRUNC;
    }

    int md = shm_open(path,
                      flags,
                      S_IRUSR | S_IWUSR);

    if (CGUTILS_COMPILER_LIKELY(md >= 0))
    {
        *segment_size = cloudutils_shared_memory_segment_handler_compute_size(data_size);

        result = cgutils_file_ftruncate(md, (off_t) segment_size);

        if (CGUTILS_COMPILER_LIKELY(result == 0))
        {
            *segment = mmap(NULL,
                            *segment_size,
                            writable == true ? PROT_READ | PROT_WRITE : PROT_READ,
                            MAP_SHARED,
                            md,
                            0);

            if (CGUTILS_COMPILER_LIKELY(*segment != MAP_FAILED))
            {
                if (creation == true)
                {
                    (*segment)->data_size = data_size;
                    memset((*segment)->data, 0, data_size);
                }
            }
            else
            {
                result = errno;
                CGUTILS_ERROR("Error while mapping shared memory for %s: %d",
                              path,
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error while resizing shared memory for %s: %d",
                          path,
                          result);
        }

        cgutils_file_close(md), md = -1;

        if (CGUTILS_COMPILER_UNLIKELY(result != 0) &&
            creation == true)
        {
            int res = shm_unlink(path);

            if (res != 0)
            {
                res = errno;
                CGUTILS_ERROR("Error unlinking shared memory for %s: %d",
                              path,
                              res);
            }
        }
    }
    else
    {
        result = errno;
        CGUTILS_ERROR("Error opening shared memory %s: %d",
                      path,
                      result);
    }

    return result;
}

int cloudutils_shared_memory_segment_handler_create(char const * const path,
                                                    size_t const data_size,
                                                    cloudutils_shared_memory_segment_handler ** out)
{
    int result = EINVAL;

    if (CGUTILS_COMPILER_LIKELY(path != NULL &&
                                data_size > 0 &&
                                (SIZE_MAX - sizeof(cloudutils_shared_memory_segment)) > data_size &&
                                out != NULL))
    {
        pthread_rwlockattr_t lockattr;

        result = pthread_rwlockattr_init(&lockattr);

        if (result == 0)
        {
            result = pthread_rwlockattr_setpshared(&lockattr,
                                                   PTHREAD_PROCESS_SHARED);

            if (result == 0)
            {
                cloudutils_shared_memory_segment * segment = NULL;
                size_t segment_size = 0;

                result = cloudutils_shared_memory_segment_map(path,
                                                              true,
                                                              data_size,
                                                              true,
                                                              &segment,
                                                              &segment_size);

                if (result == 0)
                {
                    CGUTILS_ASSERT(segment != NULL);

                    result = pthread_rwlock_init(&(segment->lock), &lockattr);

                    if (result == 0)
                    {
                        result = cloudutils_shared_memory_segment_handler_init(path,
                                                                               segment,
                                                                               segment_size,
                                                                               out);

                        if (result == 0)
                        {
                        }
                        else
                        {
                            CGUTILS_ERROR("Error in data init for shared segment %s: %d",
                                          path,
                                          result);
                        }

                        if (result != 0)
                        {
                            pthread_rwlock_destroy(&(segment->lock));
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating rw lock for path %s: %d",
                                      path,
                                      result);
                    }

                    if (CGUTILS_COMPILER_UNLIKELY(result != 0))
                    {
                        int res = munmap(segment, segment_size);

                        if (res != 0)
                        {
                            res = errno;
                            CGUTILS_ERROR("Error unmapping memory for segment %s: %d",
                                          path,
                                          res);
                        }

                        res = shm_unlink(path);

                        if (res != 0)
                        {
                            res = errno;
                            CGUTILS_ERROR("Error unlinking shared memory %s: %d",
                                          path,
                                          res);
                        }
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error mapping shared memory segment for %s: %d",
                                  path,
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error setting rwlock attr to process shared for segment %s: %d",
                              path,
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error in rwlock attr init for segment %s: %d",
                          path,
                          result);
        }
    }

    return result;
}

int cloudutils_shared_memory_segment_handler_attach(char const * const path,
                                                    bool const writable,
                                                    size_t const data_size,
                                                    cloudutils_shared_memory_segment_handler ** out)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(path != NULL &&
                        data_size > 0 &&
                        out != NULL))
    {
        cloudutils_shared_memory_segment * segment = NULL;
        size_t segment_size = 0;

        result = cloudutils_shared_memory_segment_map(path,
                                                      writable,
                                                      data_size,
                                                      false,
                                                      &segment,
                                                      &segment_size);

        if (CGUTILS_COMPILER_LIKELY(result == 0))
        {
            result = cloudutils_shared_memory_segment_handler_init(path,
                                                                   segment,
                                                                   segment_size,
                                                                   out);

            if (CGUTILS_COMPILER_LIKELY(result == 0))
            {

            }
            else
            {
                CGUTILS_ERROR("Error in data init for shared segment %s: %d",
                              path,
                              result);
            }

            if (CGUTILS_COMPILER_UNLIKELY(result != 0))
            {
                int res = munmap(segment, segment_size);

                if (res != 0)
                {
                    res = errno;
                    CGUTILS_ERROR("Error unmapping memory for segment %s: %d",
                                  path,
                                  res);
                }
            }
        }
        else
        {
            CGUTILS_ERROR("Error mapping shared memory segment for %s: %d",
                          path,
                          result);
        }
    }

    return result;
}

int cloudutils_shared_memory_segment_handler_copy(cloudutils_shared_memory_segment_handler * this,
                                                  void * const buffer,
                                                  size_t const buffer_size)
{
    int result = EINVAL;

    if (CGUTILS_COMPILER_LIKELY(this != NULL &&
                                buffer != NULL &&
                                buffer_size > 0))
    {
        CGUTILS_ASSERT(this->path != NULL);
        CGUTILS_ASSERT(this->segment != NULL);
        CGUTILS_ASSERT(this->segment_size > 0);

        result = pthread_rwlock_rdlock(&(this->segment->lock));

        if (result == 0)
        {
            if (CGUTILS_COMPILER_LIKELY(this->segment->data_size >= buffer_size))
            {
                memcpy(buffer, this->segment->data, buffer_size);
            }
            else
            {
                CGUTILS_ERROR("Trying to retrieve data with an invalid buffer size, go away (%zu / %zu).",
                              buffer_size,
                              this->segment->data_size);
            }

            int res = pthread_rwlock_unlock(&(this->segment->lock));

            if (CGUTILS_COMPILER_UNLIKELY(res != 0))
            {
                CGUTILS_ERROR("Error unlocking shared data: %d",
                              res);
            }
        }
        else
        {
            CGUTILS_ERROR("Error locking shared data: %d",
                          result);
        }
    }

    return result;
}

int cloudutils_shared_memory_segment_handler_update(cloudutils_shared_memory_segment_handler * this,
                                                    void const * new_data,
                                                    size_t const new_data_size)
{
    int result = EINVAL;

    if (CGUTILS_COMPILER_LIKELY(this != NULL &&
                                new_data != NULL &&
                                new_data_size > 0))
    {
        CGUTILS_ASSERT(this->path != NULL);
        CGUTILS_ASSERT(this->segment != NULL);
        CGUTILS_ASSERT(this->segment_size > 0);

        result = pthread_rwlock_wrlock(&(this->segment->lock));

        if (result == 0)
        {
            if (CGUTILS_COMPILER_LIKELY(this->segment->data_size == new_data_size))
            {
                memcpy(this->segment->data, new_data, new_data_size);
            }
            else
            {
                CGUTILS_ERROR("Trying to update data with different data size, go away (%zu / %zu).",
                              new_data_size,
                              this->segment->data_size);
            }

            int res = pthread_rwlock_unlock(&(this->segment->lock));

            if (CGUTILS_COMPILER_UNLIKELY(res != 0))
            {
                CGUTILS_ERROR("Error unlocking shared data: %d",
                              res);
            }
        }
        else
        {
            CGUTILS_ERROR("Error locking shared data: %d",
                          result);
        }
    }

    return result;
}

void cloudutils_shared_memory_segment_handler_detach(cloudutils_shared_memory_segment_handler * this)
{
    if (CGUTILS_COMPILER_LIKELY(this != NULL))
    {
        if (this->segment != NULL &&
            this->segment_size > 0)
        {
            int result = munmap(this->segment, this->segment_size);

            if (result != 0)
            {
                result = errno;

                CGUTILS_ERROR("Error unmapping segment %s: %d",
                              this->path,
                              result);
            }
        }

        this->segment = NULL;
        this->segment_size = 0;

        cloudutils_shared_memory_segment_handler_free(this), this = NULL;
    }
}

int cloudutils_shared_memory_segment_handler_destroy(cloudutils_shared_memory_segment_handler * this)
{
    int result = EINVAL;

    if (CGUTILS_COMPILER_LIKELY(this != NULL))
    {
        CGUTILS_ASSERT(this->path != NULL);
        CGUTILS_ASSERT(this->segment != NULL);
        CGUTILS_ASSERT(this->segment_size > 0);

        result = munmap(this->segment, this->segment_size);

        if (result != 0)
        {
            result = errno;

            CGUTILS_ERROR("Error unmapping segment %s: %d",
                          this->path,
                          result);
        }

        this->segment = NULL;
        this->segment_size = 0;

        result = shm_unlink(this->path);

        if (result != 0)
        {
            result = errno;

            if (result != 0)
            {
                CGUTILS_ERROR("Error unlinking segment %s: %d",
                              this->path,
                              result);
            }
        }
    }

    return result;
}
