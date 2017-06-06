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
#include <string.h>

#include <cloudutils/cloudutils_buffer.h>
#include <cloudutils/cloudutils_crypto.h>

#include <cgsm/cg_storage_filter.h>
#include <cgsm/cg_storage_io.h>

struct cg_storage_io_ctx
{
    cgutils_buffer buf;
    cg_storage_io * io;
    size_t offset;
    size_t ctx_size;
    size_t ctx_pos;
    cg_storage_io_read_cb * read_cb;
    void * read_cb_data;
};

typedef enum
{
    cg_storage_io_type_none = 0,
    cg_storage_io_type_source = 1,
    cg_storage_io_type_destination = 2,
} cg_storage_io_type;

typedef enum
{
    cg_storage_io_support_type_none = 0,
    cg_storage_io_support_type_file = 1,
    cg_storage_io_support_type_mem = 2
} cg_storage_io_support_type;

struct cg_storage_io
{
    cgutils_aio * aio;
    cgutils_llist * filter_ctx_list;
    cgutils_crypto_hash_context * hash_ctx;

    cg_storage_io_cb * finish_cb;
    void * finish_cb_data;

    char * membuf;

    size_t filters_count;

    size_t support_size;
    off_t offset;
    int fd;

    cg_storage_io_type type;
    cg_storage_io_support_type support_type;

    /* Underlying support is EOF,
       only makes sense while reading (type == source) */
    bool eof;
    /* storage_io_finish has been called */
    bool finished;
    bool compute_hash;
};

static bool cg_storage_io_has_filters(cg_storage_io const * const io)
{
    bool result = false;

    assert(io != NULL);

    if (io->filters_count > 0)
    {
        result = true;
    }

    return result;
}

static bool cg_storage_io_ctx_has_filters(cg_storage_io_ctx const * const this)
{
    assert(this != NULL);

    int result = cg_storage_io_has_filters(this->io);

    return result;
}

static int cg_storage_io_finish_filters(cg_storage_io * const this,
                                        char ** out,
                                        size_t * out_size)
{
    int result = 0;

    assert(this != NULL);
    assert(out != NULL);
    assert(out_size != NULL);
    assert(this->type == cg_storage_io_type_source ||
           this->type == cg_storage_io_type_destination);

    *out = NULL;
    *out_size = 0;

    this->finished = true;

    if (cg_storage_io_has_filters(this))
    {
        char * in = NULL;
        size_t in_size = 0;
        cgutils_llist_elt * elt = NULL;
        cgutils_llist_elt * (*next)(cgutils_llist_elt *) = NULL;

        if (this->type == cg_storage_io_type_source)
        {
            elt = cgutils_llist_get_first(this->filter_ctx_list);
            next = &cgutils_llist_elt_get_next;
        }
        else
        {
            elt = cgutils_llist_get_last(this->filter_ctx_list);
            next = &cgutils_llist_elt_get_previous;
        }

        while (result == 0 && elt != NULL)
        {
            cg_storage_filter_ctx * ctx = cgutils_llist_elt_get_object(elt);
            assert(ctx != NULL);

            if (in == NULL)
            {
                result = cg_storage_filter_finish(ctx,
                                                  out,
                                                  out_size);

                if (COMPILER_LIKELY(result == 0))
                {
                    assert(*out_size > 0 || *out == NULL);
                    in = *out;
                    in_size = *out_size;
                }
                else
                {
                    CGUTILS_ERROR("Error in cg_storage_filter_finish: %d", result);
                }
            }
            else
            {
                result = cg_storage_filter_do(ctx,
                                              in,
                                              in_size,
                                              out,
                                              out_size);

                CGUTILS_FREE(in);
                in_size = 0;

                if (COMPILER_LIKELY(result == 0))
                {
                    char * finished = NULL;
                    size_t finished_size = 0;

                    assert(*out_size > 0 || *out == NULL);

                    result = cg_storage_filter_finish(ctx,
                                                      &finished,
                                                      &finished_size);

                    if (COMPILER_LIKELY(result == 0))
                    {
                        assert(finished_size > 0 || finished == NULL);

                        if (finished_size > 0 && finished != NULL)
                        {
                            char * new = NULL;

                            assert(SIZE_MAX - *out_size >= finished_size);
                            CGUTILS_REALLOC(new, *out, *out_size + finished_size, sizeof **out);

                            if (COMPILER_LIKELY(new != NULL))
                            {
                                *out = new;
                                new = NULL;
                                memcpy(*out + *out_size, finished, finished_size);
                                *out_size += finished_size;
                                assert(*out_size > 0);
                            }
                            else
                            {
                                result = ENOMEM;
                                CGUTILS_ERROR("Error reallocating memory for filter result: %d", result);
                            }

                            CGUTILS_FREE(finished);
                            finished_size = 0;
                        }

                        in = *out;
                        in_size = *out_size;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error in cg_storage_filter_finish: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error in cg_storage_filter_do: %d", result);
                }
            }

            elt = (*next)(elt);
        }

        if (COMPILER_UNLIKELY(result != 0 && *out != NULL))
        {
            CGUTILS_FREE(*out);
            *out_size = 0;
        }
    }

    assert(*out_size > 0 || *out == NULL);

    return result;
}

static int cg_storage_io_apply_filters(cg_storage_io_ctx * const this,
                                       char const * const in,
                                       size_t const in_size,
                                       char ** out,
                                       size_t * out_size)
{
    int result = 0;

    assert(this != NULL);
    assert(in_size > 0);
    assert(out != NULL);
    assert(out_size != NULL);
    assert(this->io->type == cg_storage_io_type_source ||
           this->io->type == cg_storage_io_type_destination);

    char * tmp_in = NULL;
    size_t tmp_in_size = in_size;
    cgutils_llist_elt * elt = NULL;
    cgutils_llist_elt * (*next)(cgutils_llist_elt *) = NULL;

    *out = NULL;
    *out_size = 0;

    if (this->io->type == cg_storage_io_type_source)
    {
        elt = cgutils_llist_get_first(this->io->filter_ctx_list);
        next = &cgutils_llist_elt_get_next;
    }
    else
    {
        elt = cgutils_llist_get_last(this->io->filter_ctx_list);
        next = &cgutils_llist_elt_get_previous;
    }

    while (result == 0 &&
           elt != NULL &&
           tmp_in_size > 0)
    {
        cg_storage_filter_ctx * ctx = cgutils_llist_elt_get_object(elt);
        assert(ctx != NULL);

        result = cg_storage_filter_do(ctx,
                                      tmp_in != NULL ? tmp_in : in,
                                      tmp_in_size,
                                      out,
                                      out_size);

        if (tmp_in != NULL)
        {
            CGUTILS_FREE(tmp_in);
        }

        if (COMPILER_LIKELY(result == 0))
        {
            tmp_in = *out;
            tmp_in_size = *out_size;
        }
        else
        {
            CGUTILS_ERROR("Error in cg_storage_filter_do: %d", result);
        }

        elt = (*next)(elt);
    }

    if (COMPILER_UNLIKELY(result != 0 &&
                          *out != NULL))
    {
        CGUTILS_FREE(*out);
        *out_size = 0;
    }

    return result;
}

static int cg_storage_io_file_append(cg_storage_io * const this,
                                     char const * buffer,
                                     size_t const buffer_size,
                                     cg_storage_io_cb * const cb,
                                     void * const cb_data)
{
    int result = 0;

    assert(this != NULL);
    assert(buffer != NULL);
    assert(buffer_size > 0);

    result = cgutils_aio_append(this->aio,
                                this->fd,
                                buffer,
                                buffer_size,
                                cb,
                                cb_data);

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error in AIO append: %d", result);
    }

    return result;
}

static int cg_storage_io_ctx_file_write(cg_storage_io_ctx * const this,
                                        char const * buffer,
                                        size_t const buffer_size,
                                        cg_storage_io_cb * const cb,
                                        void * const cb_data)
{
    int result = 0;

    assert(this != NULL);
    assert(buffer != NULL);

    if (COMPILER_LIKELY(buffer_size > 0))
    {
        result = cgutils_aio_write(this->io->aio,
                                   this->io->fd,
                                   buffer,
                                   buffer_size,
                                   (off_t) (this->offset + this->ctx_pos),
                                   cb,
                                   cb_data);

        if (COMPILER_LIKELY(result == 0))
        {
            this->ctx_pos += buffer_size;
        }
        else
        {
            CGUTILS_ERROR("Error in AIO write: %d", result);
        }
    }

    return result;
}

static int cg_storage_io_mem_write(cg_storage_io * const this,
                                   char const * buffer,
                                   size_t const buffer_size,
                                   cg_storage_io_cb * const cb,
                                   void * const cb_data)
{
    int result = 0;

    assert(this != NULL);
    assert(buffer != NULL);

    assert(buffer_size > 0);

    if (COMPILER_LIKELY((SIZE_MAX - this->support_size) >= buffer_size))
    {
        size_t const new_size = this->support_size + buffer_size;

        char * newptr = CGUTILS_REALLOC(newptr, this->membuf,
                                        new_size,
                                        sizeof *newptr);

        if (COMPILER_LIKELY(newptr != NULL))
        {
            memcpy(newptr + this->support_size,
                   buffer,
                   buffer_size);

            this->membuf = newptr;
            this->support_size = new_size;

            result = (*cb)(0,
                           buffer_size,
                           cb_data);
        }
        else
        {
            result = ENOMEM;
        }
    }
    else
    {
        result = E2BIG;
    }

    return result;
}

static void cg_storage_io_destination_sync(cg_storage_io * const this)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->type == cg_storage_io_type_destination);

    if (this->support_type == cg_storage_io_support_type_file)
    {
        int result = cgutils_aio_fsync(this->aio,
                                       this->fd,
                                       O_DSYNC,
                                       this->finish_cb,
                                       this->finish_cb_data);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in AIO fsync: %d", result);
            (*(this->finish_cb))(result,
                                 0,
                                 this->finish_cb_data);
        }
    }
    else
    {
        /* no need to sync */
        (*(this->finish_cb))(0,
                             0,
                             this->finish_cb_data);
    }
}

static int cg_storage_io_destination_sync_before_cb(int const status,
                                                    size_t const completion,
                                                    void * const cb_data)
{
    cg_storage_io * this = cb_data;
    CGUTILS_ASSERT(cb_data != NULL);

    (void) completion;

    if (status == 0)
    {
        /* we have just written the last data remaining,
           we need to sync() then we are done. */

        cg_storage_io_destination_sync(this);
    }
    else
    {
        (*(this->finish_cb))(status,
                             0,
                             this->finish_cb_data);
    }

    return status;
}

int cg_storage_io_destination_finish(cg_storage_io * const this,
                                     cg_storage_io_cb * const cb,
                                     void * const cb_data)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(this != NULL && cb != NULL))
    {
        result = 0;

        if (this->type == cg_storage_io_type_destination &&
            this->finished == false)
        {
            char * data = NULL;
            size_t data_size = 0;

            this->finish_cb = cb;
            this->finish_cb_data = cb_data;

            if (cg_storage_io_has_filters(this))
            {
                result = cg_storage_io_finish_filters(this,
                                                      &data,
                                                      &data_size);

                if (COMPILER_LIKELY(result == 0))
                {
                    if (data_size > 0)
                    {
                        if (this->compute_hash == true &&
                            this->hash_ctx != NULL)
                        {
                            int res = cgutils_crypto_hash_context_update(this->hash_ctx,
                                                                         data,
                                                                         data_size);

                            if (res != 0)
                            {
                                CGUTILS_WARN("Error while updating the hash context: %d", res);
                                this->compute_hash = false;
                            }
                        }

                        if (this->support_type == cg_storage_io_support_type_mem)
                        {
                            /* no need to sync memory */
                            result = cg_storage_io_mem_write(this,
                                                             data,
                                                             data_size,
                                                             cb,
                                                             cb_data);
                        }
                        else if (this->support_type == cg_storage_io_support_type_file)
                        {
                            /* append the remaining data, then sync */
                            result = cg_storage_io_file_append(this,
                                                               data,
                                                               data_size,
                                                               &cg_storage_io_destination_sync_before_cb,
                                                               this);
                        }

                        if (result != 0)
                        {
                            CGUTILS_ERROR("Error in ctx_write: %d", result);
                        }
                    }
                    else
                    {
                        /* nothing more to write, just sync before returning */
                        cg_storage_io_destination_sync(this);
                    }

                    CGUTILS_FREE(data);
                }
                else
                {
                    CGUTILS_ERROR("Error finishing filters: %d", result);
                }

                if (COMPILER_UNLIKELY(result != 0))
                {
                    (*cb)(result, 0, cb_data);
                }
            }
            else
            {
                /* filters, we still want to sync before returning */
                cg_storage_io_destination_sync(this);
            }
        }
        else
        {
            /* already finished */
            (*cb)(0, 0, cb_data);
        }
    }

    return result;
}

COMPILER_PURE_FUNCTION static bool cg_storage_io_source_is_last_chunk(cg_storage_io_ctx const * const this)
{
    bool result = false;
    assert(this != NULL);
    assert(this->io->type == cg_storage_io_type_source);

    assert(SIZE_MAX - this->offset >= this->ctx_size);
    assert(SIZE_MAX - this->offset >= this->ctx_pos);

    if (this->offset + this->ctx_size == this->io->support_size)
    {
        result = true;
    }

    return result;
}

COMPILER_PURE_FUNCTION static bool cg_storage_io_buffer_empty(cg_storage_io_ctx const * const this)
{
    assert(this != NULL);

    bool result = cgutils_buffer_get_available_data(&(this->buf)) == 0;

    return result;
}

static bool cg_storage_io_source_need_only_finish(cg_storage_io_ctx const * const this)
{
    bool result = false;
    assert(this != NULL);
    assert(this->io->type == cg_storage_io_type_source);

    /* If we have data available */
    if (cg_storage_io_buffer_empty(this))
    {
        if (cg_storage_io_source_is_last_chunk(this))
        {
            /* We are the last part */
            if (this->ctx_pos == this->ctx_size)
            {
                result = (this->io->finished == false);
            }
        }
    }

    return result;
}

static bool cg_storage_io_source_is_eof(cg_storage_io_ctx const * const this)
{
    /* We are EOF if :
       - We are at the end of our chunk if we are _NOT_ the last part
       - We are at the end of the underlying source AND our filters are finished()
    */
    bool result = false;
    assert(this != NULL);
    assert(this->io->type == cg_storage_io_type_source);

    if (cg_storage_io_source_is_last_chunk(this))
    {
        /* We are the last part */
        if (this->ctx_pos == this->ctx_size)
        {
            result = this->io->finished;
        }
    }
    else
    {
        result = this->ctx_pos == this->ctx_size;
    }

    return result;
}

static int cg_storage_io_source_fill_from_buffered_data(cg_storage_io_ctx * const this,
                                                        char * const buffer,
                                                        size_t const buffer_size,
                                                        size_t * const written,
                                                        bool * const eof)
{
    int result = 0;

    assert(this != NULL);
    assert(cg_storage_io_buffer_empty(this) == false);
    assert(written != NULL);
    assert(eof != NULL);

    char const * source = NULL;
    size_t source_len = 0;

    cgutils_buffer_get_readable_data(&(this->buf),
                                     &source,
                                     &source_len);

    size_t const to_copy = buffer_size > source_len ? source_len : buffer_size;

    if (source != NULL && to_copy > 0)
    {
        memcpy(buffer, source, to_copy);
    }

    cgutils_buffer_consume(&(this->buf), to_copy);

    *written = to_copy;

    if (cgutils_buffer_get_available_data(&(this->buf)) == 0)
    {
        *eof = cg_storage_io_source_is_eof(this);
    }
    else
    {
        *eof = false;
    }

    return result;
}

static int cg_storage_io_source_evaluate_optimal_read_size(cg_storage_io_ctx const * const this,
                                                           size_t buffer_size,
                                                           size_t * const optimal)
{
    int result = 0;
    assert(this != NULL);
    assert(optimal != NULL);

    assert(buffer_size > 0);

    cgutils_llist * const filter_ctx_lst = this->io->filter_ctx_list;

    for (cgutils_llist_elt * elt = cgutils_llist_get_first(filter_ctx_lst);
         elt != NULL && buffer_size > 0;
         elt = cgutils_llist_elt_get_next(elt))
    {
        cg_storage_filter_ctx * ctx = cgutils_llist_elt_get_object(elt);

        assert(ctx != NULL);

        buffer_size = cg_storage_filter_max_input_for_buffer(ctx,
                                                             buffer_size);
    }

    /* Maybe we should not allocate a buffer less than CURL_MAX_WRITE_SIZE ? */
    *optimal = buffer_size;

    return result;
}

static int cg_storage_io_ctx_source_do_finish_filters(cg_storage_io_ctx * const this)
{
    int result = 0;
    char * filtered = NULL;
    size_t filtered_size = 0;
    assert(this != NULL);
    assert(cg_storage_io_source_is_last_chunk(this));
    assert(this->io->finished == false);
    assert(cgutils_buffer_get_available_data(&(this->buf)) == 0);

    result = cg_storage_io_finish_filters(this->io,
                                          &filtered,
                                          &filtered_size);

    if (COMPILER_LIKELY(result == 0))
    {
        assert(filtered_size > 0 || filtered == NULL);

        if (filtered_size > 0)
        {
            assert(filtered != NULL);

            cgutils_buffer_set_buffer(&(this->buf),
                                      filtered,
                                      filtered_size);
        }
        else if (COMPILER_UNLIKELY(filtered != NULL))
        {
            /* Shouldn't happen, but hey. */
            CGUTILS_FREE(filtered);
        }
    }
    else
    {
        CGUTILS_ERROR("Error in cg_storage_io_finish_filters: %d", result);
    }

    if (cg_storage_io_source_is_eof(this))
    {
        this->io->eof = true;
    }

    return result;
}

static int cg_storage_io_ctx_file_read(cg_storage_io_ctx * const this);

static int cg_storage_io_ctx_read_done(int const status,
                                       size_t const got,
                                       void * const cb_data)
{
    int result = status;
    bool pending = false;
    cg_storage_io_ctx * const this = cb_data;

    assert(cb_data != NULL);

    assert(cgutils_buffer_get_available_data(&(this->buf)) == 0);

    cgutils_buffer_add_readable(&(this->buf), got);

    if (COMPILER_LIKELY(status == 0))
    {
        char * filtered = NULL;
        size_t filtered_size = 0;

        if (COMPILER_LIKELY(got > 0))
        {
            char const * in = NULL;
            size_t in_size = 0;

            cgutils_buffer_get_readable_data(&(this->buf),
                                             &in,
                                             &in_size);

            if (this->io->compute_hash == true &&
                this->io->hash_ctx != NULL)
            {
                int res = cgutils_crypto_hash_context_update(this->io->hash_ctx,
                                                             in,
                                                             in_size);

                if (COMPILER_UNLIKELY(res != 0))
                {
                    CGUTILS_WARN("Error while updating the hash context: %d", res);
                    this->io->compute_hash = false;
                }
            }

            /* apply filters */
            if (cg_storage_io_ctx_has_filters(this))
            {
                result = cg_storage_io_apply_filters(this,
                                                     in,
                                                     in_size,
                                                     &filtered,
                                                     &filtered_size);

                if (COMPILER_LIKELY(result == 0))
                {
                    if (filtered_size > 0 &&
                        filtered != NULL)
                    {
                        cgutils_buffer_set_buffer(&(this->buf),
                                                  filtered,
                                                  filtered_size);
                    }
                    else
                    {
                        /* Discard previously read data, which has been consumed
                           by the filters anyway. */
                        cgutils_buffer_discard(&(this->buf));

                        /* No more data after filters, trying to read some more */
                        result = cg_storage_io_ctx_file_read(this);

                        if (COMPILER_LIKELY(result == 0))
                        {
                            pending = true;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error while reading: %d", result);
                        }
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error in cg_storage_io_apply_filters: %d", result);
                }
            }
        }
        else
        {
            /* no more data avail */
            if (cg_storage_io_source_is_last_chunk(this) &&
                this->io->finished == false)
            {
                result = cg_storage_io_ctx_source_do_finish_filters(this);

                if (COMPILER_LIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error in cg_storage_io_ctx_source_do_finish_filters: %d", result);
                }
            }
        }
    }

    if (pending == false)
    {
        (*(this->read_cb))(result,
                           this->read_cb_data);
    }

    return result;
}

static int cg_storage_io_ctx_file_read(cg_storage_io_ctx * const this)
{
    int result = 0;
    char * buffer = NULL;
    size_t buffer_size = 0;

    assert(this != NULL);
    assert(this->io->support_size >= this->offset + this->ctx_size);
    assert(cgutils_buffer_get_usable_size(&(this->buf)) > 0);

    cgutils_buffer_get_writable_buf(&(this->buf),
                                    &buffer,
                                    &buffer_size);

    size_t const avail = this->ctx_size - this->ctx_pos;
    size_t const to_read = avail > buffer_size ? buffer_size : avail;

    if (to_read > 0)
    {
        result = cgutils_aio_read(this->io->aio,
                                  this->io->fd,
                                  buffer,
                                  to_read,
                                  (off_t) (this->offset + this->ctx_pos),
                                  &cg_storage_io_ctx_read_done,
                                  this);

        if (COMPILER_LIKELY(result == 0))
        {
            this->ctx_pos += to_read;
        }
        else
        {
            CGUTILS_ERROR("Error in AIO read: %d", result);
        }
    }
    else
    {
        /* May happen if we are at the end of the source,
           but we have filters and they haven't been finished() yet. */
        cg_storage_io_ctx_read_done(0, 0, this);
    }

    return result;
}

bool cg_storage_io_ctx_source_has_data_ready(cg_storage_io_ctx const * const this)
{
    bool result = false;

    if (COMPILER_LIKELY(this != NULL && this->io->type == cg_storage_io_type_source))
    {
        if (cgutils_buffer_get_available_data(&(this->buf)) > 0 ||
            cg_storage_io_source_is_eof(this) ||
            cg_storage_io_source_need_only_finish(this))
        {
            result = true;
        }
    }

    return result;
}

bool cg_storage_io_ctx_destination_need_suspend(cg_storage_io_ctx const * const this)
{
    bool result = false;

    if (COMPILER_LIKELY(this != NULL && this->io->type == cg_storage_io_type_destination))
    {
        if (this->io->support_type == cg_storage_io_support_type_file)
        {
            result = true;
        }
    }

    return result;
}

int cg_storage_io_ctx_read(cg_storage_io_ctx * const this,
                           char * const buffer,
                           size_t const buffer_size,
                           size_t * const written,
                           bool * const eof,
                           bool * const io_pending,
                           cg_storage_io_read_cb * const cb,
                           void * const cb_data)
{
    /* We need to fill at most buffer_size bytes into buffer,
       set *written to the number of bytes filled */
    /* Set *eof if
       - we are not the last chunk, and ctx_pos == ctx_size
       - we are the last chunk, ctx_pos == ctx_size
       AND we have finished() existing filters. */

    /* Callback is only used if we have no data available at this time,
       not to return the data but to let the initial caller know that
       a new call will be successful this time. */

    int result = EINVAL;

    if (COMPILER_LIKELY(this != NULL && buffer != NULL && written != NULL && eof != NULL && io_pending != NULL &&
                        this->io->type == cg_storage_io_type_source && buffer_size > 0))
    {
        result = 0;
        *io_pending = false;

        if (cg_storage_io_source_need_only_finish(this))
        {
            result = cg_storage_io_ctx_source_do_finish_filters(this);
        }

        if (COMPILER_LIKELY(result == 0))
        {
            if (cgutils_buffer_get_available_data(&(this->buf)) > 0)
            {
                /* If we already have buffered data, use it. */
                result = cg_storage_io_source_fill_from_buffered_data(this,
                                                                      buffer,
                                                                      buffer_size,
                                                                      written,
                                                                      eof);
            }
            else if (cg_storage_io_source_is_eof(this) == false)
            {
                /* We compute how much data we can get from underlying source without
                   overflowing buffer_size after filters. It's not mandatory not to
                   overflow buffer_size because if this happens we can still fill buffer
                   with buffer_size bytes and store the remaining data in our buffer,
                   but it consumes more memory. */

                size_t ask_for = buffer_size;

                result = cg_storage_io_source_evaluate_optimal_read_size(this,
                                                                         buffer_size,
                                                                         &ask_for);

                if (result == 0 && ask_for > 0)
                {
                    result = cgutils_buffer_make_space_for(&(this->buf),
                                                           ask_for);

                    if (result == 0)
                    {
                        this->read_cb = cb;
                        this->read_cb_data = cb_data;

                        if (this->io->support_type == cg_storage_io_support_type_mem)
                        {
                            CGUTILS_ERROR("Type cg_storage_io_support_type_mem not supported for reading");
                        }
                        else if (this->io->support_type == cg_storage_io_support_type_file)
                        {
                            result = cg_storage_io_ctx_file_read(this);
                        }

                        if (result == 0)
                        {
                            *io_pending = true;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error reading %zu bytes from support: %d", ask_for, result);
                        }
                    }
                    else
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Error allocating %zu bytes for buffer: %d", ask_for, result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error evaluating optimal read size: %d", result);
                }
            }
            else
            {
                result = 0;
                *written = 0;
                *eof = true;
            }
        }
        else
        {
            CGUTILS_ERROR("Error in cg_storage_io_ctx_source_do_finish_filters: %d", result);
        }
    }

    return result;
}

int cg_storage_io_ctx_write(cg_storage_io_ctx * const this,
                            char const * const buffer,
                            size_t const buffer_size,
                            cg_storage_io_cb * const cb,
                            void * const cb_data)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(this != NULL &&
                        this->io->type == cg_storage_io_type_destination &&
                        buffer != NULL && buffer_size > 0))
    {
        char const * dest = buffer;
        size_t dest_size = buffer_size;
        char * data = NULL;
        size_t data_size = 0;

        result = 0;

        if (cg_storage_io_ctx_has_filters(this) == true)
        {
            result = cg_storage_io_apply_filters(this, buffer, buffer_size,
                                                 &data,
                                                 &data_size);

            if (result == 0)
            {
                dest = data;
                dest_size = data_size;
            }
            else
            {
                CGUTILS_ERROR("Error applying filters: %d", result);
            }
        }

        if (COMPILER_LIKELY(result == 0))
        {
            if (dest_size > 0)
            {
                if (this->io->compute_hash == true &&
                    this->io->hash_ctx != NULL)
                {
                    int res = cgutils_crypto_hash_context_update(this->io->hash_ctx,
                                                                 dest,
                                                                 dest_size);

                    if (res != 0)
                    {
                        CGUTILS_WARN("Error while updating the hash context: %d", res);
                        this->io->compute_hash = false;
                    }
                }

                if (this->io->support_type == cg_storage_io_support_type_mem)
                {
                    result = cg_storage_io_mem_write(this->io, dest, dest_size, cb, cb_data);
                }
                else if (this->io->support_type == cg_storage_io_support_type_file)
                {
                    result = cg_storage_io_ctx_file_write(this, dest, dest_size, cb, cb_data);
                }

                if (result != 0)
                {
                    CGUTILS_ERROR("Error writing to support: %d", result);
                }
            }
            else
            {
                (*cb)(0, 0, cb_data);
            }
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            (*cb)(result, 0, cb_data);
        }

        if (data != NULL)
        {
            CGUTILS_FREE(data);
        }
    }

    return result;
}

int cg_storage_io_ctx_source_init(cg_storage_io * const io,
                                  size_t const offset,
                                  size_t const ctx_size,
                                  cg_storage_io_ctx ** const ctx)
{
    int result = EINVAL;

    if (io != NULL && ctx != NULL)
    {
        CGUTILS_ALLOCATE_STRUCT(*ctx);

        if (*ctx != NULL)
        {
            cg_storage_io_ctx * this = *ctx;
            result = 0;
            this->io = io;
            this->offset = offset;
            this->ctx_size = ctx_size;
            this->ctx_pos = 0;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cg_storage_io_ctx_destination_init(cg_storage_io * const io,
                                       cg_storage_io_ctx ** const ctx)
{
    int result = EINVAL;

    if (io != NULL && ctx != NULL)
    {
        CGUTILS_ALLOCATE_STRUCT(*ctx);

        if (*ctx != NULL)
        {
            cg_storage_io_ctx * this = *ctx;
            result = 0;
            this->io = io;
            this->offset = 0;
            this->ctx_size = 0;
            this->ctx_pos = 0;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

void cg_storage_io_ctx_free(cg_storage_io_ctx * ctx)
{
    if (ctx != NULL)
    {
        cgutils_buffer_clear(&(ctx->buf));

        ctx->io = NULL;
        ctx->offset = 0;
        ctx->ctx_size = 0;
        ctx->ctx_pos = 0;

        CGUTILS_FREE(ctx);
    }
}

bool cg_storage_io_support_parallel_ops(cg_storage_io const * const this)
{
    bool result = false;

    if (COMPILER_LIKELY(this != NULL))
    {
        /* If we have been asked to compute the digest of the data
           on disk, we can not use parallel ops. */
        if (this->compute_hash == false)
        {
            /* If we have some filters, they may rely on the data being passed
               on the right order (think CBC encryption or compression). */

            if (cg_storage_io_has_filters(this) == false)
            {
                /* And obviously, if the chunk size can not be computed in advance,
                   we are toasted (think compression). */
                result = cg_storage_io_is_chunk_size_known(this);
            }
        }
    }

    return result;
}

bool cg_storage_io_is_final_size_known(cg_storage_io const * const this)
{
    bool result = false;

    if (COMPILER_LIKELY(this != NULL))
    {
        result = true;

        if (cg_storage_io_has_filters(this))
        {
            for (cgutils_llist_elt * elt = cgutils_llist_get_first(this->filter_ctx_list);
                 result == true && elt != NULL;
                 elt = cgutils_llist_elt_get_next(elt))
            {
                cg_storage_filter_ctx const * const filter_ctx = cgutils_llist_elt_get_object(elt);

                result = cg_storage_filter_ctx_support_predictable_output_size(filter_ctx);
            }
        }
    }

    return result;
}

bool cg_storage_io_is_chunk_size_known(cg_storage_io const * const this)
{
    bool result = false;

    if (COMPILER_LIKELY(this != NULL))
    {
        if (cg_storage_io_has_filters(this) == false)
        {
            result = true;
        }
    }

    return result;
}

size_t cg_storage_io_get_support_size(cg_storage_io const * const this)
{
    size_t result = 0;

    if (COMPILER_LIKELY(this != NULL))
    {
        result = this->support_size;
    }

    return result;
}


size_t cg_storage_io_get_final_size(cg_storage_io const * const this)
{
    size_t result = 0;

    if (COMPILER_LIKELY(this != NULL))
    {
        result = cg_storage_io_get_support_size(this);

        if (cg_storage_io_has_filters(this) == true)
        {
            for (cgutils_llist_elt * elt = cgutils_llist_get_first(this->filter_ctx_list);
                 result > 0 && elt != NULL;
                 elt = cgutils_llist_elt_get_next(elt))
            {
                size_t out = 0;
                cg_storage_filter_ctx const * const filter_ctx = cgutils_llist_elt_get_object(elt);

                cg_storage_filter_get_max_final_size(filter_ctx, result, &out);

                result = out;
            }
        }
    }

    return result;
}

int cg_storage_io_ctx_source_get_final_size(cg_storage_io_ctx const * const this,
                                            size_t * const out_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(this != NULL && this->io != NULL && this->io->type == cg_storage_io_type_source))
    {
        result = 0;
        *out_size = this->ctx_size;

        if (cg_storage_io_has_filters(this->io) == true)
        {
            for (cgutils_llist_elt * elt = cgutils_llist_get_first(this->io->filter_ctx_list);
                 result == 0 &&
                     *out_size > 0 &&
                     elt != NULL;
                 elt = cgutils_llist_elt_get_next(elt))
            {
                cg_storage_filter_ctx const * const filter = cgutils_llist_elt_get_object(elt);

                if (cg_storage_filter_ctx_support_predictable_output_size(filter) == true)
                {
                    size_t out = 0;

                    result = cg_storage_filter_get_max_final_size(filter,
                                                                  *out_size,
                                                                  &out);

                    if (result == 0)
                    {
                        *out_size = out;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error getting max final size");
                    }
                }
                else
                {
                    CGUTILS_DEBUG("Unpredictable output size");
                    result = EIO;
                }
            }

            if (result != 0)
            {
                *out_size = 0;
            }
        }
    }
    else
    {
        CGUTILS_DEBUG("EINVAL");
    }

    return result;
}

size_t cg_storage_io_get_max_final_size(cg_storage_io const * const this)
{
    size_t result = 0;

    if (cg_storage_io_has_filters(this))
    {
        int res = 0;

        for (cgutils_llist_elt * elt = cgutils_llist_get_first(this->filter_ctx_list);
             res == 0 && result > 0 && elt != NULL;
             elt = cgutils_llist_elt_get_next(elt))
        {
            cg_storage_filter_ctx const * const filter = cgutils_llist_elt_get_object(elt);

            res = cg_storage_filter_get_max_final_size(filter,
                                                       result,
                                                       &result);
        }
    }
    else
    {
        result = this->support_size;
    }

    return result;
}

static int cg_storage_io_init_from_fd(cg_storage_io_type const type,
                                      cgutils_aio * const aio,
                                      int const fd,
                                      size_t const file_size,
                                      cg_storage_io ** const out)
{
    int result = 0;

    assert(aio != NULL);
    assert(fd >= 0);
    assert(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(*out);

    if (*out != NULL)
    {
        cg_storage_io * io = *out;
        io->filters_count = 0;
        io->aio = aio;
        io->support_size = file_size;
        io->offset = 0;
        io->fd = fd;
        io->type = type;
        io->support_type = cg_storage_io_support_type_file;
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}


int cg_storage_io_source_init_from_fd(cgutils_aio * const aio,
                                      int const fd,
                                      size_t const support_size,
                                      cg_storage_io ** const out)
{
    int result = EINVAL;

    if (aio != NULL && fd >= 0 && out != NULL)
    {
        result = cg_storage_io_init_from_fd(cg_storage_io_type_source,
                                            aio,
                                            fd,
                                            support_size,
                                            out);
    }

    return result;
}

int cg_storage_io_destination_init_from_fd(cgutils_aio * const aio,
                                           int const fd,
                                           cg_storage_io ** const out)
{
        int result = EINVAL;

    if (aio != NULL && fd >= 0 && out != NULL)
    {
        result = cg_storage_io_init_from_fd(cg_storage_io_type_destination,
                                            aio,
                                            fd,
                                            0,
                                            out);
    }

    return result;
}

int cg_storage_io_destination_init_mem(cg_storage_io ** const out)
{
    int result = EINVAL;

    if (out != NULL)
    {
        result = 0;

        CGUTILS_ALLOCATE_STRUCT(*out);

        if (*out != NULL)
        {
            cg_storage_io * io = *out;
            io->offset = 0;
            io->type = cg_storage_io_type_destination;
            io->support_type = cg_storage_io_support_type_mem;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cg_storage_io_compute_hash(cg_storage_io * const this,
                               cgutils_crypto_digest_algorithm const algorithm)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(this != NULL &&
                        this->compute_hash == false &&
                        this->hash_ctx == NULL))
    {
        result = cgutils_crypto_hash_context_init(algorithm,
                                                  &(this->hash_ctx));

        if (result == 0)
        {
            this->compute_hash = true;
        }
    }

    return result;
}

int cg_storage_io_get_hash(cg_storage_io * const this,
                           void ** const hash,
                           size_t * const hash_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(this != NULL &&
                        hash != NULL &&
                        hash_size != NULL &&
                        this->hash_ctx != NULL))
    {
        if (COMPILER_LIKELY(this->compute_hash == true))
        {
            result = cgutils_crypto_hash_context_finish(this->hash_ctx,
                                                        hash,
                                                        hash_size);
        }
        else
        {
            result = EIO;
        }
    }

    return result;
}

void cg_storage_io_free(cg_storage_io * this)
{
    if (this != NULL)
    {
        if (this->filter_ctx_list != NULL)
        {
            cgutils_llist_free(&(this->filter_ctx_list), &cg_storage_filter_ctx_delete);
        }

        if (this->membuf != NULL)
        {
            CGUTILS_FREE(this->membuf);
        }

        if (this->hash_ctx != NULL)
        {
            cgutils_crypto_hash_context_free(this->hash_ctx), this->hash_ctx = NULL;
        }

        this->filters_count = 0;
        this->support_size = 0;
        this->offset = 0;
        this->fd = -1;
        this->type = cg_storage_io_type_none;
        this->support_type = cg_storage_io_support_type_none;
        this->eof = false;
        this->aio = NULL;
        this->compute_hash = false;

        CGUTILS_FREE(this);
    }
}

int cg_storage_io_add_filter(cg_storage_io * const this,
                             cg_storage_filter * const filter)
{
    int result = EINVAL;

    if (this != NULL && filter != NULL)
    {
        cg_storage_filter_mode const filter_mode =
            this->type == cg_storage_io_type_source ?
            cg_storage_filter_enc :
            cg_storage_filter_dec;

        cg_storage_filter_ctx * ctx = NULL;

        result = cg_storage_filter_ctx_init(filter,
                                            filter_mode,
                                            &ctx);

        if (result == 0)
        {
            if (this->filter_ctx_list == NULL)
            {
                result = cgutils_llist_create(&(this->filter_ctx_list));
            }

            if (result == 0)
            {
                result = cgutils_llist_insert(this->filter_ctx_list,
                                              ctx);
            }

            if (result == 0)
            {
                this->filters_count++;
            }
            else
            {
                cg_storage_filter_ctx_free(ctx), ctx = NULL;
            }
        }
    }

    return result;
}

size_t cg_storage_io_mem_get_output_size(cg_storage_io_ctx * const ctx)
{
    size_t result = 0;

    if (COMPILER_LIKELY(ctx != NULL))
    {
        result = ctx->io->support_size;
    }

    return result;
}

int cg_storage_io_mem_get_output(cg_storage_io_ctx * const ctx,
                                 char const ** const out)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(ctx != NULL &&
                        ctx->io != NULL &&
                        ctx->io->type == cg_storage_io_type_destination &&
                        ctx->io->support_type == cg_storage_io_support_type_mem))
    {
        result = 0;
        *out = ctx->io->membuf;
    }

    return result;
}
