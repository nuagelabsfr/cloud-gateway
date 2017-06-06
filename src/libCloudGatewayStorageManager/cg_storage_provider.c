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
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_llist.h>

#include <cgsm/cg_storage_manager_data.h>
#include <cgsm/cg_storage_provider.h>
#include <cgsm/cg_storage_provider_utils.h>

struct cg_storage_provider
{
    cg_storage_manager_data * global_data;
    cgutils_http_data * http;
    char * name;
    void * dl_handle;
    cg_stp_vtable const * vtable;
    void * provider_data;
};

static int cg_storage_provider_plugin_init(cg_storage_manager_data * const data,
                                           cg_storage_provider * const provider)
{
    assert(provider != NULL);
    assert(provider->vtable != NULL);

    int result = ENOSYS;

    if (provider->vtable->init != NULL)
    {
        result = (*provider->vtable->init)(data, &(provider->provider_data));
    }

    return result;
}

static int cg_storage_provider_create(cg_storage_manager_data * const global_data,
                                      char * name,
                                      void * dl_handle,
                                      cg_stp_vtable const * const vtable,
                                      cg_storage_provider ** const provider)
{
    assert(global_data != NULL);
    assert(name != NULL);
    assert(dl_handle != NULL);
    assert(vtable != NULL);
    assert(provider != NULL);

    int result = ENOMEM;

    CGUTILS_ALLOCATE_STRUCT(*provider);

    if (*provider)
    {
        (*provider)->global_data = global_data;
        (*provider)->name = name;
        (*provider)->dl_handle = dl_handle;
        (*provider)->vtable = vtable;

        result = cg_storage_provider_plugin_init(global_data, *provider);

        if (result != 0)
        {
            cg_storage_provider_free(*provider), *provider = NULL;
        }
    }
    else
    {
        CGUTILS_FREE(name);
        dlclose(dl_handle), dl_handle = NULL;
    }

    return result;
}

static int cg_storage_provider_init_destination_file_io(cg_storage_provider const * const this,
                                                        cgutils_aio * const aio,
                                                        int const fd,
                                                        cgutils_llist * const filters_list,
                                                        bool * const has_filters,
                                                        cg_storage_io ** const out)
{
    assert(this != NULL);
    assert(aio != NULL);
    assert(fd >= 0);
    assert(has_filters != NULL);
    assert(out != NULL);

    int result = cg_storage_io_destination_init_from_fd(aio,
                                                        fd,
                                                        out);

    if (result == 0)
    {
        cg_storage_io * io = *out;

        if (filters_list != NULL &&
            cgutils_llist_get_count(filters_list) > 0)
        {
            *has_filters = false;

            for (cgutils_llist_elt * filter_elt = cgutils_llist_get_first(filters_list);
                 result == 0 && filter_elt != NULL;
                 filter_elt = cgutils_llist_elt_get_next(filter_elt))
            {
                cg_storage_filter * const filter = cgutils_llist_elt_get_object(filter_elt);
                assert(filter != NULL);

                if (this->vtable->capabilities.chunked_upload == true ||
                    cg_storage_filter_support_predictable_output_size(filter) == true)
                {
                    result = cg_storage_io_add_filter(io,
                                                      filter);

                    if (result == 0)
                    {
                        if (*has_filters == false)
                        {
                            *has_filters = true;
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error adding filter to IO: %d", result);
                    }
                }
            }
        }

        if (result != 0)
        {
            cg_storage_io_free(io), io = NULL;
            *out = NULL;
        }
    }

    else
    {
        CGUTILS_ERROR("Error in cg_storage_io_destination_init_from_fd: %d", result);
    }

    return result;
}

static int cg_storage_provider_init_source_io(cg_storage_provider const * const this,
                                              cgutils_aio * aio,
                                              int const fd,
                                              size_t const file_size,
                                              cgutils_llist * const filters_list,
                                              bool * const compressed,
                                              bool * const encrypted,
                                              cg_storage_io ** const out)
{
    assert(this != NULL);
    assert(aio != NULL);
    assert(fd >= 0);
    assert(compressed != NULL);
    assert(encrypted != NULL);
    assert(out != NULL);

    int result = cg_storage_io_source_init_from_fd(aio,
                                                   fd,
                                                   file_size,
                                                   out);

    if (result == 0)
    {
        cg_storage_io * io = *out;

        if (filters_list != NULL &&
            cgutils_llist_get_count(filters_list) > 0)
        {
            for (cgutils_llist_elt * filter_elt = cgutils_llist_get_first(filters_list);
                 result == 0 && filter_elt != NULL;
                 filter_elt = cgutils_llist_elt_get_next(filter_elt))
            {
                cg_storage_filter * const filter = cgutils_llist_elt_get_object(filter_elt);
                assert(filter != NULL);

                if (this->vtable->capabilities.chunked_upload == true ||
                    cg_storage_filter_support_predictable_output_size(filter) == true)
                {
                    result = cg_storage_io_add_filter(io,
                                                      filter);

                    if (result == 0)
                    {
                        cg_storage_filter_type const type = cg_storage_filter_get_type(filter);

                        if (type == cg_storage_filter_type_compression)
                        {
                            *compressed = true;
                        }
                        else if (type == cg_storage_filter_type_encryption)
                        {
                            *encrypted = true;
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error adding filter to IO: %d", result);
                    }
                }
                else
                {
                    CGUTILS_INFO("Discarding filter %s with provider %s, because the filter can not predict its output size and the provider does not support chunked uploading.",
                                 cg_storage_filter_get_name(filter),
                                 this->name);
                }
            }
        }

        if (result != 0)
        {
            cg_storage_io_free(io), io = NULL;
            *out = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Error in cg_storage_io_source_init_from_fd: %d", result);
    }

    return result;
}

void cg_storage_provider_request_free(cg_storage_provider_request * this)
{
    if (this != NULL)
    {
        if (this->received_headers != NULL)
        {
            cgutils_llist_free(&(this->received_headers), &cgutils_http_header_delete);
        }

        if (this->source_io != NULL)
        {
            cg_storage_io_ctx_free(this->source_io), this->source_io = NULL;
        }

        if (this->payload != NULL)
        {
            CGUTILS_FREE(this->payload);
        }

        if (this->dest_io != NULL)
        {
            cg_storage_io_ctx_free(this->dest_io), this->dest_io = NULL;
        }

        if (this->multipart_etag != NULL)
        {
            CGUTILS_FREE(this->multipart_etag);
        }

        if (this->object_hash_ctx != NULL)
        {
            cgutils_crypto_hash_context_free(this->object_hash_ctx),
                this->object_hash_ctx = NULL;
        }

        this->ctx = NULL;
        this->raw_request_cb = NULL;
        this->xml_request_cb = NULL;
        this->request_cb_data = NULL;
        this->part_number = 0;

        CGUTILS_FREE(this);
    }
}

static void cg_storage_provider_ctx_clean_for_next_request(cg_storage_provider_request_ctx * this)
{
    assert(this != NULL);

    /* Sometimes two requests or more share the same context but not the same
       destination IO */
    if (this->dest_io != NULL)
    {
        cg_storage_io_free(this->dest_io), this->dest_io = NULL;
    }

    this->has_dest_filters = false;
}

static void cg_storage_provider_request_delete(void * const this)
{
    cg_storage_provider_request_free(this);
}

static int cg_storage_provider_request_init(cg_storage_provider_request_ctx * const ctx,
                                            size_t const part_number,
                                            cg_storage_provider_request ** const out)
{
    int result = 0;
    assert(ctx != NULL);
    assert(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(*out);

    if (*out != NULL)
    {
        cg_storage_provider_request * this = *out;
        this->part_number = part_number;
        this->ctx = ctx;

        result = cgutils_llist_insert(ctx->parts,
                                      this);

        if (result != 0)
        {
            CGUTILS_FREE(this);
            *out = NULL;
            CGUTILS_ERROR("Error adding request to context: %d", result);
        }
    }
    else
    {
        result = ENOMEM;
        CGUTILS_ERROR("Error allocating memory for provider request: %d", result);
    }

    return result;
}

static int cg_storage_provider_request_io_source_init(cg_storage_provider_request_ctx * const ctx,
                                                      cg_storage_io * const io,
                                                      size_t const io_offset,
                                                      size_t const io_size,
                                                      size_t const part_number,
                                                      cg_storage_provider_request ** const out)
{
    int result = 0;

    assert(io != NULL);
    assert(ctx != NULL);
    assert(out != NULL);

    cg_storage_io_ctx * io_ctx = NULL;

    result = cg_storage_io_ctx_source_init(io,
                                           io_offset,
                                           io_size,
                                           &io_ctx);

    if (result == 0)
    {
        result = cg_storage_provider_request_init(ctx,
                                                  part_number,
                                                  out);

        if (result == 0)
        {
            assert(*out != NULL);
            cg_storage_provider_request * this = *out;
            this->source_io = io_ctx;
            io_ctx = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error creating request: %d", result);
        }

        if (result != 0)
        {
            if (io_ctx != NULL)
            {
                cg_storage_io_ctx_free(io_ctx), io_ctx = NULL;
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Error creating IO ctx: %d", result);
        CGUTILS_DEBUG("IO is %p, offset is %zu, size is %zu",
                      io, io_offset, io_size);
    }

    return result;
}

static int cg_storage_provider_request_io_dest_init(cg_storage_provider_request_ctx * const ctx,
                                                    cg_storage_io * const io,
                                                    cg_storage_provider_request ** const out)
{
    int result = 0;

    assert(io != NULL);
    assert(ctx != NULL);
    assert(out != NULL);

    cg_storage_io_ctx * io_ctx = NULL;

    result = cg_storage_io_ctx_destination_init(io,
                                                &io_ctx);

    if (result == 0)
    {
        result = cg_storage_provider_request_init(ctx,
                                                  0,
                                                  out);

        if (result == 0)
        {
            assert(*out != NULL);
            cg_storage_provider_request * this = *out;
            this->dest_io = io_ctx;
            io_ctx = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error creating request: %d", result);
        }

        if (result != 0)
        {
            if (io_ctx != NULL)
            {
                cg_storage_io_ctx_free(io_ctx), io_ctx = NULL;
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Error creating IO ctx: %d", result);
    }

    return result;
}

/*
   Asking the storage provider layer to compute
   a digest of the received / sent data in order
   to compare it with the digest provided by the
   provider (eg S3, Swift) if any.
*/
static void cg_storage_provider_init_object_hash(cg_storage_provider const * const this,
                                                 cg_storage_provider_request * const request)
{
    /* Failure to init object hash is non fatal. */
    assert(request != NULL);
    assert(this != NULL);

    if (this->vtable->capabilities.object_hashing == true &&
        this->vtable->init_object_hash != NULL &&
        this->vtable->update_object_hash != NULL &&
        this->vtable->check_object_hash != NULL)
    {
        int res = (*this->vtable->init_object_hash)(request);

        if (COMPILER_UNLIKELY(res != 0))
        {
            CGUTILS_WARN("Error in object hash context init: %d", res);
        }
    }
}

/*
   Asking the storage provider layer to update
   the digest of the received / sent data in order
   to compare it with the digest provided by the
   provider (eg S3, Swift) if any.
*/
int cg_storage_provider_update_object_hash(cg_storage_provider_request * const request,
                                           void const * const data,
                                           size_t const data_size)
{
    int result = 0;
    assert(request != NULL);
    assert(data != NULL);
    assert(request->ctx != NULL);
    assert(request->ctx->provider != NULL);

    cg_storage_provider * const this = request->ctx->provider;

    if (data_size > 0 &&
        request->compute_object_hash == true)
    {
        assert(this->vtable->capabilities.object_hashing == true);
        assert(this->vtable->update_object_hash != NULL);

        int res = (*this->vtable->update_object_hash)(request,
                                                      data,
                                                      data_size);

        if (COMPILER_UNLIKELY(res != 0))
        {
            /* For now, failure to update object hash context is not fatal. */
            CGUTILS_WARN("Error while updating object hash: %d", res);
        }
    }

    return result;
}

/*
   Asking the storage provider layer to compare
   the computed digest of the received / sent data
   with the digest provided by the
   provider (eg S3, Swift), if any.
*/
int cg_storage_provider_check_object_hash(cg_storage_provider_request * const request)
{
    int result = 0;

    assert(request != NULL);
    assert(request->ctx != NULL);
    assert(request->ctx->provider != NULL);

    cg_storage_provider * const this = request->ctx->provider;

    if (request->compute_object_hash == true)
    {
        bool valid = false;
        assert(this->vtable->capabilities.object_hashing == true);
        assert(this->vtable->check_object_hash != NULL);
        int res = (*this->vtable->check_object_hash)(request, &valid);

        if (COMPILER_LIKELY(res == 0))
        {
            if (COMPILER_UNLIKELY(valid == false))
            {
                CGUTILS_WARN("Invalid object hash: %d", res);
                result = EIO;
            }
        }
        else
        {
            CGUTILS_WARN("Error while checking object hash: %d", res);
        }
    }

    return result;
}

static int cg_storage_provider_multipart_send_a_part(cg_storage_provider_request_ctx * const ctx,
                                                     size_t const part_number)
{
    int result = 0;

    assert(ctx != NULL);
    assert(part_number > 0);

    size_t const support_size = cg_storage_io_get_support_size(ctx->source_io);
    size_t const file_size_for_part = ctx->part_support_size;
    size_t const already_handled = (part_number - 1) * file_size_for_part;
    size_t this_part_size = file_size_for_part;

    cg_storage_provider_request * request = NULL;

    cg_storage_provider_ctx_clean_for_next_request(ctx);

    if (part_number == ctx->number_of_parts)
    {
        this_part_size = support_size - already_handled;
    }

    result = cg_storage_provider_request_io_source_init(ctx,
                                                        ctx->source_io,
                                                        already_handled,
                                                        this_part_size,
                                                        part_number,
                                                        &request);

    if (result == 0)
    {
        /* Compute the digest of the data we will send in this part (after filters),
           to be able to compare it to the digest that the (S3, Swift) provider will return.
        */
        cg_storage_provider_init_object_hash(ctx->provider, request);

        result = (*ctx->provider->vtable->put_multipart_part)(request);
        request = NULL;
    }
    else
    {
        CGUTILS_ERROR("Error in cg_storage_provider_request_io_init: %d", result);
    }

    return result;
}

static int cg_storage_provider_multipart_finish(cg_storage_provider_request_ctx * ctx)
{
    int result = 0;

    assert(ctx != NULL);

    cg_storage_provider_request * request = NULL;

    cg_storage_provider_ctx_clean_for_next_request(ctx);

    result = cg_storage_provider_request_init(ctx,
                                              0,
                                              &request);
    if (result == 0)
    {
        request->ctx->state = cg_storage_provider_state_multipart_finish;
        result = (*(request->ctx->provider->vtable->put_multipart_finish))(request);
        request = NULL;
    }
    else
    {
        CGUTILS_ERROR("Error in cg_storage_provider_request_init: %d", result);
    }

    return result;
}

static int cg_storage_provider_multipart_cancel(cg_storage_provider_request_ctx * ctx)
{
    int result = 0;
    cg_storage_provider_request * request = NULL;

    assert(ctx != NULL);

    cg_storage_provider_ctx_clean_for_next_request(ctx);

    result = cg_storage_provider_request_init(ctx,
                                              0,
                                              &request);
    if (result == 0)
    {
        request->ctx->state = cg_storage_provider_state_multipart_cancel;
        (*(request->ctx->provider->vtable->put_multipart_cancel))(request);
        request = NULL;
    }
    else
    {
        CGUTILS_ERROR("Error in cg_storage_provider_request_init: %d", result);
    }

    return result;
}

static int cg_storage_provider_multipart_handle(cg_storage_provider_request * request,
                                                int const status)
{
    int result = status;
    assert(request != NULL);
    assert(request->ctx != NULL);

    bool const parallel_send = cg_storage_io_support_parallel_ops(request->ctx->source_io);
    bool all_parts_sent = false;
    bool pending_request = true;

    request->ctx->finished_parts++;

/*    CGUTILS_INFO("Debug: part %zu finished with status %d (ctx %p, ctx st. %d), finished parts %zu/%zu, parallel %d",
                 request->part_number,
                 status,
                 request->ctx,
                 request->ctx->status_code,
                 request->ctx->finished_parts,
                 request->ctx->number_of_parts,
                 parallel_send);*/

    if (request->ctx->finished_parts == request->ctx->number_of_parts)
    {
        all_parts_sent = true;
    }

    if (all_parts_sent == true || parallel_send == false)
    {
        pending_request = false;
    }

    if (status == 0)
    {
        if (request->ctx->status_code == 0)
        {
            if (all_parts_sent)
            {
                result = cg_storage_provider_multipart_finish(request->ctx);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error sending multipart finish: %d",
                                  result);

                }
            }
            else if (parallel_send == false)
            {
                result = cg_storage_provider_multipart_send_a_part(request->ctx,
                                                                   request->part_number + 1);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Error sending multipart request (%p) %zu: %d",
                      request,
                      request->part_number,
                      status);
    }

    if (result != 0)
    {
        if (request->ctx->status_code == 0)
        {
            request->ctx->status_code = result;
        }
    }

    if (request->ctx->status_code != 0)
    {
        if (pending_request == false)
        {
            bool handled = false;

            if (request->ctx->provider->vtable->put_multipart_cancel != NULL)
            {
                if (cg_storage_provider_multipart_cancel(request->ctx) == 0)
                {
                    handled = true;
                    request = NULL;
                }
            }

            if (handled == false)
            {
                CGUTILS_ASSERT(request->ctx->cb_type == cg_storage_provider_request_callback_type_put);

                result = (*(request->ctx->final_put_cb))(request->ctx->status_code,
                                                         NULL,
                                                         request->ctx->final_cb_data);

                cg_storage_provider_request_ctx_free(request->ctx), request = NULL;
            }
        }
    }

    if (result != 0 && pending_request == false)
    {
        if (request != NULL)
        {
            cg_storage_provider_request_ctx_free(request->ctx), request = NULL;
        }
    }

    return result;
}

static int cg_storage_provider_multipart_send(cg_storage_provider_request_ctx * ctx)
{
    int result = 0;
    assert(ctx != NULL);
    assert(ctx->source_io != NULL);

    /* First case :
       - Amazon-like, no filter, need to notify part size before hand

       - File size = part_size / (nb parts - 1) + remaining

       Second case :
       - Openstack-like, filters, no need to notify part size (chunked upload)

       - Max file size has been obtained from IO, based on filters.
         Part size may vary but we have a large margin anyway.
    */

    ctx->state = cg_storage_provider_state_multipart_parts;

    bool const parallel_send = cg_storage_io_support_parallel_ops(ctx->source_io);
    size_t part_number = 1;

    do
    {
        result = cg_storage_provider_multipart_send_a_part(ctx, part_number);

        part_number++;
    }
    while(result == 0 &&
          parallel_send == true &&
          part_number <= ctx->number_of_parts);

    return result;
}

static int cg_storage_provider_handle_status_callback(int const status,
                                                      cg_storage_provider_request_ctx const * const ctx)
{
    int result = status;
    cg_storage_instance_infos infos =
        {
            .compressed = ctx->compressed,
            .encrypted = ctx->encrypted,
            .digest = NULL,
            .digest_size = 0,
            .algo = ctx->digest_algo,
        };

    switch(ctx->cb_type)
    {
    case cg_storage_provider_request_callback_type_status:
        result = (*(ctx->final_status_cb))(status,
                                           ctx->final_cb_data);
        break;
    case cg_storage_provider_request_callback_type_get:
        if (infos.algo != cgutils_crypto_digest_algorithm_none &&
            result == 0)
        {
            /* Get the digest of the data after the filters have been applied,
               ie what really is on the cache. */
            int res = cg_storage_io_get_hash(ctx->dest_io,
                                             &(infos.digest),
                                             &(infos.digest_size));

            if (res != 0)
            {
                infos.algo = cgutils_crypto_digest_algorithm_none;
                CGUTILS_WARN("Error getting destination object hash: %d", res);
            }
        }

        result = (*(ctx->final_get_cb))(status,
                                        &infos,
                                        ctx->final_cb_data);
        break;
    case cg_storage_provider_request_callback_type_put:
        if (infos.algo != cgutils_crypto_digest_algorithm_none &&
            result == 0)
        {
            /* Get the digest of the data before the filters have been applied,
               ie what really is on the cache. */
            int res = cg_storage_io_get_hash(ctx->source_io,
                                             &(infos.digest),
                                             &(infos.digest_size));

            if (res != 0)
            {
                infos.algo = cgutils_crypto_digest_algorithm_none;
                CGUTILS_WARN("Error getting source object hash: %d", res);
            }
        }

        result = (*(ctx->final_put_cb))(status,
                                        &infos,
                                        ctx->final_cb_data);
        break;
    case cg_storage_provider_request_callback_type_none:
    case cg_storage_provider_request_callback_type_list:
    case cg_storage_provider_request_callback_type_container_stats:
    case cg_storage_provider_request_callback_type_count:
        CGUTILS_ERROR("Error, this kind of callback type (%d) is not handled by this function!",
                      ctx->cb_type);
        result = EINVAL;
        break;
    }

    return result;
}

static int cg_storage_provider_io_finish_cb(int const status,
                                            size_t const completion,
                                            void * const cb_data)
{
    int result = 0;
    cg_storage_provider_request_ctx * ctx = cb_data;
    int final_status = status;

    if (ctx->status_code != 0)
    {
        final_status = ctx->status_code;
    }

    (void) completion;

    if (status != 0)
    {
        CGUTILS_ERROR("Error in cg_storage_io_destination_ctx_finish: %d", status);
    }

    result = cg_storage_provider_handle_status_callback(final_status,
                                                        ctx);

    cg_storage_provider_request_ctx_free(ctx), ctx = NULL;

    return result;
}

int cg_storage_provider_handle_status_response(cg_storage_provider_request * request,
                                               int const status)
{
    int result = status;
    bool finished = false;

    assert(request != NULL);
    assert(request->ctx != NULL);
    cg_storage_provider_request_ctx * ctx = request->ctx;

    switch (ctx->state)
    {
    case cg_storage_provider_state_none:
        CGUTILS_ERROR("WTF");
        finished = true;
        result = EINVAL;
        break;
    case cg_storage_provider_state_single_request:
        ctx->status_code = status;
        finished = true;
        break;
    case cg_storage_provider_state_multipart_init:
    {
        if (status == 0)
        {
            result = cg_storage_provider_multipart_send(ctx);

            if (result != 0)
            {
                finished = true;
                CGUTILS_ERROR("Error in cg_storage_provider_multipart_send: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error initiating multipart: %d", status);
            finished = true;
        }
        break;
    }
    case cg_storage_provider_state_multipart_parts:
    {
        result = cg_storage_provider_multipart_handle(request, status);
        request = NULL;
        break;
    }
    case cg_storage_provider_state_multipart_finish:
        request = NULL;
        finished = true;
        break;
    case cg_storage_provider_state_multipart_cancel:
        finished = true;
        result = ctx->status_code;
        break;
    }

    if (finished == true)
    {
        int res = 0;

        if (ctx->has_dest_filters == true &&
            ctx->dest_io != NULL)
        {
            /* We need to notify the IO layer that we have nothing more,
               because some filters (encryption, compression) may have buffered
               output.
            */
            res = cg_storage_io_destination_finish(ctx->dest_io,
                                                   &cg_storage_provider_io_finish_cb,
                                                   ctx);

            ctx = NULL;

            if (res == 0)
            {
            }
            else
            {
                CGUTILS_ERROR("Error in cg_storage_io_destination_finish: %d", res);
            }
        }

        /* If we have destination filters, and cg_storage_io_destination_finish()
           did not return an error, the callback will be handled in cg_storage_provider_io_finish_cb().
        */
        if (ctx != NULL &&
            (ctx->has_dest_filters == false ||
             ctx->dest_io == NULL ||
             res != 0))
        {
            cg_storage_provider_handle_status_callback(result, ctx);

            cg_storage_provider_request_ctx_free(ctx), ctx = NULL;
            request = NULL;
        }
    }

    return result;
}

int cg_storage_provider_handle_list_response(cg_storage_provider_request * request,
                                             int const status,
                                             cgutils_llist * list)
{
    int result = status;
    CGUTILS_ASSERT(request != NULL);
    CGUTILS_ASSERT(request->ctx != NULL);
    cg_storage_provider_request_ctx * ctx = request->ctx;
    CGUTILS_ASSERT(ctx->state == cg_storage_provider_state_single_request);

    if (ctx->cb_type == cg_storage_provider_request_callback_type_list)
    {
        if (ctx->final_list_cb != NULL)
        {
            result = (*(ctx->final_list_cb))(status, list, ctx->final_cb_data);
        }
    }
    else
    {
        CGUTILS_ERROR("This kind of callback (%d) is not handled by this function!",
                      ctx->cb_type);
        result = EINVAL;
    }

    list = NULL;
    cg_storage_provider_request_ctx_free(ctx), ctx = NULL;

    return result;
}

int cg_storage_provider_handle_container_stats_response(cg_storage_provider_request * request,
                                                        int const status,
                                                        cg_storage_instance_container_stats const * const stats)
{
    int result = status;
    CGUTILS_ASSERT(request != NULL);
    CGUTILS_ASSERT(request->ctx != NULL);
    cg_storage_provider_request_ctx * ctx = request->ctx;
    CGUTILS_ASSERT(ctx->state == cg_storage_provider_state_single_request);

    if (ctx->cb_type == cg_storage_provider_request_callback_type_container_stats)
    {
        if (ctx->final_container_stats_cb != NULL)
        {
            result = (*(ctx->final_container_stats_cb))(status, stats, ctx->final_cb_data);
        }
    }
    else
    {
        CGUTILS_ERROR("This kind of callback (%d) is not handled by this function!",
                      ctx->cb_type);
        result = EINVAL;
    }

    cg_storage_provider_request_ctx_free(ctx), ctx = NULL;

    return result;
}

static int cg_storage_provider_multipart_put(cg_storage_provider_request_ctx * const request_ctx,
                                             size_t const max_single_part_size,
                                             size_t const max_file_size)
{
    int result = 0;

    assert(request_ctx != NULL);
    assert(max_single_part_size < max_file_size);
    cg_storage_provider * const this = request_ctx->provider;

    /* Determine the maximum number of parts */

    request_ctx->number_of_parts = max_file_size / max_single_part_size;

    if (max_file_size % max_single_part_size > 0)
    {
        request_ctx->number_of_parts++;
    }

    request_ctx->part_support_size = max_file_size / request_ctx->number_of_parts;

    time(&(request_ctx->timestamp));

    if (this->vtable->put_multipart_init != NULL)
    {
        cg_storage_provider_request * request = NULL;

        cg_storage_provider_ctx_clean_for_next_request(request_ctx);

        result = cg_storage_provider_request_init(request_ctx,
                                                  0,
                                                  &request);

        if (result == 0)
        {
            request_ctx->state = cg_storage_provider_state_multipart_init;

            result = (*(this->vtable->put_multipart_init))(request);

            request = NULL;

            if (result != 0)
            {
                CGUTILS_ERROR("Error in PUT multipart init: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error in cg_storage_provider_request_init: %d", result);
        }
    }
    else
    {
        result = cg_storage_provider_multipart_send(request_ctx);

        if (result != 0)
        {
            CGUTILS_ERROR("Error in cg_storage_provider_multipart_send: %d", result);
        }
    }

    return result;
}

static int cg_storage_provider_request_ctx_init(cg_storage_provider * const this,
                                                void * const instance_specifics,
                                                cg_storage_io * const src_io,
                                                cg_storage_io * const dest_io,
                                                char const * const id,
                                                cgutils_llist * const metadata,
                                                cg_storage_provider_request_callback_type const cb_type,
                                                cg_storage_instance_status_cb * const status_cb,
                                                cg_storage_instance_list_cb * const list_cb,
                                                cg_storage_instance_put_status_cb * const put_cb,
                                                cg_storage_instance_get_status_cb * const get_cb,
                                                cg_storage_instance_container_stats_cb * const container_stats_cb,
                                                void * const cb_data,
                                                cg_storage_provider_request_ctx ** const out)
{
    int result = 0;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(out != NULL);
    CGUTILS_ASSERT(cb_type >= cg_storage_provider_request_callback_type_none &&
                   cb_type < cg_storage_provider_request_callback_type_count);
    CGUTILS_ASSERT(cb_type == cg_storage_provider_request_callback_type_none ||
                   status_cb != NULL ||
                   list_cb != NULL ||
                   put_cb != NULL ||
                   get_cb != NULL ||
                   container_stats_cb != NULL);

    CGUTILS_ALLOCATE_STRUCT(*out);

    if (*out != NULL)
    {
        cg_storage_provider_request_ctx * ctx = *out;

        switch(cb_type)
        {
        case cg_storage_provider_request_callback_type_status:
            ctx->final_status_cb = status_cb;
            break;
        case cg_storage_provider_request_callback_type_list:
            ctx->final_list_cb = list_cb;
            break;
        case cg_storage_provider_request_callback_type_put:
            ctx->final_put_cb = put_cb;
            break;
        case cg_storage_provider_request_callback_type_get:
            ctx->final_get_cb = get_cb;
            break;
        case cg_storage_provider_request_callback_type_container_stats:
            ctx->final_container_stats_cb = container_stats_cb;
            break;
        case cg_storage_provider_request_callback_type_none:
            break;
        case cg_storage_provider_request_callback_type_count:
            CGUTILS_ERROR("Invalid callback type %d !",
                          cb_type);
            result = EINVAL;
            break;
        }

        if (result == 0)
        {
            ctx->cb_type = cb_type;

            if (id != NULL)
            {
                ctx->key = cgutils_strdup(id);

                if (ctx->key == NULL)
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error allocating memory for request ctx key: %d", result);
                }
            }

            if (result == 0)
            {
                result = cgutils_llist_create(&(ctx->parts));

                if (result != 0)
                {
                    CGUTILS_ERROR("Error creating parts list: %d", result);
                }
            }

            if (result == 0)
            {
                ctx->provider = this;
                ctx->http = this->http;
                ctx->provider_data = this->provider_data;
                ctx->instance_specifics = instance_specifics;
                ctx->dest_io = dest_io;
                ctx->source_io = src_io;
                ctx->state = cg_storage_provider_state_single_request;
                ctx->metadata = metadata;
                ctx->final_cb_data = cb_data;
            }
        }

        if (result != 0)
        {
            cg_storage_provider_request_ctx_free(*out), *out = NULL;
        }
    }
    else
    {
        result = ENOMEM;
        CGUTILS_ERROR("Error allocating memory for request ctx: %d", result);
    }

    return result;
}

int cg_storage_provider_single_request_init(cg_storage_provider * const this,
                                            void * const instance_specifics,
                                            char const * const id,
                                            cg_storage_provider_request_callback_type const cb_type,
                                            cg_storage_instance_status_cb * const status_cb,
                                            cg_storage_instance_list_cb * const list_cb,
                                            cg_storage_instance_put_status_cb * const put_cb,
                                            cg_storage_instance_get_status_cb * const get_cb,
                                            cg_storage_instance_container_stats_cb * const containers_stats_cb,
                                            void * const cb_data,
                                            cg_storage_provider_request ** const out)
{
    int result = 0;
    cg_storage_provider_request_ctx * ctx = NULL;

    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(out != NULL);

    result = cg_storage_provider_request_ctx_init(this,
                                                  instance_specifics,
                                                  CG_STP_UTILS_NO_SRC_IO,
                                                  CG_STP_UTILS_NO_DST_IO,
                                                  id,
                                                  CG_STP_UTILS_NO_METADATA,
                                                  cb_type,
                                                  status_cb,
                                                  list_cb,
                                                  put_cb,
                                                  get_cb,
                                                  containers_stats_cb,
                                                  cb_data,
                                                  &ctx);

    if (result == 0)
    {
        assert(ctx != NULL);

        result = cg_storage_provider_request_init(ctx,
                                                  0,
                                                  out);

        if (result != 0)
        {
            cg_storage_provider_request_ctx_free(ctx), ctx = NULL;
        }
    }

    return result;
}

int cg_storage_provider_put_file(cg_storage_provider * const this,
                                 void * const instance_specifics,
                                 char const * const id,
                                 int const fd,
                                 size_t const file_size,
                                 cgutils_llist * filters_list,
                                 cgutils_llist * metadata_list,
                                 cgutils_crypto_digest_algorithm const digest_to_compute,
                                 cg_storage_instance_put_status_cb * const cb,
                                 void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL && id != NULL && cb != NULL && fd >= 0 && cb_data != NULL)
    {
        result = ENOSYS;
        assert(this->vtable != NULL);
        assert(this->global_data != NULL);

        if (this->vtable->put_file != NULL ||
            this->vtable->put_multipart_part != NULL)
        {
            cgutils_aio * const aio = cg_storage_manager_data_get_aio(this->global_data);
            cg_storage_provider_request_ctx * request_ctx = NULL;
            cg_storage_provider_request * request = NULL;
            cg_storage_io * io = NULL;
            bool compressed = false;
            bool encrypted = false;

            assert(aio != NULL);

            result = cg_storage_provider_init_source_io(this,
                                                        aio,
                                                        fd,
                                                        file_size,
                                                        filters_list,
                                                        &compressed,
                                                        &encrypted,
                                                        &io);
            if (result == 0)
            {
                result = cg_storage_provider_request_ctx_init(this,
                                                              instance_specifics,
                                                              io,
                                                              CG_STP_UTILS_NO_DST_IO,
                                                              id,
                                                              metadata_list,
                                                              cg_storage_provider_request_callback_type_put,
                                                              CG_STP_UTILS_NO_STATUS_CB,
                                                              CG_STP_UTILS_NO_LIST_CB,
                                                              cb,
                                                              CG_STP_UTILS_NO_GET_CB,
                                                              CG_STP_UTILS_NO_CONTAINER_STATS_CB,
                                                              cb_data,
                                                              &request_ctx);

                if (result == 0)
                {
                    size_t const max_single_part_size = (*(this->vtable->get_single_upload_size))(instance_specifics);
                    size_t max_file_size = 0;

                    request_ctx->compressed = compressed;
                    request_ctx->encrypted = encrypted;

                    metadata_list = NULL;

                    if (digest_to_compute != cgutils_crypto_digest_algorithm_none)
                    {
                        /* We have been asked to compute a digest of the data
                           before filters (ie, of what is in the cache). */
                        int res = cg_storage_io_compute_hash(io,
                                                             digest_to_compute);

                        if (res == 0)
                        {
                            request_ctx->digest_algo = digest_to_compute;
                        }
                        else
                        {
                            CGUTILS_WARN("Error asking for source object digest computation: %d", res);
                        }
                    }

                    if (cg_storage_io_is_final_size_known(io))
                    {
                        max_file_size = cg_storage_io_get_final_size(io);
                    }
                    else
                    {
                        max_file_size = cg_storage_io_get_max_final_size(io);
                    }

                    if (max_single_part_size > 0
                        && max_file_size > max_single_part_size)
                    {
                        if (this->vtable->put_multipart_part != NULL)
                        {
                            result = cg_storage_provider_multipart_put(request_ctx,
                                                                       max_single_part_size,
                                                                       max_file_size);
                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error in cg_storage_provider_multipart_put: %d", result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("File is too large for simple upload but no multipart upload method is supported by this provider");
                            result = ENOSYS;
                        }
                    }
                    else if (this->vtable->put_file != NULL)
                    {
                        result = cg_storage_provider_request_io_source_init(request_ctx,
                                                                            request_ctx->source_io,
                                                                            0,
                                                                            file_size,
                                                                            0,
                                                                            &request);

                        if (result == 0)
                        {
                            /* Compute digest of in-flight data, ie data
                               after filters.
                            */
                            cg_storage_provider_init_object_hash(this, request);

                            result = (*this->vtable->put_file)(request);

                            if (result == 0)
                            {
                                request = NULL;
                                request_ctx = NULL;
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error in source init: %d", result);
                        }
                    }
                    else
                    {
                        result = ENOSYS;
                    }

                    if (result != 0)
                    {
                        if (request_ctx != NULL)
                        {
                            cg_storage_provider_request_ctx_free(request_ctx), request_ctx = NULL;
                        }
                    }

                    io = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error in cg_storage_provider_request_ctx_init: %d", result);
                }

                if (result != 0)
                {
                    if (io != NULL)
                    {
                        cg_storage_io_free(io), io = NULL;
                    }
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting source IO: %d", result);
            }
        }
    }
    else
    {
        CGUTILS_TRACE("EINVAL with this %p, id %s, cb %p fd %d cb_data %p",
                      this,
                      id,
                      cb,
                      fd,
                      cb_data);
    }

    if (result != 0 && metadata_list != NULL)
    {
        cgutils_llist_free(&metadata_list, &cg_storage_provider_metadata_delete);
    }

    return result;
}

int cg_storage_provider_delete_file(cg_storage_provider * const this,
                                    void * const instance_specifics,
                                    char const * const id,
                                    cg_storage_instance_status_cb * const cb,
                                    void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL && id != NULL && cb != NULL && cb_data != NULL)
    {
        if (this->vtable->delete_file != NULL)
        {
            cg_storage_provider_request * request = NULL;

            result = cg_storage_provider_single_request_init(this,
                                                             instance_specifics,
                                                             id,
                                                             cg_storage_provider_request_callback_type_status,
                                                             cb,
                                                             CG_STP_UTILS_NO_LIST_CB,
                                                             CG_STP_UTILS_NO_PUT_CB,
                                                             CG_STP_UTILS_NO_GET_CB,
                                                             CG_STP_UTILS_NO_CONTAINER_STATS_CB,
                                                             cb_data,
                                                             &request);

            if (result == 0)
            {
                result = (*this->vtable->delete_file)(request);

                if (result == 0)
                {
                    request = NULL;
                }
                else
                {
                    cg_storage_provider_request_ctx_free(request->ctx), request = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error in request init: %d", result);
            }
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}

int cg_storage_provider_create_container(cg_storage_provider * const this,
                                         void * const instance_specifics,
                                         char const * const container_name,
                                         cg_storage_instance_status_cb * const cb,
                                         void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL &&
        container_name != NULL &&
        cb != NULL &&
        cb_data != NULL)
    {
        if (this->vtable->create_container != NULL)
        {
            cg_storage_provider_request * request = NULL;

            result = cg_storage_provider_single_request_init(this,
                                                             instance_specifics,
                                                             CG_STP_UTILS_NO_ID,
                                                             cg_storage_provider_request_callback_type_status,
                                                             cb,
                                                             CG_STP_UTILS_NO_LIST_CB,
                                                             CG_STP_UTILS_NO_PUT_CB,
                                                             CG_STP_UTILS_NO_GET_CB,
                                                             CG_STP_UTILS_NO_CONTAINER_STATS_CB,
                                                             cb_data,
                                                             &request);

            if (result == 0)
            {
                result = (*this->vtable->create_container)(request,
                                                           container_name);

                if (result == 0)
                {
                    request = NULL;
                }
                else
                {
                    cg_storage_provider_request_ctx_free(request->ctx), request = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error in request init: %d", result);
            }
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}

int cg_storage_provider_remove_empty_container(cg_storage_provider * const this,
                                               void * const instance_specifics,
                                               char const * const container_name,
                                               cg_storage_instance_status_cb * const cb,
                                               void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL &&
        container_name != NULL &&
        cb != NULL &&
        cb_data != NULL)
    {
        if (this->vtable->remove_empty_container != NULL)
        {
            cg_storage_provider_request * request = NULL;

            result = cg_storage_provider_single_request_init(this,
                                                             instance_specifics,
                                                             CG_STP_UTILS_NO_ID,
                                                             cg_storage_provider_request_callback_type_status,
                                                             cb,
                                                             CG_STP_UTILS_NO_LIST_CB,
                                                             CG_STP_UTILS_NO_PUT_CB,
                                                             CG_STP_UTILS_NO_GET_CB,
                                                             CG_STP_UTILS_NO_CONTAINER_STATS_CB,
                                                             cb_data,
                                                             &request);

            if (result == 0)
            {
                result = (*this->vtable->remove_empty_container)(request,
                                                           container_name);

                if (result == 0)
                {
                    request = NULL;
                }
                else
                {
                    cg_storage_provider_request_ctx_free(request->ctx), request = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error in request init: %d", result);
            }
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}

int cg_storage_provider_list_containers(cg_storage_provider * const this,
                                        void * const instance_specifics,
                                        cg_storage_instance_list_cb * const cb,
                                        void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL && cb != NULL && cb_data != NULL)
    {
        if (this->vtable->list_containers != NULL)
        {
            cg_storage_provider_request * request = NULL;

            result = cg_storage_provider_single_request_init(this,
                                                             instance_specifics,
                                                             CG_STP_UTILS_NO_ID,
                                                             cg_storage_provider_request_callback_type_list,
                                                             CG_STP_UTILS_NO_STATUS_CB,
                                                             cb,
                                                             CG_STP_UTILS_NO_PUT_CB,
                                                             CG_STP_UTILS_NO_GET_CB,
                                                             CG_STP_UTILS_NO_CONTAINER_STATS_CB,
                                                             cb_data,
                                                             &request);

            if (result == 0)
            {
                result = (*this->vtable->list_containers)(request);

                if (result == 0)
                {
                    request = NULL;
                }
                else
                {
                    cg_storage_provider_request_ctx_free(request->ctx), request = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error in request init: %d", result);
            }
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}

int cg_storage_provider_get_container_stats(cg_storage_provider * const this,
                                            void * const instance_specifics,
                                            char const * const container_name,
                                            cg_storage_instance_container_stats_cb * const cb,
                                            void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL &&
        cb != NULL &&
        cb_data != NULL)
    {
        if (this->vtable->get_container_stats != NULL)
        {
            cg_storage_provider_request * request = NULL;

            result = cg_storage_provider_single_request_init(this,
                                                             instance_specifics,
                                                             CG_STP_UTILS_NO_ID,
                                                             cg_storage_provider_request_callback_type_container_stats,
                                                             CG_STP_UTILS_NO_STATUS_CB,
                                                             CG_STP_UTILS_NO_LIST_CB,
                                                             CG_STP_UTILS_NO_PUT_CB,
                                                             CG_STP_UTILS_NO_GET_CB,
                                                             cb,
                                                             cb_data,
                                                             &request);

            if (result == 0)
            {
                result = (*this->vtable->get_container_stats)(request,
                                                              container_name);

                if (result == 0)
                {
                    request = NULL;
                }
                else
                {
                    cg_storage_provider_request_ctx_free(request->ctx), request = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error in request init: %d", result);
            }
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}

int cg_storage_provider_list_files(cg_storage_provider * const this,
                                   void * const instance_specifics,
                                   cg_storage_instance_list_cb * const cb,
                                   void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL && cb != NULL && cb_data != NULL)
    {
        if (this->vtable->list_files != NULL)
        {
            cg_storage_provider_request * request = NULL;

            result = cg_storage_provider_single_request_init(this,
                                                             instance_specifics,
                                                             CG_STP_UTILS_NO_ID,
                                                             cg_storage_provider_request_callback_type_list,
                                                             CG_STP_UTILS_NO_STATUS_CB,
                                                             cb,
                                                             CG_STP_UTILS_NO_PUT_CB,
                                                             CG_STP_UTILS_NO_GET_CB,
                                                             CG_STP_UTILS_NO_CONTAINER_STATS_CB,
                                                             cb_data,
                                                             &request);

            if (result == 0)
            {
                result = (*this->vtable->list_files)(request);

                if (result == 0)
                {
                    request = NULL;
                }
                else
                {
                    cg_storage_provider_request_ctx_free(request->ctx), request = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error in request init: %d", result);
            }
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}

int cg_storage_provider_get_file(cg_storage_provider * const this,
                                 void * const instance_specifics,
                                 char const * const id,
                                 int const fd,
                                 cgutils_llist * filters_list,
                                 cgutils_crypto_digest_algorithm const digest_to_compute,
                                 cg_storage_instance_get_status_cb * const cb,
                                 void * const cb_data)
{
    int result = EINVAL;

    if (this != NULL && id != NULL && cb != NULL && fd >= 0 && cb_data != NULL)
    {
        assert(this->vtable != NULL);
        assert(this->global_data != NULL);

        if (this->vtable->get_file != NULL)
        {
            cgutils_aio * const aio = cg_storage_manager_data_get_aio(this->global_data);
            cg_storage_provider_request_ctx * request_ctx = NULL;
            cg_storage_provider_request * request = NULL;
            cg_storage_io * io = NULL;
            bool has_filters = false;
            assert(aio != NULL);

            result = cg_storage_provider_init_destination_file_io(this,
                                                                  aio,
                                                                  fd,
                                                                  filters_list,
                                                                  &has_filters,
                                                                  &io);
            if (result == 0)
            {
                result = cg_storage_provider_request_ctx_init(this,
                                                              instance_specifics,
                                                              CG_STP_UTILS_NO_SRC_IO,
                                                              io,
                                                              id,
                                                              CG_STP_UTILS_NO_METADATA,
                                                              cg_storage_provider_request_callback_type_get,
                                                              CG_STP_UTILS_NO_STATUS_CB,
                                                              CG_STP_UTILS_NO_LIST_CB,
                                                              CG_STP_UTILS_NO_PUT_CB,
                                                              cb,
                                                              CG_STP_UTILS_NO_CONTAINER_STATS_CB,
                                                              cb_data,
                                                              &request_ctx);

                if (result == 0)
                {
                    request_ctx->has_dest_filters = has_filters;

                    result = cg_storage_provider_request_io_dest_init(request_ctx,
                                                                      io,
                                                                      &request);
                    if (result == 0)
                    {
                        /* Compute digest of in-flight data, ie data
                           after filters.
                        */
                        cg_storage_provider_init_object_hash(this, request);

                        if (digest_to_compute != cgutils_crypto_digest_algorithm_none)
                        {
                            /* We have been asked to compute a digest of the data
                               before filters (ie, of what is in the cache). */

                            int res = cg_storage_io_compute_hash(io,
                                                                 digest_to_compute);

                            if (res == 0)
                            {
                                request_ctx->digest_algo = digest_to_compute;
                            }
                            else
                            {
                                CGUTILS_WARN("Error asking for destination object digest computation: %d", res);
                            }
                        }

                        result = (*this->vtable->get_file)(request);

                        if (result != 0)
                        {
                            CGUTILS_ERROR("Error in get_file: %d", result);
                            cg_storage_provider_request_ctx_free(request_ctx), request_ctx = NULL;
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error in cg_storage_provider_request_init: %d", result);
                        cg_storage_provider_request_ctx_free(request_ctx), request_ctx = NULL;
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error in cg_storage_provider_request_ctx_init: %d", result);
                    cg_storage_io_free(io), io = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error in cg_storage_provider_init_destination_io: %d", result);
            }
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}

int cg_storage_provider_setup(cg_storage_provider * const this,
                              void * const instance_specifics)
{
    int result = EINVAL;

    if (this != NULL)
    {
        this->http = cg_storage_manager_data_get_http(this->global_data);

        if (this->vtable->setup != NULL)
        {
            result = (*this->vtable->setup)(this, this->provider_data, instance_specifics);
        }
        else
        {
            result = 0;
        }
    }

    return result;
}

cg_storage_provider_capabilities const * cg_storage_provider_get_capabilities(cg_storage_provider const * const this)
{
    cg_storage_provider_capabilities const * result = NULL;

    if (this != NULL)
    {
        result = &(this->vtable->capabilities);
    }

    return result;
}

char const * cg_storage_provider_get_name(cg_storage_provider const * const provider)
{
    char const * result = NULL;

    if (provider != NULL)
    {
        result = provider->name;
    }

    return result;
}

void cg_storage_provider_free(cg_storage_provider * provider)
{
    if (provider != NULL)
    {
        if (provider->vtable != NULL)
        {
            if (provider->vtable->destroy != NULL)
            {
                (*(provider->vtable->destroy))(provider->provider_data);
            }
            provider->vtable = NULL;
        }

        if (provider->dl_handle != NULL)
        {
            dlclose(provider->dl_handle), provider->dl_handle = NULL;
        }

        if (provider->name != NULL)
        {
            CGUTILS_FREE(provider->name);
        }

        provider->provider_data = NULL;

        CGUTILS_FREE(provider);
    }
}

static int cg_storage_provider_load(cg_storage_manager_data * const global_data,
                                    char * name,
                                    cg_storage_provider ** const out)
{
    int result = 0;
    char * name_lower = NULL;
    assert(name != NULL);
    assert(global_data != NULL);
    assert(out != NULL);

    result = cgutils_str_tolower(name, &name_lower);

    if (result == 0)
    {
        char const * providers_path = cg_storage_manager_data_get_providers_path(global_data);
        char * provider_file = NULL;
        assert(name_lower);
        assert(providers_path != NULL);

        result = cgutils_asprintf(&provider_file,
                                  "%s/cg_storage_provider_%s.so",
                                  providers_path,
                                  name_lower);

        if (result == 0)
        {
            if (cgutils_file_exists(provider_file) == true)
            {
                char * provider_vtable_name = NULL;

                result = cgutils_asprintf(&provider_vtable_name,
                                          "cg_storage_provider_%s_vtable",
                                          name_lower);

                if (result == 0)
                {
                    dlerror();

                    void * handle = dlopen(provider_file, RTLD_NOW);

                    if (handle != NULL)
                    {
                        cg_stp_vtable const * provider_vtable = dlsym(handle,
                                                                      provider_vtable_name);

                        if (provider_vtable != NULL)
                        {
                            result = cg_storage_provider_create(global_data,
                                                                name,
                                                                handle,
                                                                provider_vtable,
                                                                out);
                            name = NULL;
                            handle = NULL;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error looking for symbol %s in provider %s (%s): %s",
                                          provider_vtable_name,
                                          name,
                                          provider_file,
                                          dlerror());
                            result = EINVAL;
                        }

                        if (result != 0 && handle != NULL)
                        {
                            dlclose(handle), handle = NULL;
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error while loading provider named %s (%s): %s",
                                      name,
                                      provider_file,
                                      dlerror());
                        result = EINVAL;
                    }

                    CGUTILS_FREE(provider_vtable_name);
                }
            }
            else
            {
                CGUTILS_ERROR("Provider not found %s (%s)",
                              name,
                              provider_file);
                result = ENOENT;
            }

            CGUTILS_FREE(provider_file);
        }

        CGUTILS_FREE(name_lower);
    }

    if (name != NULL)
    {
        CGUTILS_FREE(name);
    }

    return result;
}

int cg_storage_provider_init_with_defaults(cg_storage_manager_data * const global_data,
                                           char const * const name,
                                           cg_storage_provider ** const out)
{
    int result = EINVAL;

    if (global_data != NULL && name != NULL && out != NULL)
    {
        char * name_dup = cgutils_strdup(name);

        if (name_dup != NULL)
        {
            result = cg_storage_provider_load(global_data,
                                              name_dup,
                                              out);

        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}


int cg_storage_provider_init(cg_storage_manager_data * const global_data,
                             cgutils_configuration const * const config,
                             cg_storage_provider ** const out)
{
    int result = EINVAL;

    if (global_data != NULL && config != NULL && out != NULL)
    {
        char * name = NULL;

        result = cgutils_configuration_get_string(config, "Name", &name);

        if (result == 0)
        {
            result = cg_storage_provider_load(global_data,
                                              name,
                                              out);

        }
    }

    return result;
}

int cg_storage_provider_parse_specific_config(cg_storage_provider const * const provider,
                                              cgutils_configuration * const provider_specifics,
                                              void ** const data)
{
    int result = EINVAL;

    if (provider != NULL && provider_specifics != NULL && data != NULL)
    {
        if (provider->vtable->parse_specifics != NULL)
        {
            result = (*provider->vtable->parse_specifics)(provider->provider_data,
                                                          provider_specifics,
                                                          data);
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;
}

void cg_storage_provider_clear_specific_config(cg_storage_provider const * const provider,
                                              void * const data)
{
    if (provider != NULL && data != NULL)
    {
        if (provider->vtable->clear_specifics != NULL)
        {
            (*provider->vtable->clear_specifics)(data);
        }
    }
}

bool cg_storage_provider_is_valid_response_code(cg_storage_provider_request const * const request,
                                                uint16_t const code)
{
    bool result = false;

    if (request != NULL && code >= 100 && code < 600)
    {
        if (request->ctx->provider->vtable->is_valid_response_code != NULL)
        {
            result = (*(request->ctx->provider->vtable->is_valid_response_code))(request, code);
        }
        else
        {
            result = ENOSYS;
        }
    }

    return result;

}

void cg_storage_provider_request_ctx_free(cg_storage_provider_request_ctx * ctx)
{
    if (ctx != NULL)
    {
        if (ctx->source_io != NULL)
        {
            cg_storage_io_free(ctx->source_io), ctx->source_io = NULL;
        }

        if (ctx->dest_io != NULL)
        {
            cg_storage_io_free(ctx->dest_io), ctx->dest_io = NULL;
        }

        if (ctx->key != NULL)
        {
            CGUTILS_FREE(ctx->key);
        }

        if (ctx->multipart_id)
        {
            CGUTILS_FREE(ctx->multipart_id);
        }

        if (ctx->parts != NULL)
        {
            cgutils_llist_free(&(ctx->parts), &cg_storage_provider_request_delete);
        }

        if (ctx->metadata != NULL)
        {
            cgutils_llist_free(&(ctx->metadata), &cg_storage_provider_metadata_delete);
        }

        ctx->number_of_parts = 0;
        ctx->finished_parts = 0;
        ctx->status_code = 0;
        ctx->state = cg_storage_provider_state_none;
        ctx->final_status_cb = NULL;
        ctx->final_list_cb = NULL;
        ctx->final_get_cb = NULL;
        ctx->final_put_cb = NULL;
        ctx->final_container_stats_cb = NULL;
        ctx->final_cb_data = NULL;

        ctx->provider = NULL;
        ctx->http = NULL;
        ctx->provider_data = NULL;
        ctx->instance_specifics = NULL;

        ctx->buffer_size = 0;
        CGUTILS_FREE(ctx->buffer);

        CGUTILS_FREE(ctx);
    }
}

void cg_storage_provider_notify_end_of_headers(cg_storage_provider_request * const request)
{
    assert(request != NULL);
    assert(request->ctx != NULL);
    assert(request->ctx->provider != NULL);

    cg_storage_provider * this = request->ctx->provider;
    assert(this != NULL);
    assert(this->vtable != NULL);

    request->end_of_headers = true;

    if (this->vtable->all_headers_received != NULL)
    {
        (*(this->vtable->all_headers_received))(request);
    }
}

void cg_storage_provider_metadata_free(cg_storage_provider_metadata * this)
{
    if (this != NULL)
    {
        if (this->key != NULL)
        {
            CGUTILS_FREE(this->key);
        }

        if (this->value != NULL)
        {
            CGUTILS_FREE(this->value);
        }

        CGUTILS_FREE(this);
    }
}

int cg_storage_provider_metadata_add(cgutils_llist * const list,
                                     char const * const key,
                                     char const * const value)
{
    int result = EINVAL;

    if (list != NULL && key != NULL && value != NULL)
    {
        cg_storage_provider_metadata * data = NULL;

        result = ENOMEM;

        CGUTILS_ALLOCATE_STRUCT(data);

        if (data != NULL)
        {
            data->key = cgutils_strdup(key);

            if (data->key != NULL)
            {
                data->value = cgutils_strdup(value);

                if (data->value != NULL)
                {
                    result = cgutils_llist_insert(list, data);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error adding metadata to list: %d", result);
                    }
                }
            }

            if (result != 0)
            {
                cg_storage_provider_metadata_free(data), data = NULL;
            }
        }
    }

    return result;
}
