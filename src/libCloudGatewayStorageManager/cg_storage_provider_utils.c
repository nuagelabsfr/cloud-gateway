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

#include <cgsm/cg_storage_provider.h>
#include <cgsm/cg_storage_provider_utils.h>

#define CG_STORAGE_PROVIDER_UTILS_BUFFER_SIZE (16 * 1024)

int cg_storage_provider_utils_http_json_response_callback(cgutils_http_data * http_data,
                                                          cgutils_http_request * request,
                                                          cgutils_http_response * response,
                                                          void * cb_data)
{
    cg_storage_provider_request * pv_request = cb_data;

    int result = 0;
    cgutils_json_reader * json_response = NULL;
    assert(http_data != NULL);
    assert(request != NULL);
    assert(response != NULL);
    assert(cb_data != NULL);

    uint16_t const response_code = cgutils_http_response_get_status(response);
    cgutils_http_method const method = cgutils_http_request_get_method(request);
    bool const code_ok = cg_storage_provider_is_valid_response_code(pv_request,
                                                                    response_code);

    (void) http_data;

    if (code_ok)
    {
        size_t const response_data_size = cg_storage_io_mem_get_output_size(pv_request->dest_io);

        if (response_data_size > 0)
        {
            char const * response_data = NULL;

            result = cg_storage_io_mem_get_output(pv_request->dest_io,
                                                  &response_data);

            if (result == 0)
            {
                result = cgutils_json_reader_from_buffer(response_data,
                                                         response_data_size,
                                                         &json_response);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error parsing JSON response: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting response data: %d", result);
            }
        }
    }
    else if (response_code == 404)
    {
        result = ENOENT;
    }
    else if (response_code == 403)
    {
        char const * const method_str = cgutils_http_method_to_str(method);
        char const * const uri = cgutils_http_request_get_uri(request);

        CGUTILS_ERROR("Authentication error (%d) while requesting a %s to uri %s",
                      response_code,
                      method_str,
                      uri);
        result = EPERM;
    }
    else if (response_code == 401)
    {
        char const * const method_str = cgutils_http_method_to_str(method);
        char const * const uri = cgutils_http_request_get_uri(request);

        CGUTILS_ERROR("Authentication error (%d) while requesting a %s to uri %s",
                      response_code,
                      method_str,
                      uri);
        result = EACCES;
    }
    else
    {
        char const * const method_str = cgutils_http_method_to_str(method);
        char const * const uri = cgutils_http_request_get_uri(request);
        uint16_t const error_code = cgutils_http_response_get_error(response);

        if (response_code == 0 &&
            error_code != 0)
        {
            char const * const error_code_str = cgutils_http_response_get_error_str(response);
            char const * const error_str = cgutils_http_request_get_error_buffer(request);

            CGUTILS_ERROR("Unexpected error for request %s to uri %s : (%d) %s [%s]",
                          method_str,
                          uri,
                          error_code,
                          error_code_str,
                          error_str);
        }
        else
        {
            CGUTILS_ERROR("Unexpected response code received for request %s to uri %s : %d (%d)",
                          method_str,
                          uri,
                          response_code,
                          error_code);
        }

        result = EIO;
    }

    if (pv_request->json_request_cb)
    {
        result = (*(pv_request->json_request_cb))(result, json_response, cb_data);
    }

    if (json_response != NULL)
    {
        cgutils_json_reader_free(json_response), json_response = NULL;
    }

    cgutils_http_response_free(response);
    cgutils_http_request_free(request);

    return result;
}

int cg_storage_provider_utils_http_xml_response_callback(cgutils_http_data * http_data,
                                                         cgutils_http_request * request,
                                                         cgutils_http_response * response,
                                                         void * cb_data)
{
    cg_storage_provider_request * pv_request = cb_data;

    int result = 0;
    cgutils_xml_reader * xml_response = NULL;
    assert(http_data != NULL);
    assert(request != NULL);
    assert(response != NULL);
    assert(cb_data != NULL);

    uint16_t const response_code = cgutils_http_response_get_status(response);
    cgutils_http_method const method = cgutils_http_request_get_method(request);
    bool const code_ok = cg_storage_provider_is_valid_response_code(pv_request,
                                                                    response_code);

    (void) http_data;

    if (code_ok)
    {
        size_t const response_data_size = cg_storage_io_mem_get_output_size(pv_request->dest_io);

        if (response_data_size > 0)
        {
            char const * response_data = NULL;

            result = cg_storage_io_mem_get_output(pv_request->dest_io,
                                                  &response_data);

            if (result == 0)
            {
                result = cgutils_xml_reader_from_buffer(response_data,
                                                        response_data_size,
                                                        &xml_response);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error parsing XML response: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting response data: %d", result);
            }
        }
    }
    else if (response_code == 404)
    {
        result = ENOENT;
    }
    else if (response_code == 403)
    {
        char const * const method_str = cgutils_http_method_to_str(method);
        char const * const uri = cgutils_http_request_get_uri(request);

        CGUTILS_ERROR("Authentication error (%d) while requesting a %s to uri %s",
                      response_code,
                      method_str,
                      uri);
        result = EPERM;
    }
    else if (response_code == 401)
    {
        char const * const method_str = cgutils_http_method_to_str(method);
        char const * const uri = cgutils_http_request_get_uri(request);

        CGUTILS_ERROR("Authentication error (%d) while requesting a %s to uri %s",
                      response_code,
                      method_str,
                      uri);
        result = EACCES;
    }
    /* FOR DEBUG ONLY */
#if 0
    else if (response_code == 400)
    {
        size_t const response_data_size = cg_storage_io_mem_get_output_size(pv_request->dest_io);

        if (response_data_size > 0)
        {
            char const * response_data = NULL;

            result = cg_storage_io_mem_get_output(pv_request->dest_io,
                                                  &response_data);

            if (result == 0)
            {
                CGUTILS_DEBUG("Got 400 response [%zu][%s]",
                              response_data_size,
                              response_data);
            }
        }

        result = EIO;
    }
#endif /* 0 */
    else
    {
        char const * const method_str = cgutils_http_method_to_str(method);
        char const * const uri = cgutils_http_request_get_uri(request);
        uint16_t const error_code = cgutils_http_response_get_error(response);

        if (response_code == 0 && error_code != 0)
        {
            char const * const error_code_str = cgutils_http_response_get_error_str(response);
            char const * const error_str = cgutils_http_request_get_error_buffer(request);

            CGUTILS_ERROR("Unexpected error for request %s to uri %s : (%d) %s [%s]",
                          method_str,
                          uri,
                          error_code,
                          error_code_str,
                          error_str);
        }
        else
        {
            CGUTILS_ERROR("Unexpected response code received for request %s to uri %s : %d (%d)",
                          method_str,
                          uri,
                          response_code,
                          error_code);
        }

        result = EIO;
    }

    if (pv_request->xml_request_cb)
    {
        result = (*(pv_request->xml_request_cb))(result, xml_response, cb_data);
    }

    if (xml_response != NULL)
    {
        cgutils_xml_reader_free(xml_response), xml_response = NULL;
    }

    cgutils_http_response_free(response);
    cgutils_http_request_free(request);

    return result;
}

int cg_storage_provider_utils_http_raw_response_callback(cgutils_http_data * http_data,
                                                         cgutils_http_request * request,
                                                         cgutils_http_response * response,
                                                         void * cb_data)
{
    int result = 0;
    cg_storage_provider_request * pv_request = cb_data;
    uint16_t const response_code = cgutils_http_response_get_status(response);

    cgutils_http_method const method = cgutils_http_request_get_method(request);
    bool const code_ok = cg_storage_provider_is_valid_response_code(pv_request,
                                                                    response_code);
    assert(http_data != NULL);
    assert(request != NULL);
    assert(response != NULL);
    assert(cb_data != NULL);

    (void) http_data;

    if (code_ok)
    {
        if (pv_request->object_hash_ctx != NULL &&
            (method == CGUTILS_HTTP_METHOD_PUT ||
             method == CGUTILS_HTTP_METHOD_GET)
            )
        {
            result = cg_storage_provider_check_object_hash(pv_request);
        }
    }
    else if (response_code == 404)
    {
        result = ENOENT;
    }
    else if (response_code == 403)
    {
        char const * const method_str = cgutils_http_method_to_str(method);
        char const * const uri = cgutils_http_request_get_uri(request);

        CGUTILS_ERROR("Authentication error (%d) while requesting a %s to uri %s",
                      response_code,
                      method_str,
                      uri);
        result = EPERM;
    }
    else if (response_code == 401)
    {
        char const * const method_str = cgutils_http_method_to_str(method);
        char const * const uri = cgutils_http_request_get_uri(request);

        CGUTILS_ERROR("Authentication error (%d) while requesting a %s to uri %s",
                      response_code,
                      method_str,
                      uri);
        result = EACCES;
    }
    else
    {
        char const * const method_str = cgutils_http_method_to_str(method);
        char const * const uri = cgutils_http_request_get_uri(request);
        uint16_t const error_code = cgutils_http_response_get_error(response);

        if (response_code == 0 && error_code != 0)
        {
            char const * const error_code_str = cgutils_http_response_get_error_str(response);

            CGUTILS_ERROR("Unexpected error for request %s to uri %s : (%d) %s",
                          method_str,
                          uri,
                          error_code,
                          error_code_str);
        }
        else
        {
            CGUTILS_ERROR("Unexpected response code received for request %s to uri %s : %d (%d)",
                          method_str,
                          uri,
                          response_code,
                          error_code);
        }

        result = EIO;
    }

    if (pv_request->raw_request_cb)
    {
        result = (*(pv_request->raw_request_cb))(result, cb_data);
    }

    cgutils_http_response_free(response);
    cgutils_http_request_free(request);

    return result;
}

static int cg_storage_provider_utils_write_done(int const status,
                                                size_t const completion,
                                                void * const cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    assert(cb_data != NULL);

    (void) completion;

    if (COMPILER_UNLIKELY(status != 0))
    {
        CGUTILS_ERROR("Error writing data: %d", result);
    }

    bool const need_suspend = cg_storage_io_ctx_destination_need_suspend(pv_request->dest_io);

    if (need_suspend == true)
    {
        int res = cgutils_http_resume_request_download(pv_request->request);
        if (COMPILER_UNLIKELY(res != 0))
        {
            CGUTILS_ERROR("Error resuming request: %d", res);
        }
    }

    cgutils_http_remove_pending_io(pv_request->request);

    return result;
}

int cg_storage_provider_utils_write_cb(cgutils_http_data * const http_data,
                                       cgutils_http_request * const request,
                                       void * const ptr,
                                       size_t const data_size,
                                       void * const cb_data)
{
    /* We have received data from the HTTP server */
    int result = 0;
    cg_storage_provider_request * pv_request = cb_data;

    assert(http_data != NULL);
    assert(request != NULL);
    assert(ptr != NULL);
    assert(cb_data != NULL);

    (void) http_data;
    (void) request;

    if (COMPILER_LIKELY(data_size > 0))
    {
        if (COMPILER_UNLIKELY(pv_request->end_of_headers == false))
        {
            cg_storage_provider_notify_end_of_headers(pv_request);
        }

        cgutils_http_add_pending_io(pv_request->request);

        if (COMPILER_UNLIKELY(pv_request->dest_io == NULL))
        {
            if (pv_request->ctx->dest_io == NULL)
            {
                result = cg_storage_io_destination_init_mem(&(pv_request->ctx->dest_io));

                if (result != 0)
                {
                    CGUTILS_ERROR("Error in cg_storage_io_destination_init_mem: %d", result);
                }
            }

            if (COMPILER_LIKELY(result == 0))
            {
                result = cg_storage_io_ctx_destination_init(pv_request->ctx->dest_io,
                                                            &(pv_request->dest_io));

                if (result != 0)
                {
                    CGUTILS_ERROR("Error in cg_storage_io_ctx_destination_init: %d", result);
                }
            }
        }

        if (COMPILER_LIKELY(result == 0))
        {
            bool const need_suspend = cg_storage_io_ctx_destination_need_suspend(pv_request->dest_io);

            if (need_suspend == true)
            {
                result = cgutils_http_suspend_request_download(pv_request->request);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error suspending download: %d", result);
                }
            }

            if (result == 0)
            {
                if (data_size > 0 &&
                    pv_request->compute_object_hash == true)
                {
                    cg_storage_provider_update_object_hash(pv_request, ptr, data_size);
                }

                result = cg_storage_io_ctx_write(pv_request->dest_io,
                                                 ptr,
                                                 data_size,
                                                 &cg_storage_provider_utils_write_done,
                                                 pv_request);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error in cg_storage_io_ctx_write: %d", result);

                    if (need_suspend)
                    {
                        int res = cgutils_http_resume_request_download(pv_request->request);
                        if (res != 0)
                        {
                            CGUTILS_ERROR("Error resuming request: %d", res);
                        }
                    }
                }
            }
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            cgutils_http_remove_pending_io(pv_request->request);
        }
    }

    return result;
}

static int cg_storage_provider_utils_read_done(int const status,
                                               void * const cb_data)
{
    int result = status;

    assert(cb_data != NULL);
    cg_storage_provider_request * request = cb_data;

    if (COMPILER_UNLIKELY(status != 0))
    {
        CGUTILS_ERROR("Error in read: %d", status);
    }

    int res = cgutils_http_resume_request(request->request);
    if (COMPILER_UNLIKELY(res != 0))
    {
        CGUTILS_ERROR("Error resuming request: %d", res);
    }

    cgutils_http_remove_pending_io(request->request);

    return result;
}

int cg_storage_provider_utils_payload_read_cb(cgutils_http_data * const http_data,
                                              cgutils_http_request * const request,
                                              void * const ptr,
                                              size_t const data_size,
                                              size_t * const written,
                                              bool * const eof,
                                              void * const cb_data)
{
    int result = 0;
    cg_storage_provider_request * pv_request = cb_data;
    /* We need to send data to the HTTP server */
    assert(http_data != NULL);
    assert(request != NULL);
    assert(ptr != NULL);
    assert(written != NULL);
    assert(eof != NULL);
    assert(cb_data != NULL);


    (void) http_data;
    (void) request;

    *written = 0;

    if (COMPILER_LIKELY(data_size > 0))
    {
        size_t const remaining = pv_request->payload_size - pv_request->payload_position;

        size_t const to_copy = data_size > remaining ? remaining : data_size;

        if (COMPILER_LIKELY(to_copy > 0))
        {
            memcpy(ptr, pv_request->payload, to_copy);
            *written = to_copy;
            pv_request->payload_position += to_copy;
        }
        else
        {
            *eof = true;
        }
    }

    return result;
}

int cg_storage_provider_utils_read_cb(cgutils_http_data * const http_data,
                                      cgutils_http_request * const request,
                                      void * const ptr,
                                      size_t const data_size,
                                      size_t * const written,
                                      bool * const eof,
                                      void * const cb_data)
{
    int result = 0;
    cg_storage_provider_request * pv_request = cb_data;
    /* We need to send data to the HTTP server */
    assert(http_data != NULL);
    assert(request != NULL);
    assert(ptr != NULL);
    assert(written != NULL);
    assert(eof != NULL);
    assert(cb_data != NULL);

    (void) http_data;
    (void) request;

    *written = 0;

    if (COMPILER_LIKELY(data_size > 0))
    {
        bool io_pending = false;
        assert(pv_request->source_io != NULL);
        bool const data_ready = cg_storage_io_ctx_source_has_data_ready(pv_request->source_io);

        if (data_ready == false)
        {
            result = cgutils_http_suspend_request_upload(request);
            cgutils_http_add_pending_io(pv_request->request);
        }

        if (COMPILER_LIKELY(result == 0))
        {
            result = cg_storage_io_ctx_read(pv_request->source_io,
                                            ptr,
                                            data_size,
                                            written,
                                            eof,
                                            &io_pending,
                                            &cg_storage_provider_utils_read_done,
                                            pv_request);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error in cg_storage_io_ctx_read: %d", result);
            }

            if (!data_ready && (result != 0 || !io_pending))
            {
                int res = cgutils_http_resume_request(request);
                cgutils_http_remove_pending_io(pv_request->request);

                if (res != 0)
                {
                    CGUTILS_ERROR("Error resuming request: %d", res);
                }
            }
        }
        else
        {
            CGUTILS_ERROR("Error pausing request: %d", result);
        }

        if (result == 0 &&
            *written > 0 &&
            pv_request->compute_object_hash == true)
        {
            cg_storage_provider_update_object_hash(pv_request, ptr, *written);
        }
    }

    return result;
}

int cg_storage_provider_utils_header_cb(cgutils_http_data * const http_data,
                                        cgutils_http_request * const request,
                                        void * const ptr,
                                        size_t const size,
                                        void * const cb_data)
{
    int result = 0;
    cg_storage_provider_request * pv_request = cb_data;

    assert(http_data != NULL);
    assert(request != NULL);
    assert(ptr != NULL);
    assert(size > 0);
    assert(cb_data != NULL);

    (void) request;
    (void) http_data;

    if (COMPILER_UNLIKELY(pv_request->received_headers == NULL))
    {
        result = cgutils_llist_create(&(pv_request->received_headers));

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error creating llist: %d", result);
        }
    }

    if (COMPILER_LIKELY(result == 0))
    {
        char const * name = ptr;
        char const * value = NULL;
        size_t idx = 0;

        for (; idx < ((size) - 1) && value == NULL; idx++)
        {
            if (name[idx] == ':')
            {
                value = &(name[idx+1]);
            }
        }

        if (value != NULL && idx > 1)
        {
            size_t const name_len = idx - 1;
            size_t value_len = size - idx;

            for (; idx < size && *value == ' '; idx++)
            {
                value++;
                value_len--;
            }

            if (idx < size)
            {
                char * name_str = cgutils_strndup(name, name_len);

                if (name_str != NULL)
                {
                    for (; value_len > 1; value_len--)
                    {
                        if (value[value_len - 1] != '\r' &&
                            value[value_len - 1] != '\n')
                        {
                            break;
                        }
                    }

                    char * value_str = cgutils_strndup(value, value_len);

                    if (value_str != NULL)
                    {
                        result = cgutils_http_add_header_to_list(pv_request->received_headers, name_str, value_str);

                        if (result != 0)
                        {
                            CGUTILS_ERROR("Error adding header to list: %d", result);
                            CGUTILS_FREE(value_str);
                        }
                    }
                    else
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Error allocating value string: %d", result);
                    }

                    CGUTILS_FREE(name_str);
                }
                else
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error allocating name string: %d", result);
                }
            }
        }
    }

    return result;
}

int cg_storage_provider_utils_get_normalized_header_value(cgutils_llist * const headers,
                                                          char const * const header_name,
                                                          char ** const normalized_value,
                                                          size_t * const normalized_value_len)
{
    int result = 0;
    cgutils_http_header const * header = NULL;
    assert(headers != NULL);
    assert(header_name != NULL);
    assert(normalized_value != NULL);
    assert(normalized_value_len != NULL);

    result = cgutils_http_get_header_by_name(headers,
                                             header_name,
                                             &header);

    if (result == 0)
    {
        assert(header != NULL);
        assert(header->name != NULL);
        assert(header->value != NULL);

        *normalized_value_len = strlen(header->value);
        size_t begin_pos = 0;

        if (*normalized_value_len > 1)
        {
            if (header->value[0] == '"' &&
                header->value[*normalized_value_len - 1] == '"')
            {
                begin_pos = 1;
                *normalized_value_len -= 2;
            }
        }

        CGUTILS_MALLOC(*normalized_value, *normalized_value_len + 1, 1);

        if (*normalized_value != NULL)
        {
            memcpy(*normalized_value, header->value + begin_pos, *normalized_value_len);
            (*normalized_value)[*normalized_value_len] = '\0';
        }
        else
        {
            result = ENOMEM;
        }

        header = NULL;
    }

    return result;
}

int cg_storage_provider_utils_add_header_from_meta(cg_storage_provider_request * const request,
                                                   char const * const meta_data_key,
                                                   char const * const header_name,
                                                   cgutils_llist * const headers)
{
    int result = 0;
    assert(request != NULL);
    assert(meta_data_key != NULL);
    assert(header_name != NULL);
    assert(headers != NULL);
    assert(request->ctx != NULL);

    if (request->ctx->metadata != NULL)
    {
        bool found = false;

        for (cgutils_llist_elt * elt = cgutils_llist_get_first(request->ctx->metadata);
             found == false && elt != NULL && result == 0;
             elt = cgutils_llist_elt_get_next(elt))
        {
            cg_storage_provider_metadata const * const meta = cgutils_llist_elt_get_object(elt);
            assert(meta != NULL);
            assert(meta->key != NULL);

            if (strcmp(meta_data_key, meta->key) == 0)
            {
                found = true;

                result = cgutils_http_add_header_to_list_dup(headers, header_name, meta->value);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error adding header to list: %d", result);
                }
            }
        }
    }

    return result;
}

static int cg_storage_provider_utils_io_finish_cb(int const status,
                                                  size_t const completion,
                                                  void * const cb_data)
{
    int result = status;
    cg_storage_provider_request * request = cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) completion;

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error finishing writing data to IO destination: %d",
                      result);
    }

    CGUTILS_ASSERT(request->raw_request_cb);
    (*(request->raw_request_cb))(result, request->request_cb_data);

    return result;
}

static int cg_storage_provider_utils_io_copy_cb(int const status,
                                                void * cb_data);

static int cg_storage_provider_utils_io_write_cb(int const status,
                                                 size_t const completion,
                                                 void * const cb_data)
{
    int result = status;
    cg_storage_provider_request * request = cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) completion;

    if (COMPILER_LIKELY(result == 0))
    {
        cg_storage_provider_utils_io_copy_cb(0,
                                             request);
    }
    else
    {
        CGUTILS_ERROR("Error writing data to IO destination: %d",
                      result);
    }

    if (result != 0)
    {
        CGUTILS_ASSERT(request->raw_request_cb);
        (*(request->raw_request_cb))(result, request->request_cb_data);
    }

    return result;
}

static int cg_storage_provider_utils_io_copy_cb(int const status,
                                                void * cb_data)
{
    int result = status;
    cg_storage_provider_request * request = cb_data;
    CGUTILS_ASSERT(request != NULL);

    if (COMPILER_LIKELY(result == 0))
    {
        size_t written = 0;
        bool eof = false;
        bool io_pending = false;

        result = cg_storage_io_ctx_read(request->source_io,
                                        request->ctx->buffer,
                                        request->ctx->buffer_size,
                                        &written,
                                        &eof,
                                        &io_pending,
                                        &cg_storage_provider_utils_io_copy_cb,
                                        request);

        if (COMPILER_LIKELY(result == 0))
        {
            if (written > 0)
            {
                result = cg_storage_io_ctx_write(request->dest_io,
                                                 request->ctx->buffer,
                                                 written,
                                                 &cg_storage_provider_utils_io_write_cb,
                                                 request);

                if (COMPILER_LIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error writing data to IO destination: %d",
                                  result);
                }
            }
            else if (eof == true)
            {
                result = cg_storage_io_destination_finish(request->ctx->dest_io,
                                                          &cg_storage_provider_utils_io_finish_cb,
                                                          request);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error finishing IO: %d",
                                  result);
                }
            }
        }
        else
        {
            CGUTILS_ERROR("Error reading data from IO source: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading data from IO source: %d",
                      result);
    }

    if (result != 0)
    {
        CGUTILS_ASSERT(request->raw_request_cb);
        (*(request->raw_request_cb))(result, request->request_cb_data);
    }

    return result;
}

int cg_storage_provider_utils_io_copy(cg_storage_provider_request * const request)
{
    int result = 0;
    CGUTILS_ASSERT(request != NULL);
    CGUTILS_ASSERT(request->raw_request_cb != NULL);
    CGUTILS_ASSERT(request->source_io != NULL);
    CGUTILS_ASSERT(request->dest_io != NULL);
    CGUTILS_ASSERT(request->ctx != NULL);
    CGUTILS_ASSERT(request->ctx->source_io != NULL);
    CGUTILS_ASSERT(request->ctx->dest_io != NULL);

    CGUTILS_MALLOC(request->ctx->buffer, 1, CG_STORAGE_PROVIDER_UTILS_BUFFER_SIZE);

    if (request->ctx->buffer != NULL)
    {
        request->ctx->buffer_size = CG_STORAGE_PROVIDER_UTILS_BUFFER_SIZE;

        result = cg_storage_provider_utils_io_copy_cb(0,
                                                      request);
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}
