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
#include <time.h>
#include <unistd.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_event.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_http.h>
#include <cloudutils/cloudutils_network.h>

#include <curl/curl.h>

struct cgutils_http_data
{
    cgutils_http_global_params global_params;
    cgutils_event_data * event;
    cgutils_event * timer_event;
    /* llist of cgutils_http_request * */
    cgutils_llist * pending_requests;
    CURLM * curl_multi;
    FILE * null_file;
    size_t running_queries;
};

struct cgutils_http_request
{
    char error_buffer[CURL_ERROR_SIZE];
    cgutils_http_callbacks callbacks;
    cgutils_http_timeouts timeouts;
    cgutils_http_request_options options;
    CURL * handler;
    char * uri;
    void * cb_data;
    cgutils_http_data * data;
    cgutils_event * ev;
    struct curl_slist * curl_headers;
    size_t content_length;
    size_t pending_io;
    size_t in_callback_count;
    size_t sent_bytes;
    size_t recv_bytes;
    time_t start_time;
    cgutils_event_flags event_flags;
    cgutils_http_method method;
    curl_socket_t sock;
    CURLcode status;
    int curl_paused;
    bool in_pending;
    bool deletion;
    bool content_length_set;
    bool chunked_transfer_encoding;
    bool finished;
    bool released;
};

struct cgutils_http_response
{
    uint16_t status_code;
    uint16_t error_code;
    double total_time;
    double namelookup_time;
    double connect_time;
};

static int cgutils_http_header_list_to_curl_headers(cgutils_llist * const headers,
                                                    cgutils_http_request * const request)
{
    assert(request != NULL);

    int result = 0;

    if (headers != NULL)
    {
        cgutils_llist_elt * elt = cgutils_llist_get_iterator(headers);

        while (elt != NULL && result == 0)
        {
            cgutils_http_header const * const header = cgutils_llist_elt_get_object(elt);
            assert(header != NULL);
            assert(header->name != NULL);
            assert(header->value != NULL);

            char * str = NULL;
            static char const separator[] = ": ";
            static size_t const separator_len = sizeof separator - 1;
            size_t const name_len = strlen(header->name);
            size_t const value_len = strlen(header->value);

            CGUTILS_MALLOC(str, name_len + value_len + separator_len + 1, 1);

            if (str != NULL)
            {
                memcpy(str, header->name, name_len);
                memcpy(str + name_len, separator, separator_len);
                memcpy(str + name_len + separator_len, header->value, value_len);
                str[name_len + value_len + separator_len] = '\0';

                struct curl_slist * chunk = curl_slist_append(request->curl_headers, str);

                if (chunk != NULL)
                {
                    if (request->curl_headers == NULL)
                    {
                        request->curl_headers = chunk;
                    }
                }
                else
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error adding curl header: %d", result);
                }
                CGUTILS_FREE(str);
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Unable to allocate memory for str: %d", result);
            }

            elt = cgutils_llist_elt_get_next(elt);
        }
    }

    return result;
}

static size_t cgutils_http_write_callback(void * const ptr,
                                          size_t const size,
                                          size_t const nmemb,
                                          void * const cb_data)
{
    assert(cb_data != NULL);
    assert(ptr != NULL);
    size_t realsize = size * nmemb;

    cgutils_http_request * request = cb_data;
    assert(request->callbacks.write_cb != NULL);
    assert(request->data != NULL);
    assert(request->cb_data != NULL);

    int result = (request->callbacks.write_cb)(request->data,
                                               request,
                                               ptr,
                                               realsize,
                                               request->cb_data);

    if (COMPILER_UNLIKELY(result != 0))
    {
        realsize = 0;
    }
    else if (COMPILER_LIKELY(SIZE_MAX - request->recv_bytes > realsize))
    {
        request->recv_bytes += realsize;
    }

    return realsize;
}

static size_t cgutils_http_read_callback(void * const ptr,
                                         size_t const size,
                                         size_t const nmemb,
                                         void * const cb_data)
{
    assert(cb_data != NULL);
    assert(ptr != NULL);
    size_t written = 0;

    cgutils_http_request * request = cb_data;
    assert(request->callbacks.read_cb != NULL);
    assert(request->data != NULL);
    assert(request->cb_data != NULL);
    bool eof = false;

    int result = (request->callbacks.read_cb)(request->data,
                                              request,
                                              ptr,
                                              size * nmemb,
                                              &written,
                                              &eof,
                                              request->cb_data);
    if (COMPILER_LIKELY(result == 0))
    {
        if (written > 0 &&
            SIZE_MAX - request->sent_bytes > written)
        {
            request->sent_bytes += written;
        }

        if (written == 0 &&
            eof == false)
        {
            written = CURL_READFUNC_PAUSE;
        }
    }
    else
    {
        CGUTILS_ERROR("got result of %d", result);
        written = 0;
    }

    return written;
}

static size_t cgutils_http_header_recv_callback(void * const ptr,
                                                size_t const size,
                                                size_t const nmemb,
                                                void * const cb_data)
{
    assert(cb_data != NULL);
    assert(ptr != NULL);
    size_t written = 0;

    cgutils_http_request * request = cb_data;
    assert(request->callbacks.header_cb != NULL);
    assert(nmemb <= (SIZE_MAX / size));
    assert(request->data != NULL);
    assert(request->cb_data != NULL);

    int result = (request->callbacks.header_cb)(request->data,
                                                request,
                                                ptr,
                                                size * nmemb,
                                                request->cb_data);
    if (COMPILER_LIKELY(result == 0))
    {
        written = size * nmemb;
    }
    else
    {
        CGUTILS_ERROR("got result of %d", result);
        written = 0;
    }

    return written;
}

static COMPILER_PURE_FUNCTION bool cgutils_http_request_has_custom_method(cgutils_http_request const * const request)
{
    static cgutils_http_method const custom_methods[] =
        {
#define METHOD(method)
#define CUSTOM_METHOD(method) CGUTILS_HTTP_METHOD_ ## method,
#include "cloudutils/cloudutils_http_methods.itm"
#undef CUSTOM_METHOD
#undef METHOD
        };
    static size_t const custom_methods_count = sizeof custom_methods / sizeof *custom_methods;
    bool result = false;

    assert(request != NULL);

    for (size_t idx = 0; idx < custom_methods_count && result == false; idx++)
    {
        if (request->method == custom_methods[idx])
        {
            result = true;
        }
    }

    return result;
}

static int cgutils_http_request_prepare(cgutils_http_request * const request,
                                        CURL ** handler)
{
    assert(request != NULL);
    assert(request->uri != NULL);
    assert(request->data != NULL);
    assert(handler != NULL && *handler == NULL);

    cgutils_http_request_options const * options = &(request->options);
    int result = 0;

    *handler = curl_easy_init();

    if (*handler != NULL)
    {
        curl_off_t max_upload_speed = 0;
        curl_off_t max_download_speed = 0;
        CURLcode res = 0;
        char const * custom_method = cgutils_http_request_has_custom_method(request) ?
            cgutils_http_method_to_str(request->method) : NULL;

        if (options->max_upload_speed > 0)
        {
            max_upload_speed = (curl_off_t) options->max_upload_speed;
        }

        if (options->max_download_speed > 0)
        {
            max_download_speed = (curl_off_t) options->max_download_speed;
        }

#define DO_EASY_SETOPT(handler, option, parameter, condition)           \
        if (result == 0 && (condition) == true)                         \
        {                                                               \
            res = curl_easy_setopt((handler), (option), (parameter));   \
            if (res != 0)                                               \
            {                                                           \
                result = EINVAL;                                        \
            }                                                           \
        }                                                               \

        DO_EASY_SETOPT(*handler,
                       CURLOPT_PRIVATE,
                       request,
                       true);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_URL,
                       request->uri,
                       true);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_SSL_VERIFYPEER,
                       options->ssl_no_verify_peer == true ? 0L : 1L, true);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_SSL_VERIFYHOST,
                       options->ssl_no_verify_host == true ? 0L : 2L, true);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_SSL_CIPHER_LIST,
                       options->ssl_ciphers,
                       options->ssl_ciphers != NULL && strlen(options->ssl_ciphers) > 0);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_TIMEOUT,
                       request->timeouts.timeout, request->timeouts.timeout > 0);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_HTTPGET,
                       1L,
                       request->method == CGUTILS_HTTP_METHOD_GET);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_NOBODY,
                       1L,
                       request->method == CGUTILS_HTTP_METHOD_HEAD);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_UPLOAD,
                       1L,
                       request->method == CGUTILS_HTTP_METHOD_PUT);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_POST,
                       1L,
                       request->method == CGUTILS_HTTP_METHOD_POST);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_CUSTOMREQUEST,
                       custom_method,
                       custom_method != NULL);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_POSTFIELDS,
                       options->data_to_send,
                       (options->data_to_send != NULL));
        DO_EASY_SETOPT(*handler,
                       CURLOPT_POSTFIELDSIZE_LARGE,
                       (curl_off_t) request->content_length,
                       (request->method == CGUTILS_HTTP_METHOD_POST &&
                        request->content_length_set == true));
        DO_EASY_SETOPT(*handler,
                       CURLOPT_INFILESIZE_LARGE,
                       (curl_off_t) request->content_length,
                       request->method == CGUTILS_HTTP_METHOD_PUT &&
                       request->content_length_set == true);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_POSTFIELDSIZE_LARGE,
                       (curl_off_t) options->data_to_send_size,
                       (request->method == CGUTILS_HTTP_METHOD_POST &&
                        request->content_length_set == false &&
                        options->data_to_send != NULL && options->data_to_send_size > 0));
        DO_EASY_SETOPT(*handler,
                       CURLOPT_WRITEFUNCTION,
                       &cgutils_http_write_callback,
                       request->callbacks.write_cb != NULL);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_WRITEDATA,
                       request,
                       request->callbacks.write_cb != NULL);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_WRITEDATA,
                       request->data->null_file,
                       request->callbacks.write_cb == NULL);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_READFUNCTION,
                       &cgutils_http_read_callback,
                       request->callbacks.read_cb != NULL);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_READDATA,
                       request,
                       request->callbacks.read_cb != NULL);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_HEADERFUNCTION,
                       &cgutils_http_header_recv_callback,
                       request->callbacks.header_cb != NULL);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_HEADERDATA,
                       request,
                       request->callbacks.header_cb != NULL);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_HTTPAUTH,
                       CURLAUTH_BASIC,
                       (options->authentication == true && options->username != NULL && options->password != NULL));
        DO_EASY_SETOPT(*handler,
                       CURLOPT_USERNAME,
                       options->username,
                       (options->authentication == true && options->username != NULL && options->password != NULL));
        DO_EASY_SETOPT(*handler,
                       CURLOPT_PASSWORD,
                       options->password,
                       (options->authentication == true && options->username != NULL && options->password != NULL));
        DO_EASY_SETOPT(*handler,
                       CURLOPT_USERAGENT,
                       options->user_agent,
                       (options->user_agent != NULL));
        DO_EASY_SETOPT(*handler,
                       CURLOPT_VERBOSE,
                       options->verbose ? 1L : 0L,
                       true);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_NOSIGNAL,
                       1L,
                       true);
        DO_EASY_SETOPT(*handler,
                       CURLOPT_MAX_SEND_SPEED_LARGE,
                       max_upload_speed,
                       max_upload_speed > 0 &&
                       max_upload_speed <= LONG_MAX);

        DO_EASY_SETOPT(*handler,
                       CURLOPT_MAX_RECV_SPEED_LARGE,
                       max_download_speed,
                       max_download_speed > 0 &&
                       max_download_speed <= LONG_MAX);

        DO_EASY_SETOPT(*handler,
                       CURLOPT_LOW_SPEED_LIMIT,
                       options->low_speed_limit,
                       options->low_speed_limit > 0 &&
                       options->low_speed_limit <= LONG_MAX &&
                       options->low_speed_time > 0 &&
                       options->low_speed_time <= LONG_MAX);

        DO_EASY_SETOPT(*handler,
                       CURLOPT_LOW_SPEED_TIME,
                       options->low_speed_time,
                       options->low_speed_limit > 0 &&
                       options->low_speed_limit <= LONG_MAX &&
                       options->low_speed_time > 0 &&
                       options->low_speed_time <= LONG_MAX);

        DO_EASY_SETOPT(*handler,
                       CURLOPT_CAINFO,
                       request->data->global_params.ca_bundle_file,
                       true);

        DO_EASY_SETOPT(*handler,
                       CURLOPT_CAPATH,
                       request->data->global_params.ca_bundle_path,
                       true);

        DO_EASY_SETOPT(*handler,
                       CURLOPT_ERRORBUFFER,
                       request->error_buffer,
                       true);

        if (result == 0 &&
            options->ssl_client_certificate_file != NULL &&
            options->ssl_client_certificate_key_file != NULL)
        {
            DO_EASY_SETOPT(*handler,
                           CURLOPT_SSLCERT,
                           options->ssl_client_certificate_file,
                           options->ssl_client_certificate_file != NULL);
            DO_EASY_SETOPT(*handler,
                           CURLOPT_SSLKEY,
                           options->ssl_client_certificate_key_file,
                           options->ssl_client_certificate_key_file != NULL);
            DO_EASY_SETOPT(*handler,
                           CURLOPT_KEYPASSWD,
                           options->ssl_client_certificate_key_password,
                           options->ssl_client_certificate_key_password != NULL);
        }

#undef DO_EASY_SETOPT

#if LIBCURL_VERSION_NUM >= 0x073100
        if (result == 0 &&
            options->disable_fast_open == false)
        {
            curl_easy_setopt(*handler, CURLOPT_TCP_FASTOPEN, 1);
        }
#endif /* LIBCURL_VERSION_NUM >= 0x073100 */

        if (result == 0)
        {
            if ((request->content_length_set == false &&
                (
                    (request->method == CGUTILS_HTTP_METHOD_POST ||
                     request->method == CGUTILS_HTTP_METHOD_PUT) && request->callbacks.read_cb != NULL)) ||
                request->chunked_transfer_encoding == true)
            {
                struct curl_slist * chunk = curl_slist_append(request->curl_headers, "Transfer-Encoding: chunked");

                if (chunk != NULL)
                {
                    if (request->curl_headers == NULL)
                    {
                        request->curl_headers = chunk;
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error setting Transfer-Encoding header");
                }
            }

            if (request->options.disable_100_continue == true)
            {
                struct curl_slist * expect = curl_slist_append(request->curl_headers, "Expect:");

                if (expect != NULL)
                {
                    if (request->curl_headers == NULL)
                    {
                        request->curl_headers = expect;
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error setting Expect header");
                }
            }
        }

        if (result == 0 && request->curl_headers != NULL)
        {
            result = curl_easy_setopt(*handler, CURLOPT_HTTPHEADER, request->curl_headers);
        }

        if (result != 0)
        {
            curl_easy_cleanup(*handler), *handler = NULL;
        }
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static void cgutils_http_handle_response(cgutils_http_request * request)
{
    assert(request != NULL);

    if (request->callbacks.response_cb != NULL && request->pending_io == 0)
    {
        cgutils_http_response * response = NULL;
        CGUTILS_ALLOCATE_STRUCT(response);

        if (response != NULL)
        {
            long status = 0;

            CURLcode res = CURLE_OK;
#define GETOPT(option, storage)                                         \
            if (res == 0)                                               \
            {                                                           \
                res = curl_easy_getinfo(request->handler, option, &storage); \
            }
            GETOPT(CURLINFO_RESPONSE_CODE, status);
            GETOPT(CURLINFO_TOTAL_TIME, response->total_time);
            GETOPT(CURLINFO_NAMELOOKUP_TIME, response->namelookup_time);
            GETOPT(CURLINFO_CONNECT_TIME, response->connect_time);
#undef GETOPT

            if (res == 0 && status >= 0 && status <= UINT16_MAX)
            {
                response->error_code = (uint16_t) request->status;
                response->status_code = (uint16_t) status;
                assert(request->callbacks.response_cb != NULL);

                if (request->options.print_requests == true)
                {
                    CGUTILS_INFO("Got status %d for request %p %s %s (%f / %f / %f)",
                                 response->status_code,
                                 request,
                                 cgutils_http_method_to_str(cgutils_http_request_get_method(request)),
                                 cgutils_http_request_get_uri(request),
                                 response->total_time,
                                 response->namelookup_time,
                                 response->connect_time);
                }

                (request->callbacks.response_cb)(request->data, request, response, request->cb_data);
            }
            else
            {
                CGUTILS_ERROR("Error, res is %d and status is %ld", res, status);
                cgutils_http_response_free(response), response = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Allocation error for HTTP response: %d", ENOMEM);
        }
    }
}

static void cgutils_http_cleanup_multi(cgutils_http_data * const data)
{
    CURLMsg * msg = NULL;
    int msgs_left = 0;
    int still_running = 0;
    assert(data != NULL);

    curl_multi_socket_action(data->curl_multi,
                             CURL_SOCKET_TIMEOUT, 0, &still_running);


    while ((msg = curl_multi_info_read(data->curl_multi, &msgs_left)) != NULL)
    {
        if (msg->msg == CURLMSG_DONE)
        {
            cgutils_http_request * request = NULL;
            CURL * const easy = msg->easy_handle;
            CURLcode const status = msg->data.result;

            curl_easy_getinfo(easy, CURLINFO_PRIVATE, (char **) &request);

            curl_multi_remove_handle(data->curl_multi, easy);

            request->finished = true;
            request->status = status;
            cgutils_http_handle_response(request);
        }
    }
}

/* Called by cgutils_event when something
   is happening on the socket */
static void cgutils_http_event_on_socket_cb(int fd,
                                            short flags,
                                            void * cb_data)
{
    cgutils_http_request * request = cb_data;
    assert(fd >= 0);
    assert(cb_data != NULL);
    assert(request->data != NULL);
    cgutils_http_data * const data = request->data;

    if (request->finished == false &&
        request->in_callback_count == 0)
    {
        assert(request->data->curl_multi != NULL);

        int still_running = 0;
        int curl_flags = 0;

        if (flags & CGUTILS_EVENT_READ)
        {
            curl_flags |= CURL_CSELECT_IN;
        }

        if (flags & CGUTILS_EVENT_WRITE)
        {
            curl_flags |= CURL_CSELECT_OUT;
        }

        request->in_callback_count++;

        CURLMcode const code = curl_multi_socket_action(data->curl_multi,
                                                        fd,
                                                        curl_flags,
                                                        &still_running);

        cgutils_http_cleanup_multi(data);

        if (COMPILER_UNLIKELY(code != CURLM_OK))
        {
            CGUTILS_ERROR("curl_multi_socket_action() failed: %s (%d)",
                          curl_multi_strerror(code),
                          code);
        }

        request->in_callback_count--;

        if (request->released == true)
        {
            cgutils_http_request_free(request), request = NULL;
        }
    }
}

static int cgutils_http_set_event_for_request(cgutils_http_request * const request,
                                              int const action)
{
    assert(request != NULL);
    assert(request->data != NULL);
    assert(request->data->event != NULL);

    cgutils_event_flags flags = CGUTILS_EVENT_PERSIST;

    if (action & CURL_POLL_IN)
    {
        flags |= CGUTILS_EVENT_READ;
    }

    if (action & CURL_POLL_OUT)
    {
        flags |= CGUTILS_EVENT_WRITE;
    }

    int result = 0;
    bool need_enable = true;

    request->event_flags = flags;

    if (request->ev == NULL)
    {
        cgutils_event_create_fd_event(request->data->event,
                                      request->sock,
                                      &cgutils_http_event_on_socket_cb,
                                      request,
                                      flags,
                                      &request->ev);
    }
    else
    {
        need_enable = cgutils_event_is_enabled(request->ev) == false;

        result = cgutils_event_reassign(request->ev, flags, &cgutils_http_event_on_socket_cb);
    }

    if (result == 0 &&
        need_enable == true)
    {
        result = cgutils_event_enable(request->ev, NULL);
    }

    return result;
}

/* Called by curl to request FD notification changes
 */
static int cgutils_http_socket_cb(CURL * const handle,
                                  curl_socket_t sockfd,
                                  int const action,
                                  void * const callback_data,
                                  void * socket_data)
{
    assert(handle != NULL);
    assert(sockfd >= 0);
    assert(callback_data != NULL);
    cgutils_http_data * data = callback_data;

    int result = 0;

    /* action can be :
       CURL_POLL_NONE (0)
       register, not interested in readiness (yet)
       CURL_POLL_IN (1)
       register, interested in read readiness
       CURL_POLL_OUT (2)
       register, interested in write readiness
       CURL_POLL_INOUT (3)
       register, interested in both read and write readiness
       CURL_POLL_REMOVE (4)
       unregister
    */

    if (action == CURL_POLL_REMOVE)
    {
        cgutils_http_request * request = socket_data;
        assert(request != NULL);

        if (request->deletion == false)
        {
            request->deletion = true;

            cgutils_event_disable(request->ev);

            data->running_queries--;

            if (data->running_queries == 0)
            {
                cgutils_event_disable(data->timer_event);
            }
        }
    }
    else
    {
        if (socket_data == NULL)
        {
            data->running_queries++;

            /* not yet assigned, new connection.
             It may not be a new HTTP request, just a new connection for the
            same request. */
            CURLcode const code = curl_easy_getinfo(handle, CURLINFO_PRIVATE,
                                                    (char **) &socket_data);

            if (code == CURLE_OK &&
                socket_data != NULL)
            {
                cgutils_http_request * request = socket_data;

                if (request->ev != NULL)
                {
                    cgutils_event_free(request->ev), request->ev = NULL;
                }

                request->sock = sockfd;

                CURLMcode const mcode = curl_multi_assign(data->curl_multi,
                                                          sockfd,
                                                          socket_data);

                if (mcode == CURLM_OK)
                {
                    result = cgutils_http_set_event_for_request(request, action);
                }
                else
                {
                    CGUTILS_ERROR("Error in curl_multi_assign: %s (%d)",
                                  curl_multi_strerror(mcode),
                                  mcode);
                    result = EIO;
                }
            }
            else
            {
                result = EIO;
            }
        }
        else
        {
            cgutils_http_request * request = socket_data;
            assert(request != NULL);

            if (sockfd != request->sock)
            {
                CGUTILS_ERROR("Error, the socket associated to this request does not match the one the even occured on: %d %d",
                              sockfd,
                              request->sock);
            }

            result = cgutils_http_set_event_for_request(request, action);
        }
    }

    return result;
}

/* This function is called by cURL to request a timeout change */
static int cgutils_http_multi_timer_cb(CURLM * const multi,
                                       long timeout_ms,
                                       cgutils_http_data * data)
{
    int result = 0;
    assert(data != NULL);
    assert(multi == data->curl_multi);

    assert(data->timer_event != NULL);

    (void) multi;

    if (timeout_ms < 0)
    {
        cgutils_event_disable(data->timer_event);

        cgutils_http_cleanup_multi(data);
    }
    else
    {
        struct timeval timeout = { .tv_sec = timeout_ms / 1000,
                                   .tv_usec = (timeout_ms%1000)*1000
        };

        result = cgutils_event_enable(data->timer_event, &timeout);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error enabling event: %d", result);
            result = EIO;
        }
    }


    return result;
}

/* this function is called when a timeout requested by cURL expires */
static void cgutils_http_timer_cb(void * cb_data)
{
    assert(cb_data != NULL);
    cgutils_http_data * data = cb_data;

    assert(data->curl_multi != NULL);
    cgutils_http_cleanup_multi(data);
}

int cgutils_http_data_init(cgutils_event_data * const event_data,
                           cgutils_http_global_params const * params,
                           cgutils_http_data ** const data)
{
    int result = EINVAL;

    if (event_data != NULL && data != NULL)
    {
        CGUTILS_ALLOCATE_STRUCT(*data);

        if (*data != NULL)
        {
            cgutils_http_global_params global_params =
                {
                    .connections_cache_size = 0,
                    .max_connections_by_host = 0,
                    .max_concurrent_connections = 0,
                    .ca_bundle_file = NULL,
                    .ca_bundle_path = NULL,
                };


            if (params != NULL)
            {
                global_params = *params;
            }

            result = cgutils_file_fopen("/dev/null", "w", &((*data)->null_file));

            if (result == 0)
            {
                result = cgutils_event_create_timer_event(event_data,
                                                          0,
                                                          &cgutils_http_timer_cb,
                                                          *data,
                                                          &((*data)->timer_event));

                if (result == 0)
                {
                    result = cgutils_llist_create(&((*data)->pending_requests));

                    if (result == 0)
                    {
                        (*data)->curl_multi = curl_multi_init();
                        if ((*data)->curl_multi != NULL)
                        {
                            result = EIO;
                            /* set the function called by cURL to request FD notification changes */
                            CURLMcode mcode = curl_multi_setopt((*data)->curl_multi,
                                                                CURLMOPT_SOCKETFUNCTION,
                                                                &cgutils_http_socket_cb);

                            if (mcode == CURLM_OK)
                            {
                                mcode = curl_multi_setopt((*data)->curl_multi,
                                                          CURLMOPT_SOCKETDATA,
                                                          *data);

                                if (mcode == CURLM_OK)
                                {
                                    /* set the function called by cURL to request timeout */
                                    curl_multi_setopt((*data)->curl_multi, CURLMOPT_TIMERFUNCTION,
                                                      &cgutils_http_multi_timer_cb);
                                    curl_multi_setopt((*data)->curl_multi, CURLMOPT_TIMERDATA, *data);

                                    if (global_params.connections_cache_size > 0 &&
                                        global_params.connections_cache_size < LONG_MAX)
                                    {
                                        curl_multi_setopt((*data)->curl_multi, CURLMOPT_MAXCONNECTS,
                                                          (long) global_params.connections_cache_size);
                                    }

                                    if (global_params.max_connections_by_host > 0 &&
                                        global_params.max_connections_by_host < LONG_MAX)
                                    {
                                        curl_multi_setopt((*data)->curl_multi, CURLMOPT_MAX_HOST_CONNECTIONS,
                                                          (long) global_params.max_connections_by_host);
                                    }

                                    if (global_params.max_concurrent_connections > 0 &&
                                        global_params.max_concurrent_connections < LONG_MAX)
                                    {
                                        curl_multi_setopt((*data)->curl_multi, CURLMOPT_MAX_TOTAL_CONNECTIONS,
                                                          (long) global_params.max_concurrent_connections);
                                    }

                                    result = 0;
                                    (*data)->event = event_data;
                                    (*data)->global_params = global_params;
                                }
                            }
                        }
                        else
                        {
                            result = ENOMEM;
                        }
                    }
                }
            }

            if (result != 0)
            {
                cgutils_http_data_free(*data), *data = NULL;
            }
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_http_request_init(cgutils_http_data * const data,
                              char const * const uri,
                              cgutils_http_method const method,
                              cgutils_llist * headers,
                              cgutils_http_callbacks const * const callbacks,
                              cgutils_http_timeouts const * const timeouts,
                              cgutils_http_request_options const * options,
                              void * const cb_data,
                              cgutils_http_request ** const request)
{
    int result = EINVAL;

    if (data != NULL && uri != NULL &&
        callbacks != NULL && timeouts != NULL && request != NULL &&
        options != NULL &&
        (options->data_to_send_size == 0 || options->data_to_send != NULL))
    {
        CGUTILS_ALLOCATE_STRUCT(*request);

        if (*request != NULL)
        {
            (*request)->uri = cgutils_strdup(uri);

            if ((*request)->uri != NULL)
            {
                result = cgutils_http_header_list_to_curl_headers(headers, *request);

                if (result == 0)
                {
                    result = cgutils_llist_insert(data->pending_requests,
                                                  *request);

                    if (result == 0)
                    {
                        (*request)->callbacks = *callbacks;
                        (*request)->timeouts = *timeouts;
                        (*request)->cb_data = cb_data;
                        (*request)->method = method;
                        (*request)->data = data;
                        (*request)->options = *options;
                        (*request)->in_pending = true;
                    }

                    cgutils_llist_free(&headers, &cgutils_http_header_delete);
                }
            }
            else
            {
                result = ENOMEM;
            }

            if (result != 0)
            {
                cgutils_http_request_free(*request), *request = NULL;
            }
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

cgutils_http_method cgutils_http_request_get_method(cgutils_http_request const * const request)
{
    cgutils_http_method result = 0;

    if (request != NULL)
    {
        result = request->method;
    }

    return result;
}

char const * cgutils_http_request_get_uri(cgutils_http_request const * const request)
{
    char const * result = 0;

    if (request != NULL)
    {
        result = request->uri;
    }

    return result;
}

char const * cgutils_http_request_get_error_buffer(cgutils_http_request const * const request)
{
    char const * result = 0;

    if (request != NULL)
    {
        result = request->error_buffer;
    }

    return result;
}

void cgutils_http_request_free(cgutils_http_request * request)
{
    if (request != NULL)
    {
        if (request->in_callback_count == 0)
        {
            if (request->data != NULL &&
                request->data->pending_requests != NULL &&
                request->in_pending == true)
            {
                cgutils_llist_remove_by_object(request->data->pending_requests,
                                               request);
            }

            if (request->curl_headers != NULL)
            {
                curl_slist_free_all(request->curl_headers), request->curl_headers = NULL;
            }

            if (request->ev != NULL)
            {
                cgutils_event_disable(request->ev);
                cgutils_event_free(request->ev), request->ev = NULL;
            }

            if (request->handler != NULL)
            {
                curl_easy_cleanup(request->handler), request->handler = NULL;
            }

            if (request->uri)
            {
                CGUTILS_FREE(request->uri);
            }

            CGUTILS_FREE(request);
        }
        else
        {
            request->released = true;
        }
    }
}

static void cgutils_http_request_delete(void * request)
{
    cgutils_http_request_free(request);
}

int cgutils_http_send(cgutils_http_request * const request)
{
    int result = EINVAL;

    if (request != NULL)
    {
        result = cgutils_http_request_prepare(request,
                                              &(request->handler));

        if (result == 0)
        {
            assert(request->data != NULL);
            assert(request->data->curl_multi != NULL);
            assert(request->handler != NULL);

            if (request->options.print_requests == true)
            {
                CGUTILS_INFO("Sending request %p %s %s",
                             request,
                             cgutils_http_method_to_str(cgutils_http_request_get_method(request)),
                             cgutils_http_request_get_uri(request));
            }

            CURLMcode const code = curl_multi_add_handle(request->data->curl_multi,
                                                         request->handler);

            if (code == CURLM_OK)
            {
                /* curl_multi_add_handle() schedules a timeout of 1 ms,
                   no need to kickstart it ourselves. */
                request->start_time = time(NULL);
            }
            else
            {
                CGUTILS_ERROR("Error adding multi handle: %s (%d)",
                              curl_multi_strerror(code), code);
                result = EIO;
            }
        }
    }

    return result;
}

uint16_t cgutils_http_response_get_status(cgutils_http_response const * const response)
{
    uint16_t result = 0;

    if (response != NULL)
    {
        result = response->status_code;
    }

    return result;
}

uint16_t cgutils_http_response_get_error(cgutils_http_response const * const response)
{
    uint16_t result = 0;

    if (response != NULL)
    {
        result = response->error_code;
    }

    return result;
}

char const * cgutils_http_response_get_error_str(cgutils_http_response const * const response)
{
    char const * result = 0;

    if (response != NULL)
    {
        result = curl_easy_strerror(response->error_code);
    }

    return result;
}

double cgutils_http_response_total_time(cgutils_http_response const * const response)
{
    double result = 0;

    if (response != NULL)
    {
        result = response->total_time;
    }

    return result;
}

double cgutils_http_response_namelookup_time(cgutils_http_response const * const response)
{
    double result = 0;

    if (response != NULL)
    {
        result = response->namelookup_time;
    }

    return result;
}

double cgutils_http_response_connect_time(cgutils_http_response const * const response)
{
    double result = 0;

    if (response != NULL)
    {
        result = response->connect_time;
    }

    return result;
}

int cgutils_http_header_consume_init(char const * name,
                                     char * value,
                                     cgutils_http_header ** out)
{
    int result = EINVAL;

    if (name != NULL && value != NULL && out != NULL)
    {
        char * new_name = cgutils_strdup(name);
        result = ENOMEM;

        if (new_name != NULL)
        {
            CGUTILS_ALLOCATE_STRUCT(*out);

            if (*out != NULL)
            {
                result = 0;
                (*out)->name = new_name;
                (*out)->value = value;
            }

            if (result != 0)
            {
                CGUTILS_FREE(new_name);
            }
        }
    }

    return result;
}

int cgutils_http_header_init(char const * name,
                             char const * value,
                             cgutils_http_header ** out)
{
    int result = EINVAL;

    if (name != NULL && value != NULL && out != NULL)
    {
        char * new_value = cgutils_strdup(value);

        if (new_value != NULL)
        {
            result = cgutils_http_header_consume_init(name, new_value, out);

            if (result != 0)
            {
                CGUTILS_FREE(new_value);
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_http_add_header_to_list(cgutils_llist * const headers,
                                    char const * const name,
                                    char * value)
{
    int result = EINVAL;

    if (headers != NULL && name != NULL && value != NULL)
    {
        cgutils_http_header * header = NULL;

        result = cgutils_http_header_consume_init(name, value, &header);

        if (result == 0)
        {
            value = NULL;

            result = cgutils_llist_insert(headers, header);

            if (result != 0)
            {
                CGUTILS_ERROR("Error adding header to list: %d", result);
                cgutils_http_header_free(header), header = NULL;
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating header: %d", result);
            CGUTILS_FREE(value);
        }
    }

    if (result != 0 && value != NULL)
    {
        CGUTILS_FREE(value);
    }

    return result;
}

int cgutils_http_add_header_to_list_dup(cgutils_llist * const headers,
                                        char const * const name,
                                        char const * const value)
{
    int result = EINVAL;

    if (headers != NULL && name != NULL && value != NULL)
    {
        char * value_dup = cgutils_strdup(value);

        if (value_dup != NULL)
        {
            result = cgutils_http_add_header_to_list(headers, name, value_dup);
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_http_get_header_by_name(cgutils_llist * const headers,
                                    char const * const name,
                                    cgutils_http_header const ** const out)
{
    int result = EINVAL;

    if (headers != NULL && name != NULL && out != NULL)
    {
        result = ENOENT;

        for (cgutils_llist_elt * elt = cgutils_llist_get_iterator(headers);
             elt != NULL && result == ENOENT;
             elt = cgutils_llist_elt_get_next(elt))
        {
            cgutils_http_header const * const header = cgutils_llist_elt_get_object(elt);
            assert(header != NULL);

            /* Remember, rfc2616 states that HTTP headers are case insensitive in
               section 4.2 Message Headers. */

            if (strcasecmp(header->name, name) == 0)
            {
                result = 0;
                *out = header;
            }
        }
    }

    return result;
}

void cgutils_http_header_free(cgutils_http_header * header)
{
    if (header != NULL)
    {
        if (header->name != NULL)
        {
            CGUTILS_FREE(header->name);
        }

        if (header->value != NULL)
        {
            CGUTILS_FREE(header->value);
        }

        CGUTILS_FREE(header);
    }
}

void cgutils_http_request_options_free(cgutils_http_request_options * options)
{
    if (options != NULL)
    {
        if (options->data_to_send != NULL)
        {
            CGUTILS_FREE(options->data_to_send);
        }

        CGUTILS_FREE(options);
    }
}

void cgutils_http_response_free(cgutils_http_response * response)
{
    if (response != NULL)
    {
        CGUTILS_FREE(response);
    }
}

char const * cgutils_http_method_to_str(cgutils_http_method const method)
{
    char const * result = NULL;

    static struct
    {
        cgutils_http_method const method;
        char const * const str;
    }
    const methods[] =
    {
#define METHOD(method) { CGUTILS_HTTP_METHOD_ ## method, #method },
#define CUSTOM_METHOD(method) { CGUTILS_HTTP_METHOD_ ## method, #method },
#include "cloudutils/cloudutils_http_methods.itm"
#undef CUSTOM_METHOD
#undef METHOD
    };

    size_t const methods_count = sizeof methods / sizeof *methods;

    assert(method < methods_count);

    if (method < methods_count)
    {
        result = methods[method].str;
    }

    return result;
}

static int cgutils_http_resume_request_internal(cgutils_http_request * const request,
                                                int const curl_type,
                                                short const event_flags)
{
    int result = 0;
    assert(request != NULL);
    request->curl_paused &= !curl_type;

    CURLcode res = curl_easy_pause(request->handler, request->curl_paused);

    if (COMPILER_LIKELY(res == CURLE_OK))
    {
        cgutils_http_event_on_socket_cb(request->sock, event_flags, request);
    }
    else
    {
        result = EIO;
        CGUTILS_ERROR("Got error code %d when trying to resume request: %d", res, result);
    }

    return result;
}

int cgutils_http_resume_request(cgutils_http_request * const request)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(request != NULL))
    {
        result = cgutils_http_resume_request_internal(request,
                                                      CURLPAUSE_CONT,
                                                      CGUTILS_EVENT_WRITE|CGUTILS_EVENT_READ);
    }

    return result;
}

int cgutils_http_resume_request_download(cgutils_http_request * const request)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(request != NULL))
    {
        result = cgutils_http_resume_request_internal(request,
                                                      !CURLPAUSE_RECV_CONT,
                                                      CGUTILS_EVENT_WRITE|CGUTILS_EVENT_READ);
    }

    return result;
}

static int cgutils_http_suspend_request_internal(cgutils_http_request * const request,
                                                 int const type)
{
    int result = 0;
    assert(request != NULL);
    request->curl_paused |= type;

    CURLcode res = curl_easy_pause(request->handler, request->curl_paused);

    if (COMPILER_UNLIKELY(res != CURLE_OK))
    {
        result = EIO;
        CGUTILS_ERROR("Got error code %d when trying to suspend request: %d", res, result);
    }

    return result;
}

int cgutils_http_suspend_request(cgutils_http_request * const request)
{
    int result = EINVAL;
    assert(request != NULL);

    if (COMPILER_LIKELY(request != NULL))
    {
        result = cgutils_http_suspend_request_internal(request, CURLPAUSE_ALL);
    }

    return result;
}

int cgutils_http_suspend_request_upload(cgutils_http_request * const request)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(request != NULL))
    {
        result = cgutils_http_suspend_request_internal(request, CURLPAUSE_SEND);
    }

    return result;
}

int cgutils_http_suspend_request_download(cgutils_http_request * const request)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(request != NULL))
    {
        result = cgutils_http_suspend_request_internal(request, CURLPAUSE_RECV);
    }

    return result;
}

int cgutils_http_set_content_length(cgutils_http_request * const request,
                                    size_t const content_length)
{
    int result = EINVAL;

    if (request != NULL)
    {
        result = 0;
        request->content_length = content_length;
        request->content_length_set = true;
        request->chunked_transfer_encoding = false;
    }

    return result;
}

int cgutils_http_set_chunked_transfer_encoding(cgutils_http_request * const request)
{
    int result = EINVAL;

    if (request != NULL)
    {
        result = 0;
        request->content_length = 0;
        request->content_length_set = false;
        request->chunked_transfer_encoding = true;
    }

    return result;
}

void cgutils_http_add_pending_io(cgutils_http_request * const request)
{
    if (COMPILER_LIKELY(request != NULL))
    {
        request->pending_io++;
    }
}

void cgutils_http_remove_pending_io(cgutils_http_request * const request)
{
    if (COMPILER_LIKELY(request != NULL))
    {
        assert(request->pending_io > 0);
        request->pending_io--;

        if (COMPILER_UNLIKELY(request->pending_io == 0 && request->finished == true))
        {
            /* If we had an AIO write request pending, the HTTP request might have been
               reported finished by CURL already. */
            cgutils_http_handle_response(request);
        }
    }
}

int cgutils_http_init(void)
{
    int result = 0;
    CURLcode const code = curl_global_init(CURL_GLOBAL_ALL);

    if (code != 0)
    {
        result = ENOMEM;
    }

    return result;
}

void cgutils_http_destroy(void)
{
    curl_global_cleanup();
}

void cgutils_http_data_free(cgutils_http_data * data)
{
    if (data != NULL)
    {
        if (data->pending_requests != NULL)
        {
            for (cgutils_llist_elt * elt = cgutils_llist_get_first(data->pending_requests);
                 elt != NULL;
                 elt = cgutils_llist_elt_get_next(elt))
            {
                cgutils_http_request * request = cgutils_llist_elt_get_object(elt);
                assert(request != NULL);
                request->in_pending = false;

                curl_multi_remove_handle(data->curl_multi,
                                         request->handler);
            }

            cgutils_llist_free(&(data->pending_requests), &cgutils_http_request_delete);
        }

        if (data->null_file != NULL)
        {
            cgutils_file_fclose(data->null_file), data->null_file = NULL;
        }

        if (data->timer_event != NULL)
        {
            cgutils_event_free(data->timer_event), data->timer_event = NULL;
        }

        if (data->curl_multi != NULL)
        {
            curl_multi_cleanup(data->curl_multi), data->curl_multi = NULL;
        }

        data->event = NULL;
        CGUTILS_FREE(data);
    }
}

void cgutils_http_request_print_infos(cgutils_http_request const * const request)
{
    if (request != NULL)
    {
        time_t const now = time(NULL);
        uint64_t const elapsed = (uint64_t) now - (uint64_t) request->start_time ;

        CGUTILS_INFO("request: %p, %s %s, CL: %zu, p. IO: %zu, sent: %zu (%zu kB/s), recv: %zu (%zu kB/s), CL set: %d, CTE: %d, paused: %d, polrd %d, polwr %d",
                     request,
                     cgutils_http_method_to_str(cgutils_http_request_get_method(request)),
                     cgutils_http_request_get_uri(request),
                     request->content_length,
                     request->pending_io,
                     request->sent_bytes,
                     elapsed > 0 ? (request->sent_bytes / 1024 / elapsed) : 0,
                     request->recv_bytes ,
                     elapsed > 0 ? (request->recv_bytes / 1024 / elapsed) : 0,
                     request->content_length_set,
                     request->chunked_transfer_encoding,
                     request->curl_paused,
                     request->event_flags & CGUTILS_EVENT_READ,
                     request->event_flags & CGUTILS_EVENT_WRITE);
    }
}

/* Kids, don't do this at home */
//extern void curl_multi_dump(CURLM const * multi_handle);

void cgutils_http_dump_state(cgutils_http_data const * const data)
{
    if (data != NULL)
    {
        /* First, we dump our pending requests */

        for (cgutils_llist_elt * elt = cgutils_llist_get_first(data->pending_requests);
             elt != NULL;
             elt = cgutils_llist_elt_get_next(elt))
        {
            cgutils_http_request * request = cgutils_llist_elt_get_object(elt);
            assert(request != NULL);

            cgutils_http_request_print_infos(request);
        }

/*        if (data->curl_multi != NULL)
        {
            curl_multi_dump(data->curl_multi);
        }*/
    }
}
