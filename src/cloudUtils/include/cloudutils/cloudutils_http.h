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

#ifndef CLOUD_UTILS_HTTP_H_H
#define CLOUD_UTILS_HTTP_H_H

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_event.h>

typedef struct cgutils_http_data cgutils_http_data;
typedef struct cgutils_http_request cgutils_http_request;
typedef struct cgutils_http_response cgutils_http_response;

typedef struct cgutils_http_global_params
{
    char * ca_bundle_file;
    char * ca_bundle_path;
    size_t connections_cache_size;
    size_t max_connections_by_host;
    size_t max_concurrent_connections;
} cgutils_http_global_params;

typedef struct cgutils_http_header
{
    char * name;
    char * value;
} cgutils_http_header;

typedef enum
{
#define METHOD(method) CGUTILS_HTTP_METHOD_ ## method,
#define CUSTOM_METHOD(method) CGUTILS_HTTP_METHOD_ ## method,
#include "cloudutils/cloudutils_http_methods.itm"
#undef CUSTOM_METHOD
#undef METHOD
} cgutils_http_method;

typedef struct cgutils_http_timeouts
{
    /* timeout in s */
    long timeout;
} cgutils_http_timeouts;

typedef struct cgutils_http_request_options
{
    char const * username;
    char const * password;
    char const * user_agent;
    char const * ssl_ciphers;
    char const * ssl_client_certificate_file;
    char const * ssl_client_certificate_key_file;
    char const * ssl_client_certificate_key_password;
    void * data_to_send;
    size_t data_to_send_size;
    /* in bytes per second, 0 means unlimited */
    uint64_t max_upload_speed;
    /* in bytes per second, 0 means unlimited */
    uint64_t max_download_speed;
    /* in bytes per second, 0 means disabled */
    uint64_t low_speed_limit;
    /* in seconds, 0 means disabled */
    uint64_t low_speed_time;
    bool ssl_no_verify_peer;
    bool ssl_no_verify_host;
    bool authentication;
    bool verbose;
    bool print_requests;
    bool disable_100_continue;
    bool disable_fast_open;
} cgutils_http_request_options;

typedef struct cgutils_http_callbacks
{
    int (*response_cb)(cgutils_http_data * http_data,
                       cgutils_http_request * request,
                       cgutils_http_response * response,
                       void * cb_data);
    int (*read_cb)(cgutils_http_data * http_data,
                   cgutils_http_request * request,
                   void * ptr,
                   size_t data_size,
                   size_t * written,
                   bool * eof,
                   void * cb_data);
    int (*write_cb)(cgutils_http_data * http_data,
                    cgutils_http_request * request,
                    void * ptr,
                    size_t data_size,
                    void * cb_data);
    int (*header_cb)(cgutils_http_data * http_data,
                     cgutils_http_request * request,
                     void * ptr,
                     size_t data_size,
                     void * cb_data);
} cgutils_http_callbacks;

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_http_init(void);
void cgutils_http_destroy(void);

int cgutils_http_data_init(cgutils_event_data * event,
                           /* optional parameters */
                           cgutils_http_global_params const * params,
                           cgutils_http_data ** data);
void cgutils_http_data_free(cgutils_http_data * data);

int cgutils_http_request_init(cgutils_http_data * data,
                              char const * uri,
                              cgutils_http_method method,
                              /* llist of cgutils_http_header */
                              cgutils_llist * headers,
                              cgutils_http_callbacks const * callbacks,
                              cgutils_http_timeouts const * timeouts,
                              cgutils_http_request_options const * options,
                              void * cb_data,
                              cgutils_http_request ** request);

cgutils_http_method cgutils_http_request_get_method(cgutils_http_request const * request) COMPILER_PURE_FUNCTION;
char const * cgutils_http_request_get_uri(cgutils_http_request const * request) COMPILER_PURE_FUNCTION;
char const * cgutils_http_request_get_error_buffer(cgutils_http_request const * request);

void cgutils_http_request_free(cgutils_http_request * request);

int cgutils_http_send(cgutils_http_request * request);

uint16_t cgutils_http_response_get_status(cgutils_http_response const * response) COMPILER_PURE_FUNCTION;
uint16_t cgutils_http_response_get_error(cgutils_http_response const * response) COMPILER_PURE_FUNCTION;
char const * cgutils_http_response_get_error_str(cgutils_http_response const * response) COMPILER_PURE_FUNCTION;
cgutils_llist * cgutils_http_response_get_headers(cgutils_http_response const * response);
void const * cgutils_http_response_get_data(cgutils_http_response const * response);
size_t cgutils_http_response_get_data_size(cgutils_http_response const * response);
double cgutils_http_response_total_time(cgutils_http_response const * response) COMPILER_PURE_FUNCTION;
double cgutils_http_response_namelookup_time(cgutils_http_response const * response) COMPILER_PURE_FUNCTION;
double cgutils_http_response_connect_time(cgutils_http_response const * response) COMPILER_PURE_FUNCTION;

void cgutils_http_response_free(cgutils_http_response * response);

int cgutils_http_header_init(char const * name,
                             char const * value,
                             cgutils_http_header ** out);
int cgutils_http_header_consume_init(char const * name,
                                     char * value,
                                     cgutils_http_header ** out);
int cgutils_http_add_header_to_list(cgutils_llist * headers,
                                    char const * name,
                                    char * value);

int cgutils_http_add_header_to_list_dup(cgutils_llist * headers,
                                        char const * name,
                                        char const * value);

int cgutils_http_get_header_by_name(cgutils_llist * headers,
                                    char const * name,
                                    cgutils_http_header const ** header);
void cgutils_http_header_free(cgutils_http_header * header);
static inline void cgutils_http_header_delete(void * header)
{
    cgutils_http_header_free(header);
}

void cgutils_http_request_options_free(cgutils_http_request_options * options);

char const * cgutils_http_method_to_str(cgutils_http_method method) COMPILER_CONST_FUNCTION;

int cgutils_http_set_content_length(cgutils_http_request * request,
                                    size_t content_length);
int cgutils_http_set_chunked_transfer_encoding(cgutils_http_request * request);

int cgutils_http_resume_request(cgutils_http_request * request);
int cgutils_http_resume_request_download(cgutils_http_request * const request);
int cgutils_http_suspend_request(cgutils_http_request * request);
int cgutils_http_suspend_request_upload(cgutils_http_request * request);
int cgutils_http_suspend_request_download(cgutils_http_request * request);

void cgutils_http_add_pending_io(cgutils_http_request * request);
void cgutils_http_remove_pending_io(cgutils_http_request * request);

void cgutils_http_request_print_infos(cgutils_http_request const * const request);
void cgutils_http_dump_state(cgutils_http_data const * data);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_HTTP_H_H */
