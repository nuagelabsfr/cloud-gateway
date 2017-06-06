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

#ifndef CLOUD_GATEWAY_STORAGE_PROVIDER_UTILS_H_
#define CLOUD_GATEWAY_STORAGE_PROVIDER_UTILS_H_

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cloudutils/cloudutils_aio.h>
#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_crypto.h>
#include <cloudutils/cloudutils_http.h>
#include <cloudutils/cloudutils_json_reader.h>
#include <cloudutils/cloudutils_xml_reader.h>

#include <cgsm/cg_storage_provider.h>
#include <cgsm/cg_storage_instance.h>
#include <cgsm/cg_storage_io.h>

#define CG_STP_NO_ADDITIONAL_HEADERS (NULL)
#define CG_STP_XML_RESPONSE (true)
#define CG_STP_RAW_RESPONSE (false)
#define CG_STP_NO_OPT_HTTP_CALLBACKS (NULL)
#define CG_STP_NO_OPT_HTTP_TIMEOUTS (NULL)

#define CG_STP_DEFAULT_TLS_CIPHER_SUITES "ALL!EXPORT!EXPORT40!EXPORT56!aNULL!eNULL!LOW!DES!SSLv2!SSLv3"

typedef enum
{
    CG_STP_RESPONSE_FORMAT_RAW = 0,
    CG_STP_RESPONSE_FORMAT_XML,
    CG_STP_RESPONSE_FORMAT_JSON
} cg_stp_response_format;

typedef struct cg_storage_provider_request cg_storage_provider_request;
typedef struct cg_storage_provider_request_ctx cg_storage_provider_request_ctx;

typedef struct cg_stp_funcs
{
    cg_storage_provider_capabilities capabilities;

    int (*init)(cg_storage_manager_data * global_data,
                void ** data);
    void (*destroy)(void * data);
    int (*parse_specifics)(void * provider_data,
                          cgutils_configuration * config,
                          void ** data);
    void (*clear_specifics)(void *data);
    int (*setup)(cg_storage_provider * provider,
                 void * provider_data,
                 void * instance_specifics);
    int (*create_container)(cg_storage_provider_request * request,
                            char const * container_name);
    int (*remove_empty_container)(cg_storage_provider_request * request,
                                  char const * container_name);
    int (*list_containers)(cg_storage_provider_request * request);
    int (*get_container_stats)(cg_storage_provider_request * request,
                               char const * const container);
    int (*list_files)(cg_storage_provider_request * request);
    int (*get_file)(cg_storage_provider_request * request);
    int (*put_file)(cg_storage_provider_request * request);
    int (*delete_file)(cg_storage_provider_request * request);
    int (*put_multipart_init)(cg_storage_provider_request * request);
    int (*put_multipart_part)(cg_storage_provider_request * request);
    int (*put_multipart_finish)(cg_storage_provider_request * request);
    int (*put_multipart_cancel)(cg_storage_provider_request * request);
    bool (*is_valid_response_code)(cg_storage_provider_request const * request,
                                   uint16_t code);
    int (*init_object_hash)(cg_storage_provider_request * request);
    int (*update_object_hash)(cg_storage_provider_request * request,
                              void const * data,
                              size_t data_size);
    int (*check_object_hash)(cg_storage_provider_request * request,
                             bool * valid);
    void (*all_headers_received)(cg_storage_provider_request * request);
    size_t (*get_single_upload_size)(void const * instance_specifics);
} cg_stp_vtable;

#define CG_STP_UTILS_RETRIEVE_TYPE(config, object, retriever, result, name, path, required) \
    if (result == 0)                                                    \
    {                                                                   \
        result = retriever(config, path, &(object->name));              \
        if (result == ENOENT && required == false)                      \
        {                                                               \
            result = 0;                                                 \
        }                                                               \
        else if (result != 0)                                           \
        {                                                               \
            CGUTILS_ERROR("Unable to retrieve parameter %s: %d", path, result); \
        }                                                               \
    }

#define CG_STP_UTILS_RETRIEVE_STRING(config, object, result, name, path, required) \
    CG_STP_UTILS_RETRIEVE_TYPE(config, object, cgutils_configuration_get_string, result, name, path, required)

#define CG_STP_UTILS_RETRIEVE_BOOLEAN(config, object, result, name, path, required) \
    CG_STP_UTILS_RETRIEVE_TYPE(config, object, cgutils_configuration_get_boolean, result, name, path, required)

#define CG_STP_UTILS_RETRIEVE_UINT64(config, object, result, name, path, required) \
    CG_STP_UTILS_RETRIEVE_TYPE(config, object, cgutils_configuration_get_unsigned_integer, result, name, path, required)

#define CG_STP_UTILS_RETRIEVE_SIZE(config, object, result, name, path, required) \
    CG_STP_UTILS_RETRIEVE_TYPE(config, object, cgutils_configuration_get_size, result, name, path, required)

#define CG_STP_UTILS_RETRIEVE_UINT8(config, object, result, name, path, required) \
    if (result == 0)                                                    \
    {                                                                   \
        uint64_t cg_stp_utils_value = 0;                                \
        result = cgutils_configuration_get_unsigned_integer(config, path, &cg_stp_utils_value); \
        if (result == 0)                                                \
        {                                                               \
            if (cg_stp_utils_value <= UINT8_MAX)                        \
            {                                                           \
                object->name = (uint8_t) cg_stp_utils_value;            \
            }                                                           \
            else                                                        \
            {                                                           \
                result = EINVAL;                                        \
                CGUTILS_ERROR("Invalid value for parameter %s: %d", path, result); \
            }                                                           \
        }                                                               \
        if (result == ENOENT && required == false)                      \
        {                                                               \
            result = 0;                                                 \
        }                                                               \
        else if (result != 0)                                           \
        {                                                               \
            CGUTILS_ERROR("Unable to retrieve parameter %s: %d", path, result); \
        }                                                               \
    }

typedef int (cg_storage_provider_raw_response_cb)(int status,
                                                  /* cg_storage_provider_request * */
                                                  void * cb_data);

typedef int (cg_storage_provider_xml_response_cb)(int status,
                                                  cgutils_xml_reader * reader,
                                                  /* cg_storage_provider_request * */
                                                  void * cb_data);

typedef int (cg_storage_provider_json_response_cb)(int status,
                                                   cgutils_json_reader * reader,
                                                   /* cg_storage_provider_request * */
                                                   void * cb_data);

struct cg_storage_provider_request
{
    cg_storage_provider_request_ctx * ctx;
    cgutils_http_request * request;
    cgutils_llist * received_headers;

    /* Request CB, in the specific provider */
    /* Called by cg_storage_provider_utils_http_*response_callback */
    union
    {
        cg_storage_provider_raw_response_cb * raw_request_cb;
        cg_storage_provider_xml_response_cb * xml_request_cb;
        cg_storage_provider_json_response_cb * json_request_cb;
    };

    void * request_cb_data;

    cg_storage_io_ctx * dest_io;
    cg_storage_io_ctx * source_io;

    /* Providers supporting object hashing use this context
       when transfering object. */
    cgutils_crypto_hash_context * object_hash_ctx;

    /* Request payload, should be done with source_io */
    char * payload;

    /* Multipart ETAG, for providers using it */
    char * multipart_etag;

    size_t part_number;

    /* For in-memory, unfiltered payload, used by
       cg_storage_provider_utils_payload_read_cb.
       This is necessary for in-memory payload with PUT
       requests, as libcurl only supports CURLOPT_POSTFIELDS
       for POST requests. */
    size_t payload_size;
    size_t payload_position;

    /* Whether or not to compute object.
       The provider can decide that it is not needed
       at any time, for example after receiving a specific header. */
    bool compute_object_hash;

    /* Has the end of headers callback been called */
    bool end_of_headers;
};

typedef enum
{
    cg_storage_provider_state_none = 0,
    cg_storage_provider_state_single_request = 1,
    cg_storage_provider_state_multipart_init = 2,
    cg_storage_provider_state_multipart_parts = 3,
    cg_storage_provider_state_multipart_finish = 4,
    cg_storage_provider_state_multipart_cancel = 5
} cg_storage_provider_request_state;

typedef enum
{
    cg_storage_provider_request_callback_type_none = 0,
    cg_storage_provider_request_callback_type_status,
    cg_storage_provider_request_callback_type_put,
    cg_storage_provider_request_callback_type_get,
    cg_storage_provider_request_callback_type_list,
    cg_storage_provider_request_callback_type_container_stats,
    cg_storage_provider_request_callback_type_count,
} cg_storage_provider_request_callback_type;

struct cg_storage_provider_request_ctx
{
    cg_storage_provider * provider;
    cgutils_http_data * http;

    /* cg_stp_XXXX_provider_data */
    void * provider_data;
    /* cg_stp_XXXX_specific */
    void * instance_specifics;

    /* cg_stp_XXXX_request_ctx_data */
    void * provider_request_ctx_data;

    cg_storage_io * dest_io;
    cg_storage_io * source_io;

    /* Final (external) Callback */
    union
    {
        cg_storage_instance_status_cb * final_status_cb;
        cg_storage_instance_put_status_cb * final_put_cb;
        cg_storage_instance_get_status_cb * final_get_cb;
        cg_storage_instance_list_cb * final_list_cb;
        cg_storage_instance_container_stats_cb * final_container_stats_cb;
    };

    void * final_cb_data;

    /* object key, if present, used to construct the request path */
    char * key;

    /* Metadata values, if any. list of cg_storage_provider_metadata * */
    cgutils_llist * metadata;

    /* Multipart */
    /* Multipart ID, for providers using it */
    char * multipart_id;

    cgutils_llist * parts;
    size_t part_support_size;
    size_t number_of_parts;
    size_t finished_parts;

    /* buffer for copy IO */
    char * buffer;
    size_t buffer_size;

    /* For now, only set for multipart upload before
       calling the multipart_init callback.
    */
    time_t timestamp;

    /* Store status code for multipart cancel
       or filtered requests */
    int status_code;
    cg_storage_provider_request_state state;
    cg_storage_provider_request_callback_type cb_type;
    cgutils_crypto_digest_algorithm digest_algo;
    bool has_dest_filters;
    bool compressed;
    bool encrypted;
};

#define CG_STP_UTILS_NO_SRC_IO (NULL)
#define CG_STP_UTILS_NO_DST_IO (NULL)
#define CG_STP_UTILS_NO_ID (NULL)
#define CG_STP_UTILS_NO_METADATA (NULL)
#define CG_STP_UTILS_NO_STATUS_CB (NULL)
#define CG_STP_UTILS_NO_LIST_CB (NULL)
#define CG_STP_UTILS_NO_PUT_CB (NULL)
#define CG_STP_UTILS_NO_GET_CB (NULL)
#define CG_STP_UTILS_NO_CONTAINER_STATS_CB (NULL)

COMPILER_BLOCK_VISIBILITY_DEFAULT

bool cg_storage_provider_is_valid_response_code(cg_storage_provider_request const * request,
                                                uint16_t const code);

int cg_storage_provider_single_request_init(cg_storage_provider * this,
                                            void * instance_specifics,
                                            char const * id,
                                            cg_storage_provider_request_callback_type cb_type,
                                            cg_storage_instance_status_cb * status_cb,
                                            cg_storage_instance_list_cb * list_cb,
                                            cg_storage_instance_put_status_cb * put_cb,
                                            cg_storage_instance_get_status_cb * get_cb,
                                            cg_storage_instance_container_stats_cb * container_stats_cb,
                                            void * cb_data,
                                            cg_storage_provider_request ** out);

void cg_storage_provider_request_ctx_free(cg_storage_provider_request_ctx * ctx);
void cg_storage_provider_request_free(cg_storage_provider_request * this);


int cg_storage_provider_handle_status_response(cg_storage_provider_request * request,
                                               int status);

int cg_storage_provider_handle_list_response(cg_storage_provider_request * request,
                                             int status,
                                             cgutils_llist * list);

int cg_storage_provider_handle_container_stats_response(cg_storage_provider_request * request,
                                                        int status,
                                                        cg_storage_instance_container_stats const * stats);

int cg_storage_provider_update_object_hash(cg_storage_provider_request * request,
                                           void const * data,
                                           size_t data_size);

int cg_storage_provider_check_object_hash(cg_storage_provider_request * request);

void cg_storage_provider_notify_end_of_headers(cg_storage_provider_request * request);

int cg_storage_provider_utils_http_xml_response_callback(cgutils_http_data * http_data,
                                                         cgutils_http_request * request,
                                                         cgutils_http_response * response,
                                                         void * cb_data);

int cg_storage_provider_utils_http_json_response_callback(cgutils_http_data * http_data,
                                                          cgutils_http_request * request,
                                                          cgutils_http_response * response,
                                                          void * cb_data);

int cg_storage_provider_utils_http_raw_response_callback(cgutils_http_data * http_data,
                                                         cgutils_http_request * request,
                                                         cgutils_http_response * response,
                                                         void * cb_data);

int cg_storage_provider_utils_write_cb(cgutils_http_data * http_data,
                                       cgutils_http_request * request,
                                       void * ptr,
                                       size_t data_size,
                                       void * cb_data);

/* In-memory payload stored in the payload field, for PUT requests. */
int cg_storage_provider_utils_payload_read_cb(cgutils_http_data * http_data,
                                              cgutils_http_request * request,
                                              void * ptr,
                                              size_t ptr_size,
                                              size_t * written,
                                              bool * eof,
                                              void * cb_data);

int cg_storage_provider_utils_read_cb(cgutils_http_data * http_data,
                                      cgutils_http_request * request,
                                      void * ptr,
                                      size_t ptr_size,
                                      size_t * written,
                                      bool * eof,
                                      void * cb_data);

int cg_storage_provider_utils_header_cb(cgutils_http_data * http_data,
                                        cgutils_http_request * request,
                                        void * ptr,
                                        size_t size,
                                        void * cb_data);

int cg_storage_provider_utils_get_normalized_header_value(cgutils_llist * headers,
                                                          char const * header_name,
                                                          char ** normalized_value,
                                                          size_t * normalized_value_len);

int cg_storage_provider_utils_add_header_from_meta(cg_storage_provider_request * request,
                                                   char const * meta_data_key,
                                                   char const * header_name,
                                                   cgutils_llist * headers);

int cg_storage_provider_utils_io_copy(cg_storage_provider_request * request);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_GATEWAY_STORAGE_PROVIDER_UTILS_H_ */
