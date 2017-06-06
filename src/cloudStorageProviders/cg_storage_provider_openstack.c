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
#include <inttypes.h>
#include <time.h>


#include <cloudutils/cloudutils_crypto.h>
#include <cloudutils/cloudutils_encoding.h>
#include <cloudutils/cloudutils_xml_reader.h>

#include "cg_storage_provider_openstack_common.h"
#include "cg_storage_provider_openstack_auth.h"

/* General concepts:

   - Authentication is done against the Authentication Endpoint found in the configuration,
   with the credentials obtained in the same way. The exact authentication process depends on the
   version of the identity API used, but anyway we should get a token valid for a certain period
   and a final endpoint, which may differ from the Authentication one.

   - All subsequent requests are done in a form like this one:

   /<api version>/<account>/(<container>/(<object id>(<format>)?)?)?

   The Openstack API being what it is, the /<api version>/<account> is already present
   in the endpoint we retrieve from the authentication phase.

   Most of the operations use the container name, obtained from the configuration, except
   obviously the list_containers() one.

   Operations on objects (get, put, delete) uses the object id.

   Some operations support a format parameter in order to specify in which format
   we want to receive the response. Currently, we always use the XML one
   (look for CG_STP_OPENSTACK_XML_SUFFIX).

   - For segmented uploads, we need a way to be able to know the exact name of all
   segments used by the final object, as a delete on the final object does not delete
   the individual parts (aka segments).

   In order to do this, we add two special headers called CG_STP_OPENSTACK_MANIFEST_HEADER and
   CG_STP_OPENSTACK_MULTIPART_NUMBER_OF_PARTS to the final object.
   The first one, CG_STP_OPENSTACK_MANIFEST_HEADER, contains the common part of the name of all segments,
   while the second one, CG_STP_OPENSTACK_MULTIPART_NUMBER_OF_PARTS, contains the number of parts
   used for this object.

   For an object named <object id> composed of NNNN parts and uploaded at instant <timestamp>,
   the full path of the object is:
   /<api version>/<account>/<container>/<object id>

   The CG_STP_OPENSTACK_MULTIPART_NUMBER_OF_PARTS header value is: NNN
   The CG_STP_OPENSTACK_MANIFEST_HEADER value is: <container>/<object id>CG_STP_OPENSTACK_SEGMENT_KEYWORD<timestamp>

   The full path of the segment number XX is then: <container>/<object id>CG_STP_OPENSTACK_SEGMENT_KEYWORD<timestamp>-0XX

*/


typedef int (cg_stp_openstack_cb)(cg_storage_provider_request * pv_request);

typedef struct
{
    /* Raw request CB, the one that needs to be called after
       deleting the remaining segments, which happen when :
        - we overwrite a previous segmented objects, we then
        need to delete the previous segments
        - a segmented upload fails, we then need to delete
        the already uploaded new segments.
    */
    cg_storage_provider_raw_response_cb * initial_request_cb;

    /* Internal function to call after retrieving and parsing the manifest,
       if needed.
       For now this can be:
       - cg_stp_openstack_real_put_file
       - cg_stp_openstal_real_delete_file
       - NULL, obviously.
    */
    cg_stp_openstack_cb * next_cb;

    /* Some informations to be able to restore
       the initial request in case of simple PUT
       operation. Not used in case of multipart_init. */
    cg_storage_io * ctx_dest_io;
    cg_storage_io_ctx * request_dest_io;

    /* We retrieve these information before updating
       multipart segments, or deleting the manifest
       of an existing segmented object.
       It allows us to delete the remaining
       segments of the previous version afterward. */
    char * previous_radical;
    size_t remaining_segments;
    size_t total_segments_count;

    /* Status of the command, before trying to remove
       remaining segments if any. */
    int status;
} cg_stp_openstack_request_ctx_data;


#define CG_STP_OPENSTACK_USE_XML_FORMAT (true)
#define CG_STP_OPENSTACK_USE_RAW_FORMAT (false)
#define CG_STP_OPENSTACK_ADD_LEADING_SLASH (true)
#define CG_STP_OPENSTACK_NO_LEADING_SLASH (false)
#define CG_STP_OPENSTACK_NO_DATA (NULL)
#define CG_STP_OPENSTACK_NO_DATA_SIZE (0)
#define CG_STP_OPENSTACK_DEFAULT_HTTP_TIMEOUT (0)

#define CG_STP_OPENSTACK_XML_SUFFIX "?format=xml"

#define CG_STP_OPENSTACK_MANIFEST_HEADER "X-Object-Manifest"
#define CG_STP_OPENSTACK_MULTIPART_NUMBER_OF_PARTS "X-Object-Meta-CG-NumberOfParts"
#define CG_STP_OPENSTACK_SEGMENT_KEYWORD "-segment-"

#define CG_STP_OPENSTACK_OBJECT_HASH_ALGO (cgutils_crypto_digest_algorithm_md5)
#define CG_STP_OPENSTACK_OBJECT_HASH_ALGO_LEN ((size_t) 32)

#define CG_STP_OPENSTACK_MAGIC_HEADER_NAME_ETAG "Etag"

/* Openstack is (by default) limiting PUT request to 5 GB,
   requiring the use of multi-part object otherwise */
#define CG_STP_OPENSTACK_MAX_PART_SIZE ((size_t) 5 * 1024 * 1024 * 1024)
#define CG_STP_OPENSTACK_MIN_PART_SIZE ((size_t) 4 * 1024 * 1024)
/*
   We use an inferior value here because parallel uploads
   make sense for large file anyway */
#define CG_STP_OPENSTACK_MAX_SIMPLE_UP_FILE_SIZE_DEFAULT ((size_t) 1 * 1024 * 1024 * 1024)
COMPILER_STATIC_ASSERT(CG_STP_OPENSTACK_MAX_SIMPLE_UP_FILE_SIZE_DEFAULT <= CG_STP_OPENSTACK_MAX_PART_SIZE,
                       "We should split file in parts way before the maximum single part authorized size");

//#define CG_STP_OPENSTACK_MAX_SEGMENTS_NUMBER ((size_t) 1000000000)

/* Original object name */
#define CG_STP_OPENSTACK_METADATA_HEADER_FILENAME "X-Object-Meta-CG-Name"

/* Default config values */
#define CG_STP_OPENSTACK_REFRESH_AUTH_DELAY (6 * 60 * 60)
#define CG_STP_OPENSTACK_AUTH_TOKEN_RECENT_DELAY (60)

#define CG_STP_OPENSTACK_NO_AUTH_ERROR (EACCES)

#define CG_STP_OPENSTACK_DEFAULT_USER_AGENT "CloudGateway (https://www.nuagelabs.fr)"

static int cg_stp_openstack_init(cg_storage_manager_data * const global_data,
                                 void ** const data)
{
    int result = EINVAL;

    if (global_data != NULL && data != NULL)
    {
        cg_stp_openstack_provider_data * pvd = NULL;
        CGUTILS_ALLOCATE_STRUCT(pvd);

        if (pvd != NULL)
        {
            pvd->http = cg_storage_manager_data_get_http(global_data);
            pvd->event_data = cg_storage_manager_data_get_event(global_data);
            pvd->data = global_data;
            result = 0;
            *data = pvd;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

static void cg_stp_openstack_destroy(void * data)
{
    if (data != NULL)
    {
        CGUTILS_FREE(data);
    }
}

static void cg_stp_openstack_clear_specifics(void * data)
{
    if (data != NULL)
    {
        cg_stp_openstack_specifics * obj = data;

#define STRING_PARAM(name, path, required) CGUTILS_FREE(obj->name);
#define UINT8_PARAM(name, path, required) obj->name = 0;
#define UINT64_PARAM(name, path, required) obj->name = 0;
#define SIZE_PARAM(name, path, required) obj->name = 0;
#define BOOLEAN_PARAM(name, path, required)
#include "cg_storage_provider_openstack_parameters.itm"
#undef BOOLEAN_PARAM
#undef SIZE_PARAM
#undef UINT64_PARAM
#undef UINT8_PARAM
#undef STRING_PARAM

        if (obj->auth_timer != NULL)
        {
            cgutils_event_free(obj->auth_timer), obj->auth_timer = NULL;
        }

        CGUTILS_FREE(obj->auth_token);
        CGUTILS_FREE(obj->timer_data);
        CGUTILS_FREE(obj->endpoint);

        CGUTILS_FREE(obj);
    }
}

static void cg_stp_openstack_request_ctx_data_free(cg_stp_openstack_request_ctx_data * this)
{
    if (this != NULL)
    {
        if (this->previous_radical != NULL)
        {
            CGUTILS_FREE(this->previous_radical);
        }

        CGUTILS_FREE(this);
    }
}

static void cg_stp_openstack_auth_timer_cb(void * data)
{
    assert(data != NULL);
    cg_stp_openstack_timer_data * const timer_data = data;

    cg_stp_openstack_auth_refresh(timer_data->pvd,
                                  timer_data->specifics);
}

static int cg_stp_openstack_prepare_request(cg_storage_provider_request * const pv_request,
                                            char const * const host,
                                            cgutils_http_method const method,
                                            char const * const path,
                                            cgutils_llist * additional_headers,
                                            char * const data,
                                            size_t const data_size,
                                            cg_stp_response_format const response_format,
                                            cgutils_http_callbacks const * const op_http_cb,
                                            cgutils_http_timeouts const * const op_http_timeouts,
                                            cgutils_http_request ** const request)
{
    assert(pv_request != NULL);
    cg_stp_openstack_specifics const * const specifics = pv_request->ctx->instance_specifics;
    cgutils_http_data * const http = pv_request->ctx->http;
    assert(specifics != NULL);
    assert(host != NULL);
    assert(path != NULL);
    assert(request != NULL);

    int result = 0;

    if (additional_headers == NULL)
    {
        result = cgutils_llist_create(&additional_headers);

        if (result != 0)
        {
            CGUTILS_ERROR("Error creating headers: %d", result);
        }
    }

    if (result == 0)
    {
        result = cg_stp_openstack_auth_add(pv_request,
                                           specifics,
                                           additional_headers);
        if (result == 0)
        {
            size_t const path_len = strlen(path);
            size_t const host_len = strlen(host);
            size_t uri_len = host_len + path_len;
            char * uri = NULL;
            bool add_leading_slash = false;

            if (*path != '/')
            {
                /* No leading slash on the path, add one. */
                add_leading_slash = true;
                uri_len++;
            }

            CGUTILS_MALLOC(uri, uri_len + 1, 1);

            if (uri != NULL)
            {
                uri_len = 0;

                memcpy(uri + uri_len, host, host_len);
                uri_len += host_len;

                if (add_leading_slash == true)
                {
                    uri[uri_len] = '/';
                    uri_len++;
                }

                memcpy(uri + uri_len, path, path_len);
                uri_len += path_len;
                uri[uri_len] = '\0';

                cgutils_http_callbacks const cbs = {
                    .response_cb = response_format == CG_STP_RESPONSE_FORMAT_RAW ?
                    &cg_storage_provider_utils_http_raw_response_callback :
                    (response_format == CG_STP_RESPONSE_FORMAT_XML ?
                     &cg_storage_provider_utils_http_xml_response_callback :
                     &cg_storage_provider_utils_http_json_response_callback),
                    .write_cb = &cg_storage_provider_utils_write_cb,
                    .header_cb = &cg_storage_provider_utils_header_cb,
                };
                cgutils_http_request_options const options = {
                    .verbose = specifics->verbose,
                    .print_requests = specifics->show_http_requests,
                    .disable_100_continue = specifics->disable_100_continue,
                    .disable_fast_open = specifics->disable_fast_open,
                    .data_to_send = data,
                    .data_to_send_size = data_size,
                    .ssl_no_verify_peer = specifics->allow_insecure_https,
                    .ssl_no_verify_host = specifics->allow_insecure_https,
                    .ssl_ciphers = specifics->ssl_ciphers,
                    .ssl_client_certificate_file = specifics->ssl_client_certificate_file,
                    .ssl_client_certificate_key_file = specifics->ssl_client_certificate_key_file,
                    .ssl_client_certificate_key_password = specifics->ssl_client_certificate_key_password,
                    .max_upload_speed = specifics->max_upload_speed,
                    .max_download_speed = specifics->max_download_speed,
                    .low_speed_limit = specifics->low_speed_limit,
                    .low_speed_time = specifics->low_speed_time,
                    .user_agent = specifics->http_user_agent ?: CG_STP_OPENSTACK_DEFAULT_USER_AGENT,
                };
                cgutils_http_timeouts const timeouts = { (long) specifics->http_timeout };

                result = cgutils_http_request_init(http,
                                                   uri,
                                                   method,
                                                   additional_headers,
                                                   op_http_cb != NULL ? op_http_cb : &cbs,
                                                   op_http_timeouts != NULL ? op_http_timeouts : &timeouts,
                                                   &options,
                                                   pv_request,
                                                   request);

                if (result == 0)
                {
                    pv_request->request = *request;
                }
                else
                {
                    CGUTILS_ERROR("Error creating request: %d", result);
                }

                CGUTILS_FREE(uri);
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Unable to allocate memory for uri: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error adding authorization to headers list: %d", result);
        }
    }

    if (result != 0 && additional_headers != NULL)
    {
        cgutils_llist_free(&additional_headers, &cgutils_http_header_delete);
    }

    return result;
}

int cg_stp_openstack_send_get_request(cg_storage_provider_request * const pv_request,
                                      char const * const host,
                                      char const * const path,
                                      cgutils_llist * additional_headers,
                                      cg_stp_response_format const response_format,
                                      cgutils_http_callbacks const * const op_http_cb,
                                      cgutils_http_timeouts const * const op_http_timeouts)
{
    assert(pv_request != NULL);
    assert(host != NULL);
    assert(path != NULL);

    cgutils_http_request * request = NULL;

    int result = cg_stp_openstack_prepare_request(pv_request,
                                                  host,
                                                  CGUTILS_HTTP_METHOD_GET,
                                                  path,
                                                  additional_headers,
                                                  CG_STP_OPENSTACK_NO_DATA,
                                                  CG_STP_OPENSTACK_NO_DATA_SIZE,
                                                  response_format,
                                                  op_http_cb,
                                                  op_http_timeouts,
                                                  &request);

    if (result == 0)
    {
        result = cgutils_http_send(request);

        if (result != 0)
        {
            CGUTILS_ERROR("Error sending request: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error preparing request: %d", result);
    }

    return result;
}

static int cg_stp_openstack_send_head_request(cg_storage_provider_request * const pv_request,
                                              char const * const host,
                                              char const * const path,
                                              cgutils_llist * additional_headers,
                                              cg_stp_response_format const response_format,
                                              cgutils_http_callbacks const * const op_http_cb,
                                              cgutils_http_timeouts const * const op_http_timeouts)
{
    assert(pv_request != NULL);
    assert(path != NULL);


    cgutils_http_request * request = NULL;

    int result = cg_stp_openstack_prepare_request(pv_request,
                                                  host,
                                                  CGUTILS_HTTP_METHOD_HEAD,
                                                  path,
                                                  additional_headers,
                                                  CG_STP_OPENSTACK_NO_DATA,
                                                  CG_STP_OPENSTACK_NO_DATA_SIZE,
                                                  response_format,
                                                  op_http_cb,
                                                  op_http_timeouts,
                                                  &request);

    if (result == 0)
    {
        result = cgutils_http_send(request);

        if (result != 0)
        {
            CGUTILS_ERROR("Error sending request: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error preparing request: %d", result);
    }

    return result;
}

static int cg_stp_openstack_send_delete_request(cg_storage_provider_request * const pv_request,
                                                char const * const path,
                                                cgutils_llist * additional_headers,
                                                cg_stp_response_format const response_format,
                                                cgutils_http_callbacks const * const op_http_cb,
                                                cgutils_http_timeouts const * const op_http_timeouts)
{
    assert(pv_request != NULL);
    assert(path != NULL);

    cgutils_http_request * request = NULL;
    cg_stp_openstack_specifics * const specifics = pv_request->ctx->instance_specifics;

    int result = cg_stp_openstack_prepare_request(pv_request,
                                                  specifics->endpoint,
                                                  CGUTILS_HTTP_METHOD_DELETE,
                                                  path,
                                                  additional_headers,
                                                  CG_STP_OPENSTACK_NO_DATA,
                                                  CG_STP_OPENSTACK_NO_DATA_SIZE,
                                                  response_format,
                                                  op_http_cb,
                                                  op_http_timeouts,
                                                  &request);

    if (result == 0)
    {
        result = cgutils_http_send(request);

        if (result != 0)
        {
            CGUTILS_ERROR("Error sending request: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error preparing request: %d", result);
    }

    return result;
}

int cg_stp_openstack_send_post_request(cg_storage_provider_request * const pv_request,
                                       char const * const host,
                                       char const * const path,
                                       cgutils_llist * additional_headers,
                                       char * const data,
                                       size_t const data_size,
                                       cg_stp_response_format const response_format,
                                       cgutils_http_callbacks const * const op_http_cb,
                                       cgutils_http_timeouts const * const op_http_timeouts,
                                       bool const chunked_transfer)
{
    cgutils_http_request * request = NULL;

    int result = cg_stp_openstack_prepare_request(pv_request,
                                                  host,
                                                  CGUTILS_HTTP_METHOD_POST,
                                                  path,
                                                  additional_headers,
                                                  data,
                                                  data_size,
                                                  response_format,
                                                  op_http_cb,
                                                  op_http_timeouts,
                                                  &request);

    if (result == 0)
    {
        if (chunked_transfer == CG_STP_OPENSTACK_OPT_HTTP_CHUNKED_TRANSFER)
        {
            result = cgutils_http_set_chunked_transfer_encoding(request);
        }

        if (result == 0)
        {
            result = cgutils_http_send(request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending request: %d", result);
            }
        }
        else
        {
            cgutils_http_request_free(request), request = NULL;
            CGUTILS_ERROR("Error setting content length: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error preparing request: %d", result);
    }

    return result;
}

static int cg_stp_openstack_send_put_request(cg_storage_provider_request * const pv_request,
                                             char const * const path,
                                             cgutils_llist * additional_headers,
                                             cg_stp_response_format const response_format,
                                             cgutils_http_callbacks const * const op_http_cb,
                                             cgutils_http_timeouts const * const op_http_timeouts)
{
    cgutils_http_request * request = NULL;
    cg_stp_openstack_specifics * const specifics = pv_request->ctx->instance_specifics;

    int result = cg_stp_openstack_prepare_request(pv_request,
                                                  specifics->endpoint,
                                                  CGUTILS_HTTP_METHOD_PUT,
                                                  path,
                                                  additional_headers,
                                                  CG_STP_OPENSTACK_NO_DATA,
                                                  CG_STP_OPENSTACK_NO_DATA_SIZE,
                                                  response_format,
                                                  op_http_cb,
                                                  op_http_timeouts,
                                                  &request);

    if (result == 0)
    {
        result = cgutils_http_set_chunked_transfer_encoding(request);

        if (result == 0)
        {
            result = cgutils_http_send(request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending request: %d", result);
            }
        }
        else
        {
            cgutils_http_request_free(request), request = NULL;
            CGUTILS_ERROR("Error setting content length: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error preparing request: %d", result);
    }

    return result;
}

static int cg_stp_openstack_send_empty_put_request(cg_storage_provider_request * const pv_request,
                                                   char const * const path,
                                                   cgutils_llist * additional_headers,
                                                   cg_stp_response_format const response_format,
                                                   cgutils_http_callbacks const * const op_http_cb,
                                                   cgutils_http_timeouts const * const op_http_timeouts)
{
    cgutils_http_request * request = NULL;
    cg_stp_openstack_specifics * const specifics = pv_request->ctx->instance_specifics;

    int result = cg_stp_openstack_prepare_request(pv_request,
                                                  specifics->endpoint,
                                                  CGUTILS_HTTP_METHOD_PUT,
                                                  path,
                                                  additional_headers,
                                                  CG_STP_OPENSTACK_NO_DATA,
                                                  CG_STP_OPENSTACK_NO_DATA_SIZE,
                                                  response_format,
                                                  op_http_cb,
                                                  op_http_timeouts,
                                                  &request);

    if (result == 0)
    {
        result = cgutils_http_set_content_length(request, 0);

        if (result == 0)
        {
            result = cgutils_http_send(request);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending request: %d", result);
            }
        }
        else
        {
            cgutils_http_request_free(request), request = NULL;
            CGUTILS_ERROR("Error setting content length: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error preparing request: %d", result);
    }

    return result;
}


static int cg_stp_openstack_construct_path(bool const xml_format,
                                           bool const add_leading_slash,
                                           char const * const container,
                                           char const * const object,
                                           char ** const path)
{
    int result = 0;

    /* Syntax is /<api version>/<account>/<container>/<object>?format=xml

       But the /<api version>/<account> is already handled in the endpoint
     */

    /* We have a leading / anyway */
    size_t path_len = add_leading_slash ? 1 : 0;
    size_t container_len = 0;
    size_t object_len = 0;
    size_t xml_format_len = 0;

    if (container != NULL)
    {
        container_len = strlen(container);
        /* container + trailing / */
        path_len += container_len + 1;

        if (object != NULL)
        {
            /* object */
            object_len = strlen(object);
            path_len += object_len;
        }
    }

    if (xml_format == true)
    {
        xml_format_len = sizeof CG_STP_OPENSTACK_XML_SUFFIX - 1;

        path_len += xml_format_len;
    }

    CGUTILS_MALLOC(*path, path_len + 1, 1);

    if (*path != NULL)
    {
        char * dest = *path;

        if (add_leading_slash == true)
        {
            *dest = '/';
            dest++;
        }

        if (container_len > 0)
        {
            CGUTILS_ASSERT(container != NULL);

            memcpy(dest, container, container_len);
            dest += container_len;
            *dest = '/';
            dest++;

            if (object_len > 0 &&
                object != NULL)
            {
                CGUTILS_ASSERT(object != NULL);

                memcpy(dest, object, object_len);
                dest += object_len;
            }
        }

        if (xml_format_len > 0)
        {
            memcpy(dest, CG_STP_OPENSTACK_XML_SUFFIX, xml_format_len);
            dest += xml_format_len;
        }

        *dest = '\0';
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static void cg_stp_openstack_clean_request(cg_storage_provider_request * const request)
{
    assert(request != NULL);

    if (request->received_headers != NULL)
    {
        cgutils_llist_free(&(request->received_headers), &cgutils_http_header_delete);
    }

    if (request->dest_io != NULL)
    {
        cg_storage_io_ctx_free(request->dest_io);
    }
}

static int cg_stp_openstack_get_segment_path_from_radical(char const * const radical,
                                                          size_t const segment_number,
                                                          size_t const total_segments_count,
                                                          char ** const out)
{
    int result = 0;
    assert(radical != NULL);
    assert(segment_number > 0);
    assert(total_segments_count > 0);
    assert(segment_number <= total_segments_count);
    assert(out != NULL);

    size_t const alignment = cgutils_get_next_log10(total_segments_count);

    if (alignment <= INT_MAX)
    {
        result = cgutils_asprintf(out, "%s-%.*zu",
                                  radical,
                                  (int) alignment,
                                  segment_number);

        if (result != 0)
        {
            CGUTILS_ERROR("Error allocating memory for segment path: %d", result);
        }
    }
    else
    {
        result = E2BIG;
        CGUTILS_ERROR("Invalid number of segments: %d", result);
    }

    return result;
}

static int cg_stp_openstack_delete_one_segment(cg_storage_provider_request * const request,
                                               cg_stp_openstack_request_ctx_data * const ctx_data)
{
    int result = 0;
    char * path = NULL;

    assert(request != NULL);
    assert(ctx_data != NULL);

    assert(ctx_data->previous_radical != NULL);

    result = cg_stp_openstack_get_segment_path_from_radical(ctx_data->previous_radical,
                                                            ctx_data->remaining_segments,
                                                            ctx_data->total_segments_count,
                                                            &path);

    if (result == 0)
    {
        cgutils_http_callbacks const http_cbs = {
            .response_cb = &cg_storage_provider_utils_http_raw_response_callback,
            .header_cb = &cg_storage_provider_utils_header_cb,
        };

        result = cg_stp_openstack_send_delete_request(request,
                                                      path,
                                                      CG_STP_NO_ADDITIONAL_HEADERS,
                                                      CG_STP_RAW_RESPONSE,
                                                      &http_cbs,
                                                      CG_STP_NO_OPT_HTTP_TIMEOUTS);

        if (result != 0)
        {
            CGUTILS_ERROR("Error sending request: %d", result);
        }

        CGUTILS_FREE(path);
    }
    else
    {
        CGUTILS_ERROR("Error creating request path: %d", result);
    }

    return result;
}

static int cg_stp_openstack_remaining_segment_deleted(int const status,
                                                      void * const cb_data)
{
    int result = 0;
    cg_storage_provider_request * request = cb_data;
    assert(request != NULL);
    assert(request->ctx != NULL);
    assert(request->ctx->provider_request_ctx_data != NULL);
    cg_stp_openstack_request_ctx_data * ctx_data = request->ctx->provider_request_ctx_data;
    assert(ctx_data->remaining_segments > 0);

    if (status != 0)
    {
        CGUTILS_WARN("Error deleting remaining segment %zu: %d",
                     ctx_data->remaining_segments,
                     status);
    }

    ctx_data->remaining_segments--;

    if (ctx_data->remaining_segments > 0)
    {
        cg_stp_openstack_clean_request(request);

        result = cg_stp_openstack_delete_one_segment(request, ctx_data);
    }

    if (result != 0 || ctx_data->remaining_segments == 0)
    {
        int old_status = ctx_data->status;
        request->raw_request_cb = ctx_data->initial_request_cb;

        cg_stp_openstack_request_ctx_data_free(request->ctx->provider_request_ctx_data);
        request->ctx->provider_request_ctx_data = NULL;

        cg_storage_provider_handle_status_response(request, old_status);
    }

    return result;
}

static void cg_stp_openstack_delete_remaining_segments(cg_storage_provider_request * const request,
                                                       bool const set_status,
                                                       int const status)
{
    bool waiting = false;

    assert(request != NULL);
    assert(request->ctx != NULL);

    if (request->ctx->provider_request_ctx_data != NULL)
    {
        cg_stp_openstack_request_ctx_data * ctx_data = request->ctx->provider_request_ctx_data;

        if (ctx_data->remaining_segments > 0)
        {
            cg_stp_openstack_clean_request(request);

            if (set_status == true)
            {
                ctx_data->status = status;
            }

            ctx_data->initial_request_cb = request->raw_request_cb;

            request->raw_request_cb = &cg_stp_openstack_remaining_segment_deleted;

            int result = cg_stp_openstack_delete_one_segment(request, ctx_data);

            if (result == 0)
            {
                waiting = true;
            }
            else
            {
                request->raw_request_cb = ctx_data->initial_request_cb;
            }
        }
    }

    if (waiting == false)
    {
        cg_stp_openstack_request_ctx_data_free(request->ctx->provider_request_ctx_data);
        request->ctx->provider_request_ctx_data = NULL;
        cg_storage_provider_handle_status_response(request, status);
    }
}

static int cg_stp_openstack_add_manifest_number_of_parts_header(cg_storage_provider_request const * const pv_request,
                                                                cgutils_llist * const headers)
{
    assert(pv_request != NULL);
    assert(headers != NULL);

    char * parts_number_str = NULL;

    int result = cgutils_asprintf(&parts_number_str,
                                  "%"PRIu64,
                                  pv_request->ctx->number_of_parts);

    if (result == 0)
    {
        result = cgutils_http_add_header_to_list(headers,
                                                 CG_STP_OPENSTACK_MULTIPART_NUMBER_OF_PARTS,
                                                 parts_number_str);

        if (result != 0)
        {
            CGUTILS_ERROR("Error adding header: %d", result);
            CGUTILS_FREE(parts_number_str);
        }
    }

    return result;
}

COMPILER_STATIC_ASSERT(sizeof (time_t) <= sizeof (int64_t),
                       "The size of a time_t should be inferior or equal to the size of a int64_t");

static int cg_stp_openstack_get_segment_object_radical(char const * const object,
                                                       time_t const timestamp,
                                                       char ** const radical)
{
    int result = 0;
    assert(object != NULL);
    assert(radical != NULL);

    result = cgutils_asprintf(radical,
                              "%s" CG_STP_OPENSTACK_SEGMENT_KEYWORD "%"PRId64,
                              object,
                              timestamp);

    if (result != 0)
    {
        CGUTILS_ERROR("Error allocating memory for radical object: %d", result);
    }

    return result;
}

static int cg_stp_openstack_construct_segment_path(char const * const container,
                                                   size_t const estimated_number_of_parts,
                                                   char const * const object,
                                                   size_t const part_number,
                                                   time_t const request_timestamp,
                                                   char ** const path)
{
    int result = 0;
    char * radical = NULL;
    assert(container != NULL);
    assert(estimated_number_of_parts > 0);
    assert(object != NULL);
    assert(part_number > 0 && part_number <= estimated_number_of_parts);
    assert(path != NULL);

    result = cg_stp_openstack_get_segment_object_radical(object,
                                                         request_timestamp,
                                                         &radical);

    if (result == 0)
    {
        char * part_object = NULL;

        result = cg_stp_openstack_get_segment_path_from_radical(radical,
                                                                part_number,
                                                                estimated_number_of_parts,
                                                                &part_object);

        if (result == 0)
        {
            result = cg_stp_openstack_construct_path(CG_STP_OPENSTACK_USE_RAW_FORMAT,
                                                     CG_STP_OPENSTACK_ADD_LEADING_SLASH,
                                                     container,
                                                     part_object,
                                                     path);

            CGUTILS_FREE(part_object);
        }

        CGUTILS_FREE(radical);
    }

    return result;
}

static int cg_stp_openstack_get_segment_manifest_header_value(cg_storage_provider_request const * const pv_request,
                                                              char const * const container,
                                                              char const * const object,
                                                              char ** const out)
{
    int result = 0;
    char * object_str = NULL;

    assert(pv_request != NULL);
    assert(container != NULL);
    assert(out != NULL);

    result = cg_stp_openstack_get_segment_object_radical(object,
                                                         pv_request->ctx->timestamp,
                                                         &object_str);

    if (result == 0)
    {
        result = cg_stp_openstack_construct_path(CG_STP_OPENSTACK_USE_RAW_FORMAT,
                                                 CG_STP_OPENSTACK_NO_LEADING_SLASH,
                                                 container,
                                                 object_str,
                                                 out);

        CGUTILS_FREE(object_str);
    }

    return result;
}


static int cg_stp_openstack_add_segment_manifest_header(cg_storage_provider_request const * const pv_request,
                                                        cgutils_llist * const headers,
                                                        char const * const container,
                                                        char const * const object)
{
    int result = 0;
    char * path = NULL;

    assert(pv_request != NULL);
    assert(headers != NULL);
    assert(container != NULL);
    assert(object != NULL);

    result = cg_stp_openstack_get_segment_manifest_header_value(pv_request,
                                                                container,
                                                                object,
                                                                &path);
    if (result == 0)
    {
        result = cgutils_http_add_header_to_list(headers,
                                                 CG_STP_OPENSTACK_MANIFEST_HEADER,
                                                 path);

        if (result != 0)
        {
            CGUTILS_ERROR("Error adding header: %d", result);
            CGUTILS_FREE(path);
        }
    }

    return result;
}

static int cg_stp_openstack_list_containers_cb(int status,
                                               cgutils_xml_reader * response,
                                               void * cb_data)
{
    assert(cb_data != NULL);
    cg_storage_provider_request * pv_request = cb_data;

    int result = status;
    cgutils_llist * names = NULL;

    if (result == 0)
    {
        if (response != NULL)
        {
            result = cgutils_llist_create(&names);

            if (result == 0)
            {
                cgutils_llist * containers = NULL;

                result = cgutils_xml_reader_get_all(response, "container", &containers);

                if (result == 0)
                {
                    cgutils_llist_elt * elt = cgutils_llist_get_iterator(containers);

                    while (result == 0 && elt != NULL)
                    {
                        cgutils_xml_reader * container = cgutils_llist_elt_get_object(elt);
                        assert(container != NULL);

                        char * name = NULL;
                        result = cgutils_xml_reader_get_string(container, "name", &name);

                        if (result == 0)
                        {
                            result = cgutils_llist_insert(names, name);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error adding name to list: %d", result);
                                CGUTILS_FREE(name);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Unable to get name from container: %d", result);
                        }

                        elt = cgutils_llist_elt_get_next(elt);
                    }

                    cgutils_llist_free(&containers, &cgutils_xml_reader_delete);
                }
                else if (result == ENOENT)
                {
                    CGUTILS_ERROR("No container found");
                    result = 0;
                }
                else
                {
                    CGUTILS_ERROR("Error while looking for container: %d", result);
                }

                if (result != 0)
                {
                    cgutils_llist_free(&names, &free);
                }
            }
            else
            {
                CGUTILS_ERROR("Error creating name list: %d", result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Error in request: %d", result);
    }

    result = cg_storage_provider_handle_list_response(pv_request, status, names);

    return result;
}

static int cg_stp_openstack_list_containers(cg_storage_provider_request * pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            cg_stp_openstack_specifics * const specifics = pv_request->ctx->instance_specifics;

            pv_request->xml_request_cb = &cg_stp_openstack_list_containers_cb;
            pv_request->request_cb_data = pv_request;

            result = cg_stp_openstack_send_get_request(pv_request,
                                                       specifics->endpoint,
                                                       "/" CG_STP_OPENSTACK_XML_SUFFIX,
                                                       CG_STP_NO_ADDITIONAL_HEADERS,
                                                       CG_STP_RESPONSE_FORMAT_XML,
                                                       CG_STP_NO_OPT_HTTP_CALLBACKS,
                                                       CG_STP_NO_OPT_HTTP_TIMEOUTS);

            if (result == 0)
            {
                pv_request = NULL;
            }
            else
            {
                cg_storage_provider_handle_list_response(pv_request, result, NULL);
                CGUTILS_ERROR("Error sending request: %d", result);
            }
        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }
    }

    return result;
}

#define CG_STP_OPENSTACK_HEADER_CONTAINER_OBJECTS_COUNT "X-Container-Object-Count"
#define CG_STP_OPENSTACK_HEADER_CONTAINER_BYTES_COUNT "X-Container-Bytes-Used"

static int cg_stp_openstack_get_container_stats_cb(int status,
                                                   void * cb_data)
{
    assert(cb_data != NULL);
    cg_storage_instance_container_stats stats = (cg_storage_instance_container_stats) { 0 };
    cg_storage_provider_request * pv_request = cb_data;

    int result = status;

    if (result == 0)
    {
        cgutils_http_header const * objects_count_header = NULL;
        cgutils_http_header const * bytes_count_header = NULL;

        result = cgutils_http_get_header_by_name(pv_request->received_headers,
                                                 CG_STP_OPENSTACK_HEADER_CONTAINER_OBJECTS_COUNT,
                                                 &objects_count_header);

        if (result == 0)
        {
            result = cgutils_str_to_unsigned_int64(objects_count_header->value,
                                                   &(stats.objects_count));

            if (result != 0)
            {
                CGUTILS_WARN("Error parsing header %s on container stats: %d",
                             CG_STP_OPENSTACK_HEADER_CONTAINER_OBJECTS_COUNT,
                             result);
            }
        }
        else
        {
            CGUTILS_DEBUG("Error getting header %s on container stats: %d",
                          CG_STP_OPENSTACK_HEADER_CONTAINER_OBJECTS_COUNT,
                          result);
        }

        result = cgutils_http_get_header_by_name(pv_request->received_headers,
                                                 CG_STP_OPENSTACK_HEADER_CONTAINER_BYTES_COUNT,
                                                 &bytes_count_header);

        if (result == 0)
        {
            result = cgutils_str_to_unsigned_int64(bytes_count_header->value,
                                                   &(stats.bytes_count));

            if (result != 0)
            {
                CGUTILS_WARN("Error parsing header %s on container stats: %d",
                             CG_STP_OPENSTACK_HEADER_CONTAINER_BYTES_COUNT,
                             result);
            }
        }
        else
        {
            CGUTILS_DEBUG("Error getting header %s on container stats: %d",
                          CG_STP_OPENSTACK_HEADER_CONTAINER_BYTES_COUNT,
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error in request: %d", result);
    }

    result = cg_storage_provider_handle_container_stats_response(pv_request,
                                                                 status,
                                                                 &stats);

    return result;
}

static int cg_stp_openstack_get_container_stats(cg_storage_provider_request * pv_request,
                                                char const * const container_name)
{
    int result = EINVAL;

    if (pv_request != NULL &&
        container_name != NULL)
    {
        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            cg_stp_openstack_specifics * const specifics = pv_request->ctx->instance_specifics;
            char * path = NULL;

            pv_request->raw_request_cb = &cg_stp_openstack_get_container_stats_cb;
            pv_request->request_cb_data = pv_request;

            result = cg_stp_openstack_construct_path(CG_STP_OPENSTACK_USE_RAW_FORMAT,
                                                     CG_STP_OPENSTACK_ADD_LEADING_SLASH,
                                                     container_name,
                                                     NULL,
                                                     &path);

            if (result == 0)
            {
                result = cg_stp_openstack_send_head_request(pv_request,
                                                            specifics->endpoint,
                                                            path,
                                                            CG_STP_NO_ADDITIONAL_HEADERS,
                                                            CG_STP_RAW_RESPONSE,
                                                            CG_STP_NO_OPT_HTTP_CALLBACKS,
                                                            CG_STP_NO_OPT_HTTP_TIMEOUTS);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error sending request: %d", result);
                }

                CGUTILS_FREE(path);
            }
            else
            {
                CGUTILS_ERROR("Error creating request path: %d", result);
            }

            if (result == 0)
            {
                pv_request = NULL;
            }
            else
            {
                cg_storage_provider_handle_container_stats_response(pv_request, result, NULL);
                CGUTILS_ERROR("Error sending request: %d", result);
            }
        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }
    }

    return result;
}


static int cg_stp_openstack_create_container_cb(int const status,
                                                void * const cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    assert(cb_data != NULL);
    (void) pv_request;

    if (result == 0)
    {
    }
    else
    {
        CGUTILS_ERROR("Error in request: %d", status);
    }

    cg_storage_provider_handle_status_response(pv_request, result);

    return result;
}

static int cg_stp_openstack_create_container(cg_storage_provider_request * const pv_request,
                                             char const * const container_name)
{
    int result = EINVAL;

    if (pv_request != NULL &&
        container_name != NULL)
    {
        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            char * path = NULL;

            pv_request->raw_request_cb = &cg_stp_openstack_create_container_cb;
            pv_request->request_cb_data = pv_request;

            result = cg_stp_openstack_construct_path(CG_STP_OPENSTACK_USE_RAW_FORMAT,
                                                     CG_STP_OPENSTACK_ADD_LEADING_SLASH,
                                                     container_name,
                                                     NULL,
                                                     &path);

            if (result == 0)
            {
                result = cg_stp_openstack_send_empty_put_request(pv_request,
                                                                 path,
                                                                 CG_STP_NO_ADDITIONAL_HEADERS,
                                                                 CG_STP_RAW_RESPONSE,
                                                                 CG_STP_NO_OPT_HTTP_CALLBACKS,
                                                                 CG_STP_NO_OPT_HTTP_TIMEOUTS);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error sending request: %d", result);
                }

                CGUTILS_FREE(path);
            }
            else
            {
                CGUTILS_ERROR("Error creating request path: %d", result);
            }

            if (result != 0)
            {
                cg_storage_provider_handle_status_response(pv_request, result);
            }
        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }
    }

    return result;
}

static int cg_stp_openstack_remove_empty_container_cb(int const status,
                                                      void * const cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    assert(cb_data != NULL);
    (void) pv_request;

    if (result == 0)
    {
    }
    else
    {
        CGUTILS_ERROR("Error in request: %d", status);
    }

    cg_storage_provider_handle_status_response(pv_request, result);

    return result;
}

static int cg_stp_openstack_remove_empty_container(cg_storage_provider_request * const pv_request,
                                                   char const * const container_name)
{
    int result = EINVAL;

    if (pv_request != NULL &&
        container_name != NULL)
    {
        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            char * path = NULL;

            pv_request->raw_request_cb = &cg_stp_openstack_remove_empty_container_cb;
            pv_request->request_cb_data = pv_request;

            result = cg_stp_openstack_construct_path(CG_STP_OPENSTACK_USE_RAW_FORMAT,
                                                     CG_STP_OPENSTACK_ADD_LEADING_SLASH,
                                                     container_name,
                                                     NULL,
                                                     &path);
            if (result == 0)
            {
                result = cg_stp_openstack_send_delete_request(pv_request,
                                                              path,
                                                              CG_STP_NO_ADDITIONAL_HEADERS,
                                                              CG_STP_RAW_RESPONSE,
                                                              CG_STP_NO_OPT_HTTP_CALLBACKS,
                                                              CG_STP_NO_OPT_HTTP_TIMEOUTS);
                if (result != 0)
                {
                    CGUTILS_ERROR("Error sending request: %d", result);
                }

                CGUTILS_FREE(path);
            }
            else
            {
                CGUTILS_ERROR("Error creating request path: %d", result);
            }

            if (result != 0)
            {
                cg_storage_provider_handle_status_response(pv_request, result);
            }
        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }
    }

    return result;
}

static int cg_stp_openstack_list_files_cb(int status,
                                          cgutils_xml_reader * response,
                                          void * cb_data)
{
    assert(cb_data != NULL);
    cg_storage_provider_request * const pv_request = cb_data;

    int result = status;
    cgutils_llist * names = NULL;

    if (result == 0)
    {
        if (response != NULL)
        {
            result = cgutils_llist_create(&names);

            if (result == 0)
            {
                cgutils_llist * contents = NULL;
                result = cgutils_xml_reader_get_all(response, "object", &contents);

                if (result == 0)
                {
                    cgutils_llist_elt * elt = cgutils_llist_get_iterator(contents);

                    while (result == 0 && elt != NULL)
                    {
                        cgutils_xml_reader * content = cgutils_llist_elt_get_object(elt);
                        assert(content != NULL);

                        {
                            char * name = NULL;
                            result = cgutils_xml_reader_get_string(content, "name", &name);

                            if (result == 0)
                            {
                                result = cgutils_llist_insert(names, name);

                                if (result != 0)
                                {
                                    CGUTILS_ERROR("Error adding name to list: %d", result);
                                    CGUTILS_FREE(name);
                                }
                            }
                            else
                            {
                                CGUTILS_ERROR("Unable to get name from content: %d", result);
                            }
                        }

                        elt = cgutils_llist_elt_get_next(elt);
                    }

                    cgutils_llist_free(&contents, &cgutils_xml_reader_delete);
                }
                else if (result == ENOENT)
                {
                    result = 0;
                }
                else
                {
                    CGUTILS_ERROR("Error while looking for file: %d", result);
                }

                if (result != 0)
                {
                    cgutils_llist_free(&names, &free);
                }
            }
            else
            {
                CGUTILS_ERROR("Error creating name list: %d", result);
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Error in request: %d", result);
    }

    result = cg_storage_provider_handle_list_response(pv_request, status, names);

    return result;
}

static int cg_stp_openstack_list_files(cg_storage_provider_request * const pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            cg_stp_openstack_specifics * specifics = pv_request->ctx->instance_specifics;
            char * path = NULL;

            pv_request->xml_request_cb = &cg_stp_openstack_list_files_cb;
            pv_request->request_cb_data = pv_request;

            result = cg_stp_openstack_construct_path(CG_STP_OPENSTACK_USE_XML_FORMAT,
                                                     CG_STP_OPENSTACK_ADD_LEADING_SLASH,
                                                     specifics->container,
                                                     NULL,
                                                     &path);

            if (result == 0)
            {
                result = cg_stp_openstack_send_get_request(pv_request,
                                                           specifics->endpoint,
                                                           path,
                                                           CG_STP_NO_ADDITIONAL_HEADERS,
                                                           CG_STP_RESPONSE_FORMAT_XML,
                                                           CG_STP_NO_OPT_HTTP_CALLBACKS,
                                                           CG_STP_NO_OPT_HTTP_TIMEOUTS);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error sending request: %d", result);
                }

                CGUTILS_FREE(path);
            }
            else
            {
                CGUTILS_ERROR("Error creating request path: %d", result);
            }

            if (result != 0)
            {
                cg_storage_provider_handle_list_response(pv_request, result, NULL);
            }
        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }
    }

    return result;
}

static int cg_stp_openstack_get_file_cb(int status,
                                        void * cb_data)
{
    cg_storage_provider_request * pv_request = cb_data;
    int result = status;
    assert(cb_data != NULL);

    if (result != 0 &&
        result != ENOENT)
    {
        CGUTILS_ERROR("Error in request: %d", result);
    }

    result = cg_storage_provider_handle_status_response(pv_request, status);

    return result;
}

static int cg_stp_openstack_get_file(cg_storage_provider_request * const pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            cg_stp_openstack_specifics * specifics = pv_request->ctx->instance_specifics;
            char * path = NULL;

            assert(pv_request->ctx != NULL && pv_request->ctx->key != NULL);

            pv_request->raw_request_cb = &cg_stp_openstack_get_file_cb;
            pv_request->request_cb_data = pv_request;

            result = cg_stp_openstack_construct_path(CG_STP_OPENSTACK_USE_RAW_FORMAT,
                                                     CG_STP_OPENSTACK_ADD_LEADING_SLASH,
                                                     specifics->container,
                                                     pv_request->ctx->key,
                                                     &path);

            if (result == 0)
            {
                cgutils_http_callbacks const http_cbs = {
                    .response_cb = &cg_storage_provider_utils_http_raw_response_callback,
                    .write_cb = &cg_storage_provider_utils_write_cb,
                    .header_cb = &cg_storage_provider_utils_header_cb,
                };

                result = cg_stp_openstack_send_get_request(pv_request,
                                                           specifics->endpoint,
                                                           path,
                                                           CG_STP_NO_ADDITIONAL_HEADERS,
                                                           CG_STP_RAW_RESPONSE,
                                                           &http_cbs,
                                                           CG_STP_NO_OPT_HTTP_TIMEOUTS);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error sending request: %d", result);
                }

                CGUTILS_FREE(path);
            }
            else
            {
                CGUTILS_ERROR("Error creating request path: %d", result);
            }

            if (result != 0)
            {
                cg_storage_provider_handle_status_response(pv_request, result);
            }
        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }
    }

    return result;
}

static int cg_stp_openstack_delete_file_cb(int status,
                                           void * cb_data)
{
    assert(cb_data != NULL);
    cg_storage_provider_request * pv_request = cb_data;

    int result = status;

    if (result == 0)
    {
    }
    else if (result != ENOENT)
    {
        CGUTILS_ERROR("Error in request: %d", status);
    }

    cg_stp_openstack_delete_remaining_segments(pv_request, true, status);

    return result;
}

static int cg_stp_openstack_real_delete_file(cg_storage_provider_request * const pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            cg_stp_openstack_specifics * specifics = pv_request->ctx->instance_specifics;
            char * path = NULL;
            assert(pv_request->ctx != NULL && pv_request->ctx->key != NULL);

            pv_request->raw_request_cb = &cg_stp_openstack_delete_file_cb;
            pv_request->request_cb_data = pv_request;

            result = cg_stp_openstack_construct_path(CG_STP_OPENSTACK_USE_RAW_FORMAT,
                                                     CG_STP_OPENSTACK_ADD_LEADING_SLASH,
                                                     specifics->container,
                                                     pv_request->ctx->key,
                                                     &path);

            if (result == 0)
            {
                cgutils_http_callbacks const http_cbs = {
                    .response_cb = &cg_storage_provider_utils_http_raw_response_callback,
                    .header_cb = &cg_storage_provider_utils_header_cb,
                };

                result = cg_stp_openstack_send_delete_request(pv_request,
                                                              path,
                                                              CG_STP_NO_ADDITIONAL_HEADERS,
                                                              CG_STP_RAW_RESPONSE,
                                                              &http_cbs,
                                                              CG_STP_NO_OPT_HTTP_TIMEOUTS);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error sending request: %d", result);
                }

                CGUTILS_FREE(path);
            }
            else
            {
                CGUTILS_ERROR("Error creating request path: %d", result);
            }

        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }

        if (result != 0)
        {
            cg_stp_openstack_request_ctx_data_free(pv_request->ctx->provider_request_ctx_data);
            pv_request->ctx->provider_request_ctx_data = NULL;

            cg_storage_provider_handle_status_response(pv_request, result);
        }
    }

    return result;
}

static int cg_stp_openstack_put_file_cb(int const status,
                                        void * const cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    assert(cb_data != NULL);

    if (result == 0)
    {
    }
    else if (result == ENOENT)
    {
        char const * container_name = "";

        if (pv_request->ctx != NULL &&
            pv_request->ctx->instance_specifics != NULL)
        {
            cg_stp_openstack_specifics const * const specifics = pv_request->ctx->instance_specifics;
            if (specifics->container != NULL)
            {
                container_name = specifics->container;
            }
        }

        CGUTILS_ERROR("Error (%d) while trying to upload an object, are you sure that the container %s exists?",
                      status,
                      container_name);
    }
    else
    {
        CGUTILS_ERROR("Error in request: %d", status);
    }

    cg_stp_openstack_delete_remaining_segments(pv_request, true, status);

    return result;
}

static int cg_stp_openstack_multipart_put_file_cb(int const status,
                                                  void * const cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    CGUTILS_ASSERT(cb_data != NULL);

    if (result != 0)
    {
        CGUTILS_ERROR("Error in request: %d", status);
    }

    cg_storage_provider_handle_status_response(pv_request, result);

    return result;
}

static int cg_stp_openstack_real_put_file(cg_storage_provider_request * pv_request)
{
    int result = 0;

    if (pv_request != NULL)
    {
        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            cgutils_llist * headers = NULL;
            cg_stp_openstack_specifics * specifics = pv_request->ctx->instance_specifics;
            char * path = NULL;

            assert(pv_request->ctx != NULL && pv_request->ctx->key != NULL);

            pv_request->raw_request_cb = &cg_stp_openstack_put_file_cb;
            pv_request->request_cb_data = pv_request;

            if (pv_request->ctx->metadata != NULL)
            {
                result = cgutils_llist_create(&headers);

                if (result == 0)
                {
                    result = cg_storage_provider_utils_add_header_from_meta(pv_request,
                                                                            "filename",
                                                                            CG_STP_OPENSTACK_METADATA_HEADER_FILENAME,
                                                                            headers);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error adding filename metadata to headers: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error creating headers list: %d", result);
                }
            }

            if (result == 0)
            {
                result = cg_stp_openstack_construct_path(CG_STP_OPENSTACK_USE_RAW_FORMAT,
                                                         CG_STP_OPENSTACK_ADD_LEADING_SLASH,
                                                         specifics->container,
                                                         pv_request->ctx->key,
                                                         &path);

                if (result == 0)
                {
                    cgutils_http_callbacks const http_cbs = {
                        .response_cb = &cg_storage_provider_utils_http_raw_response_callback,
                        .read_cb = &cg_storage_provider_utils_read_cb,
                        .header_cb = &cg_storage_provider_utils_header_cb,
                    };

                    result = cg_stp_openstack_send_put_request(pv_request,
                                                               path,
                                                               headers,
                                                               CG_STP_RAW_RESPONSE,
                                                               &http_cbs,
                                                               CG_STP_NO_OPT_HTTP_TIMEOUTS);


                    if (result == 0)
                    {
                        pv_request = NULL;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error sending request: %d", result);
                    }

                    CGUTILS_FREE(path);
                }
                else
                {
                    CGUTILS_ERROR("Error creating request path: %d", result);
                }
            }

            if (result != 0)
            {
                if (headers != NULL)
                {
                    cgutils_llist_free(&headers, &cgutils_http_header_delete);
                }
            }
        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }

        if (result != 0)
        {
            cg_stp_openstack_request_ctx_data_free(pv_request->ctx->provider_request_ctx_data);
            pv_request->ctx->provider_request_ctx_data = NULL;

            cg_storage_provider_handle_status_response(pv_request, result);
        }
    }

    return result;
}

static void cg_stp_openstack_parse_manifest_headers(int const status,
                                                    cg_storage_provider_request * const pv_request,
                                                    cg_stp_openstack_request_ctx_data * const ctx_data)
{
    assert(pv_request != NULL);
    assert(ctx_data != NULL);

    if (status == 0)
    {
        if (pv_request->received_headers != NULL)
        {
            cgutils_http_header const * object_manifest_header = NULL;

            int result = cgutils_http_get_header_by_name(pv_request->received_headers,
                                                         CG_STP_OPENSTACK_MANIFEST_HEADER,
                                                         &object_manifest_header);

            if (result == 0)
            {
                cgutils_http_header const * number_of_parts_header = NULL;

                result = cgutils_http_get_header_by_name(pv_request->received_headers,
                                                         CG_STP_OPENSTACK_MULTIPART_NUMBER_OF_PARTS,
                                                         &number_of_parts_header);

                if (result == 0)
                {
                    ctx_data->previous_radical = cgutils_strdup(object_manifest_header->value);

                    if (ctx_data->previous_radical != NULL)
                    {
                        result = cgutils_str_to_unsigned_int64(number_of_parts_header->value,
                                                               &(ctx_data->total_segments_count));

                        if (result == 0)
                        {
                            ctx_data->remaining_segments = ctx_data->total_segments_count;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error parsing number of parts: %d", result);
                        }
                    }
                    else
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Error allocating memory for previous radical: %d", result);
                    }
                }
            }
        }
    }
}

static int cg_stp_openstack_retrieve_manifest_cb(int status,
                                                 void * cb_data)
{
    cg_storage_provider_request * pv_request = cb_data;
    int result = status;
    assert(cb_data != NULL);

    if (result == 0 ||
        result == ENOENT)
    {
        cg_stp_openstack_request_ctx_data * ctx_data = pv_request->ctx->provider_request_ctx_data;
        assert(ctx_data != NULL);

        cg_stp_openstack_parse_manifest_headers(status,
                                                pv_request,
                                                ctx_data);

        if (ctx_data->next_cb == NULL)
        {
            result = cg_storage_provider_handle_status_response(pv_request, 0);
        }
        else
        {
            /* restore request */
            if (pv_request->received_headers != NULL)
            {
                cgutils_llist_free(&(pv_request->received_headers), &cgutils_http_header_delete);
            }

            if (pv_request->dest_io != NULL)
            {
                cg_storage_io_ctx_free(pv_request->dest_io);
            }

            pv_request->dest_io = ctx_data->request_dest_io;

            if (pv_request->ctx->dest_io != NULL)
            {
                cg_storage_io_free(pv_request->ctx->dest_io);
            }

            pv_request->ctx->dest_io = ctx_data->ctx_dest_io;

            result = (*(ctx_data->next_cb))(pv_request);
        }
    }
    else
    {
        CGUTILS_ERROR("Error in request: %d", result);

        cg_stp_openstack_request_ctx_data_free(pv_request->ctx->provider_request_ctx_data);
        pv_request->ctx->provider_request_ctx_data = NULL;

        result = cg_storage_provider_handle_status_response(pv_request, result);
    }

    return result;
}

/* This function is called before PUTting or DELETing a file, in order to retrieve
   informations needed to be able to delete the remaining segments
   if the file already exists and is a segmented one. */
static int cg_stp_openstack_retrieve_manifest(cg_storage_provider_request * const pv_request,
                                              cg_stp_openstack_cb * const cb)
{
    assert(pv_request != NULL);
    assert(pv_request->ctx != NULL && pv_request->ctx->key != NULL);
    cg_stp_openstack_specifics * specifics = pv_request->ctx->instance_specifics;
    char * path = NULL;

    pv_request->raw_request_cb = &cg_stp_openstack_retrieve_manifest_cb;
    pv_request->request_cb_data = pv_request;

    int result = cg_stp_openstack_construct_path(CG_STP_OPENSTACK_USE_RAW_FORMAT,
                                                 CG_STP_OPENSTACK_ADD_LEADING_SLASH,
                                                 specifics->container,
                                                 pv_request->ctx->key,
                                                 &path);

    if (result == 0)
    {
        cg_stp_openstack_request_ctx_data * ctx_data = NULL;

        CGUTILS_ALLOCATE_STRUCT(ctx_data);

        if (ctx_data != NULL)
        {
            CGUTILS_ASSERT(pv_request->ctx->provider_request_ctx_data == NULL);

            pv_request->ctx->provider_request_ctx_data = ctx_data;

            ctx_data->next_cb = cb;

            ctx_data->ctx_dest_io = pv_request->ctx->dest_io;
            pv_request->ctx->dest_io = NULL;
            ctx_data->request_dest_io = pv_request->dest_io;
            pv_request->dest_io = NULL;

            cgutils_http_callbacks const http_cbs = {
                .response_cb = &cg_storage_provider_utils_http_raw_response_callback,
                .write_cb = &cg_storage_provider_utils_write_cb,
                .header_cb = &cg_storage_provider_utils_header_cb,
            };

            result = cg_stp_openstack_send_head_request(pv_request,
                                                        specifics->endpoint,
                                                        path,
                                                        CG_STP_NO_ADDITIONAL_HEADERS,
                                                        CG_STP_RAW_RESPONSE,
                                                        &http_cbs,
                                                        CG_STP_NO_OPT_HTTP_TIMEOUTS);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending request: %d", result);

                cg_stp_openstack_request_ctx_data_free(ctx_data), ctx_data = NULL;
                pv_request->ctx->provider_request_ctx_data = NULL;
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for provider request context data: %d", result);
        }

        CGUTILS_FREE(path);
    }
    else
    {
        CGUTILS_ERROR("Error creating request path: %d", result);
    }

    return result;
}

static int cg_stp_openstack_put_multipart_init(cg_storage_provider_request * const pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL &&
        pv_request->ctx != NULL &&
        pv_request->ctx->key != NULL)
    {
        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            result = cg_stp_openstack_retrieve_manifest(pv_request, NULL);

            if (result != 0)
            {
                cg_stp_openstack_request_ctx_data_free(pv_request->ctx->provider_request_ctx_data);
                pv_request->ctx->provider_request_ctx_data = NULL;

                cg_storage_provider_handle_status_response(pv_request, result);
            }
        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }
    }

    return result;
}

static int cg_stp_openstack_put_multipart_part(cg_storage_provider_request * pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            cg_stp_openstack_specifics * specifics = pv_request->ctx->instance_specifics;
            char * path = NULL;

            assert(pv_request->ctx != NULL && pv_request->ctx->key != NULL);

            pv_request->raw_request_cb = &cg_stp_openstack_multipart_put_file_cb;
            pv_request->request_cb_data = pv_request;

            result = cg_stp_openstack_construct_segment_path(specifics->container,
                                                             pv_request->ctx->number_of_parts,
                                                             pv_request->ctx->key,
                                                             pv_request->part_number,
                                                             pv_request->ctx->timestamp,
                                                             &path);

            if (result == 0)
            {
                cgutils_http_callbacks const http_cbs = {
                    .response_cb = &cg_storage_provider_utils_http_raw_response_callback,
                    .read_cb = &cg_storage_provider_utils_read_cb,
                    .header_cb = &cg_storage_provider_utils_header_cb,
                };

                result = cg_stp_openstack_send_put_request(pv_request,
                                                           path,
                                                           CG_STP_NO_ADDITIONAL_HEADERS,
                                                           CG_STP_RAW_RESPONSE,
                                                           &http_cbs,
                                                           CG_STP_NO_OPT_HTTP_TIMEOUTS);


                if (result == 0)
                {
                    pv_request = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error sending request: %d", result);
                }

                CGUTILS_FREE(path);
            }
            else
            {
                CGUTILS_ERROR("Error creating request path: %d", result);
            }

            if (result != 0)
            {
                cg_stp_openstack_request_ctx_data_free(pv_request->ctx->provider_request_ctx_data);
                pv_request->ctx->provider_request_ctx_data = NULL;

                cg_storage_provider_handle_status_response(pv_request, result);
            }
        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }
    }

    return result;
}

static int cg_stp_openstack_segmented_upload_completed(int const status,
                                                       void * cb_data)
{
    assert(cb_data != NULL);

    int result = status;
    cg_storage_provider_request * pv_request = cb_data;

    if (result == 0)
    {
        CGUTILS_TRACE("Segmented upload completed");
    }
    else
    {
        CGUTILS_ERROR("Error completing segmented upload: %d", result);
    }

    cg_stp_openstack_delete_remaining_segments(pv_request, true, status);

    return result;
}

static int cg_stp_openstack_put_multipart_finish(cg_storage_provider_request * const pv_request)
{
    int result = EINVAL;

    if(pv_request != NULL)
    {
        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            /* do a PUT with a 0 content-length and a special header named
               CG_STP_OPENSTACK_MANIFEST_HEADER: container/object/segments-prefix".
               We add an custom header CG_STP_OPENSTACK_MULTIPART_NUMBER_OF_PARTS
               in order to be able to delete segments afterward.
            */
            cg_stp_openstack_specifics * specifics = pv_request->ctx->instance_specifics;
            cgutils_llist * headers = NULL;

            pv_request->raw_request_cb = &cg_stp_openstack_segmented_upload_completed;
            pv_request->request_cb_data = pv_request;

            result = cgutils_llist_create(&headers);

            if (result == 0)
            {
                result = cg_stp_openstack_add_segment_manifest_header(pv_request,
                                                                      headers,
                                                                      specifics->container,
                                                                      pv_request->ctx->key);

                if (result == 0)
                {
                    result = cg_stp_openstack_add_manifest_number_of_parts_header(pv_request,
                                                                                  headers);

                    if (result == 0)
                    {
                        char * path = NULL;

                        if (pv_request->ctx->metadata != NULL)
                        {
                            result = cg_storage_provider_utils_add_header_from_meta(pv_request,
                                                                                    "filename",
                                                                                    CG_STP_OPENSTACK_METADATA_HEADER_FILENAME,
                                                                                    headers);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error adding filename metadata to headers: %d", result);
                            }
                        }

                        if (result == 0)
                        {
                            result = cg_stp_openstack_construct_path(CG_STP_OPENSTACK_USE_RAW_FORMAT,
                                                                     CG_STP_OPENSTACK_ADD_LEADING_SLASH,
                                                                     specifics->container,
                                                                     pv_request->ctx->key,
                                                                     &path);

                            if (result == 0)
                            {
                                result = cg_stp_openstack_send_empty_put_request(pv_request,
                                                                                 path,
                                                                                 headers,
                                                                                 CG_STP_RAW_RESPONSE,
                                                                                 CG_STP_NO_OPT_HTTP_CALLBACKS,
                                                                                 CG_STP_NO_OPT_HTTP_TIMEOUTS);

                                if (result != 0)
                                {
                                    CGUTILS_ERROR("Error sending request: %d", result);
                                }

                                CGUTILS_FREE(path);
                            }
                            else
                            {
                                CGUTILS_ERROR("Error getting path: %d", result);
                            }
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error adding custom number of parts header: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error adding manifest header: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error creating headers list: %d", result);
            }

            if (result != 0)
            {
                cgutils_llist_free(&headers, &cgutils_http_header_delete);
                cg_stp_openstack_request_ctx_data_free(pv_request->ctx->provider_request_ctx_data);
                pv_request->ctx->provider_request_ctx_data = NULL;

                cg_storage_provider_handle_status_response(pv_request, result);
            }
        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }
    }

    return result;
}


static int cg_stp_openstack_put_multipart_cancel(cg_storage_provider_request * const pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        assert(pv_request->ctx != NULL);

        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            cg_stp_openstack_specifics * specifics = pv_request->ctx->instance_specifics;
            cg_stp_openstack_request_ctx_data * ctx_data = pv_request->ctx->provider_request_ctx_data;
            assert(specifics != NULL);
            assert(ctx_data != NULL);

            CGUTILS_WARN("Openstack segmented upload has been aborted, parts may remain.");

            /* Set previous radical to the current radical.
               Set remaining_segments to the possible number of remaining parts.
               Set total_segments_count to the number of parts that were scheduled to be uploaded.
            */

            ctx_data->remaining_segments = pv_request->ctx->number_of_parts;
            ctx_data->total_segments_count = pv_request->ctx->number_of_parts;

            if (ctx_data->previous_radical != NULL)
            {
                CGUTILS_FREE(ctx_data->previous_radical);
            }

            result = cg_stp_openstack_get_segment_manifest_header_value(pv_request,
                                                                        specifics->container,
                                                                        pv_request->ctx->key,
                                                                        &(ctx_data->previous_radical));

            if (result == 0)
            {
                cg_stp_openstack_delete_remaining_segments(pv_request, false, result);
            }
            else
            {
                cg_stp_openstack_request_ctx_data_free(pv_request->ctx->provider_request_ctx_data);
                pv_request->ctx->provider_request_ctx_data = NULL;

                result = cg_storage_provider_handle_status_response(pv_request, 0);
            }
        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }
    }

    return result;
}


static int cg_stp_openstack_put_file(cg_storage_provider_request * const pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL &&
        pv_request->ctx != NULL &&
        pv_request->ctx->key != NULL)
    {
        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            result = cg_stp_openstack_retrieve_manifest(pv_request, &cg_stp_openstack_real_put_file);

            if (result != 0)
            {
                cg_storage_provider_handle_status_response(pv_request, result);
            }
        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }
    }

    return result;
}

static int cg_stp_openstack_delete_file(cg_storage_provider_request * const pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL &&
        pv_request->ctx != NULL &&
        pv_request->ctx->key != NULL)
    {
        if (cg_stp_openstack_auth_performed(pv_request) == true)
        {
            result = cg_stp_openstack_retrieve_manifest(pv_request, &cg_stp_openstack_real_delete_file);

            if (result != 0)
            {
                cg_storage_provider_handle_status_response(pv_request, result);
            }
        }
        else
        {
            result = CG_STP_OPENSTACK_NO_AUTH_ERROR;
        }
    }

    return result;
}

static bool cg_stp_openstack_is_valid_response_code(cg_storage_provider_request const * const pv_request,
                                                    uint16_t const code)
{
    bool result = false;

    if (pv_request != NULL)
    {
        assert(pv_request->ctx != NULL);
        assert(pv_request->ctx->instance_specifics != NULL);
        assert(pv_request->ctx->provider_data != NULL);

        if (code >= 200 && code <= 299)
        {
            result = true;
        }
        else if (code == 401)
        {
            /* A 401 code may means that our auth token has expired. */
            cg_stp_openstack_specifics * specifics = pv_request->ctx->instance_specifics;
            cg_stp_openstack_provider_data * const pvd = pv_request->ctx->provider_data;

            if (cg_stp_openstack_auth_token_is_old(specifics) == true &&
                specifics->auth_refresh_in_progress == false)
            {
                int res = 0;

                CGUTILS_INFO("Got a 401 response and our token is not very recent, trying to get a new one.");

                res = cg_stp_openstack_auth_refresh(pvd,
                                                    specifics);

                if (res != 0)
                {
                    CGUTILS_ERROR("Error trying to refresh our auth token: %d", res);
                }
            }
        }
    }

    return result;
}

static int cg_stp_openstack_setup(cg_storage_provider * const provider,
                                  void * const provider_data,
                                  void * const specifics_gen)
{
    int result = EINVAL;

    if (provider != NULL && provider_data != NULL && specifics_gen != NULL)
    {
        cg_stp_openstack_specifics * const specifics = specifics_gen;
        cg_stp_openstack_provider_data * const pvd = provider_data;

        if (pvd->http == NULL)
        {
            pvd->http = cg_storage_manager_data_get_http(pvd->data);
        }

        if (pvd->event_data == NULL)
        {
            pvd->event_data = cg_storage_manager_data_get_event(pvd->data);
        }

        pvd->provider = provider;

        cg_storage_manager_data_set_provider_init_pending(pvd->data);

        result = cg_stp_openstack_auth_refresh(pvd, specifics);

        if (result == 0)
        {
            /* create a timer calling cg_stp_openstack_auth_refresh
               when needed. */

            CGUTILS_ALLOCATE_STRUCT(specifics->timer_data);

            if (specifics->timer_data != NULL)
            {
                specifics->timer_data->pvd = pvd;
                specifics->timer_data->specifics = specifics;

                result = cgutils_event_create_timer_event(pvd->event_data,
                                                          CGUTILS_EVENT_PERSIST,
                                                          &cg_stp_openstack_auth_timer_cb,
                                                          specifics->timer_data,
                                                          &(specifics->auth_timer));
                if (result == 0)
                {
                }
                else
                {

                    CGUTILS_ERROR("Error creating timer event: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Allocation error: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error refreshing auth: %d", result);
        }
    }

    return result;
}

static int cg_stp_openstack_parse_specifics(void * const provider_data,
                                           cgutils_configuration * const config,
                                           void ** data)
{
    int result = EINVAL;

    (void) provider_data;

    if (config != NULL && data != NULL)
    {
        cg_stp_openstack_specifics * specifics = NULL;

        CGUTILS_ALLOCATE_STRUCT(specifics);

        if (specifics != NULL)
        {
            char * auth_format = NULL;
            /* Defaults values, may be overridden by configuration */
            specifics->auth_format = cg_stp_openstack_identity_auth_format_xml;
            specifics->http_timeout = CG_STP_OPENSTACK_DEFAULT_HTTP_TIMEOUT;
            specifics->check_object_hash = true;
            specifics->verbose = false;
            specifics->show_http_requests = false;
            specifics->disable_100_continue = false;
            specifics->disable_fast_open = false;
            specifics->allow_insecure_https = false;
            specifics->identity_version = cg_stp_openstack_identity_version_2_0;
            specifics->authentication_max_lifetime = CG_STP_OPENSTACK_REFRESH_AUTH_DELAY;
            specifics->authentication_token_recent_delay = CG_STP_OPENSTACK_AUTH_TOKEN_RECENT_DELAY;
            result = 0;
            specifics->init = true;

#define STRING_PARAM(name, path, required) CG_STP_UTILS_RETRIEVE_STRING(config, specifics, result, name, path, required)
#define UINT8_PARAM(name, path, required) CG_STP_UTILS_RETRIEVE_UINT8(config, specifics, result, name, path, required)
#define UINT64_PARAM(name, path, required) CG_STP_UTILS_RETRIEVE_UINT64(config, specifics, result, name, path, required)
#define SIZE_PARAM(name, path, required) CG_STP_UTILS_RETRIEVE_SIZE(config, specifics, result, name, path, required)
#define BOOLEAN_PARAM(name, path, required) CG_STP_UTILS_RETRIEVE_BOOLEAN(config, specifics, result, name, path, required)
#include "cg_storage_provider_openstack_parameters.itm"
#undef STRING_PARAM
#undef SIZE_PARAM
#undef UINT64_PARAM
#undef UINT8_PARAM
#undef BOOLEAN_PARAM

            if (result == 0)
            {
                result = cgutils_configuration_get_string(config, "AuthenticationFormat", &auth_format);

                if (result == ENOENT)
                {
                    result = 0;
                }
                else if (result != 0)
                {
                    CGUTILS_ERROR("Unable to retrieve parameter %s: %d", "AuthenticationFormat", result);
                }
            }

            if (result == 0)
            {
                specifics->container_len = strlen(specifics->container);

                if (specifics->username == NULL ||
                    strlen(specifics->username) == 0)
                {
                    CGUTILS_ERROR("Empty Openstack Username");
                    result = EINVAL;
                }

                if (specifics->identity_version != cg_stp_openstack_identity_version_1_0 &&
                    specifics->identity_version != cg_stp_openstack_identity_version_2_0)
                {
                    CGUTILS_ERROR("Wrong Identity Version");
                    result = EINVAL;
                }

                if (specifics->identity_version == cg_stp_openstack_identity_version_1_0 &&
                    (specifics->api_access_key == NULL ||
                     strlen(specifics->api_access_key) == 0))
                {
                    CGUTILS_ERROR("Empty Openstack API Access Key");
                    result = EINVAL;
                }

                if (specifics->identity_version == cg_stp_openstack_identity_version_2_0 &&
                    ( specifics->password == NULL ||
                      strlen(specifics->password) == 0))
                {
                    CGUTILS_ERROR("Empty Openstack Password");
                    result = EINVAL;
                }

                if (specifics->identity_version == cg_stp_openstack_identity_version_2_0 &&
                    (specifics->tenant_name == NULL ||
                     strlen(specifics->tenant_name) == 0) &&
                    (specifics->tenant_id == NULL ||
                     strlen(specifics->tenant_id) == 0))
                {
                    CGUTILS_ERROR("Empty Openstack Tenant Name and Tenant Id");
                    result = EINVAL;
                }

                if (specifics->container_len == 0)
                {
                    CGUTILS_ERROR("Empty Openstack container name");
                    result = EINVAL;
                }

                if (specifics->auth_endpoint == NULL ||
                    strlen(specifics->auth_endpoint) == 0)
                {
                    CGUTILS_ERROR("Empty Openstack Endpoint");
                    result = EINVAL;
                }

                if (specifics->authentication_max_lifetime == 0)
                {
                    specifics->authentication_max_lifetime = CG_STP_OPENSTACK_REFRESH_AUTH_DELAY;
                }

                if (specifics->max_single_upload_size < CG_STP_OPENSTACK_MIN_PART_SIZE)
                {
                    specifics->max_single_upload_size = CG_STP_OPENSTACK_MAX_SIMPLE_UP_FILE_SIZE_DEFAULT;
                }
                else if (specifics->max_single_upload_size > (CG_STP_OPENSTACK_MAX_PART_SIZE))
                {
                    CGUTILS_WARN("Warning, the default size for a single part for most OpenStack installations is %zu, you are using %zu.",
                                 (CG_STP_OPENSTACK_MAX_PART_SIZE),
                                 specifics->max_single_upload_size);
                }

                if (specifics->ssl_ciphers == NULL)
                {
                    specifics->ssl_ciphers = cgutils_strdup(CG_STP_DEFAULT_TLS_CIPHER_SUITES);
                }

                if (specifics->ssl_client_certificate_file == NULL ||
                    specifics->ssl_client_certificate_key_file == NULL)
                {
                    /* We need both to be able to use X.509 client certificate authentication */
                    if (specifics->ssl_client_certificate_file != NULL)
                    {
                        CGUTILS_FREE(specifics->ssl_client_certificate_file);
                    }

                    if (specifics->ssl_client_certificate_key_file != NULL)
                    {
                        CGUTILS_FREE(specifics->ssl_client_certificate_key_file);
                    }

                    if (specifics->ssl_client_certificate_key_password != NULL)
                    {
                        CGUTILS_FREE(specifics->ssl_client_certificate_key_password);
                    }
                }

                if (auth_format != NULL &&
                    strcasecmp(auth_format, "JSON") == 0)
                {
                    specifics->auth_format = cg_stp_openstack_identity_auth_format_json;
                }
                else
                {
                    specifics->auth_format = cg_stp_openstack_identity_auth_format_xml;
                }
            }

            if (result != 0)
            {
                cg_stp_openstack_clear_specifics(specifics), specifics = NULL;
            }

            *data = specifics;

            CGUTILS_FREE(auth_format);
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

static int cg_stp_openstack_init_object_hash(cg_storage_provider_request * const request)
{
    int result = EINVAL;

    if (request != NULL)
    {
        cg_stp_openstack_specifics const * const specifics = request->ctx->instance_specifics;
        assert(specifics != NULL);
        assert(request->object_hash_ctx == NULL);
        assert(request->compute_object_hash == false);

        result = 0;

        if (specifics->check_object_hash == true)
        {
            result = cgutils_crypto_hash_context_init(CG_STP_OPENSTACK_OBJECT_HASH_ALGO,
                                                      &(request->object_hash_ctx));

            if (result == 0)
            {
                request->compute_object_hash = true;
            }
            else
            {
                CGUTILS_ERROR("Error creating object hashing context: %d", result);
            }
        }
    }

    return result;
}

static int cg_stp_openstack_update_object_hash(cg_storage_provider_request * const request,
                                               void const * const data,
                                               size_t const data_size)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(request != NULL && data != NULL))
    {
        assert(request->object_hash_ctx != NULL);
        assert(request->compute_object_hash == true);

        if (COMPILER_LIKELY(data_size > 0))
        {
            result = cgutils_crypto_hash_context_update(request->object_hash_ctx,
                                                        data,
                                                        data_size);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error updating object hashing context: %d", result);
            }
        }
    }

    return result;
}

static int cg_stp_openstack_check_object_hash(cg_storage_provider_request * const request,
                                              bool * const valid)
{
    int result = EINVAL;

    if (request != NULL &&
        valid != NULL)
    {
        assert(request->object_hash_ctx != NULL);
        assert(request->compute_object_hash == true);

        *valid = false;

        if (request->received_headers != NULL)
        {
            char * etag_value = NULL;
            size_t etag_value_len = 0;

            result = cg_storage_provider_utils_get_normalized_header_value(request->received_headers,
                                                                           CG_STP_OPENSTACK_MAGIC_HEADER_NAME_ETAG,
                                                                           &etag_value,
                                                                           &etag_value_len);
            if (result == 0)
            {
                cgutils_http_header const * number_of_parts = NULL;

                result = cgutils_http_get_header_by_name(request->received_headers,
                                                         CG_STP_OPENSTACK_MULTIPART_NUMBER_OF_PARTS,
                                                         &number_of_parts);

                if (result == ENOENT)
                {
                    /* If the CG_STP_OPENSTACK_MULTIPART_NUMBER_OF_PARTS header is present,
                       this object has been uploaded splitted in several segments and
                       the Etag value is of no help here. */
                    void * hash = NULL;
                    size_t hash_size = 0;

                    assert(request->object_hash_ctx != NULL);

                    result = cgutils_crypto_hash_context_finish(request->object_hash_ctx,
                                                                &hash,
                                                                &hash_size);

                    if (result == 0)
                    {
                        char * hash_hex = NULL;
                        size_t hash_hex_size = 0;

                        result = cgutils_encoding_hex_sprint(hash,
                                                             hash_size,
                                                             &hash_hex,
                                                             &hash_hex_size);

                        if (result == 0)
                        {
                            if (etag_value_len == (hash_hex_size - 1))
                            {
                                if (memcmp(etag_value, hash_hex, etag_value_len) == 0)
                                {
                                    *valid = true;
                                }
                                else
                                {
                                    CGUTILS_INFO("Hash does not match:\n %s [ETAG]\n vs %s [COMPUTED]",
                                                 etag_value,
                                                 hash_hex);
                                }
                            }
                            else
                            {
                                CGUTILS_WARN("Hex hash len is %zu, etag len is %zu",
                                             hash_hex_size - 1,
                                             etag_value_len);
                            }

                            CGUTILS_FREE(hash_hex);
                        }
                        else
                        {
                            CGUTILS_ERROR("Error converting hash to hex value: %d", result);
                        }

                        CGUTILS_FREE(hash);
                    }
                    else
                    {
                        CGUTILS_ERROR("Error updating object hashing context: %d", result);
                    }
                }
                else
                {
                    CGUTILS_DEBUG("Skipping Etag value because this is a multi-part object.");
                }

                CGUTILS_FREE(etag_value);
            }
            else
            {
                CGUTILS_WARN("Error getting normalized header value: %d", result);
            }
        }
        else
        {
            CGUTILS_WARN("No headers received");
        }
    }

    return result;
}

static void cg_stp_openstack_all_headers_received(cg_storage_provider_request * const request)
{
    if (request != NULL)
    {
        assert(request->request != NULL);

        if (request->compute_object_hash == true &&
            cgutils_http_request_get_method(request->request) == CGUTILS_HTTP_METHOD_GET)
        {
            /* No need to compute object hash if the Etag header is not present
               or doesn't have the expected value. */
            bool compute = false;

            assert(request->object_hash_ctx != NULL);

            if (request->received_headers != NULL)
            {
                char * etag_value = NULL;
                size_t etag_value_len = 0;

                int result = cg_storage_provider_utils_get_normalized_header_value(request->received_headers,
                                                                                   CG_STP_OPENSTACK_MAGIC_HEADER_NAME_ETAG,
                                                                                   &etag_value,
                                                                                   &etag_value_len);

                if (result == 0)
                {
                    if (etag_value_len == CG_STP_OPENSTACK_OBJECT_HASH_ALGO_LEN)
                    {
                        cgutils_http_header const * number_of_parts = NULL;

                        result = cgutils_http_get_header_by_name(request->received_headers,
                                                                 CG_STP_OPENSTACK_MULTIPART_NUMBER_OF_PARTS,
                                                                 &number_of_parts);

                        if (result == ENOENT)
                        {
                            /* If the CG_STP_OPENSTACK_MULTIPART_NUMBER_OF_PARTS header is present,
                               this object has been uploaded splitted in several segments and
                               the Etag value is of no help here. */
                            compute = true;
                        }
                    }

                    CGUTILS_FREE(etag_value);
                }
                else
                {
                    CGUTILS_DEBUG("NO ETAG!");
                }
            }

            request->compute_object_hash = compute;
        }
    }
}

static size_t cg_stp_openstack_get_single_upload_size(void const * const data)
{
    size_t result = CG_STP_OPENSTACK_MAX_SIMPLE_UP_FILE_SIZE_DEFAULT;

    if (data != NULL)
    {
        cg_stp_openstack_specifics const * const specifics = data;
        result = specifics->max_single_upload_size;
    }

    return result;
}

COMPILER_BLOCK_VISIBILITY_DEFAULT

extern cg_stp_vtable const cg_storage_provider_openstack_vtable;

cg_stp_vtable const cg_storage_provider_openstack_vtable =
{
    .capabilities =
    {
        .chunked_upload = true,
        .object_hashing = true,
    },
    .init = &cg_stp_openstack_init,
    .destroy = &cg_stp_openstack_destroy,
    .parse_specifics = &cg_stp_openstack_parse_specifics,
    .clear_specifics = &cg_stp_openstack_clear_specifics,
    .setup = &cg_stp_openstack_setup,
    .create_container = &cg_stp_openstack_create_container,
    .remove_empty_container = &cg_stp_openstack_remove_empty_container,
    .list_containers = &cg_stp_openstack_list_containers,
    .get_container_stats = &cg_stp_openstack_get_container_stats,
    .list_files = &cg_stp_openstack_list_files,
    .get_file = &cg_stp_openstack_get_file,
    .put_file = &cg_stp_openstack_put_file,
    .delete_file = &cg_stp_openstack_delete_file,
    .put_multipart_init = &cg_stp_openstack_put_multipart_init,
    .put_multipart_part = &cg_stp_openstack_put_multipart_part,
    .put_multipart_finish = &cg_stp_openstack_put_multipart_finish,
    .put_multipart_cancel = &cg_stp_openstack_put_multipart_cancel,
    .is_valid_response_code = &cg_stp_openstack_is_valid_response_code,
    .init_object_hash = &cg_stp_openstack_init_object_hash,
    .update_object_hash = &cg_stp_openstack_update_object_hash,
    .check_object_hash = &cg_stp_openstack_check_object_hash,
    .all_headers_received = &cg_stp_openstack_all_headers_received,
    .get_single_upload_size = &cg_stp_openstack_get_single_upload_size,
};

COMPILER_BLOCK_VISIBILITY_END
