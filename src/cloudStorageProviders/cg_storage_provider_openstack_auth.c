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
#include <time.h>

#include "cg_storage_provider_openstack_common.h"
#include "cg_storage_provider_openstack_auth.h"

#include <cloudutils/cloudutils_xml_writer.h>
#include <cloudutils/cloudutils_xml.h>
#include <cloudutils/cloudutils_json_writer.h>

#define CG_STP_OPENSTACK_AUTH_TOKEN_HEADER "X-Auth-Token"

/* Openstack Identity v1.0 */
#define CG_STP_OPENSTACK_AUTH_USER_HEADER "X-Auth-User"
#define CG_STP_OPENSTACK_AUTH_KEY_HEADER "X-Auth-Key"
#define CG_STP_OPENSTACK_ENDPOINT_HEADER "X-Storage-Url"

/* Openstack Identity v2.0 aka Keystone */
#define CG_STP_OPENSTACK_IDENTITY_V2_0_AUTH_PATH "tokens"
//#define CG_STP_OPENSTACK_IDENTITY_V2_0_AUTH_SERVICE_TYPE "object-store"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_XML_NAMESPACE "http://docs.openstack.org/identity/api/v2.0"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_XML_NAMESPACE_PREFIX "identity"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_XML_GET_TOKEN_ID "identity:token/@id"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_XML_GET_TOKEN_VALIDITY "identity:token/@expires"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_XML_GET_ENDPOINTS "identity:serviceCatalog/identity:service[@type='object-store']/identity:endpoint"

#define CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_ACCESS_ROOT "access"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_TOKEN "token"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_TOKEN_ID "id"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_TOKEN_VALIDITY "expires"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_SERVICE_CATALOG "serviceCatalog"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_SERVICE_TYPE_KEY "type"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_SERVICE_TYPE_OBJECT_STORE "object-store"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_SERVICE_ENDPOINTS "endpoints"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_SERVICE_ENDPOINT_REGION "region"
#define CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_SERVICE_ENDPOINT_URL "publicURL"

/* Openstack Identity v3.0 */
/*#define CG_STP_OPENSTACK_IDENTITY_V3_0_AUTH_TOKEN_REQUEST_HEADER "X-Subject-Token"
  #define CG_STP_OPENSTACK_IDENTITY_V3_0_XML_GET_TOKEN_VALIDITY "identity:token/@expires_at"*/

#define CG_STP_OPENSTACK_AUTH_RETRY_DELAY_AFTER_SERVER_FAILURE (60)

COMPILER_CONST_FUNCTION static char const * cg_stp_openstack_identity_version_to_str(uint8_t const identity_version)
{
    static char const * const strings[] =
        {
            "None",
            "v1.0",
            "v2.0",
        };
    char const * result = NULL;

    COMPILER_STATIC_ASSERT(sizeof strings / sizeof *strings == cg_stp_openstack_identity_version_count,
                           "Openstack identity version array size does not match version count");

    if (identity_version > cg_stp_openstack_identity_version_none &&
        identity_version < cg_stp_openstack_identity_version_count)
    {
        assert(identity_version == cg_stp_openstack_identity_version_1_0 ||
               identity_version == cg_stp_openstack_identity_version_2_0);

        result = strings[identity_version];
    }

    return result;
}

bool cg_stp_openstack_auth_performed(cg_storage_provider_request * const pv_request)
{
    bool result = false;
    cg_stp_openstack_specifics * specifics = NULL;

    assert(pv_request != NULL);
    assert(pv_request->ctx != NULL);
    assert(pv_request->ctx->instance_specifics != NULL);

    specifics = pv_request->ctx->instance_specifics;

    if (specifics->endpoint != NULL &&
        specifics->auth_token != NULL)
    {
        result = true;
    }

    return result;
}

bool cg_stp_openstack_auth_token_is_old(cg_stp_openstack_specifics const * const specifics)
{
    bool result = true;

    assert(specifics != NULL);

    if (specifics->auth_token != NULL &&
        specifics->endpoint != NULL)
    {
        time_t const now = time(NULL);

        if (specifics->auth_token_last_update != (time_t) -1 &&
            now != (time_t) -1 &&
            now >= specifics->auth_token_last_update)
        {
            int64_t const delay = now - specifics->auth_token_last_update;

            if ((uint64_t) delay < specifics->authentication_token_recent_delay)
            {
                result = false;
            }
        }
    }

    return result;
}

static int cg_stp_openstack_auth_setup_timer(cg_stp_openstack_specifics * const specifics,
                                             time_t const token_expiration)
{
    int result = EINVAL;

    if (specifics->auth_timer != NULL)
    {
        time_t delay = (time_t) specifics->authentication_max_lifetime;
        time_t const now = time(NULL);
        result = 0;

        if (now != (time_t) -1 &&
            token_expiration != (time_t) -1)
        {
            time_t const token_lifetime = token_expiration - now;
            assert(now <= token_expiration);

            if ((token_lifetime / 2) < delay)
            {
                delay = token_lifetime / 2;
            }
        }

        if (result == 0)
        {
            struct timeval const timer =
                {
                    .tv_sec = delay
                };

            result = cgutils_event_enable(specifics->auth_timer,
                                          &timer);

            if (result != 0)
            {
                CGUTILS_ERROR("Error enabling timer: %d", result);
            }
        }
    }

    return result;
}

static int cg_stp_openstack_auth_update_infos(cg_stp_openstack_specifics * const specifics,
                                              char const * const auth_token,
                                              time_t const token_validity,
                                              char const * const storage_url)
{
    int result = 0;
    assert(specifics != NULL);
    assert(auth_token != NULL);
    assert(storage_url != NULL);

    CGUTILS_FREE(specifics->auth_token);
    specifics->auth_token = cgutils_strdup(auth_token);

    if (specifics->auth_token != NULL)
    {
        CGUTILS_FREE(specifics->endpoint);
        specifics->endpoint = cgutils_strdup(storage_url);

        if (specifics->endpoint != NULL)
        {
            cg_stp_openstack_auth_setup_timer(specifics,
                                              token_validity);
            result = 0;
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for endpoint: %d", result);
        }
    }
    else
    {
        result = ENOMEM;
        CGUTILS_ERROR("Error allocating memory for authorization: %d", result);
    }

    return result;
}

static int cg_stp_openstack_auth_refresh_v1_0_done(int const status,
                                                   void * cb_data)
{
    int result = status;
    bool fatal_error = false;
    assert(cb_data != NULL);
    cg_storage_provider_request * pv_request = cb_data;
    cg_stp_openstack_specifics * const specifics = pv_request->ctx->instance_specifics;
    cg_stp_openstack_provider_data * const pvd = pv_request->ctx->provider_data;
    assert(specifics != NULL);
    assert(pvd != NULL);

    if (result == 0)
    {
        /* X-Auth-Token and X-Storage-Url */
        cgutils_http_header const * auth_token = NULL;

        result = cgutils_http_get_header_by_name(pv_request->received_headers,
                                                 CG_STP_OPENSTACK_AUTH_TOKEN_HEADER,
                                                 &auth_token);

        if (result == 0)
        {
            if (auth_token->value != NULL)
            {
                cgutils_http_header const * storage_url = NULL;

                result = cgutils_http_get_header_by_name(pv_request->received_headers,
                                                         CG_STP_OPENSTACK_ENDPOINT_HEADER,
                                                         &storage_url);

                if (result == 0)
                {
                    if (storage_url->value != NULL)
                    {
                        result = cg_stp_openstack_auth_update_infos(specifics,
                                                                    auth_token->value,
                                                                    (time_t) -1,
                                                                    storage_url->value);
                    }
                    else
                    {
                        CGUTILS_WARN("Invalid endpoint value received");
                    }
                }
                else
                {
                    CGUTILS_WARN("Error getting " CG_STP_OPENSTACK_ENDPOINT_HEADER " header from response: %d", result);
                }
            }
            else
            {
                CGUTILS_WARN("Invalid endpoint value received");
            }
        }
        else
        {
            CGUTILS_WARN("Error getting " CG_STP_OPENSTACK_AUTH_TOKEN_HEADER " header from response: %d", result);
        }
    }
    else if (result == EACCES)
    {
        fatal_error = true;

        CGUTILS_ERROR("Authentication error, please check the credentials for the account %s.",
                      specifics->username);
    }
    else
    {
        CGUTILS_ERROR("Error in Authentication request for the account %s: %d",
                      specifics->username,
                      result);

    }

    if (result != 0)
    {
        if (fatal_error == true)
        {
            cg_stp_openstack_auth_setup_timer(specifics,
                                              (time_t) -1);
        }
        else
        {
            time_t const next_retry_after_failure = time(NULL) + CG_STP_OPENSTACK_AUTH_RETRY_DELAY_AFTER_SERVER_FAILURE;

            cg_stp_openstack_auth_setup_timer(specifics,
                                              next_retry_after_failure);
        }
    }

    specifics->auth_refresh_in_progress = false;
    specifics->auth_token_last_update = time(NULL);

    if (specifics->init == true)
    {
        cg_storage_manager_data_set_provider_init_finished(pvd->data, result);
    }

    cg_storage_provider_request_ctx_free(pv_request->ctx), pv_request = NULL;

    return result;
}

static int cg_stp_openstack_auth_refresh_v1_0(cg_stp_openstack_provider_data * const pvd,
                                              cg_stp_openstack_specifics * const specifics)
{
    int result = 0;
    char * path = NULL;
    assert(pvd != NULL);
    assert(specifics != NULL);
    assert(specifics->identity_version == cg_stp_openstack_identity_version_1_0);
    assert(cg_stp_openstack_identity_version_to_str(cg_stp_openstack_identity_version_1_0) != NULL);

    result = cgutils_asprintf(&path,
                              "/%s",
                              cg_stp_openstack_identity_version_to_str(cg_stp_openstack_identity_version_1_0));

    if (result == 0)
    {
        cg_storage_provider_request * pv_request = NULL;

        result = cg_storage_provider_single_request_init(pvd->provider,
                                                         specifics,
                                                         CG_STP_UTILS_NO_ID,
                                                         cg_storage_provider_request_callback_type_none,
                                                         CG_STP_UTILS_NO_STATUS_CB,
                                                         CG_STP_UTILS_NO_LIST_CB,
                                                         CG_STP_UTILS_NO_PUT_CB,
                                                         CG_STP_UTILS_NO_GET_CB,
                                                         CG_STP_UTILS_NO_CONTAINER_STATS_CB,
                                                         pvd,
                                                         &pv_request);

        if (result == 0)
        {
            /* do a GET /v1.0 HTTP/1.1 request on auth_endpoint
               with X-Auth-User: username and
               X-Auth-Key: api_access_key */

            cgutils_llist * headers = NULL;

            result = cgutils_llist_create(&headers);

            if (result == 0)
            {
                result = cgutils_http_add_header_to_list_dup(headers,
                                                             CG_STP_OPENSTACK_AUTH_USER_HEADER,
                                                             specifics->username);

                if (result == 0)
                {
                    result = cgutils_http_add_header_to_list_dup(headers,
                                                                 CG_STP_OPENSTACK_AUTH_KEY_HEADER,
                                                                 specifics->api_access_key);


                    if (result == 0)
                    {
                        assert(specifics->auth_endpoint != NULL);

                        pv_request->raw_request_cb = &cg_stp_openstack_auth_refresh_v1_0_done;
                        pv_request->request_cb_data = pv_request;

                        result = cg_stp_openstack_send_get_request(pv_request,
                                                                   specifics->auth_endpoint,
                                                                   path,
                                                                   headers,
                                                                   CG_STP_RAW_RESPONSE,
                                                                   CG_STP_NO_OPT_HTTP_CALLBACKS,
                                                                   CG_STP_NO_OPT_HTTP_TIMEOUTS);
                        headers = NULL;

                        if (result != 0)
                        {
                            CGUTILS_ERROR("Error sending Auth Refresh request: %d", result);
                            cg_storage_provider_request_ctx_free(pv_request->ctx), pv_request = NULL;
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error adding Auth Key header: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error adding Auth User header: %d", result);
                }

                if (result != 0)
                {
                    cgutils_llist_free(&headers, &cgutils_http_header_delete);
                }
            }
            else
            {
                CGUTILS_ERROR("Error creating headers list: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating pv_request for Auth Refresh request: %d", result);
        }

        CGUTILS_FREE(path);
    }
    else
    {
        CGUTILS_ERROR("Error allocating path for request: %d", result);
    }

    return result;
}

static int cg_stp_openstack_auth_refresh_v2_0_xml_extract_token(cgutils_xml_reader const * const response,
                                                                char ** const token_id,
                                                                char ** const token_expires)
{
    int result = 0;
    assert(token_id != NULL);
    assert(token_expires != NULL);

    result = cgutils_xml_reader_get_string(response,
                                           CG_STP_OPENSTACK_IDENTITY_V2_0_XML_GET_TOKEN_ID,
                                           token_id);

    if (result == 0)
    {
        result = cgutils_xml_reader_get_string(response,
                                               CG_STP_OPENSTACK_IDENTITY_V2_0_XML_GET_TOKEN_VALIDITY,
                                               token_expires);
        if (result != 0)
        {
            CGUTILS_WARN("Error getting token validity: %d", result);
            CGUTILS_FREE(*token_id);
        }
    }
    else
    {
        CGUTILS_WARN("Error getting token id: %d", result);
    }

    return result;
}

static int cg_stp_openstack_auth_refresh_v2_0_json_extract_token(cgutils_json_reader * const response,
                                                                 char ** const token_id,
                                                                 char ** const token_expires)
{
    int result = 0;
    cgutils_json_reader * token = NULL;

    CGUTILS_ASSERT(token_id != NULL);
    CGUTILS_ASSERT(token_expires != NULL);

    result = cgutils_json_reader_from_key(response,
                                          CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_TOKEN,
                                          &token);

    if (result == 0)
    {
        CGUTILS_ASSERT(token != NULL);

        result = cgutils_json_reader_get_string(token,
                                                CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_TOKEN_ID,
                                                token_id);

        if (result == 0)
        {
            result = cgutils_json_reader_get_string(token,
                                                    CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_TOKEN_VALIDITY,
                                                    token_expires);
            if (result != 0)
            {
                CGUTILS_WARN("Error getting token validity: %d", result);
                CGUTILS_FREE(*token_id);
            }
        }
        else
        {
            CGUTILS_WARN("Error getting token id: %d", result);
        }

        cgutils_json_reader_free(token), token = NULL;
    }
    else
    {
        CGUTILS_WARN("Error getting token: %d", result);
    }

    return result;
}

static int cg_stp_openstack_auth_refresh_v2_0_xml_extract_endpoint(cg_stp_openstack_specifics * const specifics,
                                                                   cgutils_xml_reader * const response,
                                                                   char ** const endpoint_str)
{
    int result = 0;
    cgutils_llist * endpoints = NULL;

    assert(specifics != NULL);
    assert(response != NULL);
    assert(endpoint_str != NULL);

    result = cgutils_xml_reader_get_all(response,
                                        CG_STP_OPENSTACK_IDENTITY_V2_0_XML_GET_ENDPOINTS,
                                        &endpoints);

    if (result == 0)
    {
        size_t const endpoints_count = cgutils_llist_get_count(endpoints);

        cgutils_xml_reader const * endpoint_xml = NULL;

        if (specifics->preferred_region != NULL &&
            endpoints_count > 1)
        {
            for (cgutils_llist_elt * endpoint_elt = cgutils_llist_get_first(endpoints);
                 endpoint_elt != NULL &&
                     endpoint_xml == NULL;
                 endpoint_elt = cgutils_llist_elt_get_next(endpoint_elt))
            {
                char * region = NULL;

                cgutils_xml_reader * temp_endpoint_xml = cgutils_llist_elt_get_object(endpoint_elt);

                result = cgutils_xml_reader_get_string(temp_endpoint_xml,
                                                       "@region",
                                                       &region);

                if (result == 0)
                {
                    if (strcmp(region, specifics->preferred_region) == 0)
                    {
                        endpoint_xml = temp_endpoint_xml;
                    }

                    CGUTILS_FREE(region);
                }
            }
        }

        if (endpoint_xml == NULL)
        {
            cgutils_llist_elt * endpoint_elt = cgutils_llist_get_first(endpoints);

            if (endpoint_elt != NULL)
            {
                endpoint_xml = cgutils_llist_elt_get_object(endpoint_elt);
            }
            else
            {
                result = ENOENT;
            }
        }

        if (result == 0)
        {
            result = cgutils_xml_reader_get_string(endpoint_xml,
                                                   "@publicURL",
                                                   endpoint_str);

            if (result != 0)
            {
                CGUTILS_WARN("Error getting endpoint public URL: %d", result);
            }
        }
        else
        {
            CGUTILS_WARN("Error getting endpoint elt: %d", result);
        }

        cgutils_llist_free(&endpoints, &cgutils_xml_reader_delete);
    }
    else if (result == ENOENT)
    {
        CGUTILS_ERROR("This provider does not supply any object-store service for this tenant");
    }
    else
    {
        CGUTILS_WARN("Error getting endpoints list: %d", result);
    }

    return result;
}

static int cg_stp_openstack_auth_refresh_v2_0_json_extract_endpoint(cg_stp_openstack_specifics * const specifics,
                                                                    cgutils_json_reader * const response,
                                                                    char ** const endpoint_str)
{
    int result = 0;
    cgutils_llist * services = NULL;
    CGUTILS_ASSERT(specifics != NULL);
    CGUTILS_ASSERT(response != NULL);
    CGUTILS_ASSERT(endpoint_str != NULL);

    result = cgutils_json_reader_get_all(response,
                                         CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_SERVICE_CATALOG,
                                         &services);

    if (result == 0)
    {
        cgutils_json_reader * object_storage_service = NULL;

        for (cgutils_llist_elt * service_elt = cgutils_llist_get_first(services);
             result == 0 &&
                 service_elt != NULL &&
                 object_storage_service == NULL;
             service_elt = cgutils_llist_elt_get_next(service_elt))
        {
            cgutils_json_reader * current_service = cgutils_llist_elt_get_object(service_elt);
            char * type = NULL;

            result = cgutils_json_reader_get_string(current_service,
                                                    CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_SERVICE_TYPE_KEY,
                                                    &type);

            if (result == 0)
            {
                CGUTILS_ASSERT(type != NULL);

                if (strcmp(type, CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_SERVICE_TYPE_OBJECT_STORE) == 0)
                {
                    /* got the swift service */
                    object_storage_service = current_service;
                }

                CGUTILS_FREE(type);
            }
            else if (result == ENOENT)
            {
                /* no type, skipping */
                result = 0;
            }
            else
            {
                CGUTILS_ERROR("Error getting type from service: %d",
                              result);
            }
        }

        if (result == 0 &&
            object_storage_service == NULL)
        {
            result = ENOENT;
        }

        if (result == 0)
        {
            cgutils_llist * endpoints = NULL;

            result = cgutils_json_reader_get_all(object_storage_service,
                                                 CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_SERVICE_ENDPOINTS,
                                                 &endpoints);

            if (result == 0)
            {
                size_t const endpoints_count = cgutils_llist_get_count(endpoints);
                cgutils_json_reader * selected_endpoint = NULL;

                if (specifics->preferred_region != NULL &&
                    endpoints_count > 1)
                {
                    for (cgutils_llist_elt * endpoint_elt = cgutils_llist_get_first(endpoints);
                         result == 0 &&
                             endpoint_elt != NULL &&
                             selected_endpoint == NULL;
                         endpoint_elt = cgutils_llist_elt_get_next(endpoint_elt))
                    {
                        cgutils_json_reader * current_endpoint = cgutils_llist_elt_get_object(endpoint_elt);
                        char * region = NULL;

                        result = cgutils_json_reader_get_string(current_endpoint,
                                                                CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_SERVICE_ENDPOINT_REGION,
                                                                &region);

                        if (result == 0)
                        {
                            CGUTILS_ASSERT(region != NULL);

                            if (strcmp(region, specifics->preferred_region) == 0)
                            {
                                selected_endpoint = current_endpoint;
                            }

                            CGUTILS_FREE(region);
                        }
                        else if (result == ENOENT)
                        {
                            /* no region, just skip over */
                            result = 0;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error getting region value: %d",
                                          result);
                        }
                    }
                }

                if (result == 0 &&
                    selected_endpoint == NULL)
                {
                    cgutils_llist_elt * endpoint_elt = cgutils_llist_get_first(endpoints);

                    if (endpoint_elt != NULL)
                    {
                        selected_endpoint = cgutils_llist_elt_get_object(endpoint_elt);
                    }
                    else
                    {
                            result = ENOENT;
                    }

                }

                if (result == 0)
                {
                    result = cgutils_json_reader_get_string(selected_endpoint,
                                                            CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_SERVICE_ENDPOINT_URL,
                                                            endpoint_str);

                    if (result != 0)
                    {
                        CGUTILS_WARN("Error getting endpoint public URL: %d", result);
                    }
                }
                else
                {
                    CGUTILS_WARN("Error getting endpoint elt: %d", result);
                }

                cgutils_llist_free(&endpoints, &cgutils_json_reader_delete);
            }
            else if (result == ENOENT)
            {
                CGUTILS_ERROR("This provider does not supply any endpoints for the object-store service.");
            }
            else
            {
                CGUTILS_WARN("Error getting endpoints list: %d", result);
            }
        }
        else if (result == ENOENT)
        {
            CGUTILS_ERROR("This provider does not supply any object-store service for this tenant");
        }
        else
        {
            CGUTILS_WARN("Error getting services list: %d", result);
        }

        cgutils_llist_free(&services, &cgutils_json_reader_delete);
    }

    return result;
}

static int cg_stp_openstack_auth_refresh_v2_0_done(cg_stp_openstack_specifics * const specifics,
                                                   char const * const token_id,
                                                   char const * const validity_str,
                                                   char const * const endpoint)
{
    int result = 0;
    time_t token_validity = -1;

    CGUTILS_ASSERT(specifics != NULL);
    CGUTILS_ASSERT(token_id != NULL);
    CGUTILS_ASSERT(endpoint != NULL);

    result = cgutils_xml_time_from_str(validity_str,
                                       &token_validity);

    if (result == 0)
    {
        result = cg_stp_openstack_auth_update_infos(specifics,
                                                    token_id,
                                                    token_validity,
                                                    endpoint);

        if (result == 0)
        {

        }
        else
        {
            CGUTILS_WARN("Error updating auth infos: %d", result);
        }
    }
    else
    {
        CGUTILS_WARN("Error parsing token validity: %d", result);
    }

    return result;
}

static int cg_stp_openstack_auth_refresh_v2_0_xml_done(int const status,
                                                       cgutils_xml_reader * response,
                                                       void * cb_data)
{
    int result = status;
    bool fatal_error = false;
    cg_storage_provider_request * pv_request = cb_data;
    assert(cb_data != NULL);
    cg_stp_openstack_specifics * const specifics = pv_request->ctx->instance_specifics;
    cg_stp_openstack_provider_data * const pvd = pv_request->ctx->provider_data;
    assert(specifics != NULL);
    assert(pvd != NULL);
    char const * tenant_prop_name = NULL;
    char const * tenant_prop_value = NULL;

    if (specifics->tenant_name != NULL &&
        strlen(specifics->tenant_name) > 0)
    {
        tenant_prop_name = "tenantName";
        tenant_prop_value = specifics->tenant_name;
    }
    else
    {
        tenant_prop_name = "tenantId";
        tenant_prop_value = specifics->tenant_id;
    }

    if (result == 0)
    {
        result = cgutils_xml_reader_register_namespace(response,
                                                       CG_STP_OPENSTACK_IDENTITY_V2_0_XML_NAMESPACE_PREFIX,
                                                       CG_STP_OPENSTACK_IDENTITY_V2_0_XML_NAMESPACE);

        if (result == 0)
        {
            char * token_id = NULL;
            char * validity_str = NULL;

            result = cg_stp_openstack_auth_refresh_v2_0_xml_extract_token(response,
                                                                          &token_id,
                                                                          &validity_str);
            if (result == 0)
            {
                char * endpoint = NULL;

                result = cg_stp_openstack_auth_refresh_v2_0_xml_extract_endpoint(specifics,
                                                                                 response,
                                                                                 &endpoint);

                if (result == 0)
                {
                    result = cg_stp_openstack_auth_refresh_v2_0_done(specifics,
                                                                     token_id,
                                                                     validity_str,
                                                                     endpoint);

                    CGUTILS_FREE(endpoint);
                }
                else
                {
                    CGUTILS_WARN("Error getting endpoint from response: %d", result);
                }

                CGUTILS_FREE(token_id);
                CGUTILS_FREE(validity_str);
            }
            else
            {
                CGUTILS_WARN("Error extracting token: %d", result);
            }
        }
        else
        {
            CGUTILS_WARN("Error registering namespace: %d", result);
        }
    }
    else if (result == EACCES)
    {
        fatal_error = true;

        CGUTILS_ERROR("Authentication error, please check the credentials for the account %s and %s %s.",
                      specifics->username,
                      tenant_prop_name,
                      tenant_prop_value);
    }
    else
    {
        CGUTILS_ERROR("Error in Authentication request for the account %s and %s %s.: %d",
                      specifics->username,
                      tenant_prop_name,
                      tenant_prop_value,
                      result);
    }

    if (result != 0)
    {
        if (fatal_error == true)
        {
            cg_stp_openstack_auth_setup_timer(specifics,
                                              (time_t) -1);
        }
        else
        {
            time_t const next_retry_after_failure = time(NULL) + CG_STP_OPENSTACK_AUTH_RETRY_DELAY_AFTER_SERVER_FAILURE;

            cg_stp_openstack_auth_setup_timer(specifics,
                                              next_retry_after_failure);
        }
    }

    specifics->auth_refresh_in_progress = false;
    specifics->auth_token_last_update = time(NULL);

    if (specifics->init == true)
    {
        cg_storage_manager_data_set_provider_init_finished(pvd->data, result);
    }

    cg_storage_provider_request_ctx_free(pv_request->ctx), pv_request = NULL;

    return result;
}

static int cg_stp_openstack_auth_refresh_v2_0_json_done(int const status,
                                                        cgutils_json_reader * response,
                                                        void * cb_data)
{
    int result = status;
    bool fatal_error = false;
    cg_storage_provider_request * pv_request = cb_data;
    assert(cb_data != NULL);
    cg_stp_openstack_specifics * const specifics = pv_request->ctx->instance_specifics;
    cg_stp_openstack_provider_data * const pvd = pv_request->ctx->provider_data;
    assert(specifics != NULL);
    assert(pvd != NULL);
    char const * tenant_prop_name = NULL;
    char const * tenant_prop_value = NULL;

    if (specifics->tenant_name != NULL &&
        strlen(specifics->tenant_name) > 0)
    {
        tenant_prop_name = "tenantName";
        tenant_prop_value = specifics->tenant_name;
    }
    else
    {
        tenant_prop_name = "tenantId";
        tenant_prop_value = specifics->tenant_id;
    }

    if (result == 0)
    {
        cgutils_json_reader * access_elt = NULL;

        result = cgutils_json_reader_from_key(response,
                                              CG_STP_OPENSTACK_IDENTITY_V2_0_JSON_GET_ACCESS_ROOT,
                                              &access_elt);

        if (result == 0)
        {
            char * token_id = NULL;
            char * validity_str = NULL;

            result = cg_stp_openstack_auth_refresh_v2_0_json_extract_token(access_elt,
                                                                           &token_id,
                                                                           &validity_str);
            if (result == 0)
            {
                char * endpoint = NULL;

                result = cg_stp_openstack_auth_refresh_v2_0_json_extract_endpoint(specifics,
                                                                                  access_elt,
                                                                                  &endpoint);

                if (result == 0)
                {
                    result = cg_stp_openstack_auth_refresh_v2_0_done(specifics,
                                                                     token_id,
                                                                     validity_str,
                                                                     endpoint);

                    CGUTILS_FREE(endpoint);
                }
                else
                {
                    CGUTILS_WARN("Error getting endpoint from response: %d", result);
                }

                CGUTILS_FREE(token_id);
                CGUTILS_FREE(validity_str);

            }
            else
            {
                CGUTILS_WARN("Error extracting token: %d", result);
            }

            cgutils_json_reader_free(access_elt), access_elt = NULL;
        }
        else
        {
            CGUTILS_WARN("Error extracting the root 'part' while looking for the token: %d",
                         result);
        }
    }
    else if (result == EACCES)
    {
        fatal_error = true;

        CGUTILS_ERROR("Authentication error, please check the credentials for the account %s and %s %s.",
                      specifics->username,
                      tenant_prop_name,
                      tenant_prop_value);
    }
    else
    {
        CGUTILS_ERROR("Error in Authentication request for the account %s and %s %s.: %d",
                      specifics->username,
                      tenant_prop_name,
                      tenant_prop_value,
                      result);
    }

    if (result != 0)
    {
        if (fatal_error == true)
        {
            cg_stp_openstack_auth_setup_timer(specifics,
                                              (time_t) -1);
        }
        else
        {
            time_t const next_retry_after_failure = time(NULL) + CG_STP_OPENSTACK_AUTH_RETRY_DELAY_AFTER_SERVER_FAILURE;

            cg_stp_openstack_auth_setup_timer(specifics,
                                              next_retry_after_failure);
        }
    }

    specifics->auth_refresh_in_progress = false;
    specifics->auth_token_last_update = time(NULL);

    if (specifics->init == true)
    {
        cg_storage_manager_data_set_provider_init_finished(pvd->data, result);
    }

    cg_storage_provider_request_ctx_free(pv_request->ctx), pv_request = NULL;

    return result;
}

static int cg_stp_openstack_auth_refresh_v2_0_get_auth_payload_xml(cg_stp_openstack_specifics * const specifics,
                                                                   char ** const payload,
                                                                   size_t * const payload_size)
{
    int result = 0;
    cgutils_xml_writer * writer = NULL;

    assert(specifics != NULL);
    assert(payload != NULL);
    assert(payload_size != NULL);
    assert(specifics->identity_version == cg_stp_openstack_identity_version_2_0);
    assert(cg_stp_openstack_identity_version_to_str(cg_stp_openstack_identity_version_2_0) != NULL);

    assert(specifics->username != NULL);
    assert(specifics->password != NULL);
    assert(specifics->tenant_name != NULL ||
           specifics->tenant_id != NULL);

    assert(specifics->auth_format == cg_stp_openstack_identity_auth_format_xml);

    result = cgutils_xml_writer_new(&writer);

    if (result == 0)
    {
        cgutils_xml_writer_element * root = NULL;

        result = cgutils_xml_writer_create_root(writer,
                                                "auth",
                                                &root);

        if (result == 0)
        {
            result = cgutils_xml_writer_element_set_ns(root,
                                                       CG_STP_OPENSTACK_IDENTITY_V2_0_XML_NAMESPACE,
                                                       CG_STP_OPENSTACK_IDENTITY_V2_0_XML_NAMESPACE_PREFIX);

            if (result == 0)
            {
                char const * tenant_prop_name = NULL;
                char const * tenant_prop_value = NULL;

                if (specifics->tenant_name != NULL &&
                    strlen(specifics->tenant_name) > 0)
                {
                    tenant_prop_name = "tenantName";
                    tenant_prop_value = specifics->tenant_name;
                }
                else
                {
                    tenant_prop_name = "tenantId";
                    tenant_prop_value = specifics->tenant_id;
                }

                result = cgutils_xml_writer_element_add_prop(root,
                                                             tenant_prop_name,
                                                             tenant_prop_value);

                if (result == 0)
                {
                    cgutils_xml_writer_element * password_cred_elt = NULL;

                    result = cgutils_xml_writer_element_add_child(root,
                                                                  "passwordCredentials",
                                                                  NULL,
                                                                  &password_cred_elt);

                    if (result == 0)
                    {
                        result = cgutils_xml_writer_element_add_prop(password_cred_elt,
                                                                     "username",
                                                                     specifics->username);

                        if (result == 0)
                        {
                            result = cgutils_xml_writer_element_add_prop(password_cred_elt,
                                                                         "password",
                                                                         specifics->password);

                            if (result == 0)
                            {
                                result = cgutils_xml_writer_get_output(writer,
                                                                       payload,
                                                                       payload_size);

                                if (result != 0)
                                {
                                    CGUTILS_ERROR("Error getting XML authentication payload: %d", result);
                                }
                            }
                            else
                            {
                                CGUTILS_ERROR("Error creating password attribute: %d", result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error creating username attribute: %d", result);
                        }

                        cgutils_xml_writer_element_release(password_cred_elt), password_cred_elt = NULL;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating passwordCredentials node: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error creating %s attribute: %d", tenant_prop_name, result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error setting root namespace to identity: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating root node: %d", result);
        }

        cgutils_xml_writer_free(writer), writer = NULL;
    }
    else
    {
        CGUTILS_ERROR("Error creating writer element: %d", result);
    }

    return result;
}

static int cg_stp_openstack_auth_refresh_v2_0_get_auth_payload_json(cg_stp_openstack_specifics * const specifics,
                                                                    char ** const payload,
                                                                    size_t * const payload_size)
{
    int result = 0;
    cgutils_json_writer * writer = NULL;

    assert(specifics != NULL);
    assert(payload != NULL);
    assert(payload_size != NULL);
    assert(specifics->identity_version == cg_stp_openstack_identity_version_2_0);
    assert(cg_stp_openstack_identity_version_to_str(cg_stp_openstack_identity_version_2_0) != NULL);

    assert(specifics->username != NULL);
    assert(specifics->password != NULL);
    assert(specifics->tenant_name != NULL ||
           specifics->tenant_id != NULL);

    assert(specifics->auth_format == cg_stp_openstack_identity_auth_format_json);

    result = cgutils_json_writer_new(&writer);

    if (result == 0)
    {
        cgutils_json_writer_element * root = cgutils_json_writer_get_root(writer);
        assert(root != NULL);
        cgutils_json_writer_element * auth = NULL;

        result = cgutils_json_writer_element_add_child(root,
                                                       "auth",
                                                       &auth);

        if (result == 0)
        {
            assert(auth != NULL);

            char const * tenant_prop_name = NULL;
            char const * tenant_prop_value = NULL;

            if (specifics->tenant_name != NULL &&
                strlen(specifics->tenant_name) > 0)
            {
                tenant_prop_name = "tenantName";
                tenant_prop_value = specifics->tenant_name;
            }
            else
            {
                tenant_prop_name = "tenantId";
                tenant_prop_value = specifics->tenant_id;
            }

            result = cgutils_json_writer_element_add_string_prop(auth,
                                                                 tenant_prop_name,
                                                                 tenant_prop_value);

            if (result == 0)
            {
                cgutils_json_writer_element * password_cred_elt = NULL;

                result = cgutils_json_writer_element_add_child(auth,
                                                               "passwordCredentials",
                                                               &password_cred_elt);

                if (result == 0)
                {
                    assert(password_cred_elt != NULL);

                    result = cgutils_json_writer_element_add_string_prop(password_cred_elt,
                                                                         "username",
                                                                         specifics->username);

                    if (result == 0)
                    {
                        result = cgutils_json_writer_element_add_string_prop(password_cred_elt,
                                                                             "password",
                                                                             specifics->password);

                        if (result == 0)
                        {
                            result = cgutils_json_writer_get_output(writer,
                                                                    payload,
                                                                    payload_size);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error getting JSON authentication payload: %d", result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error creating password attribute: %d", result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating username attribute: %d", result);
                    }

                    cgutils_json_writer_element_release(password_cred_elt), password_cred_elt = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error creating passwordCredentials node: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error creating %s attribute: %d", tenant_prop_name, result);
            }

            cgutils_json_writer_element_release(auth), auth = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error creating auth element: %d", result);
        }

        cgutils_json_writer_element_release(root), root = NULL;
        cgutils_json_writer_free(writer), writer = NULL;
    }
    else
    {
        CGUTILS_ERROR("Error creating writer element: %d", result);
    }

    return result;
}

static int cg_stp_openstack_auth_refresh_v2_0_get_auth_payload(cg_stp_openstack_specifics * const specifics,
                                                               char ** const payload,
                                                               size_t * const payload_size)
{
    int result = 0;

    assert(specifics != NULL);
    assert(payload != NULL);
    assert(payload_size != NULL);
    assert(specifics->identity_version == cg_stp_openstack_identity_version_2_0);
    assert(cg_stp_openstack_identity_version_to_str(cg_stp_openstack_identity_version_2_0) != NULL);

    assert(specifics->username != NULL);
    assert(specifics->password != NULL);
    assert(specifics->tenant_name != NULL ||
           specifics->tenant_id != NULL);

    if (specifics->auth_format == cg_stp_openstack_identity_auth_format_xml)
    {
        result = cg_stp_openstack_auth_refresh_v2_0_get_auth_payload_xml(specifics,
                                                                         payload,
                                                                         payload_size);

    }
    else if (specifics->auth_format == cg_stp_openstack_identity_auth_format_json)
    {
        result = cg_stp_openstack_auth_refresh_v2_0_get_auth_payload_json(specifics,
                                                                          payload,
                                                                          payload_size);
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

static int cg_stp_openstack_auth_refresh_v2_0(cg_stp_openstack_provider_data * const data,
                                              cg_stp_openstack_specifics * const specifics)
{
    int result = 0;
    char * str = NULL;
    size_t str_size = 0;

    assert(data != NULL);
    assert(specifics != NULL);
    assert(specifics->identity_version == cg_stp_openstack_identity_version_2_0);
    assert(cg_stp_openstack_identity_version_to_str(cg_stp_openstack_identity_version_2_0) != NULL);

    assert(specifics->username != NULL);
    assert(specifics->password != NULL);
    assert(specifics->tenant_name != NULL ||
           specifics->tenant_id != NULL);
    assert(specifics->auth_endpoint != NULL);

    result = cg_stp_openstack_auth_refresh_v2_0_get_auth_payload(specifics,
                                                                 &str,
                                                                 &str_size);

    if (result == 0)
    {
        char * path = NULL;

        result = cgutils_asprintf(&path,
                                  "/%s/" CG_STP_OPENSTACK_IDENTITY_V2_0_AUTH_PATH,
                                  cg_stp_openstack_identity_version_to_str(cg_stp_openstack_identity_version_2_0));

        if (result == 0)
        {
            cg_storage_provider_request * pv_request = NULL;

            result = cg_storage_provider_single_request_init(data->provider,
                                                             specifics,
                                                             CG_STP_UTILS_NO_ID,
                                                             cg_storage_provider_request_callback_type_none,
                                                             CG_STP_UTILS_NO_STATUS_CB,
                                                             CG_STP_UTILS_NO_LIST_CB,
                                                             CG_STP_UTILS_NO_PUT_CB,
                                                             CG_STP_UTILS_NO_GET_CB,
                                                             CG_STP_UTILS_NO_CONTAINER_STATS_CB,
                                                             data,
                                                             &pv_request);

            if (result == 0)
            {
                /* Add headers:
                   - Accept: application/xml
                   - Content-Type: application/xml
                */
                cgutils_llist * headers = NULL;

                result = cgutils_llist_create(&headers);

                if (result == 0)
                {
                    char const * content_type = NULL;
                    char const * accept_type = NULL;
                    cg_stp_response_format response_format = CG_STP_RESPONSE_FORMAT_XML;

                    if (specifics->auth_format == cg_stp_openstack_identity_auth_format_xml)
                    {
                        content_type = "application/xml";
                        accept_type = "application/xml";
                        response_format = CG_STP_RESPONSE_FORMAT_XML;
                    }
                    else
                    {
                        content_type = "application/json";
                        accept_type = "application/json";
                        response_format = CG_STP_RESPONSE_FORMAT_JSON;
                    }


                    result = cgutils_http_add_header_to_list_dup(headers,
                                                                 "Accept",
                                                                 accept_type);

                    if (result == 0)
                    {
                        result = cgutils_http_add_header_to_list_dup(headers,
                                                                     "Content-Type",
                                                                     content_type);
                        if (result == 0)
                        {
                            /* do a POST /v2.0/tokens HTTP/1.1 request on auth_endpoint */

                            if (specifics->auth_format == cg_stp_openstack_identity_auth_format_xml)
                            {
                                pv_request->xml_request_cb = &cg_stp_openstack_auth_refresh_v2_0_xml_done;
                            }
                            else
                            {
                                pv_request->json_request_cb = &cg_stp_openstack_auth_refresh_v2_0_json_done;
                            }

                            pv_request->request_cb_data = pv_request;

                            /* Should be done with source memory IO */
                            pv_request->payload = str;

                            result = cg_stp_openstack_send_post_request(pv_request,
                                                                        specifics->auth_endpoint,
                                                                        path,
                                                                        headers,
                                                                        str,
                                                                        str_size,
                                                                        response_format,
                                                                        CG_STP_NO_OPT_HTTP_CALLBACKS,
                                                                        CG_STP_NO_OPT_HTTP_TIMEOUTS,
                                                                        CG_STP_OPENSTACK_NO_OPT_HTTP_CHUNKED_TRANSFER);
                            str = NULL;

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error sending Auth Refresh request: %d", result);
                                cg_storage_provider_request_ctx_free(pv_request->ctx), pv_request = NULL;
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error adding Content-Type header: %d", result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error adding Accept header: %d", result);
                    }

                    if (result != 0)
                    {
                        cgutils_llist_free(&headers, &cgutils_http_header_delete);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error creating headers list: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error allocating pv_request for Auth Refresh request: %d", result);
            }

            CGUTILS_FREE(path);
        }
        else
        {
            CGUTILS_ERROR("Error allocating memory for path: %d", result);
        }

        if (str != NULL)
        {
            CGUTILS_FREE(str);
        }
    }
    else
    {
        CGUTILS_ERROR("Error getting authentication payload: %d", result);
    }

    return result;
}

int cg_stp_openstack_auth_refresh(cg_stp_openstack_provider_data * const pvd,
                                  cg_stp_openstack_specifics * const specifics)
{
    int result = 0;
    assert(pvd != NULL);
    assert(specifics != NULL);

    if (specifics->auth_refresh_in_progress == false)
    {
        specifics->auth_refresh_in_progress = true;

        switch(specifics->identity_version)
        {
        case cg_stp_openstack_identity_version_1_0:
            result = cg_stp_openstack_auth_refresh_v1_0(pvd, specifics);
            break;
        case cg_stp_openstack_identity_version_2_0:
            result = cg_stp_openstack_auth_refresh_v2_0(pvd, specifics);
            break;
        default:
            CGUTILS_ERROR("Identity version not supported: %d",
                          specifics->identity_version);
        }

        if (result != 0)
        {
            specifics->auth_refresh_in_progress = false;
            CGUTILS_ERROR("Error refreshing auth data: %d", result);
        }
    }

    return result;
}

int cg_stp_openstack_auth_add(cg_storage_provider_request * const pv_request,
                              cg_stp_openstack_specifics const * const specifics,
                              cgutils_llist * const headers)
{
    int result = 0;

    assert(pv_request != NULL);
    assert(specifics != NULL);
    assert(headers != NULL);

    (void) pv_request;

    if (specifics->auth_token != NULL)
    {
        result = cgutils_http_add_header_to_list_dup(headers,
                                                     CG_STP_OPENSTACK_AUTH_TOKEN_HEADER,
                                                     specifics->auth_token);
    }

    return result;
}
