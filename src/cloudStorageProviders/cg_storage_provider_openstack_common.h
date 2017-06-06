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

#ifndef CG_STORAGE_PROVIDER_OPENSTACK_COMMON_H_
#define CG_STORAGE_PROVIDER_OPENSTACK_COMMON_H_

#include <cgsm/cg_storage_provider_utils.h>
#include <cloudutils/cloudutils_http.h>

typedef enum
{
    cg_stp_openstack_identity_auth_format_none = 0,
    cg_stp_openstack_identity_auth_format_xml,
    cg_stp_openstack_identity_auth_format_json
} cg_stp_openstack_identity_auth_format;

/* Data of the openstack provider,
   not linked to a specific instance. */
typedef struct cg_stp_openstack_provider_data
{
    cgutils_http_data * http;
    cg_storage_manager_data * data;
    cgutils_event_data * event_data;
    cg_storage_provider * provider;
} cg_stp_openstack_provider_data;

typedef struct cg_stp_openstack_specifics cg_stp_openstack_specifics;

typedef struct cg_stp_openstack_timer_data
{
    cg_stp_openstack_provider_data * pvd;
    cg_stp_openstack_specifics * specifics;
} cg_stp_openstack_timer_data;

/* Data for a specific instance of
   this provider. */
struct cg_stp_openstack_specifics
{
    cgutils_event * auth_timer;
    cg_stp_openstack_timer_data * timer_data;
    char * auth_token;
    char * endpoint;
#define STRING_PARAM(name, path, required) char * name;
#define UINT64_PARAM(name, path, required) uint64_t name;
#define SIZE_PARAM(name, path, required) size_t name;
#define UINT8_PARAM(name, path, required) uint8_t name;
#define BOOLEAN_PARAM(name, path, required) bool name;
#include "cg_storage_provider_openstack_parameters.itm"
#undef STRING_PARAM
#undef UINT8_PARAM
#undef UINT64_PARAM
#undef SIZE_PARAM
#undef BOOLEAN_PARAM
    size_t container_len;
    size_t endpoint_len;
    time_t auth_token_last_update;
    cg_stp_openstack_identity_auth_format auth_format;
    bool auth_refresh_in_progress;
    bool init;
};

typedef enum
{
    cg_stp_openstack_identity_version_none = 0,
    cg_stp_openstack_identity_version_1_0 = 1,
    cg_stp_openstack_identity_version_2_0 = 2,
    cg_stp_openstack_identity_version_count
} cg_stp_openstack_identity_version_type;

#define CG_STP_OPENSTACK_NO_OPT_HTTP_CHUNKED_TRANSFER (false)
#define CG_STP_OPENSTACK_OPT_HTTP_CHUNKED_TRANSFER (true)

int cg_stp_openstack_send_get_request(cg_storage_provider_request * pv_request,
                                      char const * host,
                                      char const * path,
                                      cgutils_llist * additional_headers,
                                      cg_stp_response_format response_format,
                                      cgutils_http_callbacks const * op_http_cb,
                                      cgutils_http_timeouts const * op_http_timeouts);

int cg_stp_openstack_send_post_request(cg_storage_provider_request * pv_request,
                                       char const * host,
                                       char const * path,
                                       cgutils_llist * additional_headers,
                                       char * data,
                                       size_t data_size,
                                       cg_stp_response_format response_format,
                                       cgutils_http_callbacks const * op_http_cb,
                                       cgutils_http_timeouts const * op_http_timeouts,
                                       bool chunked_transfer);

#endif /* CG_STORAGE_PROVIDER_OPENSTACK_COMMON_H_ */
