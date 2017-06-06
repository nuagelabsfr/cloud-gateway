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

#include <cgsm/cg_storage_provider_utils.h>

#include <cloudutils/cloudutils_crypto.h>
#include <cloudutils/cloudutils_encoding.h>
#include <cloudutils/cloudutils_http.h>
#include <cloudutils/cloudutils_xml_reader.h>
#include <cloudutils/cloudutils_xml_writer.h>

#define CG_STP_AMZ_NS "http://s3.amazonaws.com/doc/2006-03-01/"

typedef struct cg_stp_amz_provider_data
{
    cg_storage_manager_data * data;
    cgutils_http_data * http;
} cg_stp_amz_provider_data;

typedef struct cg_stp_amz_specifics
{
#define STRING_PARAM(name, path, required) char * name;
#define UINT64_PARAM(name, path, required) uint64_t name;
#define SIZE_PARAM(name, path, required) size_t name;
#define BOOLEAN_PARAM(name, path, required) bool name;
#include "cg_storage_provider_amazon_parameters.itm"
#undef BOOLEAN_PARAM
#undef SIZE_PARAM
#undef UINT64_PARAM
#undef STRING_PARAM
    size_t secret_access_key_len;
    size_t access_key_id_len;
    size_t bucket_len;
    size_t endpoint_len;
    size_t endpoint_path_len;
    size_t endpoint_port_len;
    bool init;
} cg_stp_amz_specifics;

static int cg_stp_amz_init(cg_storage_manager_data * const global_data,
                           void ** const data)
{
    int result = EINVAL;

    if (global_data != NULL && data != NULL)
    {
        cg_stp_amz_provider_data * pvd = NULL;
        CGUTILS_ALLOCATE_STRUCT(pvd);

        if (pvd != NULL)
        {
            pvd->data = global_data;
            pvd->http = cg_storage_manager_data_get_http(global_data);

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

static void cg_stp_amz_destroy(void * data)
{
    if (data != NULL)
    {
        CGUTILS_FREE(data);
    }
}

static void cg_stp_amz_clear_specifics(void * data)
{
    if (data != NULL)
    {
        cg_stp_amz_specifics * obj = data;

#define STRING_PARAM(name, path, required) CGUTILS_FREE(obj->name);
#define UINT64_PARAM(name, path, required) obj->name = 0;
#define SIZE_PARAM(name, path, required) obj->name = 0;
#define BOOLEAN_PARAM(name, path, required)
#include "cg_storage_provider_amazon_parameters.itm"
#undef BOOLEAN_PARAM
#undef SIZE_PARAM
#undef UINT64_PARAM
#undef STRING_PARAM

        CGUTILS_FREE(obj);
    }
}

#define CG_STP_AMZ_DEFAULT_HTTP_TIMEOUT (0)

#define CG_STP_AMZ_USE_BUCKET (true)
#define CG_STP_AMZ_NO_BUCKET (false)
#define CG_STP_AMZ_NO_CUSTOM_BUCKET (NULL)

/* Amazon is limiting PUT request to 5 GB,
   requiring the use of multi-part object otherwise */
#define CG_STP_AMZ_MAX_PART_SIZE_DEFAULT ((size_t) 5 * 1024 * 1024 * 1024)
/*
   We use an inferior value here because parallel uploads
   make sense for large files anyway.
   Amazon recommands using it starting with a 100 MB file.
*/
#define CG_STP_AMZ_MAX_SIMPLE_UP_FILE_SIZE_DEFAULT ((size_t) 1 * 1024 * 1024 * 1024)

/* Minimum size of a multi-part object according to AMZ API */
#define CG_STP_AMZ_MIN_MULTI_PART (5 * 1024 * 1024)
COMPILER_STATIC_ASSERT(CG_STP_AMZ_MAX_SIMPLE_UP_FILE_SIZE_DEFAULT >= (CG_STP_AMZ_MIN_MULTI_PART * 2),
                       "CG_STP_AMZ_MAX_SIMPLE_UP_FILE_SIZE_DEFAULT should be at least two times CG_STP_AMZ_MIN_MULTI_PART, otherwise it doesn't make sense");

//#define CG_STP_AMZ_MAX_NUMBER_OF_MULTI_PART (10000)

#define CG_STP_AMZ_MAGIC_MULTIPART_UPLOAD "?uploads"
#define CG_STP_AMZ_MAGIC_PART_NUMBER_STR "?partNumber="
#define CG_STP_AMZ_MAGIC_PART_UPLOAD_ID_STR "uploadId="

#define CG_STP_AMZ_MAGIC_UPLOAD_KEY "CompleteMultipartUpload"
#define CG_STP_AMZ_MAGIC_PART_KEY "Part"
#define CG_STP_AMZ_MAGIC_PART_NUMBER_KEY "PartNumber"
#define CG_STP_AMZ_MAGIC_ETAG_KEY "ETag"
#define CG_STP_AMZ_MAGIC_CREATE_BUCKET_KEY "CreateBucketConfiguration"
#define CG_STP_AMZ_MAGIC_LOCATION_CONSTRAINT_KEY "LocationConstraint"

#define CG_STP_AMZ_MAGIC_HEADER_NAME_ETAG "ETag"
#define CG_STP_AMZ_MAGIC_XML_CONTENT_TYPE "text/xml"

#define CG_STP_AMZ_OBJECT_HASH_ALGO (cgutils_crypto_digest_algorithm_md5)
#define CG_STP_AMZ_OBJECT_HASH_ALGO_LEN ((size_t) 32)

/* Original object name */
//#define CG_STP_AMZ_METADATA_HEADER_FILENAME "x-amz-meta-name"

#define CG_STP_AMAZON_DEFAULT_USER_AGENT "CloudGateway (https://www.nuagelabs.fr)"

static int cg_stp_amz_get_host_with_bucket(cg_stp_amz_specifics const * const specifics,
                                           char const * const optional_custom_hostname,
                                           char const * const optional_custom_bucket,
                                           char ** const out)
{
    assert(specifics != NULL);
    assert(specifics->bucket != NULL);
    assert(specifics->endpoint != NULL);
    assert(out != NULL);

    int result = 0;

    static const char https_str[] = "https://";
    static const char http_str[] = "http://";
    static size_t const https_str_len = sizeof https_str - 1;
    static size_t const http_str_len = sizeof http_str - 1;
    char const * const hostname = optional_custom_hostname != NULL ? optional_custom_hostname : specifics->endpoint;
    size_t hostname_len = optional_custom_hostname != NULL ? strlen(optional_custom_hostname) : specifics->endpoint_len;
    char const * const bucket = optional_custom_bucket != NULL ? optional_custom_bucket : specifics->bucket;
    size_t const bucket_len = optional_custom_bucket != NULL ? strlen(optional_custom_bucket) : specifics->bucket_len;
    char const * proto_str = NULL;
    size_t proto_str_len = 0;

    if (specifics->secure_transaction == true)
    {
        proto_str = https_str;
        proto_str_len = https_str_len;
    }
    else
    {
        proto_str = http_str;
        proto_str_len = http_str_len;
    }

    /* proto + bucket + '.' + endpoint (+ : + port)? (+ endpoint path)? */
    size_t const port_len = specifics->endpoint_port_len > 0 ? specifics->endpoint_port_len + 1 : 0;
    size_t const path_len = specifics->endpoint_path_len;
    size_t host_len = proto_str_len + bucket_len + 1 + hostname_len + port_len + path_len;

    if (path_len > 0 &&
        specifics->endpoint_path[0] != '/')
    {
        host_len += 1;
    }

    CGUTILS_MALLOC(*out, host_len + 1, 1);

    if (*out != NULL)
    {
        char * ptr = *out;
        memcpy(ptr, proto_str, proto_str_len);
        ptr += proto_str_len;
        memcpy(ptr, bucket, bucket_len);
        ptr += bucket_len;
        *ptr = '.';
        ptr++;
        memcpy(ptr, hostname, hostname_len);
        ptr += hostname_len;

        if (port_len > 0)
        {
            *ptr = ':';
            ptr++;
            memcpy(ptr, specifics->endpoint_port, specifics->endpoint_port_len);
            ptr += specifics->endpoint_port_len;
        }

        if (path_len > 0)
        {
            if (specifics->endpoint_path[0] != '/')
            {
                *ptr = '/';
                ptr++;
            }

            memcpy(ptr, specifics->endpoint_path, specifics->endpoint_path_len);
            ptr += specifics->endpoint_path_len;
        }

        *ptr = '\0';
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static int cg_stp_amz_get_host_without_bucket(cg_stp_amz_specifics const * const specifics,
                                              char ** const out)
{
    assert(specifics != NULL);
    assert(specifics->endpoint != NULL);
    assert(out != NULL);

    int result = 0;

    static const char https_str[] = "https://";
    static const char http_str[] = "http://";
    static size_t const https_str_len = sizeof https_str - 1;
    static size_t const http_str_len = sizeof http_str - 1;

    char const * proto_str = NULL;
    size_t proto_str_len = 0;

    if (specifics->secure_transaction == true)
    {
        proto_str = https_str;
        proto_str_len = https_str_len;
    }
    else
    {
        proto_str = http_str;
        proto_str_len = http_str_len;
    }

    /* proto + endpoint (+ : + port )? (+ path )? */
    size_t const port_len = specifics->endpoint_port_len > 0 ? specifics->endpoint_port_len + 1 : 0;
    size_t const path_len = specifics->endpoint_path_len;
    size_t host_len = proto_str_len + specifics->endpoint_len + port_len + path_len;

    if (path_len > 0 &&
        specifics->endpoint_path[0] != '/')
    {
        host_len += 1;
    }

    CGUTILS_MALLOC(*out, host_len + 1, 1);

    if (*out != NULL)
    {
        char * ptr = *out;
        memcpy(ptr, proto_str, proto_str_len);
        ptr += proto_str_len;
        memcpy(ptr, specifics->endpoint, specifics->endpoint_len);
        ptr += specifics->endpoint_len;

        if (port_len > 0)
        {
            *ptr = ':';
            ptr++;
            memcpy(ptr, specifics->endpoint_port, specifics->endpoint_port_len);
            ptr += specifics->endpoint_port_len;
        }

        if (path_len > 0)
        {
            if (specifics->endpoint_path[0] != '/')
            {
                *ptr = '/';
                ptr++;
            }

            memcpy(ptr, specifics->endpoint_path, specifics->endpoint_path_len);
            ptr += specifics->endpoint_path_len;
        }

        *ptr = '\0';
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static int cg_stp_amz_compute_part_uri(char const * const object_name,
                                       size_t const part_number,
                                       char const * const upload_id,
                                       char ** const out)
{
    int result = 0;

    assert(object_name != NULL);
    assert(out != NULL);

    size_t const object_name_len = strlen(object_name);
    size_t upload_id_len = 0;
    size_t part_number_len = 0;
    char * part_number_str = NULL;

    if (part_number > 0)
    {
        result = cgutils_asprintf(&part_number_str,
                                  "%s%zu",
                                  CG_STP_AMZ_MAGIC_PART_NUMBER_STR,
                                  part_number);

        if (result == 0)
        {
            part_number_len = strlen(part_number_str);
        }
    }

    if (result == 0 &&
        upload_id != NULL)
    {
        /* ('?' or '&') + CG_STP_AMZ_MAGIC_PART_UPLOAD_ID_STR +  uploadId */
        upload_id_len = 1 + sizeof (CG_STP_AMZ_MAGIC_PART_UPLOAD_ID_STR) - 1 + strlen(upload_id);
    }

    if (result == 0)
    {
        /*
        /ObjectName?partNumber=PartNumber&uploadId=UploadId
        or
        /ObjectName
        */

        size_t const out_len = 1 + object_name_len + part_number_len + upload_id_len + 1;
        CGUTILS_MALLOC(*out, out_len, 1);

        if (*out != NULL)
        {
            size_t out_current_len = 0;

            (*out)[out_current_len] = '/';
            out_current_len++;

            memcpy(*out + out_current_len, object_name, object_name_len);
            out_current_len += object_name_len;

            if (part_number_len > 0)
            {
                memcpy(*out + out_current_len, part_number_str, part_number_len);
                out_current_len += part_number_len;
            }

            if (upload_id_len > 0)
            {
                (*out)[out_current_len] = part_number_len > 0 ? '&' : '?';
                out_current_len++;

                memcpy(*out + out_current_len,
                       CG_STP_AMZ_MAGIC_PART_UPLOAD_ID_STR,
                       sizeof CG_STP_AMZ_MAGIC_PART_UPLOAD_ID_STR - 1);
                out_current_len += sizeof CG_STP_AMZ_MAGIC_PART_UPLOAD_ID_STR - 1;

                memcpy(*out + out_current_len,
                       upload_id, upload_id_len - (sizeof CG_STP_AMZ_MAGIC_PART_UPLOAD_ID_STR - 1) - 1);
                out_current_len += upload_id_len - (sizeof CG_STP_AMZ_MAGIC_PART_UPLOAD_ID_STR - 1) - 1;
            }

            (*out)[out_current_len] = '\0';
        }
        else
        {
            result = ENOMEM;
        }
    }

    if (part_number_str != NULL)
    {
        CGUTILS_FREE(part_number_str);
    }

    return result;
}

static int cg_stp_amz_compute_signature(cg_stp_amz_specifics const * const specifics,
                                        cgutils_http_method const method,
                                        char const * const uri,
                                        char const * const content_md5,
                                        char const * const content_type,
                                        char const * const date,
                                        char const * const amz_canonicalized_headers,
                                        bool const use_bucket,
                                        char const * const custom_bucket,
                                        void ** const out,
                                        size_t * const out_size)
{
    assert(specifics != NULL);
    assert(uri != NULL);
    assert(date != NULL);
    assert(out != NULL);
    assert(out_size != NULL);

    /* Signature = Base64( HMAC-SHA1( UTF-8-Encoding-Of( YourSecretAccessKey, StringToSign ) ) );

       StringToSign = HTTP-Verb + "\n" +
       Content-MD5 + "\n" +
       Content-Type + "\n" +
       Date + "\n" +
       CanonicalizedAmzHeaders +
       CanonicalizedResource;

       CanonicalizedResource = [ "/" + Bucket ] +
       <HTTP-Request-URI, from the protocol name up to the query string> +
       [ sub-resource, if present. For example "?acl", "?location", "?logging", or
       "?torrent"];

       CanonicalizedAmzHeaders = <described below>
    */

    char * canonicalized_resource = NULL;
    char * lower_bucket = NULL;

    assert(specifics->bucket != NULL);

    int result = 0;

    if (use_bucket == true)
    {
        char const * const bucket = custom_bucket != NULL ? custom_bucket : specifics->bucket;

        result = cgutils_str_tolower(bucket, &lower_bucket);

        if (result != 0)
        {
            CGUTILS_ERROR("Error while converting bucket to lower case: %d", result);
        }
    }

    if (result == 0)
    {
        result = cgutils_asprintf(&canonicalized_resource, "%s%s%s",
                                  use_bucket == true ? "/" : "",
                                  use_bucket == true ? lower_bucket : "",
                                  uri);

        if (result == 0)
        {
            char const * const method_str = cgutils_http_method_to_str(method);
            assert(method_str != NULL);

            char * string_to_sign = NULL;

            result = cgutils_asprintf(&string_to_sign, "%s\n%s\n%s\n%s\n%s%s",
                                      method_str,
                                      content_md5 != NULL ? content_md5 : "",
                                      content_type != NULL ? content_type : "",
                                      date,
                                      amz_canonicalized_headers != NULL ? amz_canonicalized_headers : "",
                                      canonicalized_resource);

            if (result == 0)
            {
                assert(specifics->secret_access_key != NULL);
                assert(specifics->secret_access_key_len > 0);

                size_t const string_to_sign_len = strlen(string_to_sign);
                void * hash = NULL;
                size_t hash_size = 0;

                result = cgutils_crypto_hmac(specifics->secret_access_key,
                                             specifics->secret_access_key_len,
                                             string_to_sign,
                                             string_to_sign_len,
                                             cgutils_crypto_digest_algorithm_sha1,
                                             &hash,
                                             &hash_size);

                if (result == 0)
                {
                    result = cgutils_encoding_base64_encode(hash,
                                                            hash_size,
                                                            out,
                                                            out_size);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error in base64 encoding: %d", result);
                    }

                    CGUTILS_FREE(hash);
                }
                else
                {
                    CGUTILS_ERROR("Error computing HMAC: %d", result);
                }

                CGUTILS_FREE(string_to_sign);
            }
            else
            {
                CGUTILS_ERROR("Error allocating signature string: %d", result);
            }

            CGUTILS_FREE(canonicalized_resource);
        }
        else
        {
            CGUTILS_ERROR("Error allocating signature string: %d", result);
        }
    }

    if (lower_bucket != NULL)
    {
        CGUTILS_FREE(lower_bucket);
    }

    return result;
}

static int cg_stp_amz_extract_specific_headers(cgutils_llist * const headers,
                                               char const ** content_md5,
                                               char const ** content_type,
                                               char const ** canonicalized_amz_headers)
{
    assert(headers != NULL);
    assert(content_md5 != NULL);
    assert(content_type != NULL);
    assert(canonicalized_amz_headers != NULL);

    struct
    {
        char const * const name;
        size_t const name_len;
        char const ** storage;
        bool const is_prefix;
        bool const unique;
        bool already_found;
    } specifics[] =
          {
              { "Content-MD5", sizeof ("Content-MD5") - 1, content_md5, false, true, false},
              { "Content-Type", sizeof "Content-Type" - 1, content_type, false, true, false},
              { "x-amz-", sizeof "x-amz-" - 1, NULL, true, false, false},
          };

    size_t const specifics_count = sizeof specifics / sizeof *specifics;

    int result = 0;
    cgutils_llist_elt * elt = cgutils_llist_get_iterator(headers);

    (void) canonicalized_amz_headers;

    while (result == 0 && elt != NULL)
    {
        cgutils_http_header const * const header = cgutils_llist_elt_get_object(elt);
        assert(header != NULL);
        assert(header->name != NULL);

        bool matched = false;

        for (size_t idx = 0; result == 0 && idx < specifics_count && matched == false; idx++)
        {
            if (specifics[idx].is_prefix == false)
            {
                matched = strcasecmp(specifics[idx].name, header->name) == 0;
            }
            else
            {
                matched = strncasecmp(specifics[idx].name, header->name, specifics[idx].name_len);
            }

            if (matched == true)
            {
                if (specifics[idx].unique == false || specifics[idx].already_found == false)
                {
                    if (specifics[idx].unique == true)
                    {
                        *(specifics[idx].storage) = header->value;
                    }

                    specifics[idx].already_found = true;
                }
                else
                {
                    CGUTILS_WARN("The header named %s should only be present one time at most, and has been found at least two times.", specifics[idx].name);
                    result = EIO;
                }
            }
        }

        elt = cgutils_llist_elt_get_next(elt);
    }

    return result;
}

static int cg_stp_amz_get_authorization(cg_stp_amz_specifics const * const specifics,
                                        cgutils_http_method const method,
                                        char const * const path,
                                        cgutils_llist * headers,
                                        bool const use_bucket,
                                        char const * const custom_bucket,
                                        char const * force_content_type,
                                        char ** const out,
                                        size_t * const out_len)
{
    assert(specifics != NULL);
    assert(path != NULL);
    assert(headers != NULL);
    assert(out != NULL);
    assert(out_len != NULL);

    char const * content_md5 = NULL;
    char const * content_type = NULL;
    char const * amz_canon = NULL;

    int result = cg_stp_amz_extract_specific_headers(headers, &content_md5, &content_type, &amz_canon);

    if (force_content_type != NULL)
    {
        content_type = force_content_type;
    }

    if (result == 0)
    {
        char * date = NULL;
        size_t date_len = 0;

        result = cgutils_get_date_str(&date, &date_len);

        if (result == 0)
        {
            assert(date != NULL);

            result = cgutils_http_add_header_to_list(headers, "Date", date);

            if (result == 0)
            {

                void * signature = NULL;
                size_t signature_size = 0;

                /* Amazon authorization header is : "AWS" + " " + access_key_id + ":" + signature */

                result = cg_stp_amz_compute_signature(specifics,
                                                      method,
                                                      path,
                                                      content_md5,
                                                      content_type,
                                                      date,
                                                      amz_canon,
                                                      use_bucket,
                                                      custom_bucket,
                                                      &signature,
                                                      &signature_size);
                if (result == 0)
                {
                    static char const aws[] = "AWS ";
                    static size_t const aws_len = sizeof aws - 1;

                    CGUTILS_ASSERT(signature != NULL);

                    *out_len = aws_len + specifics->access_key_id_len + 1 + signature_size;

                    CGUTILS_MALLOC(*out, *out_len + 1, 1);

                    if (*out != NULL)
                    {
                        char * ptr = *out;
                        memcpy(ptr, aws, aws_len);
                        ptr += aws_len;
                        memcpy(ptr, specifics->access_key_id, specifics->access_key_id_len);
                        ptr += specifics->access_key_id_len;
                        *ptr = ':';
                        ptr++;
                        memcpy(ptr, signature, signature_size);
                        ptr += signature_size;
                        *ptr = '\0';
                    }
                    else
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Allocation error for signature: %d", result);
                    }

                    CGUTILS_FREE(signature);
                }
                else
                {
                    CGUTILS_ERROR("Error computing signature: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error adding Date header: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error computing Date header: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error extracting headers for signature: %d", result);
    }

    return result;
}

static int cg_stp_amz_prepare_request(cg_storage_provider_request * const pv_request,
                                      char const * const host,
                                      cgutils_http_method const method,
                                      char const * const path,
                                      char * const data,
                                      size_t const data_size,
                                      cgutils_llist * additional_headers,
                                      bool const use_bucket,
                                      char const * const custom_bucket,
                                      cg_stp_response_format const response_format,
                                      cgutils_http_callbacks const * const op_http_cb,
                                      cgutils_http_timeouts const * const op_http_timeouts,
                                      cgutils_http_request ** const request)
{
    assert(pv_request != NULL);
    cg_stp_amz_specifics const * const specifics = pv_request->ctx->instance_specifics;
    cgutils_http_data * const http = pv_request->ctx->http;
    assert(specifics != NULL);
    assert(http != NULL);
    assert(host != NULL);
    assert(path != NULL);
    assert(request != NULL);

    int result = 0;
    bool has_content_type = false;

    if (additional_headers == NULL)
    {
        result = cgutils_llist_create(&additional_headers);

        if (result != 0)
        {
            CGUTILS_ERROR("Error creating headers: %d", result);
        }
    }
    else if (method == CGUTILS_HTTP_METHOD_POST)
    {
        cgutils_http_header const * content_type_header = NULL;

        result = cgutils_http_get_header_by_name(additional_headers,
                                                 "Content-Type",
                                                 &content_type_header);

        if (result == 0)
        {
            has_content_type = true;
        }
        else
        {
            result = 0;
        }
    }

    if (result == 0)
    {
        char * authorization = NULL;
        size_t authorization_len = 0;

        result = cg_stp_amz_get_authorization(specifics,
                                              method,
                                              path,
                                              additional_headers,
                                              use_bucket,
                                              custom_bucket,
                                              method == CGUTILS_HTTP_METHOD_POST && has_content_type == false ? "application/x-www-form-urlencoded" : NULL,
                                              &authorization,
                                              &authorization_len);

        if (result == 0)
        {
            result = cgutils_http_add_header_to_list(additional_headers, "Authorization", authorization);

            if (result == 0)
            {
                size_t const host_len = strlen(host);
                size_t const path_len = strlen(path);
                size_t const uri_len = host_len + path_len;

                char * uri = NULL;
                CGUTILS_MALLOC(uri, uri_len + 1, 1);

                if (uri != NULL)
                {
                    memcpy(uri, host, host_len);
                    memcpy(uri + host_len, path, path_len);
                    uri[uri_len] = '\0';

                    cgutils_http_callbacks const cbs =
                        {
                            .response_cb = response_format == CG_STP_RESPONSE_FORMAT_RAW ?
                            &cg_storage_provider_utils_http_raw_response_callback :
                            (response_format == CG_STP_RESPONSE_FORMAT_XML ?
                             &cg_storage_provider_utils_http_xml_response_callback :
                             &cg_storage_provider_utils_http_json_response_callback),
                            .write_cb = &cg_storage_provider_utils_write_cb,
                            .header_cb = &cg_storage_provider_utils_header_cb,
                        };
                    cgutils_http_request_options const options =
                        {
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
                            .user_agent = specifics->http_user_agent ? specifics->http_user_agent : (CG_STP_AMAZON_DEFAULT_USER_AGENT),
                        };
                    cgutils_http_timeouts const timeouts =
                        {
                            (long) specifics->http_timeout,
                        };

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
        else
        {
            CGUTILS_ERROR("Error getting authorization: %d", result);
        }

        if (result != 0)
        {
            cgutils_llist_free(&additional_headers, &cgutils_http_header_delete);
        }
    }

    return result;
}

static int cg_stp_amz_send_get_request(cg_storage_provider_request * const pv_request,
                                       char const * const host,
                                       char const * const path,
                                       cgutils_llist * additional_headers,
                                       bool const use_bucket,
                                       char const * const custom_bucket,
                                       cg_stp_response_format const response_format,
                                       cgutils_http_callbacks const * const op_http_cb,
                                       cgutils_http_timeouts const * const op_http_timeouts)
{
    assert(pv_request != NULL);
    assert(host != NULL);
    assert(path != NULL);

    cgutils_http_request * request = NULL;

    int result = cg_stp_amz_prepare_request(pv_request,
                                            host,
                                            CGUTILS_HTTP_METHOD_GET,
                                            path,
                                            NULL,
                                            0,
                                            additional_headers,
                                            use_bucket,
                                            custom_bucket,
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

static int cg_stp_amz_send_delete_request(cg_storage_provider_request * const pv_request,
                                          char const * const host,
                                          char const * const path,
                                          cgutils_llist * additional_headers,
                                          bool const use_bucket,
                                          char const * const custom_bucket,
                                          cg_stp_response_format const response_format,
                                          cgutils_http_callbacks const * const op_http_cb,
                                          cgutils_http_timeouts const * const op_http_timeouts)
{
    assert(pv_request != NULL);
    assert(host != NULL);
    assert(path != NULL);

    cgutils_http_request * request = NULL;
    int result = cg_stp_amz_prepare_request(pv_request,
                                            host,
                                            CGUTILS_HTTP_METHOD_DELETE,
                                            path,
                                            NULL,
                                            0,
                                            additional_headers,
                                            use_bucket,
                                            custom_bucket,
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

static int cg_stp_amz_send_put_request(cg_storage_provider_request * const pv_request,
                                       char const * const host,
                                       char const * const path,
                                       char * const data,
                                       size_t const data_size,
                                       cgutils_llist * additional_headers,
                                       bool const use_bucket,
                                       char const * const custom_bucket,
                                       cg_stp_response_format const response_format,
                                       cgutils_http_callbacks const * const op_http_cb,
                                       cgutils_http_timeouts const * const op_http_timeouts)
{
    assert(pv_request != NULL);
    assert(host != NULL);
    assert(path != NULL);

    cgutils_http_request * request = NULL;

    int result = cg_stp_amz_prepare_request(pv_request,
                                            host,
                                            CGUTILS_HTTP_METHOD_PUT,
                                            path,
                                            data,
                                            /* When we send data via a read callback,
                                               the data_size is only used below to set the Content-Length
                                               header, but should not be passed to cgutils_http_request_init,
                                               which does not allow NULL data if data_size > 0. */
                                            data != NULL ? data_size : 0,
                                            additional_headers,
                                            use_bucket,
                                            custom_bucket,
                                            response_format,
                                            op_http_cb,
                                            op_http_timeouts,
                                            &request);

    if (result == 0)
    {
        /* The S3 API does not support Chunked Transfer Encoding on request.
           Welcome to 2013, rfc2616. */
        result = cgutils_http_set_content_length(request, data_size);

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

static int cg_stp_amz_send_post_request(cg_storage_provider_request * const pv_request,
                                        char const * const host,
                                        char const * const path,
                                        char * const data,
                                        size_t const data_size,
                                        cgutils_llist * additional_headers,
                                        bool const use_bucket,
                                        char const * const custom_bucket,
                                        cg_stp_response_format const response_format,
                                        cgutils_http_callbacks const * const op_http_cb,
                                        cgutils_http_timeouts const * const op_http_timeouts)
{
    assert(pv_request != NULL);
    assert(host != NULL);
    assert(path != NULL);

    cgutils_http_request * request = NULL;

    int result = cg_stp_amz_prepare_request(pv_request,
                                            host,
                                            CGUTILS_HTTP_METHOD_POST,
                                            path,
                                            data,
                                            data_size,
                                            additional_headers,
                                            use_bucket,
                                            custom_bucket,
                                            response_format,
                                            op_http_cb,
                                            op_http_timeouts,
                                            &request);

    if (result == 0)
    {
        /* The S3 API does not support Chunked Transfer Encoding on request.
           Welcome to 2013, rfc2616. */

        result = cgutils_http_set_content_length(request, data_size);

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

static int cg_stp_amz_list_buckets_cb(int status,
                                      cgutils_xml_reader * response,
                                      void * cb_data)
{
    assert(cb_data != NULL);
    cg_storage_provider_request * pv_request = cb_data;

    int result = status;
    cgutils_llist * names = NULL;

    if (result == 0)
    {
        result = cgutils_llist_create(&names);

        if (result == 0)
        {
            cgutils_llist * buckets = NULL;
            result = cgutils_xml_reader_register_namespace(response, "amz", CG_STP_AMZ_NS);

            if (result == 0)
            {
                result = cgutils_xml_reader_get_all(response, "amz:Buckets/amz:Bucket", &buckets);

                if (result == 0)
                {
                    cgutils_llist_elt * elt = cgutils_llist_get_iterator(buckets);

                    while (result == 0 && elt != NULL)
                    {
                        cgutils_xml_reader * bucket = cgutils_llist_elt_get_object(elt);
                        assert(bucket != NULL);

                        result = cgutils_xml_reader_register_namespace(bucket, "amz", CG_STP_AMZ_NS);

                        if (result == 0)
                        {
                            char * name = NULL;
                            result = cgutils_xml_reader_get_string(bucket, "amz:Name", &name);

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
                                CGUTILS_ERROR("Unable to get name from bucket: %d", result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Unable to register namespace: %d", result);
                        }

                        elt = cgutils_llist_elt_get_next(elt);
                    }

                    cgutils_llist_free(&buckets, &cgutils_xml_reader_delete);
                }
                else if (result == ENOENT)
                {
                    CGUTILS_ERROR("No bucket found");
                    result = 0;
                }
                else
                {
                    CGUTILS_ERROR("Error while looking for bucket: %d", result);
                }

                if (result != 0)
                {
                    cgutils_llist_free(&names, &free);
                }
            }
            else
            {
                CGUTILS_ERROR("Error registering namespace AMZ: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating name list: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error in request: %d", result);
    }

    result = cg_storage_provider_handle_list_response(pv_request, status, names);

    return result;
}

static int cg_stp_amz_list_buckets(cg_storage_provider_request * pv_request)
{
    int result = EINVAL;

    if(pv_request != NULL)
    {
        cg_stp_amz_specifics * const specifics = pv_request->ctx->instance_specifics;
        char * host = NULL;

        pv_request->xml_request_cb = &cg_stp_amz_list_buckets_cb;
        pv_request->request_cb_data = pv_request;


        result = cg_stp_amz_get_host_without_bucket(specifics, &host);

        if (result == 0)
        {
            result = cg_stp_amz_send_get_request(pv_request,
                                                 host,
                                                 "/",
                                                 CG_STP_NO_ADDITIONAL_HEADERS,
                                                 CG_STP_AMZ_NO_BUCKET,
                                                 CG_STP_AMZ_NO_CUSTOM_BUCKET,
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

            CGUTILS_FREE(host);
        }
        else
        {
            CGUTILS_ERROR("Error getting hostname: %d", result);
        }

    }

    return result;
}

static int cg_stp_amz_create_bucket_cb(int status,
                                       void * cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    assert(cb_data != NULL);

    if (result == 0)
    {
        result = cg_storage_provider_handle_status_response(pv_request, status);
    }
    else
    {
        if (result != ENOENT)
        {
            CGUTILS_ERROR("Error in request: %d", result);
        }

        result = cg_storage_provider_handle_status_response(pv_request, status);
    }

    return result;
}

static int cg_stp_amz_create_bucket(cg_storage_provider_request * pv_request,
                                    char const * const bucket_name)
{
    int result = EINVAL;

    if(pv_request != NULL &&
        bucket_name != NULL)
    {
        cg_stp_amz_specifics * const specifics = pv_request->ctx->instance_specifics;
        char * host = NULL;

        pv_request->raw_request_cb = &cg_stp_amz_create_bucket_cb;
        pv_request->request_cb_data = pv_request;

        result = cg_stp_amz_get_host_with_bucket(specifics,
                                                 specifics->bucket_management_endpoint,
                                                 bucket_name,
                                                 &host);

        if (result == 0)
        {
            char * payload = NULL;
            size_t payload_size = 0;
            cgutils_llist * headers = NULL;

            if (specifics->bucket_region != NULL &&
                strlen(specifics->bucket_region)> 0)
            {
                cgutils_xml_writer * writer = NULL;

                result = cgutils_xml_writer_new(&writer);

                if (result == 0)
                {
                    cgutils_xml_writer_element * root_elt = NULL;

                    result = cgutils_xml_writer_create_root(writer,
                                                            CG_STP_AMZ_MAGIC_CREATE_BUCKET_KEY,
                                                            &root_elt);

                    if (result == 0)
                    {
                        cgutils_xml_writer_element * location_elt = NULL;

                        result = cgutils_xml_writer_element_add_child(root_elt,
                                                                      CG_STP_AMZ_MAGIC_LOCATION_CONSTRAINT_KEY,
                                                                      specifics->bucket_region,
                                                                      &location_elt);

                        if (result == 0)
                        {
                            cgutils_xml_writer_element_release(location_elt), location_elt = NULL;

                            result = cgutils_xml_writer_get_output(writer,
                                                                   &payload,
                                                                   &payload_size);


                            if (result == 0)
                            {
                                result = cgutils_llist_create(&headers);

                                if (result == 0)
                                {
                                    result = cgutils_http_add_header_to_list_dup(headers,
                                                                                 "Content-Type",
                                                                                 CG_STP_AMZ_MAGIC_XML_CONTENT_TYPE);

                                    if (result != 0)
                                    {
                                        CGUTILS_ERROR("Error adding Content-Type header: %d",
                                                      result);
                                    }

                                    if (result != 0)
                                    {
                                        cgutils_llist_free(&headers, &cgutils_http_header_delete);
                                    }
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error creating headers list: %d",
                                                  result);
                                }

                                if (result != 0)
                                {
                                    CGUTILS_FREE(payload);
                                    payload_size = 0;
                                }
                            }
                            else
                            {
                                CGUTILS_ERROR("Error getting XML output: %d",
                                              result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error creating location element: %d",
                                          result);
                        }

                        cgutils_xml_writer_element_release(root_elt), root_elt = NULL;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating root element: %d",
                                      result);
                    }

                    cgutils_xml_writer_free(writer), writer = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error creating XML writer element: %d",
                                  result);
                }
            }

            if (result == 0)
            {
                /* Should be done with source memory IO */
                pv_request->payload = payload;
                pv_request->payload_size = payload_size;

                cgutils_http_callbacks const http_cbs = {
                    .response_cb = &cg_storage_provider_utils_http_raw_response_callback,
                    .read_cb = &cg_storage_provider_utils_payload_read_cb,
                    .header_cb = &cg_storage_provider_utils_header_cb,
                    .write_cb = &cg_storage_provider_utils_write_cb,
                };

                result = cg_stp_amz_send_put_request(pv_request,
                                                     host,
                                                     "/",
                                                     payload,
                                                     payload_size,
                                                     headers,
                                                     CG_STP_AMZ_USE_BUCKET,
                                                     bucket_name,
                                                     CG_STP_RESPONSE_FORMAT_RAW,
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
            }

            CGUTILS_FREE(host);
        }
        else
        {
            CGUTILS_ERROR("Error getting hostname: %d", result);
        }

        if (result != 0)
        {
            cg_storage_provider_handle_status_response(pv_request, result);
        }
    }

    return result;
}

static int cg_stp_amz_remove_empty_bucket_cb(int status,
                                       void * cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    assert(cb_data != NULL);

    if (result == 0)
    {
        result = cg_storage_provider_handle_status_response(pv_request, status);
    }
    else
    {
        if (result != ENOENT)
        {
            CGUTILS_ERROR("Error in request: %d", result);
        }

        result = cg_storage_provider_handle_status_response(pv_request, status);
    }

    return result;
}

static int cg_stp_amz_remove_empty_bucket(cg_storage_provider_request * pv_request,
                                          char const * const bucket_name)
{
    int result = EINVAL;

    if(pv_request != NULL &&
        bucket_name != NULL)
    {
        cg_stp_amz_specifics * const specifics = pv_request->ctx->instance_specifics;
        char * host = NULL;

        pv_request->raw_request_cb = &cg_stp_amz_remove_empty_bucket_cb;
        pv_request->request_cb_data = pv_request;

        result = cg_stp_amz_get_host_with_bucket(specifics,
                                                 NULL,
                                                 bucket_name,
                                                 &host);

        if (result == 0)
        {
            result = cg_stp_amz_send_delete_request(pv_request,
                                                    host,
                                                    "/",
                                                    CG_STP_NO_ADDITIONAL_HEADERS,
                                                    CG_STP_AMZ_USE_BUCKET,
                                                    bucket_name,
                                                    CG_STP_RESPONSE_FORMAT_RAW,
                                                    CG_STP_NO_OPT_HTTP_CALLBACKS,
                                                    CG_STP_NO_OPT_HTTP_TIMEOUTS);

            if (result == 0)
            {
                pv_request = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error sending request: %d", result);
            }

            CGUTILS_FREE(host);
        }
        else
        {
            CGUTILS_ERROR("Error getting hostname: %d", result);
        }

        if (result != 0)
        {
            cg_storage_provider_handle_status_response(pv_request, result);
        }
    }

    return result;
}

static int cg_stp_amz_list_files_cb(int status,
                                    cgutils_xml_reader * response,
                                    void * cb_data)
{
    assert(cb_data != NULL);
    cg_storage_provider_request * const pv_request = cb_data;

    int result = status;
    cgutils_llist * names = NULL;

    if (result == 0)
    {
        result = cgutils_llist_create(&names);

        if (result == 0)
        {
            cgutils_llist * contents = NULL;
            result = cgutils_xml_reader_register_namespace(response, "amz", CG_STP_AMZ_NS);

            if (result == 0)
            {
                result = cgutils_xml_reader_get_all(response, "amz:Contents", &contents);

                if (result == 0)
                {
                    cgutils_llist_elt * elt = cgutils_llist_get_iterator(contents);

                    while (result == 0 && elt != NULL)
                    {
                        cgutils_xml_reader * content = cgutils_llist_elt_get_object(elt);
                        assert(content != NULL);

                        result = cgutils_xml_reader_register_namespace(content, "amz", CG_STP_AMZ_NS);

                        if (result == 0)
                        {
                            char * name = NULL;
                            result = cgutils_xml_reader_get_string(content, "amz:Key", &name);

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
                        else
                        {
                            CGUTILS_ERROR("Enable to register namespace: %d", result);
                        }

                        elt = cgutils_llist_elt_get_next(elt);
                    }

                    cgutils_llist_free(&contents, &cgutils_xml_reader_delete);
                }
                else if (result == ENOENT)
                {
//                    CGUTILS_ERROR("No file found");
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
                CGUTILS_ERROR("Error registering namespace AMZ: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating name list: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error in request: %d", result);
    }

    result = cg_storage_provider_handle_list_response(pv_request, status, names);

    return result;
}

static int cg_stp_amz_list_files(cg_storage_provider_request * const pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        char * host = NULL;
        cg_stp_amz_specifics * specifics = pv_request->ctx->instance_specifics;

        pv_request->xml_request_cb = &cg_stp_amz_list_files_cb;
        pv_request->request_cb_data = pv_request;

        result = cg_stp_amz_get_host_with_bucket(specifics,
                                                 NULL,
                                                 NULL,
                                                 &host);

        if (result == 0)
        {
            result = cg_stp_amz_send_get_request(pv_request,
                                                 host,
                                                 "/",
                                                 CG_STP_NO_ADDITIONAL_HEADERS,
                                                 CG_STP_AMZ_USE_BUCKET,
                                                 CG_STP_AMZ_NO_CUSTOM_BUCKET,
                                                 CG_STP_RESPONSE_FORMAT_XML,
                                                 CG_STP_NO_OPT_HTTP_CALLBACKS,
                                                 CG_STP_NO_OPT_HTTP_TIMEOUTS);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending request: %d", result);
            }

            CGUTILS_FREE(host);
        }
        else
        {
            CGUTILS_ERROR("Error getting hostname: %d", result);
        }

        if (result != 0)
        {
            cg_storage_provider_handle_list_response(pv_request, result, NULL);
        }
    }

    return result;
}

static int cg_stp_amz_get_file_cb(int status,
                                  void * cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    assert(cb_data != NULL);

    if (result == 0)
    {
        result = cg_storage_provider_handle_status_response(pv_request, status);
    }
    else
    {
        if (result != ENOENT)
        {
            CGUTILS_ERROR("Error in request: %d", result);
        }

        result = cg_storage_provider_handle_status_response(pv_request, status);

    }

    return result;
}

static int cg_stp_amz_get_file(cg_storage_provider_request * const pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        char * host = NULL;
        cg_stp_amz_specifics * specifics = pv_request->ctx->instance_specifics;
        assert(pv_request->ctx != NULL && pv_request->ctx->key != NULL);

        pv_request->raw_request_cb = &cg_stp_amz_get_file_cb;
        pv_request->request_cb_data = pv_request;

        result = cg_stp_amz_get_host_with_bucket(specifics,
                                                 NULL,
                                                 NULL,
                                                 &host);

        if (result == 0)
        {
            size_t const key_len = strlen(pv_request->ctx->key);
            char * path = NULL;
            CGUTILS_MALLOC(path, key_len + 1 + 1, 1);

            if (path != NULL)
            {
                *path = '/';
                memcpy(path + 1, pv_request->ctx->key, key_len);
                path[key_len + 1] = '\0';

                cgutils_http_callbacks const http_cbs = {
                    .response_cb = &cg_storage_provider_utils_http_raw_response_callback,
                    .write_cb = &cg_storage_provider_utils_write_cb,
                    .header_cb = &cg_storage_provider_utils_header_cb,
                };

                result = cg_stp_amz_send_get_request(pv_request,
                                                     host,
                                                     path,
                                                     CG_STP_NO_ADDITIONAL_HEADERS,
                                                     CG_STP_AMZ_USE_BUCKET,
                                                     CG_STP_AMZ_NO_CUSTOM_BUCKET,
                                                     CG_STP_RESPONSE_FORMAT_RAW,
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
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for path: %d", result);
            }

            CGUTILS_FREE(host);
        }
        else
        {
            CGUTILS_ERROR("Error getting hostname: %d", result);
        }

        if (result != 0)
        {
            cg_storage_provider_handle_status_response(pv_request, result);
        }
    }

    return result;
}

static int cg_stp_amz_delete_file_cb(int const status,
                                     void * cb_data)
{
    cg_storage_provider_request * pv_request = cb_data;
    int result = status;

    assert(cb_data != NULL);

    if (result == 0)
    {
        result = cg_storage_provider_handle_status_response(pv_request, status);
    }
    else
    {
        if (result != ENOENT)
        {
            CGUTILS_ERROR("Error in request: %d", result);
        }

        result = cg_storage_provider_handle_status_response(pv_request, status);

    }

    return result;
}

static int cg_stp_amz_delete_file(cg_storage_provider_request * const pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        char * host = NULL;
        cg_stp_amz_specifics * specifics = pv_request->ctx->instance_specifics;

        assert(pv_request->ctx != NULL && pv_request->ctx->key != NULL);

        pv_request->raw_request_cb = &cg_stp_amz_delete_file_cb;
        pv_request->request_cb_data = pv_request;


        result = cg_stp_amz_get_host_with_bucket(specifics,
                                                 NULL,
                                                 NULL,
                                                 &host);

        if (result == 0)
        {
            size_t const key_len = strlen(pv_request->ctx->key);
            char * path = NULL;
            CGUTILS_MALLOC(path, key_len + 1 + 1, 1);

            if (path != NULL)
            {
                *path = '/';
                memcpy(path + 1, pv_request->ctx->key, key_len);
                path[key_len + 1] = '\0';

                cgutils_http_callbacks const http_cbs = {
                    .response_cb = &cg_storage_provider_utils_http_raw_response_callback,
                    .header_cb = &cg_storage_provider_utils_header_cb,
                };

                result = cg_stp_amz_send_delete_request(pv_request,
                                                        host,
                                                        path,
                                                        CG_STP_NO_ADDITIONAL_HEADERS,
                                                        CG_STP_AMZ_USE_BUCKET,
                                                        CG_STP_AMZ_NO_CUSTOM_BUCKET,
                                                        CG_STP_RESPONSE_FORMAT_RAW,
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
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for path: %d", result);
            }

            CGUTILS_FREE(host);
        }
        else
        {
            CGUTILS_ERROR("Error getting hostname: %d", result);
        }

        if (result != 0)
        {
            cg_storage_provider_handle_status_response(pv_request, result);
        }
    }

    return result;
}

static int cg_stp_amz_put_file_cb(int const status,
                                  void * const cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    assert(cb_data != NULL);

    if (result == 0)
    {
    }
    else
    {
        char const * uri = NULL;

        assert(pv_request->request != NULL);

        uri = cgutils_http_request_get_uri(pv_request->request);

        CGUTILS_ERROR("Error in PUT request to uri %s: %d",
                      uri,
                      status);

        if (result == ENOENT)
        {
            char const * bucket_name = "";

            if (pv_request->ctx != NULL &&
                pv_request->ctx->instance_specifics != NULL)
            {
                cg_stp_amz_specifics const * const specifics = pv_request->ctx->instance_specifics;
                if (specifics->bucket != NULL)
                {
                    bucket_name = specifics->bucket;
                }
            }

            CGUTILS_ERROR("Error (%d) while trying to upload an object, are you sure that the bucket %s exists ?",
                          status,
                          bucket_name);
        }
    }

    result = cg_storage_provider_handle_status_response(pv_request, status);

    return result;
}

static int cg_stp_amz_put_file(cg_storage_provider_request * pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        cgutils_llist * headers = NULL;
        char * host = NULL;
        cg_stp_amz_specifics * specifics = pv_request->ctx->instance_specifics;

        assert(pv_request->ctx != NULL && pv_request->ctx->key != NULL);

        pv_request->raw_request_cb = &cg_stp_amz_put_file_cb;
        pv_request->request_cb_data = pv_request;


        result = cg_stp_amz_get_host_with_bucket(specifics,
                                                 NULL,
                                                 NULL,
                                                 &host);

        if (result == 0)
        {
            /* Meta data handling is disabled for Amazon,
               because the signature does not yet handle x-amz- headers. */
            /*
            if (pv_request->ctx->metadata != NULL)
            {
                result = cgutils_llist_create(&headers);

                if (result == 0)
                {
                    result = cg_storage_provider_utils_add_header_from_meta(pv_request,
                                                                            "filename",
                                                                            CG_STP_AMZ_METADATA_HEADER_FILENAME,
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
            */

            if (result == 0)
            {
                char * path = NULL;

                result = cg_stp_amz_compute_part_uri(pv_request->ctx->key,
                                                     0,
                                                     NULL,
                                                     &path);

                if (result == 0)
                {
                    size_t put_size = 0;

                    result = cg_storage_io_ctx_source_get_final_size(pv_request->source_io,
                                                                     &put_size);

                    if (result == 0)
                    {
                        cgutils_http_callbacks const http_cbs = {
                            .response_cb = &cg_storage_provider_utils_http_raw_response_callback,
                            .read_cb = &cg_storage_provider_utils_read_cb,
                            .header_cb = &cg_storage_provider_utils_header_cb,
                        };

                        result = cg_stp_amz_send_put_request(pv_request,
                                                             host,
                                                             path,
                                                             NULL,
                                                             put_size,
                                                             headers,
                                                             CG_STP_AMZ_USE_BUCKET,
                                                             CG_STP_AMZ_NO_CUSTOM_BUCKET,
                                                             CG_STP_RESPONSE_FORMAT_RAW,
                                                             &http_cbs,
                                                             CG_STP_NO_OPT_HTTP_TIMEOUTS);

                        if (result != 0)
                        {
                            CGUTILS_ERROR("Error sending request: %d", result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error getting final size: %d", result);
                    }

                    CGUTILS_FREE(path);
                }
                else
                {
                    CGUTILS_ERROR("Error computing path: %d", result);
                }
            }

            CGUTILS_FREE(host);
        }
        else
        {
                CGUTILS_ERROR("Error getting hostname: %d", result);
        }

        if (result != 0)
        {
            if (headers != NULL)
            {
                cgutils_llist_free(&headers, &cgutils_http_header_delete);
            }

            cg_storage_provider_handle_status_response(pv_request, result);
        }
    }

    return result;
}

static int cg_stp_amz_put_multipart_init_cb(int status,
                                            cgutils_xml_reader * response,
                                            void * cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;

    if (result == 0)
    {
        assert(response != NULL);

        result = cgutils_xml_reader_register_namespace(response, "amz", CG_STP_AMZ_NS);

        if (result == 0)
        {
            result = cgutils_xml_reader_get_string(response, "amz:UploadId", &(pv_request->ctx->multipart_id));

            if (result == 0)
            {
            }
            else
            {
                CGUTILS_ERROR("Error getting upload id: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error registering AMZ namespace: %d", result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error in Multi-Part initialization request: %d", result);
    }

    result = cg_storage_provider_handle_status_response(pv_request, status);

    return result;
}

static int cg_stp_amz_put_multipart_init(cg_storage_provider_request * pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        char * host = NULL;
        cg_stp_amz_specifics * specifics = pv_request->ctx->instance_specifics;
        pv_request->xml_request_cb = &cg_stp_amz_put_multipart_init_cb;
        pv_request->request_cb_data = pv_request;

        result = cg_stp_amz_get_host_with_bucket(specifics,
                                                 NULL,
                                                 NULL,
                                                 &host);

        if (result == 0)
        {
            cgutils_llist * headers = NULL;

            /* Meta data handling is disabled for Amazon,
               because the signature does not yet handle x-amz- headers. */
            /*
            if (pv_request->ctx->metadata != NULL)
            {
                result = cgutils_llist_create(&headers);

                if (result == 0)
                {
                    result = cg_storage_provider_utils_add_header_from_meta(pv_request,
                                                                            "filename",
                                                                            CG_STP_AMZ_METADATA_HEADER_FILENAME,
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
            */

            if (result == 0)
            {
                size_t const key_len = strlen(pv_request->ctx->key);
                size_t const url_len = 1 /* for leading / */
                    + key_len + sizeof CG_STP_AMZ_MAGIC_MULTIPART_UPLOAD - 1;
                char * path = NULL;
                CGUTILS_MALLOC(path, url_len + 1, 1);

                if (path != NULL)
                {
                    *path = '/';
                    memcpy(path + 1, pv_request->ctx->key, key_len);
                    memcpy(path + 1 + key_len, CG_STP_AMZ_MAGIC_MULTIPART_UPLOAD, sizeof CG_STP_AMZ_MAGIC_MULTIPART_UPLOAD);

                    result = cg_stp_amz_send_post_request(pv_request,
                                                          host,
                                                          path,
                                                          NULL,
                                                          0,
                                                          headers,
                                                          CG_STP_AMZ_USE_BUCKET,
                                                          CG_STP_AMZ_NO_CUSTOM_BUCKET,
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
                    result = ENOMEM;
                    CGUTILS_ERROR("Error allocating memory to URI: %d", result);
                }
            }

            if (result != 0 && headers != NULL)
            {
                cgutils_llist_free(&headers, &cgutils_http_header_delete);
            }

            CGUTILS_FREE(host);
        }
        else
        {
            CGUTILS_ERROR("Error getting host: %d", result);
        }

        if (result != 0)
        {
            cg_storage_provider_handle_status_response(pv_request, result);
        }
    }

    return result;
}

static int cg_stp_amz_put_multipart_part_cb(int status,
                                            void * cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    assert(cb_data != NULL);

    if (result == 0)
    {
        cgutils_http_header const * etag_header = NULL;

        result = cgutils_http_get_header_by_name(pv_request->received_headers,
                                                 CG_STP_AMZ_MAGIC_HEADER_NAME_ETAG,
                                                 &etag_header);

        if (result == 0)
        {
            pv_request->multipart_etag = cgutils_strdup(etag_header->value);

            if (pv_request->multipart_etag != NULL)
            {
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for ETag: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to get " CG_STP_AMZ_MAGIC_HEADER_NAME_ETAG " header, required for a part upload: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error in request: %d", status);
    }

    result = cg_storage_provider_handle_status_response(pv_request, status);

    return result;
}

static int cg_stp_amz_put_multipart_part(cg_storage_provider_request * pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        char * host = NULL;
        cg_stp_amz_specifics * specifics = pv_request->ctx->instance_specifics;

        pv_request->raw_request_cb = &cg_stp_amz_put_multipart_part_cb;
        pv_request->request_cb_data = pv_request;

        result = cg_stp_amz_get_host_with_bucket(specifics,
                                                 NULL,
                                                 NULL,
                                                 &host);

        if (result == 0)
        {
            char * path = NULL;

            result = cg_stp_amz_compute_part_uri(pv_request->ctx->key,
                                                 pv_request->part_number,
                                                 pv_request->ctx->multipart_id,
                                                 &path);

            if (result == 0)
            {
                size_t put_size = 0;

                result = cg_storage_io_ctx_source_get_final_size(pv_request->source_io,
                                                                 &put_size);

                if (result == 0)
                {
                    cgutils_http_callbacks const http_cbs = {
                        .response_cb = &cg_storage_provider_utils_http_raw_response_callback,
                        .read_cb = &cg_storage_provider_utils_read_cb,
                        .header_cb = &cg_storage_provider_utils_header_cb,
                    };

                    result = cg_stp_amz_send_put_request(pv_request,
                                                         host,
                                                         path,
                                                         NULL,
                                                         put_size,
                                                         CG_STP_NO_ADDITIONAL_HEADERS,
                                                         CG_STP_AMZ_USE_BUCKET,
                                                         CG_STP_AMZ_NO_CUSTOM_BUCKET,
                                                         CG_STP_RESPONSE_FORMAT_RAW,
                                                         &http_cbs,
                                                         CG_STP_NO_OPT_HTTP_TIMEOUTS);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error sending request: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error getting final size: %d", result);
                }

                CGUTILS_FREE(path);
            }
            else
            {
                CGUTILS_ERROR("Error computing path: %d", result);
            }

            CGUTILS_FREE(host);
        }
        else
        {
            CGUTILS_ERROR("Error getting hostname: %d", result);
        }

        if (result != 0)
        {
            cg_storage_provider_handle_status_response(pv_request, result);
        }
    }

    return result;
}

static int cg_stp_amz_put_multipart_finish_cb(int const status,
                                              cgutils_xml_reader * const reader,
                                              void * cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    assert(cb_data != NULL);

    (void) reader;

    if (result == 0)
    {
        CGUTILS_TRACE("Multipart completed");
    }
    else
    {
        CGUTILS_ERROR("Error completing multipart upload: %d", result);
    }

    result = cg_storage_provider_handle_status_response(pv_request, status);

    return result;
}

static int cg_stp_amz_put_multipart_finish_send_payload(cg_storage_provider_request * pv_request,
                                                        char * payload,
                                                        size_t const payload_size)
{
    assert(pv_request != NULL);
    assert(payload != NULL);

    cg_stp_amz_specifics * specifics = pv_request->ctx->instance_specifics;
    char * host = NULL;

    pv_request->xml_request_cb = &cg_stp_amz_put_multipart_finish_cb;
    pv_request->request_cb_data = pv_request;

    int result = cg_stp_amz_get_host_with_bucket(specifics,
                                                 NULL,
                                                 NULL,
                                                 &host);

    if (result == 0)
    {
        char * path = NULL;

        result = cg_stp_amz_compute_part_uri(pv_request->ctx->key,
                                             0,
                                             pv_request->ctx->multipart_id,
                                             &path);

        if (result == 0)
        {
            cgutils_llist * headers = NULL;

            result = cgutils_llist_create(&headers);

            if (result == 0)
            {
                result = cgutils_http_add_header_to_list_dup(headers,
                                                             "Content-Type",
                                                             CG_STP_AMZ_MAGIC_XML_CONTENT_TYPE);

                if (result == 0)
                {
                    /* Should be done with source memory IO */
                    pv_request->payload = payload;

                    result = cg_stp_amz_send_post_request(pv_request,
                                                          host,
                                                          path,
                                                          payload,
                                                          payload_size,
                                                          headers,
                                                          CG_STP_AMZ_USE_BUCKET,
                                                          CG_STP_AMZ_NO_CUSTOM_BUCKET,
                                                          CG_STP_RESPONSE_FORMAT_XML,
                                                          CG_STP_NO_OPT_HTTP_CALLBACKS,
                                                          CG_STP_NO_OPT_HTTP_TIMEOUTS);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error sending request: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error adding http header: %d", result);
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
            CGUTILS_FREE(path);
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory to URI: %d", result);
        }

        CGUTILS_FREE(host);
    }
    else
    {
        CGUTILS_ERROR("Error getting host: %d", result);
    }

    return result;
}

static int cg_stp_amz_put_multipart_finish(cg_storage_provider_request * pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        cgutils_xml_writer * writer = NULL;

        result = cgutils_xml_writer_new(&writer);

        if (result == 0)
        {
            cgutils_xml_writer_element * root = NULL;

            result = cgutils_xml_writer_create_root(writer,
                                                    CG_STP_AMZ_MAGIC_UPLOAD_KEY,
                                                    &root);

            if (result == 0)
            {
                assert(pv_request->ctx != NULL);
                assert(pv_request->ctx->parts != NULL);

                for (cgutils_llist_elt * part = cgutils_llist_get_iterator(pv_request->ctx->parts);
                     result == 0 && part != NULL;
                     part = cgutils_llist_elt_get_next(part))
                {
                    cg_storage_provider_request * part_request = cgutils_llist_elt_get_object(part);
                    assert(part_request != NULL);

                    if (part_request->part_number > 0)
                    {
                        cgutils_xml_writer_element * part_element = NULL;

                        result = cgutils_xml_writer_element_add_child(root,
                                                                      CG_STP_AMZ_MAGIC_PART_KEY,
                                                                      NULL,
                                                                      &part_element);

                        if (result == 0)
                        {
                            cgutils_xml_writer_element * part_number_elt = NULL;

                            result = cgutils_xml_writer_element_add_size_child(part_element,
                                                                               CG_STP_AMZ_MAGIC_PART_NUMBER_KEY,
                                                                               part_request->part_number,
                                                                               &part_number_elt);

                            if (result == 0)
                            {
                                cgutils_xml_writer_element * etag_elt = NULL;

                                result = cgutils_xml_writer_element_add_child(part_element,
                                                                              CG_STP_AMZ_MAGIC_ETAG_KEY,
                                                                              part_request->multipart_etag,
                                                                              &etag_elt);

                                if (result == 0)
                                {
                                    cgutils_xml_writer_element_release(etag_elt), etag_elt = NULL;
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error creating part etag element: %d", result);
                                }

                                cgutils_xml_writer_element_release(part_number_elt), part_number_elt = NULL;
                            }
                            else
                            {
                                CGUTILS_ERROR("Error creating part number element: %d", result);
                            }

                            cgutils_xml_writer_element_release(part_element), part_element = NULL;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error creating part element: %d", result);
                        }
                    }
                }

                if (result == 0)
                {
                    char * str = NULL;
                    size_t str_size = 0;

                    result = cgutils_xml_writer_get_output(writer,
                                                           &str,
                                                           &str_size);

                    if (result == 0)
                    {
                        result = cg_stp_amz_put_multipart_finish_send_payload(pv_request, str, str_size);

                        if (result != 0)
                        {
                            CGUTILS_ERROR("Error in cg_storage_provider_amazon_send_complete_multipart: %d", result);

                            cgutils_xml_writer_string_free(str), str = NULL;
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error converting XML Writer to string: %d", result);
                }

                }

                cgutils_xml_writer_element_release(root), root = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error creating root element: %d", result);
            }

            cgutils_xml_writer_free(writer), writer = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error creating writer: %d", result);
        }

        if (result != 0)
        {
            cg_storage_provider_handle_status_response(pv_request, result);
        }
    }

    return result;
}

static int cg_stp_amz_put_multipart_canceled(int const status,
                                             void * const cb_data)
{
    int result = status;
    cg_storage_provider_request * pv_request = cb_data;
    assert(cb_data != NULL);

    if (result == ENOENT)
    {
        result = 0;
    }

    if (result == 0)
    {
        CGUTILS_INFO("Multipart canceled");
    }
    else
    {
        CGUTILS_ERROR("Error canceling multipart upload: %d", result);
    }

    result = cg_storage_provider_handle_status_response(pv_request, status);

    return result;
}

static int cg_stp_amz_put_multipart_cancel(cg_storage_provider_request * pv_request)
{
    int result = EINVAL;

    if (pv_request != NULL)
    {
        /* DELETE /ObjectName?uploadID=UploadID */
        cg_stp_amz_specifics * specifics = pv_request->ctx->instance_specifics;
        char * host = NULL;

        pv_request->raw_request_cb = &cg_stp_amz_put_multipart_canceled;
        pv_request->request_cb_data = pv_request;

        result = cg_stp_amz_get_host_with_bucket(specifics,
                                                 NULL,
                                                 NULL,
                                                 &host);

        if (result == 0)
        {
            char * path = NULL;

            result = cg_stp_amz_compute_part_uri(pv_request->ctx->key,
                                                 0,
                                                 pv_request->ctx->multipart_id,
                                                 &path);

            if (result == 0)
            {
                result = cg_stp_amz_send_delete_request(pv_request,
                                                        host,
                                                        path,
                                                        CG_STP_NO_ADDITIONAL_HEADERS,
                                                        CG_STP_AMZ_USE_BUCKET,
                                                        CG_STP_AMZ_NO_CUSTOM_BUCKET,
                                                        CG_STP_RESPONSE_FORMAT_RAW,
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
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory to URI: %d", result);
            }

            CGUTILS_FREE(host);
        }
        else
        {
            CGUTILS_ERROR("Error getting host: %d", result);
        }

        if (result != 0)
        {
            cg_storage_provider_handle_status_response(pv_request, result);
        }
    }

    return result;
}

static int cg_stp_amz_setup_done(int const status,
                                 cgutils_xml_reader * reader,
                                 void * cb_data)
{
    int result = status;
    assert(cb_data != NULL);
    cg_storage_provider_request * pv_request = cb_data;
    cg_stp_amz_specifics * const specifics = pv_request->ctx->instance_specifics;
    cg_stp_amz_provider_data * const pvd = pv_request->ctx->provider_data;
    assert(specifics != NULL);
    assert(pvd != NULL);

    if (result == 0)
    {
    }
    else if (result == EACCES || result == EPERM)
    {
        bool reader_allocated = false;
        size_t const response_data_size = cg_storage_io_mem_get_output_size(pv_request->dest_io);

        CGUTILS_ERROR("Authentication error, please check the credentials for the Access Key Id %s, and check your clock time.",
                      specifics->access_key_id);

        if (reader == NULL &&
            response_data_size > 0)
        {
            /* We have an XML response, but it has not been processed yet. */
            char const * response_data = NULL;
            int res = cg_storage_io_mem_get_output(pv_request->dest_io,
                                                  &response_data);

            if (res == 0)
            {
                res = cgutils_xml_reader_from_buffer(response_data,
                                                     response_data_size,
                                                     &reader);

                if (res == 0)
                {
                    reader_allocated = true;
                }
                else
                {
                    CGUTILS_ERROR("Error parsing XML response: %d", res);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting response data: %d", res);
            }
        }

        if (reader != NULL)
        {
            char * error_code = NULL;

            int res = cgutils_xml_reader_get_string(reader,
                                                    "Code",
                                                    &error_code);

            if (res == 0)
            {
                char * error_message = NULL;

                CGUTILS_ERROR("Authentication error. The error code sent by Amazon's server is: %s",
                              error_code);

                res = cgutils_xml_reader_get_string(reader,
                                                    "Message",
                                                    &error_message);

                if (res == 0)
                {
                    CGUTILS_ERROR("Authentication error. The error message sent by Amazon's server is: %s",
                                  error_message);
                    CGUTILS_FREE(error_message);
                }
                else
                {
                    CGUTILS_WARN("Error getting Amazon's error message: %d", result);
                }

                CGUTILS_FREE(error_code);
            }
            else
            {
                CGUTILS_WARN("Error getting Amazon's error message: %d", result);
            }

            if (reader != NULL &&
                reader_allocated == true)
            {
                cgutils_xml_reader_free(reader), reader = NULL;
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Error in Authentication request for Access Key Id %s: %d",
                      specifics->access_key_id,
                      result);
    }

    if (specifics->init == true)
    {
        cg_storage_manager_data_set_provider_init_finished(pvd->data, result);
    }

    cg_storage_provider_request_ctx_free(pv_request->ctx), pv_request = NULL;

    return result;
}

static int cg_stp_amz_setup(cg_storage_provider * const provider,
                            void * const provider_data,
                            void * const specifics_gen)
{
    int result = EINVAL;

    if (provider != NULL && provider_data != NULL && specifics_gen != NULL)
    {
        cg_stp_amz_provider_data * const pvd = provider_data;
        cg_stp_amz_specifics * const specifics = specifics_gen;

        cg_storage_provider_request * pv_request = NULL;

        if (pvd->http == NULL)
        {
            pvd->http = cg_storage_manager_data_get_http(pvd->data);
        }

        result = cg_storage_provider_single_request_init(provider,
                                                         specifics,
                                                         CG_STP_UTILS_NO_ID,
                                                         cg_storage_provider_request_callback_type_none,
                                                         CG_STP_UTILS_NO_STATUS_CB,
                                                         CG_STP_UTILS_NO_LIST_CB,
                                                         CG_STP_UTILS_NO_PUT_CB,
                                                         CG_STP_UTILS_NO_GET_CB,
                                                         CG_STP_UTILS_NO_CONTAINER_STATS_CB,
                                                         NULL,
                                                         &pv_request);

        if (result == 0)
        {
            char * host = NULL;

            pv_request->xml_request_cb = &cg_stp_amz_setup_done;
            pv_request->request_cb_data = pv_request;

            result = cg_stp_amz_get_host_without_bucket(specifics, &host);

            if (result == 0)
            {
                result = cg_stp_amz_send_get_request(pv_request,
                                                     host,
                                                     "/",
                                                     CG_STP_NO_ADDITIONAL_HEADERS,
                                                     CG_STP_AMZ_NO_BUCKET,
                                                     CG_STP_AMZ_NO_CUSTOM_BUCKET,
                                                     CG_STP_RESPONSE_FORMAT_XML,
                                                     CG_STP_NO_OPT_HTTP_CALLBACKS,
                                                     CG_STP_NO_OPT_HTTP_TIMEOUTS);

                if (result == 0)
                {
                    cg_storage_manager_data_set_provider_init_pending(pvd->data);
                }
                else
                {
                    CGUTILS_ERROR("Error sending Auth Request: %d", result);
                    cg_storage_provider_request_ctx_free(pv_request->ctx), pv_request = NULL;
                }

                CGUTILS_FREE(host);
            }
            else
            {
                CGUTILS_ERROR("Error getting host: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error creating request: %d", result);
        }
    }

    return result;
}

static int cg_stp_amz_parse_specifics(void * provider_data,
                                     cgutils_configuration * const config,
                                     void ** data)
{
    int result = EINVAL;

    (void) provider_data;

    if (config != NULL && data != NULL)
    {
        cg_stp_amz_specifics * specifics = NULL;

        CGUTILS_ALLOCATE_STRUCT(specifics);

        if (specifics != NULL)
        {
            /* Default values, may be overriden by configuration */
            specifics->check_object_hash = true;
            specifics->verbose = false;
            specifics->show_http_requests = false;
            specifics->disable_100_continue = false;
            specifics->disable_fast_open = false;
            specifics->allow_insecure_https = false;
            specifics->init = true;
            specifics->http_timeout = CG_STP_AMZ_DEFAULT_HTTP_TIMEOUT;
            result = 0;

#define STRING_PARAM(name, path, required) CG_STP_UTILS_RETRIEVE_STRING(config, specifics, result, name, path, required)
#define UINT64_PARAM(name, path, required) CG_STP_UTILS_RETRIEVE_UINT64(config, specifics, result, name, path, required)
#define SIZE_PARAM(name, path, required) CG_STP_UTILS_RETRIEVE_SIZE(config, specifics, result, name, path, required)
#define BOOLEAN_PARAM(name, path, required) CG_STP_UTILS_RETRIEVE_BOOLEAN(config, specifics, result, name, path, required)
#include "cg_storage_provider_amazon_parameters.itm"
#undef BOOLEAN_PARAM
#undef UINT64_PARAM
#undef SIZE_PARAM
#undef STRING_PARAM

            if (result == 0)
            {
                specifics->secret_access_key_len = strlen(specifics->secret_access_key);
                specifics->access_key_id_len = strlen(specifics->access_key_id);
                specifics->bucket_len = strlen(specifics->bucket);
                specifics->endpoint_len = strlen(specifics->endpoint);
                specifics->endpoint_path_len = specifics->endpoint_path != NULL ? strlen(specifics->endpoint_path) : 0;
                specifics->endpoint_port_len = strlen(specifics->endpoint_port);

                if (specifics->secret_access_key_len == 0)
                {
                    CGUTILS_ERROR("Empty Amazon Secret Access Key");
                    result = EINVAL;
                }

                if (specifics->access_key_id_len == 0)
                {
                    CGUTILS_ERROR("Empty Amazon Access Key ID");
                    result = EINVAL;
                }

                if (specifics->bucket_len == 0)
                {
                    CGUTILS_ERROR("Empty Amazon bucket name");
                    result = EINVAL;
                }

                if (specifics->endpoint_len == 0)
                {
                    CGUTILS_ERROR("Empty Amazon endpoint");
                    result = EINVAL;
                }

                if (specifics->max_single_upload_size < (CG_STP_AMZ_MIN_MULTI_PART * (size_t) 2))
                {
                    /* If the specified maximum size for file uploaded in a single part is too low */

                    if (specifics->max_single_upload_size > 0)
                    {
                        CGUTILS_WARN("Warning, the specified maximum size of %zu for a file uploaded in a single part (MaxSingleUploadSize) is below the minimum of %zu, the default value of %zu will be used instead.",
                                     specifics->max_single_upload_size,
                                     (CG_STP_AMZ_MIN_MULTI_PART * (size_t) 2),
                                     (CG_STP_AMZ_MAX_PART_SIZE_DEFAULT));
                    }

                    specifics->max_single_upload_size = CG_STP_AMZ_MAX_SIMPLE_UP_FILE_SIZE_DEFAULT;
                }
                else if (specifics->max_single_upload_size >= CG_STP_AMZ_MAX_PART_SIZE_DEFAULT)
                {
                    /* Warn if it is higher than the maximum part size supported by AWS S3 */
                    CGUTILS_WARN("Warning, the default size for a single part for most S3 installations is %zu, you are using %zu.",
                                 (CG_STP_AMZ_MAX_PART_SIZE_DEFAULT),
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
            }

            if (result != 0)
            {
                cg_stp_amz_clear_specifics(specifics), specifics = NULL;
            }

            *data = specifics;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

static bool cg_stp_amz_is_valid_response_code(cg_storage_provider_request const * const pv_request,
                                              uint16_t const code)
{
    bool result = false;

    if (pv_request != NULL)
    {
        if (code == 200 || code == 204)
        {
            result = true;
        }
    }

    return result;
}

static int cg_stp_amz_init_object_hash(cg_storage_provider_request * const request)
{
    int result = EINVAL;

    if (request != NULL)
    {
        cg_stp_amz_specifics const * const specifics = request->ctx->instance_specifics;
        assert(specifics != NULL);
        assert(request->object_hash_ctx == NULL);
        assert(request->compute_object_hash == false);

        result = 0;

        if (specifics->check_object_hash == true)
        {
            result = cgutils_crypto_hash_context_init(CG_STP_AMZ_OBJECT_HASH_ALGO,
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

static int cg_stp_amz_update_object_hash(cg_storage_provider_request * const request,
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

static int cg_stp_amz_check_object_hash(cg_storage_provider_request * const request,
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
                                                                           CG_STP_AMZ_MAGIC_HEADER_NAME_ETAG,
                                                                           &etag_value,
                                                                           &etag_value_len);
            if (result == 0)
            {
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
                                CGUTILS_WARN("Hash does not match:\n %s\n vs %s",
                                              etag_value,
                                              hash_hex);
                            }
                        }
                        else if (etag_value_len > 32)
                        {
                            /* The Amazon S3 API returns an opaque Etag value ([a-f0-9]{32}-[0-9]+) for object uploaded
                               using the multipart API. We have no way of verifying the object hash
                               in this case, and we have computed the hash for nothing.
                            */
                            result = ENOENT;
                        }
                        else
                        {
                            CGUTILS_WARN("Hash len doesn't match. \nHex hash is (%zu)%s\nHdr etag is (%zu)%s, ",
                                         hash_hex_size - 1,
                                         hash_hex,
                                         etag_value_len,
                                         etag_value);
                            result = ENOENT;
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
            result = ENOENT;
        }
    }

    return result;
}

static void cg_stp_amz_all_headers_received(cg_storage_provider_request * const request)
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
                                                                                   CG_STP_AMZ_MAGIC_HEADER_NAME_ETAG,
                                                                                   &etag_value,
                                                                                   &etag_value_len);

                if (result == 0)
                {
                    if (etag_value_len == CG_STP_AMZ_OBJECT_HASH_ALGO_LEN)
                    {
                        compute = true;
                    }

                    CGUTILS_FREE(etag_value);
                }
            }

            request->compute_object_hash = compute;
        }
    }
}

static size_t cg_stp_amz_get_single_upload_size(void const * const data)
{
    size_t result = CG_STP_AMZ_MAX_SIMPLE_UP_FILE_SIZE_DEFAULT;

    if (data != NULL)
    {
        cg_stp_amz_specifics const * const specifics = data;
        result = specifics->max_single_upload_size;
    }

    return result;
}

COMPILER_BLOCK_VISIBILITY_DEFAULT

extern cg_stp_vtable const cg_storage_provider_amazon_vtable;

cg_stp_vtable const cg_storage_provider_amazon_vtable =
{
    .capabilities =
    {
        /* The S3 API does not support Chunked Transfer Encoding on request.
           Welcome to 2013, rfc2616. */
        .chunked_upload = false,
        .object_hashing = true,
    },
    .init = &cg_stp_amz_init,
    .destroy = &cg_stp_amz_destroy,
    .parse_specifics = &cg_stp_amz_parse_specifics,
    .clear_specifics = &cg_stp_amz_clear_specifics,
    .setup = &cg_stp_amz_setup,
    .create_container = &cg_stp_amz_create_bucket,
    .remove_empty_container = &cg_stp_amz_remove_empty_bucket,
    .list_containers = &cg_stp_amz_list_buckets,
    .list_files = &cg_stp_amz_list_files,
    .get_file = &cg_stp_amz_get_file,
    .put_file = &cg_stp_amz_put_file,
    .delete_file = &cg_stp_amz_delete_file,
    .put_multipart_init = &cg_stp_amz_put_multipart_init,
    .put_multipart_part = &cg_stp_amz_put_multipart_part,
    .put_multipart_finish = &cg_stp_amz_put_multipart_finish,
    .put_multipart_cancel = &cg_stp_amz_put_multipart_cancel,
    .is_valid_response_code = &cg_stp_amz_is_valid_response_code,
    .init_object_hash = &cg_stp_amz_init_object_hash,
    .update_object_hash = &cg_stp_amz_update_object_hash,
    .check_object_hash = &cg_stp_amz_check_object_hash,
    .all_headers_received = &cg_stp_amz_all_headers_received,
    .get_single_upload_size = &cg_stp_amz_get_single_upload_size,
};

COMPILER_BLOCK_VISIBILITY_END
