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

#include <errno.h>
#include <string.h>

#include <cgsmclient/cgsmc_async.h>
#include <cgsmclient/cgsmc_async_connection.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_event.h>
#include <cloudutils/cloudutils_network.h>
#include <cloudutils/cloudutils_pool.h>
#include <cloudutils/cloudutils_vector.h>

#include <cgsm/cg_storage_manager_proto.h>

typedef struct cgsmc_async_request cgsmc_async_request;

typedef void (cgsmc_async_response_cb)(cgsmc_async_request *);

typedef enum
{
    cgsmc_async_request_io_type_read = 0,
    cgsmc_async_request_io_type_write = 1
} cgsmc_async_request_io_type ;

typedef enum
{
    cgsmc_async_request_type_none = 0,
    cgsmc_async_request_type_lookup_child,
    cgsmc_async_request_type_getattr,
    cgsmc_async_request_type_setattr,
    cgsmc_async_request_type_readdir,
    cgsmc_async_request_type_create_and_open,
    cgsmc_async_request_type_open,
    cgsmc_async_request_type_release,
    cgsmc_async_request_type_notify_write,
    cgsmc_async_request_type_mkdir,
    cgsmc_async_request_type_rmdir,
    cgsmc_async_request_type_unlink,
    cgsmc_async_request_type_rename,
    cgsmc_async_request_type_hardlink,
    cgsmc_async_request_type_symlink,
    cgsmc_async_request_type_readlink,
    cgsmc_async_request_type_count
} cgsmc_async_request_type;

typedef enum
{
    cgsmc_async_request_state_none = 0,
    cgsmc_async_request_state_sending,
    cgsmc_async_request_state_receiving_response_code,
    cgsmc_async_request_state_receiving_data,
    cgsmc_async_request_state_count,
} cgsmc_async_request_state;

struct cgsmc_async_request
{
    cgsmc_async_data * data;
    cgsmc_async_connection * conn;
    union
    {
        cgsmc_async_stat_cb * stat_cb;
        cgsmc_async_readdir_cb * readdir_cb;
        cgsmc_async_create_and_open_cb * create_and_open_cb;
        cgsmc_async_open_cb * open_cb;
        cgsmc_async_status_cb * status_cb;
        cgsmc_async_returning_inode_number_cb * returning_inode_number_cb;
        cgsmc_async_returning_renamed_and_deleted_inode_number_cb * returning_renamed_and_deleted_inode_number_cb;
        cgsmc_async_readlink_cb * readlink_cb;
    };
    void * cb_data;

    cgsmc_async_response_cb * response_cb;

    /* Buffered IOs */
    cgutils_event_buffered_io * io;

    /* vector of half set up cgutils_event_buffered_io_obj * */
    cgutils_vector * write_ios;
    cgutils_vector * read_ios;

    /* optional request fields */
    char const * name;
    char const * new_name;
    size_t name_len;
    size_t new_name_len;

    uint64_t ino;
    uint64_t new_ino;
    cgsm_proto_uid_type owner;
    cgsm_proto_gid_type group;
    cgsm_proto_mode_type mode;
    cgsm_proto_flags_type flags;

    /* optional response fields */
    struct stat * st;
    char * path_in_cache;
    size_t path_in_cache_len;

    cgsmc_async_entry * entries;
    size_t expected_entries_count;
    size_t entries_count;

    size_t retry_count;
    cgsm_proto_opcode_type opcode;
    cgsmc_async_request_type type;
    int result;
    cgsm_proto_response_code response_code;
    cgsm_proto_size_changed_type file_size_changed;
    cgsm_proto_dirty_type dirty;

    cgsmc_async_request_state state;

    bool io_error;
};

struct cgsmc_async_data
{
    cgutils_event_data * event_data;
    cgutils_pool * connections;
    struct addrinfo * manager_sock_binding;
    char * manager_sock;

    char const * fs_name;
    size_t fs_name_len;

    size_t name_max;
    size_t path_max;
    size_t symlink_max;

    /* Maximum idle time for a pooled connection */
    size_t max_connection_idle_time;

    /* Maximum number of times we can reuse a connection */
    size_t max_requests_per_connection;

    /* Maximum pooled connections */
    size_t max_pooled_connections;

    size_t dirtyness_delay;

    /* Minimum number of entries in a readdir response
       triggering the use of a dir index
    */
    size_t dir_index_limit;

    /* Maximum number of times we are allowed
       to retry a failed connection to the Storage Manager */
    size_t max_retry_count;

    /* Connection validity time:
       connection established after that time
       are no longer valid.
    */
    time_t connection_validity_time;
};

#define CGSMC_ASYNC_MAX_POOLED_CONNECTIONS_DEFAULT (20)
#define CGSMC_ASYNC_MAX_CONNECTION_IDLE_TIME_DEFAULT (120)
#define CGSMC_ASYNC_MAX_REQUESTS_PER_CONNECTION_DEFAULT (1000)
#define CGSMC_ASYNC_MAX_RETRY_COUNT_DEFAULT (3)

#define CGSMC_ASYNC_DIRTYNESS_DELAY_DEFAULT (10)

#define CGSMC_ASYNC_NAME_MAX_DEFAULT (255)  /* NAME_MAX */
#define CGSMC_ASYNC_PATH_MAX_DEFAULT (1024) /* PATH_MAX */
#define CGSMC_ASYNC_SYMLINK_MAX_DEFAULT (0) /* SYMLINK_MAX */

#define CGSMC_ASYNC_DIR_INDEX_LIMIT_DEFAULT (10000)

void cgsmc_async_entry_clean(cgsmc_async_entry * const this)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_FREE(this->name);
    this->name_len = 0;
    this->data = NULL;
}

void cgsmc_async_entry_free(cgsmc_async_entry * this)
{
    if (this != NULL)
    {
        cgsmc_async_entry_clean(this);
        CGUTILS_FREE(this);
    }
}

static int cgsmc_async_load_parameters_from_configuration(cgsmc_async_data * const this,
                                                          cgutils_configuration const * const configuration)
{
    int result = 0;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(configuration != NULL);

#define GET_SIZE_CONF(name, storage, defaultval)                \
    result = cgutils_configuration_get_size(configuration,      \
                                            name,               \
                                            &(storage));        \
    if (result != 0)                                            \
    {                                                           \
        storage = defaultval;                                   \
        if (result != ENOENT)                                   \
        {                                                       \
            if (result == E2BIG)                                \
            {                                                   \
                CGUTILS_WARN("More than one value found for %s, using the default.", name); \
            }                                                   \
            else                                                \
            {                                                   \
                CGUTILS_WARN("Invalid value found for %s, using the default.", name); \
            }                                                   \
        }                                                       \
    }                                                           \

    GET_SIZE_CONF("ConnectionsPoolSize", this->max_pooled_connections, CGSMC_ASYNC_MAX_POOLED_CONNECTIONS_DEFAULT);
    GET_SIZE_CONF("MaxConnectionIdleTime", this->max_connection_idle_time, CGSMC_ASYNC_MAX_CONNECTION_IDLE_TIME_DEFAULT);
    GET_SIZE_CONF("MaxRequestsPerConnection", this->max_requests_per_connection, CGSMC_ASYNC_MAX_REQUESTS_PER_CONNECTION_DEFAULT);
    GET_SIZE_CONF("RetryCount", this->max_retry_count, CGSMC_ASYNC_MAX_RETRY_COUNT_DEFAULT);
    GET_SIZE_CONF("DirtynessDelay", this->dirtyness_delay, CGSMC_ASYNC_DIRTYNESS_DELAY_DEFAULT);
    GET_SIZE_CONF("PathMax", this->path_max, CGSMC_ASYNC_PATH_MAX_DEFAULT);
    GET_SIZE_CONF("NameMax", this->name_max, CGSMC_ASYNC_NAME_MAX_DEFAULT);
    GET_SIZE_CONF("SymlinkMax", this->symlink_max, CGSMC_ASYNC_SYMLINK_MAX_DEFAULT);
    GET_SIZE_CONF("DirIndexLimit", this->dir_index_limit, CGSMC_ASYNC_DIR_INDEX_LIMIT_DEFAULT);

    return 0;
}

static int cgsmc_async_check_symlink_path_validity(cgsmc_async_data const * const this,
                                                   size_t const path_len)
{
    int result = 0;
    CGUTILS_ASSERT(this != NULL);

    if (COMPILER_UNLIKELY(this->symlink_max > 0 &&
                          path_len > this->symlink_max))
    {
        result = ENAMETOOLONG;
    }

    return result;
}

static int cgsmc_async_check_name_validity(cgsmc_async_data const * const this,
                                           size_t const name_len)
{
    int result = 0;
    CGUTILS_ASSERT(this != NULL);

    if (COMPILER_UNLIKELY(this->name_max > 0 &&
                          name_len > this->name_max))
    {
        result = ENAMETOOLONG;
    }

    return result;
}

static int cgsmc_async_get_configuration_from_cgw_file(cgsmc_async_data * const this,
                                                       char const * const configuration_file,
                                                       char const * const fs_name,
                                                       cgutils_configuration ** const configuration)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(configuration_file != NULL);
    CGUTILS_ASSERT(fs_name != NULL);
    CGUTILS_ASSERT(configuration != NULL);

    cgutils_configuration * global_configuration = NULL;
    int result = cgutils_configuration_from_xml_file(configuration_file,
                                                     &global_configuration);

    if (result == 0)
    {

        result = cgutils_configuration_get_string(global_configuration,
                                                  "General/CommunicationSocket",
                                                  &(this->manager_sock));
        if (result == 0)
        {
            char * xpath_str = NULL;

            result = cgutils_asprintf(&xpath_str,
                                      "FileSystems/FileSystem[Id='%s']",
                                      fs_name);

            if (result == 0)
            {
                CGUTILS_ASSERT(xpath_str != NULL);

                result = cgutils_configuration_from_path(global_configuration,
                                                         xpath_str,
                                                         configuration);

                if (result != 0)
                {
                    CGUTILS_ERROR("There does not seem to be a filesystem/volume named %s in this file (%s): %d",
                                  fs_name,
                                  configuration_file,
                                  result);
                }

                CGUTILS_FREE(xpath_str);
            }
            else
            {
                CGUTILS_ERROR("Error allocating memory for xpath: %d",
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to get the General/CommunicationSocket value from the Cloud Gateway Configuration file (%s): %d",
                          configuration_file,
                          result);
        }

        cgutils_configuration_free(global_configuration), global_configuration = NULL;
    }
    else
    {
        CGUTILS_ERROR("Unable to get configuration from the Cloud Gateway Configuration file (%s): %d",
                      configuration_file,
                      result);
    }

    return result;
}

static int cgsm_async_load_configuration(cgsmc_async_data * const this,
                                         char const * const configuration_file_path)
{
    int result = 0;
    cgutils_configuration * configuration = NULL;
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(configuration_file_path != NULL);

    result = cgsmc_async_get_configuration_from_cgw_file(this,
                                                         configuration_file_path,
                                                         this->fs_name,
                                                         &configuration);

    if (result == 0)
    {
        result = cgsmc_async_load_parameters_from_configuration(this,
                                                                configuration);

        if (result != 0)
        {
            CGUTILS_ERROR("Unable to load parameters from configuration: %d", result);
        }

        cgutils_configuration_free(configuration), configuration = NULL;
    }

    return result;
}

int cgsmc_async_data_init(char const * const fs_name,
                          char const * const configuration_file_path,
                          cgutils_event_data * const event_data,
                          cgsmc_async_data ** const out)
{
    int result = 0;
    cgsmc_async_data * this = NULL;
    struct addrinfo * binding = NULL;
    CGUTILS_ASSERT(fs_name != NULL);
    CGUTILS_ASSERT(configuration_file_path != NULL);
    CGUTILS_ASSERT(event_data != NULL);
    CGUTILS_ASSERT(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(this);

    if (this != NULL)
    {
        this->fs_name = fs_name;
        this->fs_name_len = strlen(fs_name);

        result = cgsm_async_load_configuration(this,
                                               configuration_file_path);

        if (result == 0)
        {
            result = cgutils_network_get_addrinfo_from_unix_path(this->manager_sock,
                                                                 &binding);

            if (result == 0)
            {
                result = cgutils_pool_init(this->max_pooled_connections,
                                           &cgsmc_async_connection_delete,
                                           false,
                                           false,
                                           &(this->connections));

                if (result == 0)
                {
                    this->manager_sock_binding = binding, binding = NULL;

                    this->event_data = event_data;

                    *out = this;
                }
                else
                {
                    CGUTILS_ERROR("Error allocating connections pool: %d",
                                  result);
                }

                if (binding != NULL)
                {
                    freeaddrinfo(binding), binding = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error parsing the Storage Manager socket path: %d",
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error loading configuration from %s: %d",
                          configuration_file_path,
                          result);
        }

        if (result != 0)
        {
            cgsmc_async_data_free(this), this = NULL;
        }
    }
    else
    {
        result = ENOMEM;
        CGUTILS_ERROR("Error allocating cgsmc object: %d",
                      result);
    }

    return result;
}

void cgsmc_async_data_free(cgsmc_async_data * this)
{
    if (this != NULL)
    {
        if (this->connections != NULL)
        {
            cgutils_pool_free(this->connections), this->connections = NULL;
        }

        if (this->manager_sock_binding != NULL)
        {
            freeaddrinfo(this->manager_sock_binding), this->manager_sock_binding = NULL;
        }

        CGUTILS_FREE(this->manager_sock);

        this->fs_name = NULL;

        this->event_data = NULL;

        this->fs_name_len = 0;

        CGUTILS_FREE(this);
    }
}

static void cgsmc_async_request_compute_opcode(cgsmc_async_request * const req)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(req->type > cgsmc_async_request_type_none);
    CGUTILS_ASSERT(req->type < cgsmc_async_request_type_count);

    switch (req->type)
    {
    case cgsmc_async_request_type_lookup_child:
        req->opcode = cgsm_proto_opcode_low_lookup_child;
        break;
    case cgsmc_async_request_type_getattr:
        req->opcode = cgsm_proto_opcode_low_getattr;
        break;
    case cgsmc_async_request_type_setattr:
        req->opcode = cgsm_proto_opcode_low_setattr;
        break;
    case cgsmc_async_request_type_readdir:
        req->opcode = cgsm_proto_opcode_low_readdir;
        break;
    case cgsmc_async_request_type_create_and_open:
        req->opcode = cgsm_proto_opcode_low_create_and_open;
        break;
    case cgsmc_async_request_type_open:
        req->opcode = cgsm_proto_opcode_low_open;
        break;
    case cgsmc_async_request_type_release:
        req->opcode = cgsm_proto_opcode_low_release;
        break;
    case cgsmc_async_request_type_notify_write:
        req->opcode = cgsm_proto_opcode_low_notify_write;
        break;
    case cgsmc_async_request_type_mkdir:
        req->opcode = cgsm_proto_opcode_low_mkdir;
        break;
    case cgsmc_async_request_type_rmdir:
        req->opcode = cgsm_proto_opcode_low_rmdir;
        break;
    case cgsmc_async_request_type_unlink:
        req->opcode = cgsm_proto_opcode_low_unlink;
        break;
    case cgsmc_async_request_type_rename:
        req->opcode = cgsm_proto_opcode_low_rename;
        break;
    case cgsmc_async_request_type_hardlink:
        req->opcode = cgsm_proto_opcode_low_hardlink;
        break;
    case cgsmc_async_request_type_symlink:
        req->opcode = cgsm_proto_opcode_low_symlink;
        break;
    case cgsmc_async_request_type_readlink:
        req->opcode = cgsm_proto_opcode_low_readlink;
        break;
    case cgsmc_async_request_type_none:
    case cgsmc_async_request_type_count:
        CGUTILS_ERROR("Invalid type %d",
                      req->type);
        break;
    }
}

static void cgsmc_async_request_release_connection(cgsmc_async_request * const req)
{
    bool pooled = false;
    CGUTILS_ASSERT(req != NULL);
    cgsmc_async_connection * conn = req->conn;
    CGUTILS_ASSERT(conn != NULL);
    req->conn = NULL;

    if (COMPILER_LIKELY(req->io_error == false))
    {
        time_t const creation_time = cgsmc_async_connection_get_creation_time(conn);
        size_t const requests = cgsmc_async_connection_get_request_count(conn);

        if (COMPILER_LIKELY(creation_time > req->data->connection_validity_time &&
                            (req->data->max_requests_per_connection == 0 ||
                             requests <= req->data->max_requests_per_connection) &&
                            cgsmc_async_connection_is_valid(conn) == true))
        {
            cgsmc_async_connection_increase_request_count(conn);
            cgsmc_async_connection_set_idle(conn);

            int result = cgutils_pool_add(req->data->connections,
                                          conn);

            if (COMPILER_LIKELY(result == 0))
            {
                conn = NULL;
                pooled = true;
            }
            else
            {
                CGUTILS_ERROR("Error adding connection to pool: %d",
                              result);
            }
        }
    }

    if (pooled == false)
    {
        cgsmc_async_connection_free(conn), conn = NULL;
    }
}

static void cgsmc_async_request_free(cgsmc_async_request * req)
{
    if (COMPILER_LIKELY(req != NULL))
    {
        CGUTILS_FREE(req->st);
        CGUTILS_FREE(req->path_in_cache);
        req->path_in_cache_len = 0;

        if (req->io != NULL)
        {
            cgutils_event_buffered_io_release(req->io), req->io = NULL;
        }

        if (req->write_ios != NULL)
        {
            cgutils_vector_deep_free(&(req->write_ios), &free), req->write_ios = NULL;
        }

        if (req->read_ios != NULL)
        {
            cgutils_vector_deep_free(&(req->read_ios), &free), req->read_ios = NULL;
        }

        if (req->conn != NULL)
        {
            cgsmc_async_request_release_connection(req), req->conn = NULL;
        }

        CGUTILS_FREE(req);
    }
}

static int cgsmc_async_request_init(cgsmc_async_data * data,
                                    cgsmc_async_request_type const type,
                                    cgsmc_async_request ** out)
{
    int result = 0;
    cgsmc_async_request * req = NULL;

    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(req);

    if (COMPILER_LIKELY(req != NULL))
    {
        req->data = data;
        req->type = type;
        req->state = cgsmc_async_request_state_none;
        *out = req;
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static int cgsmc_async_request_add_ios_to_req(cgsmc_async_request * const req,
                                              cgsmc_async_request_io_type const io_type,
                                              cgutils_event_buffered_io_obj const * const io_objects,
                                              size_t const io_objects_count)
{
    int result = 0;
    cgutils_vector * ios_vector = NULL;
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(io_objects != NULL || io_objects_count == 0);

    if (COMPILER_LIKELY(io_objects_count > 0))
    {
        result = cgutils_vector_init(io_objects_count,
                                     &ios_vector);

        if (COMPILER_LIKELY(result == 0))
        {
            for (size_t idx = 0;
                 result == 0 &&
                     idx < io_objects_count;
                 idx++)
            {
                cgutils_event_buffered_io_obj * obj = NULL;
                CGUTILS_ALLOCATE_STRUCT(obj);

                if (COMPILER_LIKELY(obj != NULL))
                {
                    *obj = io_objects[idx];

                    result = cgutils_vector_add(ios_vector,
                                                obj);

                    if (COMPILER_LIKELY(result == 0))
                    {
                        obj = NULL;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error adding IO object %zu to vector: %d",
                                      idx,
                                      result);
                        CGUTILS_FREE(obj);
                    }
                }
                else
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error allocating memory for IO object %zu: %d",
                                  idx,
                                  result);
                }
            }

            if (COMPILER_LIKELY(result == 0))
            {
                if (io_type == cgsmc_async_request_io_type_read)
                {
                    req->read_ios = ios_vector;
                }
                else
                {
                    req->write_ios = ios_vector;
                }
            }
            else
            {
                cgutils_vector_deep_free(&ios_vector, &free);
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating vector for IO objects: %d",
                          result);
        }
    }

    return result;
}

static int cgsmc_async_get_new_connection(cgsmc_async_request * const req);

static void cgsmc_async_request_clean_for_reconnection(cgsmc_async_request * const req)
{
    CGUTILS_ASSERT(req != NULL);

    /* do not even think about reusing that one */
    cgutils_event_buffered_io_release(req->io), req->io = NULL;
    cgsmc_async_connection_free(req->conn), req->conn = NULL;

    req->state = cgsmc_async_request_state_none;

    CGUTILS_FREE(req->path_in_cache);
    req->path_in_cache_len = 0;

    for (size_t idx = 0;
         idx < req->entries_count;
         idx++)
    {
        CGUTILS_FREE(req->entries[idx].name);
    }
    CGUTILS_FREE(req->entries);
    req->entries_count = 0;
    req->expected_entries_count = 0;

    req->result = 0;
    req->io_error = false;
}

static int cgsmc_async_request_retry(cgsmc_async_request * const req)
{
    int result = 0;
    CGUTILS_ASSERT(req != NULL);
    int const previous_error_code = req->result;
    bool const previous_io_error = req->io_error;

    req->retry_count++;

    cgsmc_async_request_clean_for_reconnection(req);

    result = cgsmc_async_get_new_connection(req);

    if (result != 0)
    {
        /* if reconnection failed, restore previous
           status */
        req->result = previous_error_code;
        req->io_error = previous_io_error;
    }

    return result;
}

static bool cgsmc_async_request_is_idempotent(cgsmc_async_request_type const type)
{
    bool result = false;

    switch (type)
    {
    case cgsmc_async_request_type_notify_write:
    case cgsmc_async_request_type_setattr:
    case cgsmc_async_request_type_lookup_child:
    case cgsmc_async_request_type_getattr:
    case cgsmc_async_request_type_readlink:
    case cgsmc_async_request_type_readdir:
        result = true;
        break;
    default:
        break;
    }

    return result;
}

static bool cgsmc_async_request_may_retry(cgsmc_async_request const * const req)
{
    bool result = false;
    CGUTILS_ASSERT(req != NULL);

    if (req->retry_count <= req->data->max_retry_count)
    {
        if (req->state == cgsmc_async_request_state_sending ||
            req->state == cgsmc_async_request_state_receiving_response_code)
        {
            result = true;
        }
        else if (req->state == cgsmc_async_request_state_receiving_data)
        {
            /* only idempotent requests are allowed to retry
               after having written all their parameters */

            if (cgsmc_async_request_is_idempotent(req->type) == true)
            {
                result = true;
            }
        }
    }

    if (result == false)
    {
        CGUTILS_DEBUG("May retry for req %p is %d (%zu / %d / %d)",
                      req,
                      result,
                      req->retry_count,
                      req->state,
                      cgsmc_async_request_is_idempotent(req->type));
    }

    return result;
}

static void cgsmc_async_request_error(cgsmc_async_request * req)
{
    bool retry = false;
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(req->result != 0);

    /* this callback also handle response code != 0,
       not only IO error */
    if (req->io_error == true &&
        cgsmc_async_request_may_retry(req) == true)
    {
        int result = cgsmc_async_request_retry(req);

        if (COMPILER_LIKELY(result == 0))
        {
            retry = true;
        }
    }

    if (retry == false)
    {
        switch (req->type)
        {
        case cgsmc_async_request_type_release:
        case cgsmc_async_request_type_notify_write:
        case cgsmc_async_request_type_setattr:
            (*(req->status_cb))(req->result,
                                req->cb_data);
            break;
        case cgsmc_async_request_type_lookup_child:
        case cgsmc_async_request_type_getattr:
        case cgsmc_async_request_type_mkdir:
        case cgsmc_async_request_type_hardlink:
        case cgsmc_async_request_type_symlink:
        case cgsmc_async_request_type_readlink:
            (*(req->stat_cb))(req->result,
                              NULL,
                              req->cb_data);
            break;
        case cgsmc_async_request_type_readdir:
            (*(req->readdir_cb))(req->result,
                                 NULL,
                                 0,
                                 false,
                                 req->cb_data);
            break;
        case cgsmc_async_request_type_create_and_open:
            (*(req->create_and_open_cb))(req->result,
                                         NULL,
                                         NULL,
                                         req->cb_data);
            break;
        case cgsmc_async_request_type_open:
            (*(req->open_cb))(req->result,
                              NULL,
                              req->cb_data);
            break;
        case cgsmc_async_request_type_rmdir:
        case cgsmc_async_request_type_unlink:
            (*(req->returning_inode_number_cb))(req->result,
                                                0,
                                                req->cb_data);
            break;
        case cgsmc_async_request_type_rename:
            (*(req->returning_renamed_and_deleted_inode_number_cb))(req->result,
                                                                    0,
                                                                    0,
                                                                    req->cb_data);
            break;
        case cgsmc_async_request_type_none:
        case cgsmc_async_request_type_count:
            CGUTILS_ERROR("Invalid type %d for request %p, with error %d",
                          req->type,
                          req,
                          req->result);
            break;
        }

        cgsmc_async_request_free(req), req = NULL;
    }
}

static void cgsmc_async_request_done(cgsmc_async_request * req)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(req->result == 0);
    /* this function could probably directly call the callback instead
       of using a response_cb, but well, maybe we will have some cases where we need
       that additional callback, let's see. */

    if (COMPILER_LIKELY(req->response_cb == NULL))
    {
        switch (req->type)
        {
        case cgsmc_async_request_type_release:
        case cgsmc_async_request_type_notify_write:
        case cgsmc_async_request_type_setattr:
            (*(req->status_cb))(0,
                                req->cb_data);
            break;
        case cgsmc_async_request_type_lookup_child:
        case cgsmc_async_request_type_getattr:
        case cgsmc_async_request_type_mkdir:
        case cgsmc_async_request_type_hardlink:
        case cgsmc_async_request_type_symlink:
            (*(req->stat_cb))(0,
                              req->st,
                              req->cb_data);
            req->st = NULL;

            break;
        case cgsmc_async_request_type_readdir:
            (*(req->readdir_cb))(0,
                                 req->entries,
                                 req->entries_count,
                                 req->data->dir_index_limit > 0 &&
                                 req->entries_count >= req->data->dir_index_limit,
                                 req->cb_data);
            break;
        case cgsmc_async_request_type_create_and_open:
            (*(req->create_and_open_cb))(0,
                                         req->st,
                                         req->path_in_cache,
                                         req->cb_data);
            req->st = NULL;
            req->path_in_cache = NULL;
            break;
        case cgsmc_async_request_type_open:
        case cgsmc_async_request_type_readlink:
            (*(req->open_cb))(0,
                              req->path_in_cache,
                              req->cb_data);
            req->path_in_cache = NULL;
            break;
        case cgsmc_async_request_type_rmdir:
        case cgsmc_async_request_type_unlink:
            (*(req->returning_inode_number_cb))(req->result,
                                                req->ino,
                                                req->cb_data);
            break;
        case cgsmc_async_request_type_rename:
            (*(req->returning_renamed_and_deleted_inode_number_cb))(req->result,
                                                                    req->new_ino,
                                                                    req->ino,
                                                                    req->cb_data);
            break;
        case cgsmc_async_request_type_none:
        case cgsmc_async_request_type_count:
            CGUTILS_ERROR("Invalid type %d for request %p",
                          req->type,
                          req);
            break;
        }

        cgsmc_async_request_free(req), req = NULL;
    }
    else
    {
        (*(req->response_cb))(req);
    }
}

static int cgsmc_async_request_error_dispatching_cb(cgutils_event_data * const event,
                                                    int const status,
                                                    int const fd,
                                                    cgutils_event_buffered_io_obj * const obj)
{
    CGUTILS_ASSERT(event != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    CGUTILS_ASSERT(obj->cb_data != NULL);
    cgsmc_async_request * const req = obj->cb_data;

    (void) event;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(req->io != NULL);

        if (obj->action == cgutils_event_buffered_io_reading &&
            cgutils_event_buffered_io_remaining_objects_count(req->io) == 0)
        {
            /* We were reading the response, and this object was the last one. */
            cgsmc_async_request_done(req);
        }
    }
    else
    {
        req->io_error = true;
        req->result = status;
        cgsmc_async_request_error(req);
    }

    return status;
}

static int cgsmc_async_connection_add_iovec(cgsmc_async_request * const req,
                                            cgsmc_async_request_io_type const io_type)
{
    int result = 0;
    CGUTILS_ASSERT(req != NULL);
    cgutils_vector const * const vect = io_type == cgsmc_async_request_io_type_read ?
        req->read_ios :
        req->write_ios;
    CGUTILS_ASSERT(vect != NULL);
    cgutils_event_buffered_io_action const action = io_type == cgsmc_async_request_io_type_read ?
        cgutils_event_buffered_io_reading :
        cgutils_event_buffered_io_writing;
    size_t idx = 0;
    size_t const ios_count = cgutils_vector_count(vect);


    for (;
         result == 0 &&
             idx < ios_count;
         idx++)
    {
        void * obj = NULL;

        result = cgutils_vector_get(vect,
                                    idx,
                                    &obj);

        if (COMPILER_LIKELY(result == 0))
        {
            cgutils_event_buffered_io_obj * io_obj = obj;
            io_obj->io = req->io;
            io_obj->cb = &cgsmc_async_request_error_dispatching_cb;
            io_obj->cb_data = req;
            io_obj->action = action;
            /* so we can reuse them after reconnection
               if needed */
            io_obj->do_not_free = true;

            result = cgutils_event_buffered_io_add_obj(req->io,
                                                       io_obj);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error adding object %zu to IO queue: %d",
                              idx,
                              result);
            }
        }
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        req->io_error = true;
    }

    return result;
}

static int cgsmc_async_request_status_ready_cb(cgutils_event_data * const event,
                                               int const status,
                                               int const fd,
                                               cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(event != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cgsmc_async_request * req = obj->cb_data;
    CGUTILS_ASSERT(req != NULL);

    (void) event;
    (void) fd;

    /* in fact we were already receiving the response code */
    req->state = cgsmc_async_request_state_receiving_response_code;

    if (COMPILER_LIKELY(status == 0))
    {
        // WHEN the status has been received, IF it is 0, ask for the read ios
        // call the callback

        if (COMPILER_LIKELY(req->response_code == 0))
        {
            if (COMPILER_LIKELY(req->read_ios != NULL))
            {
                req->state = cgsmc_async_request_state_receiving_data;

                result = cgsmc_async_connection_add_iovec(req,
                                                          cgsmc_async_request_io_type_read);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    req->io_error = true;
                    req->result = result;
                }
            }
            else
            {
                cgsmc_async_request_done(req), req = NULL;
            }
        }
        else
        {
            req->result = req->response_code;
        }
    }
    else
    {
        req->io_error = true;
        req->result = status;
    }

    if (COMPILER_UNLIKELY(req != NULL &&
                          req->result != 0))
    {
        cgsmc_async_request_error(req);
    }

    return status;
}

static void cgsmc_async_request_connection_ready(cgsmc_async_request * const req)
{
    int result = 0;

    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(req->conn != NULL);

    /* we've got ourselves a connection, bound to our FS ID */
    // send the request identifier
    // send the write ios
    // ask for the status (stored in req->response_code)

    cgsmc_async_request_compute_opcode(req);

    req->state = cgsmc_async_request_state_sending;

    if (req->io == NULL)
    {
        /* If the connection was just set up,
           we may already have a valid IO buffer object.
           Otherwise, we just set up a new one.
        */
        result = cgutils_event_buffered_io_init(req->data->event_data,
                                                cgsmc_async_connection_get_fd(req->conn),
                                                cgutils_event_buffered_io_writing,
                                                &(req->io));
    }

    if (COMPILER_LIKELY(result == 0))
    {
        result = cgutils_event_buffered_io_add_one(req->io,
                                                   &(req->opcode),
                                                   sizeof req->opcode,
                                                   cgutils_event_buffered_io_writing,
                                                   &cgsmc_async_request_error_dispatching_cb,
                                                   req);

        if (COMPILER_LIKELY(result == 0))
        {
            if (COMPILER_LIKELY(req->write_ios != NULL))
            {
                result = cgsmc_async_connection_add_iovec(req,
                                                          cgsmc_async_request_io_type_write);
            }

            if (COMPILER_LIKELY(result == 0))
            {
                result = cgutils_event_buffered_io_add_one(req->io,
                                                           &(req->response_code),
                                                           sizeof req->response_code,
                                                           cgutils_event_buffered_io_reading,
                                                           &cgsmc_async_request_status_ready_cb,
                                                           req);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error queuing status to IO queue: %d",
                                  result);
                }
            }
        }
        else
        {
            CGUTILS_ERROR("Error adding opcode to IO queue: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error creating IO queue: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        req->io_error = true;
        req->result = result;
        cgsmc_async_request_error(req);
    }
}

static int cgsmc_async_connection_setup_cb(cgutils_event_data * const event,
                                           int const status,
                                           int const fd,
                                           cgutils_event_buffered_io_obj * const obj)
{
    CGUTILS_ASSERT(event != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cgsmc_async_request * const req = obj->cb_data;
    CGUTILS_ASSERT(req != NULL);

    (void) event;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        cgsmc_async_request_connection_ready(req);
    }
    else
    {
        req->io_error = true;
        req->result = status;
        cgsmc_async_request_error(req);
    }

    return status;
}

static int cgsmc_async_get_connection_from_pool(cgsmc_async_data * const data,
                                                cgsmc_async_connection ** const out)
{
    int result = 0;
    CGUTILS_ASSERT(data != NULL);
    time_t const validity_time = data->connection_validity_time;
    size_t const max_connection_idle_time = data->max_connection_idle_time;
    size_t const max_requests_per_connection = data->max_requests_per_connection;

    CGUTILS_ASSERT(out != NULL);
    bool found = false;

    do
    {
        void * obj = NULL;
        result = cgutils_pool_get(data->connections,
                                  &obj);

        if (result == 0)
        {
            cgsmc_async_connection * conn = obj;

            time_t const now = time(NULL);
            time_t const last_used = cgsmc_async_connection_get_last_use(conn);
            time_t const creation_time = cgsmc_async_connection_get_creation_time(conn);
            size_t const requests = cgsmc_async_connection_get_request_count(conn);

            if (creation_time > validity_time &&
                (max_connection_idle_time == 0 ||
                 (size_t) (now - last_used) <= max_connection_idle_time) &&
                (data->max_requests_per_connection == 0 ||
                 requests <= max_requests_per_connection) &&
                cgsmc_async_connection_is_valid(conn) == true)
            {

                found = true;
                *out = conn;
            }
            else
            {
                cgsmc_async_connection_free(conn), conn = NULL;
            }
        }
        else if (COMPILER_UNLIKELY(result != ENOENT))
        {
            CGUTILS_ERROR("Error while retrieving connection from pool: %d",
                          result);
        }
    }
    while (result == 0 &&
           found == false);

    return result;
}

static int cgsmc_async_get_new_connection(cgsmc_async_request * const req)
{
    int result = 0;
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(req->conn == NULL);
    CGUTILS_ASSERT(req->data != NULL);
    CGUTILS_ASSERT(req->data->manager_sock_binding != NULL);

    do
    {
        /* we need to get a new connection, and then bind it to
           this FS */
        result = cgsmc_async_connection_init(req->data->manager_sock_binding,
                                             &(req->conn));

        if (COMPILER_LIKELY(result == 0))
        {
            req->state = cgsmc_async_request_state_sending;

            result = cgutils_event_buffered_io_init(req->data->event_data,
                                                    cgsmc_async_connection_get_fd(req->conn),
                                                    cgutils_event_buffered_io_writing,
                                                    &(req->io));

            if (COMPILER_LIKELY(result == 0))
            {
                result = cgutils_event_buffered_io_add_one(req->io,
                                                           &(req->data->fs_name_len),
                                                           sizeof (req->data->fs_name_len),
                                                           cgutils_event_buffered_io_writing,
                                                           &cgsmc_async_request_error_dispatching_cb,
                                                           req);

                if (COMPILER_LIKELY(result == 0))
                {
                    result = cgutils_event_buffered_io_add_one(req->io,
                                                               (char * ) req->data->fs_name,
                                                               req->data->fs_name_len,
                                                               cgutils_event_buffered_io_writing,
                                                               &cgsmc_async_connection_setup_cb,
                                                               req);

                    if (COMPILER_UNLIKELY(result != 0))
                    {
                        CGUTILS_ERROR("Error sending FS ID: %d",
                                      result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error sending FS ID length: %d",
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error creating buffered IO: %d",
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error getting connection: %d",
                          result);
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            req->retry_count++;
        }
    }
    while (result != 0 &&
           req->retry_count < req->data->max_retry_count);

    if (COMPILER_UNLIKELY(result != 0))
    {
        req->io_error = true;
    }

    return result;
}

static int cgsmc_async_get_connection(cgsmc_async_request * const req)
{
    int result = 0;
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(req->data != NULL);
    cgsmc_async_data * data = req->data;

    result = cgsmc_async_get_connection_from_pool(data,
                                                  &(req->conn));

    if (result == 0)
    {
        cgsmc_async_request_connection_ready(req);
    }
    else if (result == ENOENT)
    {
        result = cgsmc_async_get_new_connection(req);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error getting a new connection to the storage manager: %d",
                          result);

            if (result == ENOENT)
            {
                /* ENOENT could be interpreted has non-existing entry,
                   which we don't want! */
                result = EHOSTDOWN;
            }
        }
    }

    return result;
}

static int cgsmc_async_request_send(cgsmc_async_request * const req,
                                    cgutils_event_buffered_io_obj const * const write_io_objects,
                                    size_t const write_io_objects_count,
                                    cgutils_event_buffered_io_obj const * const read_io_objects,
                                    size_t const read_io_objects_count)

{
    int result = 0;
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(write_io_objects != NULL ||
                   write_io_objects_count == 0);
    CGUTILS_ASSERT(read_io_objects != NULL ||
                   read_io_objects_count == 0);

    result = cgsmc_async_request_add_ios_to_req(req,
                                                cgsmc_async_request_io_type_write,
                                                write_io_objects,
                                                write_io_objects_count);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cgsmc_async_request_add_ios_to_req(req,
                                                    cgsmc_async_request_io_type_read,
                                                    read_io_objects,
                                                    read_io_objects_count);

        if (COMPILER_LIKELY(result == 0))
        {
            /* once the connection has been established,
               cgsmc_async_request_connection_ready will be called.
            */
            result = cgsmc_async_get_connection(req);

            if (result != 0)
            {
                cgutils_vector_deep_free(&(req->read_ios), &free);
            }
        }

        if (result != 0)
        {
            cgutils_vector_deep_free(&(req->write_ios), &free);
        }
    }

    return result;
}

int cgsmc_async_lookup_child(cgsmc_async_data * const data,
                             uint64_t const ino,
                             char const * const name,
                             cgsmc_async_stat_cb * const cb,
                             void * const cb_data)
{
    // create a request object
    // get a connection (the binding of the connection to our FS should be handled before we get it,
    // so this call is asynchronous.
    // send ino, send name
    // read stats
    // return value

    // what if I/O fails? (reading, writing) ?
    // should we handle it here ? don't think so, the connection is fucked anyway.
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(name != NULL);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);
    size_t const name_len = strlen(name);
    int result = cgsmc_async_check_name_validity(data,
                                                 name_len);

    if (COMPILER_LIKELY(result == 0))
    {
        cgsmc_async_request * req = NULL;

        result = cgsmc_async_request_init(data,
                                          cgsmc_async_request_type_lookup_child,
                                          &req);

        if (COMPILER_LIKELY(result == 0))
        {
            req->ino = ino;
            req->name = name;
            req->name_len = name_len;
            req->stat_cb = cb;
            req->cb_data = cb_data;
            req->response_cb = NULL;

            CGUTILS_ALLOCATE_STRUCT(req->st);

            if (COMPILER_LIKELY(req->st != NULL))
            {
                cgutils_event_buffered_io_obj const write_io_objects[] =
                    {
                        { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->name_len), sizeof (req->name_len), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, (char *) req->name, req->name_len, NULL, NULL, cgutils_event_buffered_io_writing },
                    };
                size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;
                cgutils_event_buffered_io_obj const read_io_objects[] =
                    {
                        { NULL, req->st, sizeof *(req->st), NULL, NULL, cgutils_event_buffered_io_reading },
                    };
                size_t const read_io_objects_count = sizeof read_io_objects / sizeof *read_io_objects;

                result = cgsmc_async_request_send(req,
                                                  write_io_objects,
                                                  write_io_objects_count,
                                                  read_io_objects,
                                                  read_io_objects_count);

            }
            else
            {
                result = ENOMEM;
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                cgsmc_async_request_free(req), req = NULL;
            }
        }
    }

    return result;
}

static void cgsmc_async_getattr_response_cb(cgsmc_async_request * req)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(req->type == cgsmc_async_request_type_getattr);
    CGUTILS_ASSERT(req->stat_cb != NULL);
    /* errors should be handled by the error cb */
    CGUTILS_ASSERT(req->result == 0);

    (*(req->stat_cb))(req->result,
                      req->st,
                      req->cb_data);

    req->st = NULL;

    cgsmc_async_request_free(req), req = NULL;
}

int cgsmc_async_getattr(cgsmc_async_data * const data,
                        uint64_t const ino,
                        cgsmc_async_stat_cb * const cb,
                        void * const cb_data)
{
    int result = 0;
    cgsmc_async_request * req = NULL;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);

    result = cgsmc_async_request_init(data,
                                      cgsmc_async_request_type_getattr,
                                      &req);

    if (COMPILER_LIKELY(result == 0))
    {
        req->ino = ino;
        req->stat_cb = cb;
        req->cb_data = cb_data;
        req->response_cb = &cgsmc_async_getattr_response_cb;

        CGUTILS_ALLOCATE_STRUCT(req->st);

        if (COMPILER_LIKELY(req->st != NULL))
        {
            cgutils_event_buffered_io_obj const write_io_objects[] =
                {
                    { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
                };
            size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;
            cgutils_event_buffered_io_obj const read_io_objects[] =
                {
                    { NULL, req->st, sizeof *(req->st), NULL, NULL, cgutils_event_buffered_io_reading },
                };
            size_t const read_io_objects_count = sizeof read_io_objects / sizeof *read_io_objects;

            result = cgsmc_async_request_send(req,
                                              write_io_objects,
                                              write_io_objects_count,
                                              read_io_objects,
                                              read_io_objects_count);

        }
        else
        {
            result = ENOMEM;
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            cgsmc_async_request_free(req), req = NULL;
        }
    }

    return result;
}

static void cgsmc_async_readdir_ready_cb(cgsmc_async_request * req);

static int cgsmc_async_readdir_entry_ready_cb(cgutils_event_data * const event,
                                              int const status,
                                              int const fd,
                                              cgutils_event_buffered_io_obj * const obj)
{
    CGUTILS_ASSERT(event != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cgsmc_async_request * const req = obj->cb_data;
    CGUTILS_ASSERT(req != NULL);

    (void) event;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(req->entries_count <= req->expected_entries_count);
        CGUTILS_ASSERT(req->entries != NULL);
        cgsmc_async_entry * const current_entry = &(req->entries[req->entries_count]);
        CGUTILS_ASSERT(current_entry->name != NULL);
        CGUTILS_ASSERT(current_entry->name_len > 0);
        /* The size sent on the wire contains the '\0', we don't want that. */
        current_entry->name_len--;
        current_entry->name[current_entry->name_len] = '\0';
        req->entries_count++;

        cgsmc_async_readdir_ready_cb(req);

    }
    else
    {
        req->io_error = true;
        req->result = status;

        cgsmc_async_request_error(req);
    }

    return status;
}

static int cgsmc_async_readdir_name_len_ready_cb(cgutils_event_data * const event,
                                                 int const status,
                                                 int const fd,
                                                 cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(event != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cgsmc_async_request * const req = obj->cb_data;
    CGUTILS_ASSERT(req != NULL);

    (void) event;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(req->entries_count <= req->expected_entries_count);
        CGUTILS_ASSERT(req->entries != NULL);
        cgsmc_async_entry * const current_entry = &(req->entries[req->entries_count]);

        if (COMPILER_LIKELY(current_entry->name_len > 0))
        {
            CGUTILS_MALLOC(current_entry->name, current_entry->name_len, 1);

            if (COMPILER_LIKELY(current_entry->name != NULL))
            {
                result = cgutils_event_buffered_io_add_one(req->io,
                                                           current_entry->name,
                                                           current_entry->name_len,
                                                           cgutils_event_buffered_io_reading,
                                                           &cgsmc_async_request_error_dispatching_cb,
                                                           req);

                if (COMPILER_LIKELY(result == 0))
                {
                    result = cgutils_event_buffered_io_add_one(req->io,
                                                               &(current_entry->st),
                                                               sizeof current_entry->st,
                                                               cgutils_event_buffered_io_reading,
                                                               &cgsmc_async_readdir_entry_ready_cb,
                                                               req);

                    if (COMPILER_UNLIKELY(result != 0))
                    {
                        CGUTILS_ERROR("Error adding read IO for the stat data of entry %zu: %d",
                                      req->entries_count,
                                      result);
                        req->result = result;
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error adding read IO for name of entry %zu: %d",
                                  req->entries_count,
                                  result);
                    req->result = result;
                }
            }
            else
            {
                CGUTILS_ERROR("Error allocating memory for the name for entry %zu of size %zu, aborting.",
                              req->entries_count,
                              current_entry->name_len);
                req->result = ENOMEM;
            }
        }
        else
        {
            CGUTILS_ERROR("Invalid 0-sized name for entry %zu, aborting.",
                          req->entries_count);
            req->result = EIO;
        }
    }
    else
    {
        req->result = status;
    }

    if (COMPILER_UNLIKELY(req->result != 0))
    {
        req->io_error = true;
        cgsmc_async_request_error(req);
    }

    return status;
}

static void cgsmc_async_readdir_ready_cb(cgsmc_async_request * req)
{
    int result = 0;
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(req->type == cgsmc_async_request_type_readdir);
    CGUTILS_ASSERT(req->stat_cb != NULL);
    /* errors should be handled by the error cb */
    CGUTILS_ASSERT(req->result == 0);

    if (COMPILER_LIKELY(req->entries_count < req->expected_entries_count))
    {
        if (COMPILER_UNLIKELY(req->expected_entries_count > 0 &&
                              req->entries == NULL))
        {
            CGUTILS_MALLOC(req->entries,
                           req->expected_entries_count,
                           sizeof *(req->entries));

            if (COMPILER_LIKELY(req->entries != NULL))
            {
                for (size_t idx = 0;
                     idx < req->expected_entries_count;
                     idx++)
                {
                    req->entries[idx] = (cgsmc_async_entry) { 0 };
                }
            }
            else
            {
                req->result = ENOMEM;
            }
        }

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgutils_event_buffered_io_add_one(req->io,
                                                       &(req->entries[req->entries_count].name_len),
                                                       sizeof (req->entries[req->entries_count].name_len),
                                                       cgutils_event_buffered_io_reading,
                                                       &cgsmc_async_readdir_name_len_ready_cb,
                                                       req);

            if (COMPILER_UNLIKELY(result != 0))
            {
                req->result = result;
                CGUTILS_ERROR("Error adding a IO read for entry name len: %d",
                              result);
            }
        }

        if (COMPILER_UNLIKELY(req->result != 0))
        {
            cgsmc_async_request_error(req);
        }
    }
    else
    {
        (*(req->readdir_cb))(req->result,
                             req->entries,
                             req->entries_count,
                             req->data->dir_index_limit > 0 &&
                             req->entries_count >= req->data->dir_index_limit,
                             req->cb_data);

        cgsmc_async_request_free(req), req = NULL;
    }
}

int cgsmc_async_readdir(cgsmc_async_data * const data,
                        uint64_t const ino,
                        cgsmc_async_readdir_cb * const cb,
                        void * const cb_data)
{
    int result = 0;
    cgsmc_async_request * req = NULL;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);

    result = cgsmc_async_request_init(data,
                                      cgsmc_async_request_type_readdir,
                                      &req);

    if (COMPILER_LIKELY(result == 0))
    {
        req->ino = ino;
        req->readdir_cb = cb;
        req->cb_data = cb_data;
        req->response_cb = &cgsmc_async_readdir_ready_cb;

        cgutils_event_buffered_io_obj const write_io_objects[] =
            {
                { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
            };
        size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;
        cgutils_event_buffered_io_obj const read_io_objects[] =
            {
                { NULL, &(req->expected_entries_count), sizeof req->expected_entries_count, NULL, NULL, cgutils_event_buffered_io_reading },
            };
        size_t const read_io_objects_count = sizeof read_io_objects / sizeof *read_io_objects;

        result = cgsmc_async_request_send(req,
                                          write_io_objects,
                                          write_io_objects_count,
                                          read_io_objects,
                                          read_io_objects_count);

        if (COMPILER_UNLIKELY(result != 0))
        {
            cgsmc_async_request_free(req), req = NULL;
        }
    }

    return result;
}

static int cgsmc_async_create_and_open_ready_cb(cgutils_event_data * const event,
                                                int const status,
                                                int const fd,
                                                cgutils_event_buffered_io_obj * const obj)
{
    CGUTILS_ASSERT(event != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cgsmc_async_request * req = obj->cb_data;
    CGUTILS_ASSERT(req != NULL);

    (void) event;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(req->path_in_cache != NULL);

        req->path_in_cache[req->path_in_cache_len-1] = '\0';

        (*(req->create_and_open_cb))(req->result,
                                     req->st,
                                     req->path_in_cache,
                                     req->cb_data);

        req->path_in_cache = NULL;
        req->st = NULL;

        cgsmc_async_request_free(req), req = NULL;
    }
    else
    {
        req->result = status;
        req->io_error = true;
        cgsmc_async_request_error(req);
    }

    return status;
}

static void cgsmc_async_create_and_open_name_len_ready_cb(cgsmc_async_request * req)
{
    int result = 0;
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(req->type == cgsmc_async_request_type_create_and_open);
    CGUTILS_ASSERT(req->create_and_open_cb != NULL);
    /* errors should be handled by the error cb */
    CGUTILS_ASSERT(req->result == 0);

    if (COMPILER_LIKELY(req->path_in_cache_len > 0))
    {
        CGUTILS_MALLOC(req->path_in_cache, req->path_in_cache_len + 1, 1);

        if (COMPILER_LIKELY(req->path_in_cache != NULL))
        {
            result = cgutils_event_buffered_io_add_one(req->io,
                                                       req->path_in_cache,
                                                       req->path_in_cache_len,
                                                       cgutils_event_buffered_io_reading,
                                                       &cgsmc_async_create_and_open_ready_cb,
                                                       req);

            if (COMPILER_UNLIKELY(result != 0))
            {
                req->result = result;
                CGUTILS_ERROR("Error adding a IO read for path in cache: %d",
                              result);
            }
        }
        else
        {
            req->result = result;
            CGUTILS_ERROR("Error allocating memory for path in cache (%zu): %d",
                          req->path_in_cache_len,
                          result);
        }

        if (COMPILER_UNLIKELY(req->result != 0))
        {
            cgsmc_async_request_error(req);
        }
    }
    else
    {
        (*(req->create_and_open_cb))(req->result,
                                     req->st,
                                     NULL,
                                     req->cb_data);

        req->st = NULL;

        cgsmc_async_request_free(req), req = NULL;
    }
}

int cgsmc_async_create_and_open(cgsmc_async_data * const data,
                                uint64_t const parent_ino,
                                char const * const name,
                                uid_t const owner,
                                gid_t const group,
                                mode_t const mode,
                                int const flags,
                                cgsmc_async_create_and_open_cb * const cb,
                                void * const cb_data)
{
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(name != NULL);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);
    size_t const name_len = strlen(name);

    int result = cgsmc_async_check_name_validity(data,
                                                 name_len);

    if (COMPILER_LIKELY(result == 0))
    {
        cgsmc_async_request * req = NULL;

        result = cgsmc_async_request_init(data,
                                          cgsmc_async_request_type_create_and_open,
                                          &req);

        if (COMPILER_LIKELY(result == 0))
        {
            req->ino = parent_ino;
            req->owner = owner;
            req->group = group;
            req->mode = mode;
            req->flags = flags;
            req->name = name;
            req->name_len = name_len;
            req->create_and_open_cb = cb;
            req->cb_data = cb_data;
            req->response_cb = &cgsmc_async_create_and_open_name_len_ready_cb;

            CGUTILS_ALLOCATE_STRUCT(req->st);

            if (COMPILER_LIKELY(req->st != NULL))
            {
                cgutils_event_buffered_io_obj const write_io_objects[] =
                    {
                        { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->owner), sizeof (req->owner), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->group), sizeof (req->group), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->mode), sizeof (req->mode), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->flags), sizeof (req->flags), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->name_len), sizeof (req->name_len), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, (char * ) req->name, req->name_len, NULL, NULL, cgutils_event_buffered_io_writing },
                    };
                size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;
                cgutils_event_buffered_io_obj const read_io_objects[] =
                    {
                        { NULL, req->st, sizeof *(req->st), NULL, NULL, cgutils_event_buffered_io_reading },
                        { NULL, &(req->path_in_cache_len), sizeof req->path_in_cache_len, NULL, NULL, cgutils_event_buffered_io_reading },
                    };
                size_t const read_io_objects_count = sizeof read_io_objects / sizeof *read_io_objects;

                result = cgsmc_async_request_send(req,
                                                  write_io_objects,
                                                  write_io_objects_count,
                                                  read_io_objects,
                                                  read_io_objects_count);

            }
            else
            {
                result = ENOMEM;
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                cgsmc_async_request_free(req), req = NULL;
            }
        }
    }

    return result;
}

int cgsmc_async_release(cgsmc_async_data * const data,
                        uint64_t const inode,
                        bool const dirty,
                        cgsmc_async_status_cb * const cb,
                        void * const cb_data)
{
    int result = 0;
    cgsmc_async_request * req = NULL;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);

    result = cgsmc_async_request_init(data,
                                      cgsmc_async_request_type_release,
                                      &req);

    if (COMPILER_LIKELY(result == 0))
    {
        req->ino = inode;
        req->status_cb = cb;
        req->cb_data = cb_data;
        req->dirty = dirty == true ? 1 : 0;

        cgutils_event_buffered_io_obj const write_io_objects[] =
            {
                { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
                { NULL, &(req->dirty), sizeof (req->dirty), NULL, NULL, cgutils_event_buffered_io_writing },
            };
        size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;

        result = cgsmc_async_request_send(req,
                                          write_io_objects,
                                          write_io_objects_count,
                                          NULL,
                                          0);

        if (COMPILER_UNLIKELY(result != 0))
        {
            cgsmc_async_request_free(req), req = NULL;
        }
    }

    return result;
}

static int cgsmc_async_open_ready_cb(cgutils_event_data * const event,
                                     int const status,
                                     int const fd,
                                     cgutils_event_buffered_io_obj * const obj)
{
    CGUTILS_ASSERT(event != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cgsmc_async_request * req = obj->cb_data;
    CGUTILS_ASSERT(req != NULL);

    (void) event;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(req->path_in_cache != NULL);

        req->path_in_cache[req->path_in_cache_len-1] = '\0';

        (*(req->open_cb))(req->result,
                          req->path_in_cache,
                          req->cb_data);

        req->path_in_cache = NULL;

        cgsmc_async_request_free(req), req = NULL;
    }
    else
    {
        req->result = status;
        req->io_error = true;
        cgsmc_async_request_error(req);
    }

    return status;
}

static void cgsmc_async_open_name_len_ready_cb(cgsmc_async_request * req)
{
    int result = 0;
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(req->type == cgsmc_async_request_type_open);
    CGUTILS_ASSERT(req->open_cb != NULL);
    /* errors should be handled by the error cb */
    CGUTILS_ASSERT(req->result == 0);

    if (COMPILER_LIKELY(req->path_in_cache_len > 0))
    {
        CGUTILS_MALLOC(req->path_in_cache, req->path_in_cache_len + 1, 1);

        if (COMPILER_LIKELY(req->path_in_cache != NULL))
        {
            result = cgutils_event_buffered_io_add_one(req->io,
                                                       req->path_in_cache,
                                                       req->path_in_cache_len,
                                                       cgutils_event_buffered_io_reading,
                                                       &cgsmc_async_open_ready_cb,
                                                       req);

            if (COMPILER_UNLIKELY(result != 0))
            {
                req->result = result;
                CGUTILS_ERROR("Error adding a IO read for path in cache: %d",
                              result);
            }
        }
        else
        {
            req->result = result;
            CGUTILS_ERROR("Error allocating memory for path in cache (%zu): %d",
                          req->path_in_cache_len,
                          result);
        }

        if (COMPILER_UNLIKELY(req->result != 0))
        {
            cgsmc_async_request_error(req);
        }
    }
    else
    {
        (*(req->open_cb))(req->result,
                          NULL,
                          req->cb_data);

        cgsmc_async_request_free(req), req = NULL;
    }
}

int cgsmc_async_open(cgsmc_async_data * const data,
                     uint64_t const ino,
                     int const flags,
                     cgsmc_async_open_cb * const cb,
                     void * const cb_data)
{
    int result = 0;
    cgsmc_async_request * req = NULL;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(ino > 0);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);

    result = cgsmc_async_request_init(data,
                                      cgsmc_async_request_type_open,
                                      &req);

    if (COMPILER_LIKELY(result == 0))
    {
        req->ino = ino;
        req->flags = flags;
        req->open_cb = cb;
        req->cb_data = cb_data;
        req->response_cb = &cgsmc_async_open_name_len_ready_cb;

        cgutils_event_buffered_io_obj const write_io_objects[] =
            {
                { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
                { NULL, &(req->flags), sizeof (req->flags), NULL, NULL, cgutils_event_buffered_io_writing },
            };
        size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;
        cgutils_event_buffered_io_obj const read_io_objects[] =
            {
                { NULL, &(req->path_in_cache_len), sizeof req->path_in_cache_len, NULL, NULL, cgutils_event_buffered_io_reading },
            };
        size_t const read_io_objects_count = sizeof read_io_objects / sizeof *read_io_objects;

        result = cgsmc_async_request_send(req,
                                          write_io_objects,
                                          write_io_objects_count,
                                          read_io_objects,
                                          read_io_objects_count);

        if (COMPILER_UNLIKELY(result != 0))
        {
            cgsmc_async_request_free(req), req = NULL;
        }
    }

    return result;
}

int cgsmc_async_notify_write(cgsmc_async_data * const data,
                             uint64_t const ino,
                             cgsmc_async_status_cb * const cb,
                             void * const cb_data)
{
    int result = 0;
    cgsmc_async_request * req = NULL;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(ino > 0);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);

    result = cgsmc_async_request_init(data,
                                      cgsmc_async_request_type_notify_write,
                                      &req);

    if (COMPILER_LIKELY(result == 0))
    {
        req->ino = ino;
        req->status_cb = cb;
        req->cb_data = cb_data;

        cgutils_event_buffered_io_obj const write_io_objects[] =
            {
                { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
            };
        size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;

        result = cgsmc_async_request_send(req,
                                          write_io_objects,
                                          write_io_objects_count,
                                          NULL,
                                          0);

        if (COMPILER_UNLIKELY(result != 0))
        {
            cgsmc_async_request_free(req), req = NULL;
        }
    }

    return result;
}

bool cgsmc_async_need_to_notify_write(cgsmc_async_data * const data,
                                      size_t const elapsed)
{
    bool result = false;
    CGUTILS_ASSERT(data != NULL);

    if (elapsed > data->dirtyness_delay)
    {
        result = true;
    }

    return result;
}

int cgsmc_async_setattr(cgsmc_async_data * const data,
                        uint64_t const ino,
                        struct stat const * const st,
                        bool const file_size_changed,
                        cgsmc_async_status_cb * const cb,
                        void * const cb_data)
{
    int result = 0;
    cgsmc_async_request * req = NULL;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(ino > 0);
    CGUTILS_ASSERT(st != NULL);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);

    result = cgsmc_async_request_init(data,
                                      cgsmc_async_request_type_setattr,
                                      &req);

    if (COMPILER_LIKELY(result == 0))
    {
        req->ino = ino;
        req->status_cb = cb;
        req->cb_data = cb_data;
        req->file_size_changed = file_size_changed == true ? 1 : 0;

        cgutils_event_buffered_io_obj const write_io_objects[] =
            {
                { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
                { NULL, (struct stat *) st, sizeof (*st), NULL, NULL, cgutils_event_buffered_io_writing },
                { NULL, &(req->file_size_changed), sizeof (req->file_size_changed), NULL, NULL, cgutils_event_buffered_io_writing },
            };
        size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;

        result = cgsmc_async_request_send(req,
                                          write_io_objects,
                                          write_io_objects_count,
                                          NULL,
                                          0);

        if (COMPILER_UNLIKELY(result != 0))
        {
            cgsmc_async_request_free(req), req = NULL;
        }
    }

    return result;
}

int cgsmc_async_mkdir(cgsmc_async_data * const data,
                      uint64_t const parent_ino,
                      char const * const name,
                      uid_t const owner,
                      gid_t const group,
                      mode_t const mode,
                      cgsmc_async_stat_cb * const cb,
                      void * const cb_data)
{
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(name != NULL);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);
    size_t const name_len = strlen(name);
    int result = cgsmc_async_check_name_validity(data,
                                                 name_len);

    if (COMPILER_LIKELY(result == 0))
    {
        cgsmc_async_request * req = NULL;

        result = cgsmc_async_request_init(data,
                                          cgsmc_async_request_type_mkdir,
                                          &req);

        if (COMPILER_LIKELY(result == 0))
        {
            req->ino = parent_ino;
            req->owner = owner;
            req->group = group;
            req->mode = mode;
            req->name = name;
            req->name_len = name_len;
            req->stat_cb = cb;
            req->cb_data = cb_data;

            CGUTILS_ALLOCATE_STRUCT(req->st);

            if (COMPILER_LIKELY(req->st != NULL))
            {
                cgutils_event_buffered_io_obj const write_io_objects[] =
                    {
                        { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->owner), sizeof (req->owner), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->group), sizeof (req->group), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->mode), sizeof (req->mode), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->name_len), sizeof (req->name_len), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, (char * ) req->name, req->name_len, NULL, NULL, cgutils_event_buffered_io_writing },
                    };
                size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;
                cgutils_event_buffered_io_obj const read_io_objects[] =
                    {
                        { NULL, req->st, sizeof *(req->st), NULL, NULL, cgutils_event_buffered_io_reading },
                };
                size_t const read_io_objects_count = sizeof read_io_objects / sizeof *read_io_objects;

                result = cgsmc_async_request_send(req,
                                                  write_io_objects,
                                                  write_io_objects_count,
                                                  read_io_objects,
                                                  read_io_objects_count);
            }
            else
            {
                result = ENOMEM;
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                cgsmc_async_request_free(req), req = NULL;
            }
        }
    }

    return result;
}

int cgsmc_async_rmdir(cgsmc_async_data * const data,
                      uint64_t const parent_ino,
                      char const * const name,
                      cgsmc_async_returning_inode_number_cb * const cb,
                      void * const cb_data)
{
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(name != NULL);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);
    size_t const name_len = strlen(name);

    int result = cgsmc_async_check_name_validity(data,
                                                 name_len);

    if (COMPILER_LIKELY(result == 0))
    {
        cgsmc_async_request * req = NULL;

        result = cgsmc_async_request_init(data,
                                          cgsmc_async_request_type_rmdir,
                                          &req);

        if (COMPILER_LIKELY(result == 0))
        {
            req->ino = parent_ino;
            req->name = name;
            req->name_len = name_len;
            req->returning_inode_number_cb = cb;
            req->cb_data = cb_data;

            CGUTILS_ALLOCATE_STRUCT(req->st);

            if (COMPILER_LIKELY(req->st != NULL))
            {
                cgutils_event_buffered_io_obj const write_io_objects[] =
                    {
                        { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->name_len), sizeof (req->name_len), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, (char * ) req->name, req->name_len, NULL, NULL, cgutils_event_buffered_io_writing },
                    };
                size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;
                cgutils_event_buffered_io_obj const read_io_objects[] =
                    {
                        { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_reading },
                    };
                size_t const read_io_objects_count = sizeof read_io_objects / sizeof *read_io_objects;

                result = cgsmc_async_request_send(req,
                                                  write_io_objects,
                                                  write_io_objects_count,
                                                  read_io_objects,
                                                  read_io_objects_count);

            }
            else
            {
                result = ENOMEM;
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                cgsmc_async_request_free(req), req = NULL;
            }
        }
    }

    return result;
}

int cgsmc_async_unlink(cgsmc_async_data * const data,
                       uint64_t const parent_ino,
                       char const * const name,
                       cgsmc_async_returning_inode_number_cb * const cb,
                       void * const cb_data)
{
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(name != NULL);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);
    size_t const name_len = strlen(name);
    int result = cgsmc_async_check_name_validity(data,
                                                 name_len);

    if (COMPILER_LIKELY(result == 0))
    {
        cgsmc_async_request * req = NULL;

        result = cgsmc_async_request_init(data,
                                          cgsmc_async_request_type_unlink,
                                          &req);

        if (COMPILER_LIKELY(result == 0))
        {
            req->ino = parent_ino;
            req->name = name;
            req->name_len = name_len;
            req->returning_inode_number_cb = cb;
            req->cb_data = cb_data;

            CGUTILS_ALLOCATE_STRUCT(req->st);

            if (COMPILER_LIKELY(req->st != NULL))
            {
                cgutils_event_buffered_io_obj const write_io_objects[] =
                    {
                        { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->name_len), sizeof (req->name_len), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, (char * ) req->name, req->name_len, NULL, NULL, cgutils_event_buffered_io_writing },
                    };
                size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;
                cgutils_event_buffered_io_obj const read_io_objects[] =
                    {
                        { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_reading },
                    };
                size_t const read_io_objects_count = sizeof read_io_objects / sizeof *read_io_objects;

                result = cgsmc_async_request_send(req,
                                                  write_io_objects,
                                                  write_io_objects_count,
                                                  read_io_objects,
                                                  read_io_objects_count);

            }
            else
            {
                result = ENOMEM;
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                cgsmc_async_request_free(req), req = NULL;
            }
        }
    }

    return result;
}

int cgsmc_async_rename(cgsmc_async_data * const data,
                       uint64_t const old_parent,
                       char const * const old_name,
                       uint64_t const new_parent,
                       char const * const new_name,
                       cgsmc_async_returning_renamed_and_deleted_inode_number_cb * const cb,
                       void * const cb_data)
{
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(old_name != NULL);
    CGUTILS_ASSERT(new_name != NULL);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);
    size_t const new_name_len = strlen(new_name);

    int result = cgsmc_async_check_name_validity(data,
                                                 new_name_len);

    if (COMPILER_LIKELY(result == 0))
    {
        size_t const old_name_len = strlen(old_name);

        result = cgsmc_async_check_name_validity(data,
                                                 old_name_len);

        if (COMPILER_LIKELY(result == 0))
        {
            cgsmc_async_request * req = NULL;

            result = cgsmc_async_request_init(data,
                                              cgsmc_async_request_type_rename,
                                              &req);

            if (COMPILER_LIKELY(result == 0))
            {
                req->ino = old_parent;
                req->new_ino = new_parent;
                req->name = old_name;
                req->name_len = old_name_len;
                req->new_name = new_name;
                req->new_name_len = new_name_len;
                req->returning_renamed_and_deleted_inode_number_cb = cb;
                req->cb_data = cb_data;

                CGUTILS_ALLOCATE_STRUCT(req->st);

                if (COMPILER_LIKELY(req->st != NULL))
                {
                    cgutils_event_buffered_io_obj const write_io_objects[] =
                        {
                            { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
                            { NULL, &(req->new_ino), sizeof (req->new_ino), NULL, NULL, cgutils_event_buffered_io_writing },
                            { NULL, &(req->name_len), sizeof (req->name_len), NULL, NULL, cgutils_event_buffered_io_writing },
                            { NULL, &(req->new_name_len), sizeof (req->new_name_len), NULL, NULL, cgutils_event_buffered_io_writing },
                            { NULL, (char * ) req->name, req->name_len, NULL, NULL, cgutils_event_buffered_io_writing },
                            { NULL, (char * ) req->new_name, req->new_name_len, NULL, NULL, cgutils_event_buffered_io_writing },
                        };
                    size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;
                    cgutils_event_buffered_io_obj const read_io_objects[] =
                        {
                            { NULL, &(req->new_ino), sizeof (req->new_ino), NULL, NULL, cgutils_event_buffered_io_reading },
                            { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_reading },
                        };
                    size_t const read_io_objects_count = sizeof read_io_objects / sizeof *read_io_objects;

                    result = cgsmc_async_request_send(req,
                                                      write_io_objects,
                                                      write_io_objects_count,
                                                      read_io_objects,
                                                      read_io_objects_count);

                }
                else
                {
                    result = ENOMEM;
                }

                if (COMPILER_UNLIKELY(result != 0))
                {
                    cgsmc_async_request_free(req), req = NULL;
                }
            }
        }
    }

    return result;
}

int cgsmc_async_hardlink(cgsmc_async_data * const data,
                         uint64_t const existing_ino,
                         uint64_t const new_parent_ino,
                         char const * const new_name,
                         cgsmc_async_stat_cb * const cb,
                         void * const cb_data)
{
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(existing_ino > 0);
    CGUTILS_ASSERT(new_parent_ino > 0);
    CGUTILS_ASSERT(new_name != NULL);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);
    size_t const new_name_len = strlen(new_name);
    int result = cgsmc_async_check_name_validity(data,
                                                 new_name_len);

    if (COMPILER_LIKELY(result == 0))
    {
        cgsmc_async_request * req = NULL;

        result = cgsmc_async_request_init(data,
                                          cgsmc_async_request_type_hardlink,
                                          &req);

        if (COMPILER_LIKELY(result == 0))
        {
            req->ino = existing_ino;
            req->new_ino = new_parent_ino;
            req->name = new_name;
            req->name_len = new_name_len;
            req->stat_cb = cb;
            req->cb_data = cb_data;
            req->response_cb = NULL;

            CGUTILS_ALLOCATE_STRUCT(req->st);

            if (COMPILER_LIKELY(req->st != NULL))
            {
                cgutils_event_buffered_io_obj const write_io_objects[] =
                    {
                        { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->new_ino), sizeof (req->new_ino), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, &(req->name_len), sizeof (req->name_len), NULL, NULL, cgutils_event_buffered_io_writing },
                        { NULL, (char *) req->name, req->name_len, NULL, NULL, cgutils_event_buffered_io_writing },
                    };
                size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;
                cgutils_event_buffered_io_obj const read_io_objects[] =
                    {
                        { NULL, req->st, sizeof *(req->st), NULL, NULL, cgutils_event_buffered_io_reading },
                    };
                size_t const read_io_objects_count = sizeof read_io_objects / sizeof *read_io_objects;

                result = cgsmc_async_request_send(req,
                                                  write_io_objects,
                                                  write_io_objects_count,
                                                  read_io_objects,
                                                  read_io_objects_count);

            }
            else
            {
                result = ENOMEM;
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                cgsmc_async_request_free(req), req = NULL;
            }
        }
    }

    return result;
}

int cgsmc_async_symlink(cgsmc_async_data * const data,
                        uint64_t const new_parent_ino,
                        char const * const new_name,
                        char const * const link_to,
                        uid_t const owner,
                        gid_t const group,
                        cgsmc_async_stat_cb * const cb,
                        void * const cb_data)
{
    int result = 0;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(new_parent_ino > 0);
    CGUTILS_ASSERT(new_name != NULL);
    CGUTILS_ASSERT(link_to != NULL);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);
    size_t const link_to_len = strlen(link_to);
    size_t const new_name_len = strlen(new_name);

    result = cgsmc_async_check_name_validity(data,
                                             new_name_len);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cgsmc_async_check_symlink_path_validity(data,
                                                         link_to_len);

        if (COMPILER_LIKELY(result == 0))
        {
            cgsmc_async_request * req = NULL;

            result = cgsmc_async_request_init(data,
                                              cgsmc_async_request_type_symlink,
                                              &req);

            if (COMPILER_LIKELY(result == 0))
            {
                req->new_ino = new_parent_ino;
                req->new_name = new_name;
                req->new_name_len = new_name_len;
                req->name = link_to;
                req->name_len = link_to_len;
                req->owner = owner;
                req->group = group;
                req->stat_cb = cb;
                req->cb_data = cb_data;
                req->response_cb = NULL;

                CGUTILS_ALLOCATE_STRUCT(req->st);

                if (COMPILER_LIKELY(req->st != NULL))
                {
                    cgutils_event_buffered_io_obj const write_io_objects[] =
                        {
                            { NULL, &(req->new_ino), sizeof (req->new_ino), NULL, NULL, cgutils_event_buffered_io_writing },
                            { NULL, &(req->owner), sizeof (req->owner), NULL, NULL, cgutils_event_buffered_io_writing },
                            { NULL, &(req->group), sizeof (req->group), NULL, NULL, cgutils_event_buffered_io_writing },
                            { NULL, &(req->new_name_len), sizeof (req->new_name_len), NULL, NULL, cgutils_event_buffered_io_writing },
                            { NULL, &(req->name_len), sizeof (req->name_len), NULL, NULL, cgutils_event_buffered_io_writing },
                            { NULL, (char *) req->new_name, req->new_name_len, NULL, NULL, cgutils_event_buffered_io_writing },
                            { NULL, (char *) req->name, req->name_len, NULL, NULL, cgutils_event_buffered_io_writing },
                        };
                    size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;
                    cgutils_event_buffered_io_obj const read_io_objects[] =
                        {
                    { NULL, req->st, sizeof *(req->st), NULL, NULL, cgutils_event_buffered_io_reading },
                        };
                    size_t const read_io_objects_count = sizeof read_io_objects / sizeof *read_io_objects;

                    result = cgsmc_async_request_send(req,
                                                      write_io_objects,
                                                      write_io_objects_count,
                                                      read_io_objects,
                                                      read_io_objects_count);

                }
                else
                {
                    result = ENOMEM;
                }

                if (COMPILER_UNLIKELY(result != 0))
                {
                    cgsmc_async_request_free(req), req = NULL;
                }
            }
        }
    }

    return result;
}

static int cgsmc_async_readlink_ready_cb(cgutils_event_data * const event,
                                         int const status,
                                         int const fd,
                                         cgutils_event_buffered_io_obj * const obj)
{
    CGUTILS_ASSERT(event != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cgsmc_async_request * req = obj->cb_data;
    CGUTILS_ASSERT(req != NULL);

    (void) event;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(req->path_in_cache != NULL);

        req->path_in_cache[req->path_in_cache_len-1] = '\0';

        (*(req->readlink_cb))(req->result,
                              req->path_in_cache,
                              req->cb_data);

        req->path_in_cache = NULL;

        cgsmc_async_request_free(req), req = NULL;
    }
    else
    {
        req->result = status;
        req->io_error = true;
        cgsmc_async_request_error(req);
    }

    return status;
}

static void cgsmc_async_readlink_name_len_ready_cb(cgsmc_async_request * req)
{
    int result = 0;
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(req->type == cgsmc_async_request_type_readlink);
    CGUTILS_ASSERT(req->readlink_cb != NULL);
    /* errors should be handled by the error cb */
    CGUTILS_ASSERT(req->result == 0);

    if (COMPILER_LIKELY(req->path_in_cache_len > 0))
    {
        CGUTILS_MALLOC(req->path_in_cache, req->path_in_cache_len + 1, 1);

        if (COMPILER_LIKELY(req->path_in_cache != NULL))
        {
            result = cgutils_event_buffered_io_add_one(req->io,
                                                       req->path_in_cache,
                                                       req->path_in_cache_len,
                                                       cgutils_event_buffered_io_reading,
                                                       &cgsmc_async_readlink_ready_cb,
                                                       req);

            if (COMPILER_UNLIKELY(result != 0))
            {
                req->result = result;
                CGUTILS_ERROR("Error adding a IO read for link to: %d",
                              result);
            }
        }
        else
        {
            req->result = result;
            CGUTILS_ERROR("Error allocating memory for link to (%zu): %d",
                          req->path_in_cache_len,
                          result);
        }

        if (COMPILER_UNLIKELY(req->result != 0))
        {
            cgsmc_async_request_error(req);
        }
    }
    else
    {
        (*(req->readlink_cb))(req->result,
                              NULL,
                              req->cb_data);

        cgsmc_async_request_free(req), req = NULL;
    }
}

int cgsmc_async_readlink(cgsmc_async_data * const data,
                         uint64_t const ino,
                         cgsmc_async_readlink_cb * const cb,
                         void * const cb_data)
{
    int result = 0;
    cgsmc_async_request * req = NULL;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(ino > 0);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);

    result = cgsmc_async_request_init(data,
                                      cgsmc_async_request_type_readlink,
                                      &req);

    if (COMPILER_LIKELY(result == 0))
    {
        req->ino = ino;
        req->readlink_cb = cb;
        req->cb_data = cb_data;
        req->response_cb = &cgsmc_async_readlink_name_len_ready_cb;

        cgutils_event_buffered_io_obj const write_io_objects[] =
            {
                { NULL, &(req->ino), sizeof (req->ino), NULL, NULL, cgutils_event_buffered_io_writing },
            };
        size_t const write_io_objects_count = sizeof write_io_objects / sizeof *write_io_objects;
        cgutils_event_buffered_io_obj const read_io_objects[] =
            {
                { NULL, &(req->path_in_cache_len), sizeof req->path_in_cache_len, NULL, NULL, cgutils_event_buffered_io_reading },
            };
        size_t const read_io_objects_count = sizeof read_io_objects / sizeof *read_io_objects;

        result = cgsmc_async_request_send(req,
                                          write_io_objects,
                                          write_io_objects_count,
                                          read_io_objects,
                                          read_io_objects_count);

        if (COMPILER_UNLIKELY(result != 0))
        {
            cgsmc_async_request_free(req), req = NULL;
        }
    }

    return result;
}

unsigned long cgsmc_async_get_block_size(cgsmc_async_data * const data)
{
    unsigned long result = CG_STORAGE_MANAGER_BLOCK_SIZE;
    CGUTILS_ASSERT(data != NULL);
    (void) data;

    return result;
}

unsigned long cgsmc_async_get_name_max(cgsmc_async_data * const data)
{
    CGUTILS_ASSERT(data != NULL);
    unsigned long result = data->name_max;

    return result;
}
