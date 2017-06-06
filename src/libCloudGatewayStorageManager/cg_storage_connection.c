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
#include <unistd.h>

#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_network.h>

#include "cgsm/cg_storage_connection.h"
#include "cgsm/cg_storage_connection_internals.h"
#include "cgsm/cg_storage_request.h"

#define CG_ST_MAX_REQUESTS_PER_CONN_DEFAULT (1000)

static char const * cg_storage_connection_opcode_to_str(cgsm_proto_opcode_type const opcode)
{
    static char const * const opcodes_str[] =
        {
#define OPCODE(name) #name,
#include "cgsm/cg_storage_manager_proto_opcodes.itm"
#undef OPCODE
        };
    static size_t const opcodes_count = sizeof opcodes_str / sizeof *opcodes_str;
    char const * result = "Unknown";

    if (COMPILER_LIKELY(opcode < opcodes_count))
    {
        result = opcodes_str[opcode];
    }

    return result;
}

static int cg_storage_connection_cb_request_handling(cg_storage_connection * const this)
{
    int result = 0;

    assert(this != NULL);

/*    CGUTILS_TRACE("[%d] Got opcode (%"PRIu64") %s",
                  this->sock,
                  this->request.opcode,
                  cg_storage_connection_opcode_to_str(this->request.opcode));*/

    switch(this->request.opcode)
    {
#define OPCODE(name)                                                    \
        case cgsm_proto_opcode_ ## name:                                \
        {                                                               \
            result = cg_storage_request_cb_ ## name(&(this->request));  \
            break;                                                      \
        }
#include "cgsm/cg_storage_manager_proto_opcodes.itm"
#undef OPCODE
    default:
        result = ENOSYS;
        CGUTILS_WARN("[%d] Request opcode %" PRIu64 " (%s) of size %zu is not implemented: %d",
                     this->sock,
                     this->request.opcode,
                     cg_storage_connection_opcode_to_str(this->request.opcode),
                     sizeof this->request.opcode,
                     result);
    }

    return result;
}

static int cg_storage_connection_got_opcode(cgutils_event_data * data,
                                           int status,
                                           int fd,
                                           cgutils_event_buffered_io_obj * obj)
{
    assert(data != NULL);
    assert(obj != NULL);
    assert(fd >= 0);
    (void) data;
    (void) fd;

    cg_storage_connection * this = obj->cb_data;

    int result = status;

    if (COMPILER_LIKELY(result == 0))
    {
        result = cg_storage_connection_cb_request_handling(this);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in request handler for opcode %"PRIu64": %d", this->request.opcode, result);
        }
    }
    else if (result != EBADF)
    {
        CGUTILS_ERROR("Error reading opcode: %d", result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_connection_finish(this), this = NULL;
    }

    return result;
}

static int cg_storage_connection_got_fs_id(cgutils_event_data * data,
                                           int status,
                                           int fd,
                                           cgutils_event_buffered_io_obj * obj)
{
    assert(data != NULL);
    assert(obj != NULL);
    assert(fd >= 0);
    (void) data;
    (void) fd;

    cg_storage_connection * this = obj->cb_data;

    int result = status;

    if (COMPILER_LIKELY(result == 0))
    {
        this->fs_id[this->fs_id_len] = '\0';

        result = cg_storage_manager_data_get_filesystem(this->data,
                                                        this->fs_id,
                                                        &(this->fs));

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgutils_event_buffered_io_add_one(this->io,
                                                       &(this->request.opcode),
                                                       sizeof this->request.opcode,
                                                       cgutils_event_buffered_io_reading,
                                                       &cg_storage_connection_got_opcode,
                                                       this);
            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error reading opcode: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to get a corresponding filesystem (%s): %d", this->fs_id,
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading fs id: %d", result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_connection_finish(this), this = NULL;
    }

    return result;
}

static int cg_storage_connection_got_fs_id_len(cgutils_event_data * data,
                                               int status,
                                               int fd,
                                               cgutils_event_buffered_io_obj * obj)
{
    assert(data != NULL);
    assert(obj != NULL);
    assert(fd >= 0);
    (void) data;
    (void) fd;

    cg_storage_connection * this = obj->cb_data;

    int result = status;

    if (COMPILER_LIKELY(result == 0))
    {
        CGUTILS_MALLOC(this->fs_id, this->fs_id_len + 1, 1);

        if (COMPILER_LIKELY(this->fs_id != NULL))
        {
            result = cgutils_event_buffered_io_add_one(this->io,
                                                       this->fs_id,
                                                       this->fs_id_len,
                                                       cgutils_event_buffered_io_reading,
                                                       &cg_storage_connection_got_fs_id,
                                                       this);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error reading fs id: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating memory for fs id: %d", result);
            result = ENOMEM;
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading fs id len: %d", result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_connection_finish(this), this = NULL;
    }

    return result;
}

static int cg_storage_connection_set(cg_storage_manager_data * const data,
                                     int conn_sock,
                                     cg_storage_connection * const conn)
{
    assert(data != NULL);
    assert(conn_sock >= 0);
    assert(conn != NULL);

    conn->data = data;
    conn->sock = conn_sock;

    cgutils_event_data * event_data = cg_storage_manager_data_get_event(data);
    assert(event_data != NULL);

    int result = cgutils_event_buffered_io_init(event_data,
                                                conn_sock,
                                                cgutils_event_buffered_io_reading,
                                                &(conn->io));
    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Unable to create socket buffered io: %d", result);
    }

    return result;
}

int cg_storage_connection_init(cg_storage_manager_data * const data,
                               int conn_sock,
                               cg_storage_connection_end_cb * const end_cb,
                               void * const end_cb_data,
                               cg_storage_connection ** const out)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(data != NULL &&
                        conn_sock >= 0 &&
                        out != NULL))
    {
        CGUTILS_ALLOCATE_STRUCT(*out);

        if (COMPILER_LIKELY(*out != NULL))
        {
            static cg_storage_request const request_zero;
            (*out)->sock = -1;
            (*out)->request = request_zero;
            (*out)->request.conn = *out;
            (*out)->end_cb = end_cb;
            (*out)->end_cb_data = end_cb_data;

            result = cg_storage_connection_set(data, conn_sock, *out);

            if (COMPILER_UNLIKELY(result != 0))
            {
                cg_storage_connection_finish(*out), *out = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

static void cg_storage_request_clean(cg_storage_request * const this)
{
    if (this != NULL)
    {
        if (this->path != NULL)
        {
            CGUTILS_FREE(this->path);
        }
        if (this->path_to != NULL)
        {
            CGUTILS_FREE(this->path_to);
        }

        if (this->entries != NULL)
        {
            cgutils_vector_deep_free(&(this->entries), &cgdb_entry_delete);
        }

        CGUTILS_FREE(this->st);

        this->request_size = 0;
        this->response_size = 0;
        this->path_len = 0;
        this->path_to_len = 0;
        this->flags = 0;
        this->mode = 0;
        this->umask = 0;
        this->offset = 0;
        this->opcode = 0;
        this->response_code = 0;
        this->inode_number = 0;
        this->uid = 0;
        this->gid = 0;
        this->new_inode_number = 0;
        this->size_changed = 0;
        this->dirty = 0;

    }
}

static void cg_storage_connection_clean(cg_storage_connection * const this)
{
    if (this != NULL)
    {
        if (this->fs_id != NULL)
        {
            CGUTILS_FREE(this->fs_id);
        }

        if (this->io != NULL)
        {
            cgutils_event_buffered_io_release(this->io), this->io = NULL;
        }

        cg_storage_request_clean(&(this->request));

        this->data = NULL;
        this->fs_id_len = 0;
        this->fs = NULL;
        this->requests_per_conn = 0;
        this->error = false;
        this->end_cb = NULL;
        this->end_cb_data = NULL;

        if (this->sock >= 0)
        {
            /* FIXME / TODO handle shutdown gracefully (we need to shutdown(SHUT_WR), read until EOF, then only close the FD) */
            shutdown(this->sock, SHUT_RDWR);
            cgutils_file_close(this->sock), this->sock = -1;
        }
    }
}

void cg_storage_connection_release(cg_storage_connection * this)
{
    if (this != NULL)
    {
        bool reused = false;
        int result = 0;

        cg_storage_request_clean(&(this->request));

        (this->requests_per_conn)++;

        if (this->sock >= 0)
        {
            bool data_available = false;

            result = cgutils_network_socket_has_data(this->sock,
                                                     &data_available);

            if (result == 0)
            {
                size_t max_requests_per_conn = cg_storage_manager_data_get_max_requests_per_connection(this->data);

                if (max_requests_per_conn == 0)
                {
                    max_requests_per_conn = CG_ST_MAX_REQUESTS_PER_CONN_DEFAULT;
                }

                if (this->error == false &&
                    ( data_available == true ||
                      this->requests_per_conn < max_requests_per_conn))
                {
                    result = cgutils_event_buffered_io_add_one(this->io,
                                                               &(this->request.opcode),
                                                               sizeof this->request.opcode,
                                                               cgutils_event_buffered_io_reading,
                                                               &cg_storage_connection_got_opcode,
                                                               this);
                    if (result == 0)
                    {
                        reused = true;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error reading opcode: %d", result);
                    }
                }
                else
                {
                    /*
                    CGUTILS_TRACE("[%d] Closing connection (status %s, %zu / %zu, %d)",
                                  this->sock,
                                  this->error ? "true" : "false",
                                  this->requests_per_conn, max_requests_per_conn,
                                  data_available);
                    */
                }
            }
            else
            {
                CGUTILS_ERROR("Error looking for data on connection: %d", result);
            }
        }

        if (result != 0 ||
            reused == false)
        {
            if (this->end_cb != NULL)
            {
                (*(this->end_cb))(this, this->end_cb_data);
            }

            cg_storage_connection_clean(this);
            CGUTILS_FREE(this);
        }
    }
}

void cg_storage_connection_finish(cg_storage_connection * const this)
{
    if (this != NULL)
    {
        this->error = true;
        cg_storage_connection_release(this);
    }
}

int cg_storage_connection_go(cg_storage_connection * const this)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(this != NULL))
    {
        /* TODO handle timeout on connections */
        result = cgutils_event_buffered_io_add_one(this->io,
                                                   &(this->fs_id_len),
                                                   sizeof (this->fs_id_len),
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_connection_got_fs_id_len,
                                                   this);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error enabling event on socket: %d", result);
        }
    }

    return result;
}
