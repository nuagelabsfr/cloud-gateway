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
#include <string.h>

#include <cloudutils/cloudutils_compiler_specifics.h>
#include <cloudutils/cloudutils_configuration.h>

#include <cgsm/cg_storage_request.h>
#include <cgsm/cg_storage_connection_internals.h>
#include <cgsm/cg_storage_filesystem.h>
#include <cgsm/cg_storage_object.h>

typedef int (cg_storage_request_obj_cb)(int status, cg_storage_request * request);

typedef struct
{
    void * obj;
    size_t * obj_size;
    cg_storage_request_obj_cb * cb;
    cg_storage_request * request;
    bool is_string;
} cg_storage_request_obj;

static int cg_storage_request_code_sent(cgutils_event_data * const data,
                                         int const status,
                                         int const fd,
                                         cgutils_event_buffered_io_obj * const obj)
{
    (void) fd;
    (void) data;

    assert(obj != NULL);

    cg_storage_request * this = obj->cb_data;

//    CGUTILS_TRACE("[%d] Sent code %d for opcode %d", this->conn->sock, this->response_code, (int) this->opcode);

    if (COMPILER_UNLIKELY(status != 0))
    {
        CGUTILS_ERROR("Error sending code %d: %d", this->response_code, status);
        this->conn->error = true;
    }

    cg_storage_connection_release(this->conn), this = NULL;

    return status;
}

static void cg_storage_request_send_code(cg_storage_request * this,
                                          int const code)
{
    assert(this != NULL);
    assert(code >= 0 && code <= UINT8_MAX);

    this->response_code = (uint8_t) code;

//    CGUTILS_TRACE("[%d] Sending code %d for opcode %d", this->conn->sock, code, (int) this->opcode);

    int result = cgutils_event_buffered_io_add_one(this->conn->io,
                                                   &(this->response_code),
                                                   sizeof (this->response_code),
                                                   cgutils_event_buffered_io_writing,
                                                   &cg_storage_request_code_sent,
                                                   this);

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error sending code (%d): %d", code, result);
        cg_storage_connection_finish(this->conn), this = NULL;
    }
}

static int cg_storage_request_status_cb(int status,
                                    void * cb_data)
{
    int result = status;
    cg_storage_request * request = cb_data;
    assert(cb_data != NULL);

    cg_storage_request_send_code(request,
                                 result);
    return result;
}

static int cg_storage_request_io_error_handler(cgutils_event_data * const data,
                                               int const status,
                                               int const fd,
                                               cgutils_event_buffered_io_obj * const obj)
{
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd >= 0);
    CGUTILS_ASSERT(obj != NULL);

    (void) data;

    int result = status;

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request * req = obj->cb_data;
        CGUTILS_ASSERT(req != NULL);
        CGUTILS_ERROR("Error during IO (%s %zu) to the FUSE process on fd %d: %d",
                      obj->action == cgutils_event_buffered_io_reading ? "reading" : "writing",
                      obj->object_size,
                      fd,
                      result);

        cg_storage_connection_finish(req->conn), req = NULL;
    }

    return result;
}

static int cg_storage_request_read_object_done(cgutils_event_data * data,
                                               int status,
                                               int fd,
                                               cgutils_event_buffered_io_obj * obj)
{
    assert(data != NULL);
    assert(fd >= 0);
    assert(obj != NULL);

    (void) data;
    (void) fd;

    cg_storage_request_obj * this = obj->cb_data;

    int result = status;

    if (COMPILER_LIKELY(result == 0))
    {
        assert(this->cb != NULL);
        result = (this->cb)(status,
                            this->request);
    }
    else
    {
        cg_storage_connection_finish(this->request->conn), this = NULL;
    }

    CGUTILS_FREE(this);

    return result;
}

static int cg_storage_request_got_object_size_cb(cgutils_event_data * data,
                                                 int status,
                                                 int fd,
                                                 cgutils_event_buffered_io_obj * obj)
{
    assert(data != NULL);
    assert(fd >= 0);
    assert(obj != NULL);

    (void) data;
    (void) fd;

    cg_storage_request_obj * this = obj->cb_data;

    int result = status;

    if (COMPILER_LIKELY(result == 0))
    {
        void * object = NULL;

        CGUTILS_MALLOC(object,
                       *(this->obj_size) + (size_t)(this->is_string ? 1 : 0),
                       1);

        if (COMPILER_LIKELY(object != NULL))
        {
            *((char **) this->obj) = object;

            result = cgutils_event_buffered_io_add_one(this->request->conn->io,
                                                       object,
                                                       *(this->obj_size),
                                                       cgutils_event_buffered_io_reading,
                                                       &cg_storage_request_read_object_done,
                                                       this);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error adding io [%p] read request for object [%p] of size %zu: %d",
                              this->request->conn->io,
                              object,
                              *(this->obj_size),
                              result);
                this->request->conn->error = true;
                CGUTILS_FREE(object);
                *((char **) this->obj) = NULL;
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Allocation error for object of size %zu: %d",
                          *(this->obj_size),
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading object size: %d", result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_connection_finish(this->request->conn), this = NULL;
        CGUTILS_FREE(this);
    }

    return result;
}

static int cg_storage_request_writer_cb_free(cgutils_event_data * data,
                                             int status,
                                             int fd,
                                             cgutils_event_buffered_io_obj * obj)
{
    assert(data != NULL);
    assert(obj != NULL);
    assert(fd >= 0);

    (void) data;
    (void) fd;

    int result = status;
    cg_storage_request * request = obj->cb_data;

    if (COMPILER_LIKELY(result == 0))
    {
        if (request != NULL)
        {
            CGUTILS_ASSERT(obj->io != NULL);

            size_t remaining = cgutils_event_buffered_io_remaining_objects_count(obj->io);

            if (remaining == 0)
            {
                cg_storage_connection_release(request->conn), request = NULL;
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Error in writer: %d", result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_connection_finish(request->conn), request = NULL;
    }

    CGUTILS_FREE(obj->object);

    return 0;
}

static int cg_storage_request_writer_cb_nofree(cgutils_event_data * data,
                                               int status,
                                               int fd,
                                               cgutils_event_buffered_io_obj * obj)
{
    assert(data != NULL);
    assert(obj != NULL);
    assert(fd >= 0);

    (void) data;
    (void) fd;

    int result = status;
    cg_storage_request * request = obj->cb_data;

    if (COMPILER_LIKELY(result == 0))
    {
        if (request != NULL)
        {
            CGUTILS_ASSERT(obj->io != NULL);

            size_t remaining = cgutils_event_buffered_io_remaining_objects_count(obj->io);

            if (remaining == 0)
            {
                cg_storage_connection_release(request->conn), request = NULL;
            }
        }
    }
    else
    {
        CGUTILS_ERROR("Error in writer: %d", result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_connection_finish(request->conn), request = NULL;
    }

    return 0;
}

static int cg_storage_request_send_object(cg_storage_request * request,
                                          size_t const object_size,
                                          void * const object,
                                          cgutils_event_buffered_io_cb * const cb)
{
    assert(request != NULL);
    assert(object_size > 0);
    assert(object != NULL);

    cgutils_event_buffered_io_obj * final_obj = NULL;

    int result = cgutils_event_buffered_io_object_create(request->conn->io,
                                                         object,
                                                         object_size,
                                                         cgutils_event_buffered_io_writing,
                                                         cb,
                                                         request,
                                                         &final_obj);

    if (result == 0)
    {
        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(final_obj->object_size),
                                                   sizeof (final_obj->object_size),
                                                   cgutils_event_buffered_io_writing,
                                                   &cg_storage_request_io_error_handler,
                                                   request);


        if (result == 0)
        {

            result = cgutils_event_buffered_io_add_obj(request->conn->io,
                                                       final_obj);

            if (result != 0)
            {
                CGUTILS_ERROR("Error sending object: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error sending object size: %d", result);
        }

        if (result != 0)
        {
            CGUTILS_FREE(final_obj);
        }
    }
    else
    {
        CGUTILS_ERROR("Error creating final object: %d", result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_connection_finish(request->conn), request = NULL;
    }

    return result;
}

static int cg_storage_request_read_object(cg_storage_request * request,
                                          size_t * object_size,
                                          void * object,
                                          bool const is_string,
                                          cg_storage_request_obj_cb * cb)
{
    assert(request != NULL);
    assert(object_size != NULL);
    assert(object != NULL);
    assert(cb != NULL);

    int result = ENOMEM;
    cg_storage_request_obj * obj = NULL;

    CGUTILS_ALLOCATE_STRUCT(obj);

    if (COMPILER_LIKELY(obj != NULL))
    {
        obj->obj = object;
        obj->obj_size = object_size;
        obj->cb = cb;
        obj->is_string = is_string;
        obj->request = request;

        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   object_size,
                                                   sizeof *object_size,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_got_object_size_cb,
                                                   obj);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error reading object size: %d", result);
            CGUTILS_FREE(obj);
        }
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_connection_finish(request->conn), request = NULL;
    }

    return result;
}

static int cg_storage_request_low_attr_db_cb(int status,
                                             cg_storage_object const * obj,
                                             void * cb_data)
{
    cg_storage_request * request = cb_data;

    int result = status;

    if (result == 0)
    {
        CGUTILS_ALLOCATE_STRUCT(request->st);

        if (COMPILER_LIKELY(request->st != NULL))
        {
            result = cg_storage_object_get_stat(obj, request->st);

            if (COMPILER_LIKELY(result == 0))
            {
                request->response_code = 0;
                result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                           &request->response_code,
                                                           sizeof request->response_code,
                                                           cgutils_event_buffered_io_writing,
                                                           &cg_storage_request_io_error_handler,
                                                           request);

                if (COMPILER_LIKELY(result == 0))
                {
                    result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                               request->st,
                                                               sizeof *(request->st),
                                                               cgutils_event_buffered_io_writing,
                                                               &cg_storage_request_writer_cb_nofree,
                                                               request);

                    if (COMPILER_UNLIKELY(result != 0))
                    {
                        CGUTILS_ERROR("Error sending stat data: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error sending response code object: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error getting state for path %s", request->path);
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating object: %d", result);
            result = ENOMEM;
        }
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request, result);
    }

    return result;
}

static int cg_storage_request_cb_low_lookup_child_ready(int const status,
                                                        cg_storage_request * const request)
{
    int result = status;
    CGUTILS_ASSERT(request != NULL);

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(request->path != NULL);
        request->path[request->path_len] = '\0';

        result = cg_storage_filesystem_entry_get_child(request->conn->fs,
                                                       request->inode_number,
                                                       request->path,
                                                       &cg_storage_request_low_attr_db_cb,
                                                       request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_entry_get_child: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    return result;
}

int cg_storage_request_cb_low_lookup_child(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cg_storage_request_read_object(request,
                                                &(request->path_len),
                                                &(request->path),
                                                true,
                                                &cg_storage_request_cb_low_lookup_child_ready);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error adding read operation for path: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error adding read operation for inode_number: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_getattr_ready(cgutils_event_data * const data,
                                                int const status,
                                                int const fd,
                                                cgutils_event_buffered_io_obj * const obj)
{
    int result = status;

    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cg_storage_request * request = obj->cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) data;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        result = cg_storage_filesystem_entry_get_object_by_inode(request->conn->fs,
                                                                 request->inode_number,
                                                                 &cg_storage_request_low_attr_db_cb,
                                                                 request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_entry_get_object_by_inode: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_getattr(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_low_getattr_ready,
                                                   request);

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error adding read operation for inode_number: %d",
                      result);
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_readdir_db_cb(int status,
                                                size_t const entries_count,
                                                cgutils_vector * entries,
                                                void * cb_data)
{
    int result = status;
    cg_storage_request * request = cb_data;

    if (result == 0)
    {
        size_t * count = NULL;

        CGUTILS_MALLOC(count, 1, sizeof *count);

        if (count != NULL)
        {
            request->entries = entries;
            *count = entries_count;

            request->response_code = 0;
            result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                       &request->response_code,
                                                       sizeof request->response_code,
                                                       cgutils_event_buffered_io_writing,
                                                       &cg_storage_request_io_error_handler,
                                                       request);

            if (result == 0)
            {
                result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                           count,
                                                           sizeof *count,
                                                           cgutils_event_buffered_io_writing,
                                                           &cg_storage_request_writer_cb_free,
                                                           request);

                if (result == 0)
                {
                    count = NULL;

                    for(size_t idx = 0;
                        idx < entries_count &&
                            result == 0;
                        idx++)
                    {
                        cgdb_entry * entry = NULL;

                        result = cgutils_vector_get(entries,
                                                    idx,
                                                    (void **) &entry);

                        if (result == 0)
                        {
                            CGUTILS_ASSERT(entry != NULL);
                            CGUTILS_ASSERT(entry->name != NULL);

                            if (entry->name != NULL)
                            {
                                size_t const entry_name_len = strlen(entry->name);
                                CGUTILS_ASSERT(entry_name_len > 0);

                                result = cg_storage_request_send_object(request,
                                                                        entry_name_len + 1,
                                                                        entry->name,
                                                                        &cg_storage_request_io_error_handler);

                                if (result == 0)
                                {
                                    result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                                               &(entry->inode.st),
                                                                               sizeof (entry->inode.st),
                                                                               cgutils_event_buffered_io_writing,
                                                                               &cg_storage_request_writer_cb_nofree,
                                                                               request);

                                    if (result != 0)
                                    {
                                        CGUTILS_ERROR("Error adding stat to buffered writer: %d", result);
                                    }
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error adding data to buffered writer: %d", result);
                                }
                            }
                            else
                            {
                                CGUTILS_ERROR("Error, invalid NULL name for entry %zu, skipping",
                                              idx);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error getting entry %zu: %d",
                                          idx,
                                          result);
                        }
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error sending entries count: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error sending response code: %d", result);
            }

            if (result != 0 && count != NULL)
            {
                CGUTILS_FREE(count);
            }
        }
        else
        {
            CGUTILS_ERROR("Error allocating counter: %d", result);
            result = ENOMEM;
        }

        if (result == 0)
        {
            /* entries are freed when the request is freed,
               after the writer callback */
        }
        else
        {
            cgutils_vector_deep_free(&entries, &cgdb_entry_delete);
            request->entries = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Got status of: %d", result);
    }

    if (result != 0)
    {
        cg_storage_request_send_code(request, result);
    }

    return result;
}

static int cg_storage_request_low_readdir_ready(cgutils_event_data * const data,
                                                int const status,
                                                int const fd,
                                                cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cg_storage_request * request = obj->cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) data;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        result = cg_storage_filesystem_dir_get_entries_by_inode(request->conn->fs,
                                                                request->inode_number,
                                                                &cg_storage_request_low_readdir_db_cb,
                                                                request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_entry_get_entries_by_inode: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_readdir(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_low_readdir_ready,
                                                   request);

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error adding read operation for inode_number: %d",
                      result);
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_create_and_open_db_cb(int status,
                                                        cg_storage_object const * obj,
                                                        char * file_in_cache,
                                                        void * cb_data)
{
    cg_storage_request * request = cb_data;

    int result = status;

    if (result == 0)
    {
        CGUTILS_ASSERT(obj != NULL);
        CGUTILS_ASSERT(file_in_cache != NULL);

        if (COMPILER_LIKELY(file_in_cache != NULL))
        {
            CGUTILS_ALLOCATE_STRUCT(request->st);

            if (COMPILER_LIKELY(request->st != NULL))
            {
                result = cg_storage_object_get_stat(obj, request->st);

                if (COMPILER_LIKELY(result == 0))
                {
                    request->response_code = 0;
                    result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                               &request->response_code,
                                                               sizeof request->response_code,
                                                               cgutils_event_buffered_io_writing,
                                                               &cg_storage_request_io_error_handler,
                                                               request);

                    if (COMPILER_LIKELY(result == 0))
                    {
                        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                                   request->st,
                                                                   sizeof *(request->st),
                                                                   cgutils_event_buffered_io_writing,
                                                                   &cg_storage_request_writer_cb_nofree,
                                                                   request);

                        if (COMPILER_LIKELY(result == 0))
                        {
                            size_t const file_in_cache_len = strlen(file_in_cache);
                            CGUTILS_ASSERT(file_in_cache_len > 0);

                            result = cg_storage_request_send_object(request,
                                                                    file_in_cache_len + 1,
                                                                    file_in_cache,
                                                                    &cg_storage_request_writer_cb_free);

                            if (COMPILER_UNLIKELY(result != 0))
                            {
                                CGUTILS_ERROR("Error sending file in cache path data: %d",
                                              result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error sending stat data: %d",
                                          result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error sending response code object: %d",
                                      result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error getting state for path %s",
                                  request->path);
                }
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating object: %d",
                              result);
            }
        }
        else
        {
            result = EINVAL;
            CGUTILS_ERROR("Error, invalid NULL path: %d",
                          result);
        }
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request, result);
    }

    return result;
}

static int cg_storage_request_low_create_and_open_ready(int const status,
                                                        cg_storage_request * const request)
{
    int result = status;
    CGUTILS_ASSERT(request != NULL);

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(request->path != NULL);
        request->path[request->path_len] = '\0';

        result = cg_storage_filesystem_file_create_and_open(request->conn->fs,
                                                            request->inode_number,
                                                            request->path,
                                                            (uid_t) request->uid,
                                                            (gid_t) request->gid,
                                                            (mode_t) request->mode,
                                                            request->flags,
                                                            &cg_storage_request_low_create_and_open_db_cb,
                                                            request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_file_create_and_open: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_create_and_open(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->uid),
                                                   sizeof request->uid,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                       &(request->gid),
                                                       sizeof request->gid,
                                                       cgutils_event_buffered_io_reading,
                                                       &cg_storage_request_io_error_handler,
                                                       request);

            if (COMPILER_LIKELY(result == 0))
            {
                result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                           &(request->mode),
                                                           sizeof request->mode,
                                                           cgutils_event_buffered_io_reading,
                                                           &cg_storage_request_io_error_handler,
                                                           request);

                if (COMPILER_LIKELY(result == 0))
                {
                    result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                               &(request->flags),
                                                               sizeof request->flags,
                                                               cgutils_event_buffered_io_reading,
                                                               &cg_storage_request_io_error_handler,
                                                               request);

                    if (COMPILER_LIKELY(result == 0))
                    {
                        result = cg_storage_request_read_object(request,
                                                                &(request->path_len),
                                                                &(request->path),
                                                                true,
                                                                &cg_storage_request_low_create_and_open_ready);

                        if (COMPILER_UNLIKELY(result != 0))
                        {
                            CGUTILS_ERROR("Error adding read operation for path: %d",
                                          result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error adding read operation for flags: %d",
                                      result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error adding read operation for mode: %d",
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error adding read operation for gid: %d",
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error adding read operation for uid: %d",
                          result);
        }

    }
    else
    {
        CGUTILS_ERROR("Error adding read operation for inode number: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_open_file_in_cache_cb(int status,
                                                        char * path_in_cache,
                                                        void * cb_data)
{
    int result = status;
    cg_storage_request * request = cb_data;
    CGUTILS_ASSERT(cb_data != NULL);

    if (COMPILER_LIKELY(result == 0))
    {
        CGUTILS_ASSERT(path_in_cache != NULL);

        if (COMPILER_LIKELY(path_in_cache != NULL))
        {
            request->response_code = 0;
            result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                       &request->response_code,
                                                       sizeof request->response_code,
                                                       cgutils_event_buffered_io_writing,
                                                       &cg_storage_request_io_error_handler,
                                                       request);

            if (COMPILER_LIKELY(result == 0))
            {
                result = cg_storage_request_send_object(request,
                                                        strlen(path_in_cache) + 1,
                                                        (void * ) path_in_cache,
                                                        &cg_storage_request_writer_cb_free);
                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error sending path in cache: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error sending response code: %d", result);
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_FREE(path_in_cache);
            }
        }
        else
        {
            result = EINVAL;
            CGUTILS_ERROR("Error, invalid NULL path: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error getting file path in cache: %d", result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request, result);
    }

    return result;
}

static int cg_storage_request_low_open_ready(cgutils_event_data * const data,
                                             int const status,
                                             int const fd,
                                             cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cg_storage_request * request = obj->cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) data;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        result = cg_storage_filesystem_file_inode_get_path_in_cache(request->conn->fs,
                                                                    request->inode_number,
                                                                    request->flags,
                                                                    &cg_storage_request_low_open_file_in_cache_cb,
                                                                    request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_file_inode_released: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_open(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->flags),
                                                   sizeof request->flags,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_low_open_ready,
                                                   request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error adding read operation for flags: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error adding read operation for inode number: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_release_ready(cgutils_event_data * const data,
                                                int const status,
                                                int const fd,
                                                cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cg_storage_request * request = obj->cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) data;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        result = cg_storage_filesystem_file_inode_released(request->conn->fs,
                                                           request->inode_number,
                                                           request->dirty != 0,
                                                           &cg_storage_request_status_cb,
                                                           request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_file_inode_released: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_release(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->dirty),
                                                   sizeof request->dirty,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_low_release_ready,
                                                   request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error adding read operation for dirtyness flag: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error adding read operation for inode number: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_notify_write_ready(cgutils_event_data * const data,
                                                     int const status,
                                                     int const fd,
                                                     cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cg_storage_request * request = obj->cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) data;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        result = cg_storage_filesystem_file_inode_notify_write(request->conn->fs,
                                                               request->inode_number,
                                                               &cg_storage_request_status_cb,
                                                               request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_file_inode_notify_write: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_notify_write(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_low_notify_write_ready,
                                                   request);

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error adding read operation for inode number: %d",
                      result);
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

#include <cloudutils/cloudutils_system.h>

static int cg_storage_request_low_setattr_ready(cgutils_event_data * const data,
                                                int const status,
                                                int const fd,
                                                cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cg_storage_request * request = obj->cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) data;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        result = cg_storage_filesystem_entry_inode_setattr(request->conn->fs,
                                                           request->inode_number,
                                                           request->st,
                                                           request->size_changed == 1,
                                                           &cg_storage_request_status_cb,
                                                           request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_file_entry_set_attr(%"PRIu64"): %d",
                          request->inode_number,
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_setattr(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

    if (COMPILER_LIKELY(result == 0))
    {
        CGUTILS_ALLOCATE_STRUCT(request->st);

        if (COMPILER_LIKELY(request->st != NULL))
        {
            result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                       request->st,
                                                       sizeof *(request->st),
                                                       cgutils_event_buffered_io_reading,
                                                       &cg_storage_request_io_error_handler,
                                                       request);

            if (COMPILER_LIKELY(result == 0))
            {
                result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                           &(request->size_changed),
                                                           sizeof request->size_changed,
                                                           cgutils_event_buffered_io_reading,
                                                           &cg_storage_request_low_setattr_ready,
                                                           request);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error adding read operation for size changed flag: %d",
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error adding read operation for stat: %d",
                              result);
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating memory for request stat: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error adding read operation for inode number: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_mkdir_ready(int const status,
                                              cg_storage_request * const request)
{
    int result = status;
    CGUTILS_ASSERT(request != NULL);

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(request->path != NULL);
        request->path[request->path_len] = '\0';

        result = cg_storage_filesystem_dir_inode_mkdir(request->conn->fs,
                                                       request->inode_number,
                                                       request->path,
                                                       (uid_t) request->uid,
                                                       (gid_t) request->gid,
                                                       (mode_t) request->mode,
                                                       &cg_storage_request_low_attr_db_cb,
                                                       request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_dir_inode_mkdir: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_mkdir(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->uid),
                                                   sizeof request->uid,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                       &(request->gid),
                                                       sizeof request->gid,
                                                       cgutils_event_buffered_io_reading,
                                                       &cg_storage_request_io_error_handler,
                                                       request);

            if (COMPILER_LIKELY(result == 0))
            {
                result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                           &(request->mode),
                                                           sizeof request->mode,
                                                           cgutils_event_buffered_io_reading,
                                                           &cg_storage_request_io_error_handler,
                                                           request);

                if (COMPILER_LIKELY(result == 0))
                {
                    result = cg_storage_request_read_object(request,
                                                            &(request->path_len),
                                                            &(request->path),
                                                            true,
                                                            &cg_storage_request_low_mkdir_ready);

                    if (COMPILER_UNLIKELY(result != 0))
                    {
                        CGUTILS_ERROR("Error adding read operation for path: %d",
                                      result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error adding read operation for mode: %d",
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error adding read operation for gid: %d",
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error adding read operation for uid: %d",
                          result);
        }

    }
    else
    {
        CGUTILS_ERROR("Error adding read operation for inode number: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_inode_number_db_cb(int status,
                                                     uint64_t const inode_number,
                                                     void * cb_data)
{
    cg_storage_request * request = cb_data;
    CGUTILS_ASSERT(request != NULL);

    int result = status;

    if (result == 0)
    {
        request->inode_number = inode_number;
        request->response_code = 0;
        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &request->response_code,
                                                   sizeof request->response_code,
                                                   cgutils_event_buffered_io_writing,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                       &(request->inode_number),
                                                       sizeof (request->inode_number),
                                                       cgutils_event_buffered_io_writing,
                                                       &cg_storage_request_writer_cb_nofree,
                                                       request);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error sending inode_number data: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error sending response code object: %d", result);
        }
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request, result);
    }

    return result;
}

static int cg_storage_request_low_rmdir_ready(int const status,
                                              cg_storage_request * const request)
{
    int result = status;
    CGUTILS_ASSERT(request != NULL);

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(request->path != NULL);
        request->path[request->path_len] = '\0';

        result = cg_storage_filesystem_dir_inode_rmdir(request->conn->fs,
                                                       request->inode_number,
                                                       request->path,
                                                       &cg_storage_request_low_inode_number_db_cb,
                                                       request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_dir_inode_rmdir: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_rmdir(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cg_storage_request_read_object(request,
                                                &(request->path_len),
                                                &(request->path),
                                                true,
                                                &cg_storage_request_low_rmdir_ready);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error adding read operation for path: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error adding read operation for inode number: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_unlink_ready(int const status,
                                              cg_storage_request * const request)
{
    int result = status;
    CGUTILS_ASSERT(request != NULL);

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(request->path != NULL);
        request->path[request->path_len] = '\0';

        result = cg_storage_filesystem_entry_inode_unlink(request->conn->fs,
                                                          request->inode_number,
                                                          request->path,
                                                          &cg_storage_request_low_inode_number_db_cb,
                                                          request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_entry_inode_unlink: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_unlink(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cg_storage_request_read_object(request,
                                                &(request->path_len),
                                                &(request->path),
                                                true,
                                                &cg_storage_request_low_unlink_ready);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error adding read operation for path: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error adding read operation for inode number: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_rename_db_cb(int const status,
                                               uint64_t const renamed_ino,
                                               uint64_t const deleted_ino,
                                               void * const cb_data)
{
    cg_storage_request * request = cb_data;

    int result = status;

    if (result == 0)
    {
        request->inode_number = renamed_ino;
        request->new_inode_number = deleted_ino;
        request->response_code = 0;

        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &request->response_code,
                                                   sizeof request->response_code,
                                                   cgutils_event_buffered_io_writing,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                       &request->inode_number,
                                                       sizeof request->inode_number,
                                                       cgutils_event_buffered_io_writing,
                                                       &cg_storage_request_io_error_handler,
                                                       request);

            if (COMPILER_LIKELY(result == 0))
            {
                result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                           &(request->new_inode_number),
                                                           sizeof request->new_inode_number,
                                                           cgutils_event_buffered_io_writing,
                                                           &cg_storage_request_writer_cb_nofree,
                                                           request);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error sending deleted inode number data: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error sending renamed inode number data: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error sending response code object: %d", result);
        }
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request, result);
    }

    return result;
}

static int cg_storage_request_low_rename_ready(cgutils_event_data * const data,
                                               int const status,
                                               int const fd,
                                               cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cg_storage_request * request = obj->cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) data;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(request->path != NULL);
        CGUTILS_ASSERT(request->path_to != NULL);

        request->path[request->path_len] = '\0';
        request->path_to[request->path_to_len] = '\0';

        result = cg_storage_filesystem_entry_inode_rename(request->conn->fs,
                                                          request->inode_number,
                                                          request->path,
                                                          request->new_inode_number,
                                                          request->path_to,
                                                          &cg_storage_request_low_rename_db_cb,
                                                          request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_entry_inode_rename: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_rename_paths_size_ready(cgutils_event_data * const data,
                                                          int const status,
                                                          int const fd,
                                                          cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cg_storage_request * request = obj->cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) data;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        if (COMPILER_LIKELY(request->path_len > 0 &&
                            request->path_to_len > 0))
        {
            CGUTILS_MALLOC(request->path,
                           request->path_len + 1,
                           1);

            if (COMPILER_LIKELY(request->path != NULL))
            {
                CGUTILS_MALLOC(request->path_to,
                               request->path_to_len + 1,
                               1);

                if (COMPILER_LIKELY(request->path_to != NULL))
                {
                    result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                               request->path,
                                                               request->path_len,
                                                               cgutils_event_buffered_io_reading,
                                                               &cg_storage_request_io_error_handler,
                                                               request);

                    if (COMPILER_LIKELY(result == 0))
                    {
                        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                                   request->path_to,
                                                                   request->path_to_len,
                                                                   cgutils_event_buffered_io_reading,
                                                                   &cg_storage_request_low_rename_ready,
                                                                   request);

                        if (COMPILER_UNLIKELY(result != 0))
                        {
                            CGUTILS_ERROR("Error adding read operation for new entry name: %d",
                                          result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error adding read operation for old entry name: %d",
                                      result);
                    }
                }
                else
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error allocating memory for new entry name (%zu): %d",
                                  request->path_to_len,
                                  result);
                }
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for old entry name (%zu): %d",
                              request->path_len,
                              result);
            }
        }
        else
        {
            result = EINVAL;
            CGUTILS_ERROR("Error, receiving a zero-length path (%zu / %zu): %d",
                          request->path_len,
                          request->path_to_len,
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_rename(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->new_inode_number),
                                                   sizeof request->new_inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                       &(request->path_len),
                                                       sizeof request->path_len,
                                                       cgutils_event_buffered_io_reading,
                                                       &cg_storage_request_io_error_handler,
                                                       request);

            if (COMPILER_LIKELY(result == 0))
            {
                result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                           &(request->path_to_len),
                                                           sizeof request->path_to_len,
                                                           cgutils_event_buffered_io_reading,
                                                           &cg_storage_request_low_rename_paths_size_ready,
                                                           request);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error adding read operation for path to len: %d",
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error adding read operation for path len: %d",
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error adding read operation for new inode number: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error adding read operation for inode number: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_hardlink_ready(cgutils_event_data * const data,
                                                 int const status,
                                                 int const fd,
                                                 cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cg_storage_request * request = obj->cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) data;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(request->path != NULL);

        request->path[request->path_len] = '\0';

        result = cg_storage_filesystem_entry_inode_hardlink(request->conn->fs,
                                                            request->inode_number,
                                                            request->new_inode_number,
                                                            request->path,
                                                            &cg_storage_request_low_attr_db_cb,
                                                            request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_entry_inode_rename: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_hardlink_path_size_ready(cgutils_event_data * const data,
                                                           int const status,
                                                           int const fd,
                                                           cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cg_storage_request * request = obj->cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) data;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        if (COMPILER_LIKELY(request->path_len > 0))
        {
            CGUTILS_MALLOC(request->path,
                           request->path_len + 1,
                           1);

            if (COMPILER_LIKELY(request->path != NULL))
            {
                result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                           request->path,
                                                           request->path_len,
                                                           cgutils_event_buffered_io_reading,
                                                           &cg_storage_request_low_hardlink_ready,
                                                           request);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error adding read operation for new entry name: %d",
                                  result);
                }
            }

            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for new entry name (%zu): %d",
                              request->path_to_len,
                              result);
            }
        }
        else
        {
            result = EINVAL;
            CGUTILS_ERROR("Error, receiving a zero-length path: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_hardlink(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->new_inode_number),
                                                   sizeof request->new_inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                       &(request->path_len),
                                                       sizeof request->path_len,
                                                       cgutils_event_buffered_io_reading,
                                                       &cg_storage_request_low_hardlink_path_size_ready,
                                                       request);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_ERROR("Error adding read operation for path len: %d",
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error adding read operation for new inode number: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error adding read operation for inode number: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_symlink_ready(cgutils_event_data * const data,
                                                int const status,
                                                int const fd,
                                                cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cg_storage_request * request = obj->cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) data;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        CGUTILS_ASSERT(request->path != NULL);
        CGUTILS_ASSERT(request->path_to != NULL);

        request->path[request->path_len] = '\0';
        request->path_to[request->path_to_len] = '\0';

        result = cg_storage_filesystem_entry_inode_symlink(request->conn->fs,
                                                           request->new_inode_number,
                                                           request->path,
                                                           request->path_to,
                                                           (uid_t) request->uid,
                                                           (gid_t) request->gid,
                                                           &cg_storage_request_low_attr_db_cb,
                                                           request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_entry_inode_symlink: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_symlink_paths_size_ready(cgutils_event_data * const data,
                                                           int const status,
                                                           int const fd,
                                                           cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cg_storage_request * request = obj->cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) data;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        if (COMPILER_LIKELY(request->path_len > 0 &&
                            request->path_to_len > 0))
        {
            CGUTILS_MALLOC(request->path,
                           request->path_len + 1,
                           1);

            if (COMPILER_LIKELY(request->path != NULL))
            {
                CGUTILS_MALLOC(request->path_to,
                               request->path_to_len + 1,
                               1);

                if (COMPILER_LIKELY(request->path_to != NULL))
                {
                    result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                               request->path,
                                                               request->path_len,
                                                               cgutils_event_buffered_io_reading,
                                                               &cg_storage_request_io_error_handler,
                                                               request);

                    if (COMPILER_LIKELY(result == 0))
                    {
                        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                                   request->path_to,
                                                                   request->path_to_len,
                                                                   cgutils_event_buffered_io_reading,
                                                                   &cg_storage_request_low_symlink_ready,
                                                                   request);

                        if (COMPILER_UNLIKELY(result != 0))
                        {
                            CGUTILS_ERROR("Error adding read operation for new entry name: %d",
                                          result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error adding read operation for old entry name: %d",
                                      result);
                    }
                }
                else
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error allocating memory for new entry name (%zu): %d",
                                  request->path_to_len,
                                  result);
                }
            }
            else
            {
                result = ENOMEM;
                CGUTILS_ERROR("Error allocating memory for old entry name (%zu): %d",
                              request->path_len,
                              result);
            }
        }
        else
        {
            result = EINVAL;
            CGUTILS_ERROR("Error, receiving a zero-length path (%zu / %zu): %d",
                          request->path_len,
                          request->path_to_len,
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_symlink(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->new_inode_number),
                                                   sizeof request->new_inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

    if (COMPILER_LIKELY(result == 0))
    {
        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->uid),
                                                   sizeof request->uid,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

        if (COMPILER_LIKELY(result == 0))
        {
            result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                       &(request->gid),
                                                       sizeof request->gid,
                                                       cgutils_event_buffered_io_reading,
                                                       &cg_storage_request_io_error_handler,
                                                       request);

            if (COMPILER_LIKELY(result == 0))
            {
                result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                           &(request->path_len),
                                                           sizeof request->path_len,
                                                           cgutils_event_buffered_io_reading,
                                                           &cg_storage_request_io_error_handler,
                                                           request);

                if (COMPILER_LIKELY(result == 0))
                {
                    result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                               &(request->path_to_len),
                                                               sizeof request->path_to_len,
                                                               cgutils_event_buffered_io_reading,
                                                               &cg_storage_request_low_symlink_paths_size_ready,
                                                               request);

                    if (COMPILER_UNLIKELY(result != 0))
                    {
                        CGUTILS_ERROR("Error adding read operation for path to len: %d",
                                      result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error adding read operation for path len: %d",
                                  result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error adding read operation for GID: %d",
                              result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error adding read operation for UID: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error adding read operation for new inode number: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

static int cg_storage_request_low_readlink_db_cb(int const status,
                                                 char * link_to,
                                                 void * const cb_data)
{
    cg_storage_request * request = cb_data;
    int result = status;

    if (COMPILER_LIKELY(result == 0))
    {
        CGUTILS_ASSERT(link_to != NULL);
        request->response_code = 0;

        result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &request->response_code,
                                                   sizeof request->response_code,
                                                   cgutils_event_buffered_io_writing,
                                                   &cg_storage_request_io_error_handler,
                                                   request);

        if (COMPILER_LIKELY(result == 0))
        {
            size_t const link_to_len = strlen(link_to);

            result = cg_storage_request_send_object(request,
                                                    link_to_len + 1,
                                                    link_to,
                                                    &cg_storage_request_writer_cb_free);

            if (COMPILER_LIKELY(result == 0))
            {
                link_to = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error sending link destination: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error sending response code %d", result);
        }
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request, result);
    }

    CGUTILS_FREE(link_to);

    return result;
}

static int cg_storage_request_low_readlink_ready(cgutils_event_data * const data,
                                                 int const status,
                                                 int const fd,
                                                 cgutils_event_buffered_io_obj * const obj)
{
    int result = status;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(obj != NULL);
    cg_storage_request * request = obj->cb_data;
    CGUTILS_ASSERT(request != NULL);

    (void) data;
    (void) fd;

    if (COMPILER_LIKELY(status == 0))
    {
        result = cg_storage_filesystem_entry_readlink(request->conn->fs,
                                                      request->inode_number,
                                                      &cg_storage_request_low_readlink_db_cb,
                                                      request);

        if (COMPILER_UNLIKELY(result != 0))
        {
            CGUTILS_ERROR("Error in cg_storage_filesystem_entry_get_object_by_inode: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error reading from socket: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}

int cg_storage_request_cb_low_readlink(cg_storage_request * const request)
{
    CGUTILS_ASSERT(request != NULL);

    int result = cgutils_event_buffered_io_add_one(request->conn->io,
                                                   &(request->inode_number),
                                                   sizeof request->inode_number,
                                                   cgutils_event_buffered_io_reading,
                                                   &cg_storage_request_low_readlink_ready,
                                                   request);

    if (COMPILER_UNLIKELY(result != 0))
    {
        CGUTILS_ERROR("Error adding read operation for inode number: %d",
                      result);
    }

    if (COMPILER_UNLIKELY(result != 0))
    {
        cg_storage_request_send_code(request,
                                     result);
    }

    return result;
}
