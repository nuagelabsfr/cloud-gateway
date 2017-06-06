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

#ifndef CLOUD_GATEWAY_STORAGE_CONNECTION_INTERNALS_H_
#define CLOUD_GATEWAY_STORAGE_CONNECTION_INTERNALS_H_

#include <cloudutils/cloudutils_event.h>
#include <cgsm/cg_storage_manager_proto.h>

#include "cg_storage_filesystem.h"

typedef struct cg_storage_request cg_storage_request;

struct cg_storage_request
{
    cg_storage_connection * conn;
    char * path;
    char * path_to;
    struct stat * st;

    size_t request_size;
    size_t response_size;

    size_t path_len;
    size_t path_to_len;

    uint64_t inode_number;
    uint64_t new_inode_number;

    cgsm_proto_timespec_type atime;
    cgsm_proto_timespec_type mtime;
    cgsm_proto_flags_type flags;
    cgsm_proto_mode_type mode;
    cgsm_proto_mode_type umask;
    cgsm_proto_offset_type offset;
    cgsm_proto_uid_type uid;
    cgsm_proto_gid_type gid;
    cgsm_proto_opcode_type opcode;
    cgsm_proto_response_code response_code;
    cgsm_proto_size_changed_type size_changed;
    cgsm_proto_dirty_type dirty;

    /* vector of cgdb_entry * used for readdir */
    cgutils_vector * entries;
};

struct cg_storage_connection
{
    cg_storage_request request;

    cg_storage_connection_end_cb * end_cb;
    void * end_cb_data;

    cg_storage_manager_data * data;
    cgutils_event_buffered_io * io;

    cg_storage_filesystem * fs;
    char * fs_id;
    size_t fs_id_len;

    size_t requests_per_conn;

    int sock;
    bool error;
};

#endif /* CLOUD_GATEWAY_STORAGE_CONNECTION_INTERNALS_H_ */
