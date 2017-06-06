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

#ifndef LIB_CLOUD_GATEWAY_STORAGE_MANAGER_PROTO_H_
#define LIB_CLOUD_GATEWAY_STORAGE_MANAGER_PROTO_H_

#include <inttypes.h>

/* GLibc states in <asm/stat.h> that st_blocks is:
   "Number 512-byte blocks allocated"
*/
#define CG_STORAGE_MANAGER_BLOCK_SIZE (512)

typedef uint8_t cgsm_proto_response_code;
typedef size_t cgsm_proto_object_size;
typedef uint64_t cgsm_proto_opcode_type;
typedef int32_t cgsm_proto_flags_type;
typedef uint32_t cgsm_proto_mode_type;
typedef uint64_t cgsm_proto_uid_type;
typedef uint64_t cgsm_proto_gid_type;
typedef int64_t cgsm_proto_offset_type;
typedef struct timespec cgsm_proto_timespec_type;
typedef uint8_t cgsm_proto_size_changed_type;
typedef uint8_t cgsm_proto_dirty_type;

COMPILER_STATIC_ASSERT(sizeof(cgsm_proto_mode_type) >= sizeof(mode_t),
                       "cgsm_proto_mode_type is not large enough for mode_t");
COMPILER_STATIC_ASSERT(sizeof(cgsm_proto_uid_type) >= sizeof(uid_t),
                       "cgsm_proto_uid_type is not large enough for uid_t");
COMPILER_STATIC_ASSERT(sizeof(cgsm_proto_gid_type) >= sizeof(gid_t),
                       "cgsm_proto_gid_type is not large enough for gid_t");
COMPILER_STATIC_ASSERT(sizeof(cgsm_proto_offset_type) >= sizeof(off_t),
                       "cgsm_proto_offset_type is not large enough for off_t");
COMPILER_STATIC_ASSERT(sizeof(cgsm_proto_timespec_type) >= sizeof(struct timespec),
                       "cgsm_proto_timespec_type is not large enough for timespec");

typedef enum
{
#define OPCODE(name) cgsm_proto_opcode_ ## name,
#include "cgsm/cg_storage_manager_proto_opcodes.itm"
#undef OPCODE
    cgsm_proto_opcode_max
} cgsm_proto_opcode;

#endif /* LIB_CLOUD_GATEWAY_STORAGE_MANAGER_PROTO_H_ */
