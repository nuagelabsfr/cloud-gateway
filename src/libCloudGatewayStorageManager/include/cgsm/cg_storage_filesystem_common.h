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

#ifndef CLOUD_GATEWAY_STORAGE_FILESYSTEM_COMMON_H_
#define CLOUD_GATEWAY_STORAGE_FILESYSTEM_COMMON_H_

#include <stdint.h>

#include <cgsm/cg_storage_filesystem.h>
#include <cgsm/cg_storage_filter.h>
#include <cgsm/cg_storage_object.h>
#include <cgsm/cg_storage_cache.h>

#include <cloudutils/cloudutils_llist.h>
#include <cloudutils/cloudutils_rbtree.h>

#include <cgdb/cgdb.h>

#include <cgmonitor/cg_monitor_data.h>

typedef struct
{
    cg_monitor_data_instance_status_data status;
    cg_storage_instance * instance;
    cgdb_inode_instance * object_instance;
    bool usable;
} cg_storage_filesystem_instance;

struct cg_storage_filesystem
{
    cg_storage_manager_data * data;
    cg_storage_cache * cache;
    cgdb_data * db;
    cg_storage_filesystem_instance * instances;
    /* rbtree of cgutils_llist * of generic_cb_data * */
    cgutils_rbtree * pending_transfers;
    /* Filesystem Name */
    char * name;
    /* Filesystem ID */
    uint64_t id;
    /* Root of the cache directory */
    char * cache_dir;
    size_t instances_count;
    /* Cache cleaning settings */
    uint64_t clean_max_access_offset;
    uint64_t clean_min_file_size;
    uint8_t full_threshold;
    /* IO block size */
    uint32_t io_block_size;
    /* Delayed expunge settings */
    uint64_t delayed_expunge;
    unsigned int seed;
    cg_storage_filesystem_type type;
    /* Digest algorithm used to compute inodes digest */
    cgutils_crypto_digest_algorithm digest_algorithm;
    bool auto_expunge;
};

typedef enum
{
#define STATE(name) cg_storage_filesystem_state_ ## name,
#include "cg_storage_filesystem_states.h"
#undef STATE
} cg_storage_filesystem_handler_state;

#include "cg_storage_fs_cb_data.h"

char const * cg_storage_filesystem_state_to_str(cg_storage_filesystem_handler_state state);

int cg_storage_filesystem_monitor_pick_instance_from(cg_storage_filesystem * fs,
                                                     /* list of usable instances (has object, has not failed),
                                                        llist of cgdb_inode_instance * */
                                                     cgutils_llist * usable_instances,
                                                     cgdb_inode_instance ** obj_inst,
                                                     cg_storage_instance ** out);

int cg_storage_filesystem_monitor_pick_instances_to(cg_storage_filesystem * fs,
                                                    /* llist of cg_storage_instance * */
                                                    cgutils_llist ** out);

#endif /* CLOUD_GATEWAY_STORAGE_FILESYSTEM_COMMON_H_ */
