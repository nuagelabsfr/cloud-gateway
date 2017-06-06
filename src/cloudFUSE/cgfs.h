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
#ifndef CGFS_H_
#define CGFS_H_

#include <stdint.h>

#define CGFS_SET_ATTR_MODE      (1 << 0)
#define CGFS_SET_ATTR_UID       (1 << 1)
#define CGFS_SET_ATTR_GID       (1 << 2)
#define CGFS_SET_ATTR_SIZE      (1 << 3)
#define CGFS_SET_ATTR_ATIME     (1 << 4)
#define CGFS_SET_ATTR_MTIME     (1 << 5)
#define CGFS_SET_ATTR_ATIME_NOW (1 << 7)
#define CGFS_SET_ATTR_MTIME_NOW (1 << 8)

typedef struct cgfs_data cgfs_data;

#include <cgfs_cache.h>
#include <cgsmclient/cgsmc_async.h>
#include <cloudutils/cloudutils_aio.h>
#include <cloudutils/cloudutils_event.h>

struct cgfs_data
{
    cgfs_cache * cache;
    cgsmc_async_data * cgsmc_data;
    cgutils_event_data * event_data;
    cgutils_event * fuse_event;
    cgutils_event * sighup_event;
    cgutils_event * sigint_event;
    cgutils_event * sigterm_event;
    cgutils_aio * aio;
    struct fuse_session * session;
    char * cgsm_configuration_file;
    char * pid_file;
    char * fs_name;
    char * buffer;
    size_t buffer_size;
    uint64_t root_inode_number;
    /* We use segmented LRU:
       - cgfs_inode * active_lru_tail;
       - cgfs_inode * active_lru_head;
       - cgfs_inode * inactive_lru_tail;
       - cgfs_inode * inactive_lru_head;

       Inodes are first added to the inactive lru (tail) BUT ONLY AFTER their lookup count drops down to 0.
       Inactive hits are moved to the active lru (tail).
       If the active list becomes full, inodes from the head are moved back to the inactive list (tail).
       If the inactive list becomes full, inodes from the head are dropped.
    */
};

int cgfs_init(void);
void cgfs_destroy(void);

cgfs_data * cgfs_get_data(void);

void cgfs_data_clean(cgfs_data ** data);
int cgfs_data_load_configuration(cgfs_data * this);

uint64_t cgfs_translate_inode_number(cgfs_data const * data,
                                     uint64_t ino);

#endif /* CGFS_H_ */
