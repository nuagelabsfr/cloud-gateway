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
#ifndef CGFS_CACHE_H_
#define CGFS_CACHE_H_

#include <stdint.h>

typedef struct cgfs_cache cgfs_cache;

#include <cgfs_inode.h>

int cgfs_cache_init(cgfs_cache ** out);
void cgfs_cache_free(cgfs_cache * this);

int cgfs_cache_lookup_child(cgfs_cache * this,
                            uint64_t parent_ino,
                            char const * name,
                            cgfs_inode ** out);

int cgfs_cache_remove(cgfs_cache * this,
                      uint64_t ino);

int cgfs_cache_lookup(cgfs_cache * this,
                      uint64_t ino,
                      cgfs_inode ** out);

int cgfs_cache_add(cgfs_cache * this,
                   cgfs_inode * inode);

#endif /* CGFS_CACHE_H_ */
