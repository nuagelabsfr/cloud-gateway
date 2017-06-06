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

#ifndef CGFS_UTILS_H_
#define CGFS_UTILS_H_

#include <stdbool.h>

#include <cgfs.h>
#include <cgfs_file_handler.h>
#include <cgfs_inode.h>

int cgfs_utils_open_file(cgfs_inode * inode,
                         char const * path,
                         int * mode,
                         cgfs_file_handler ** out);

void cgfs_utils_update_inode_mtime(cgfs_inode * inode);

bool cgfs_utils_writable_flags(int flags);

bool cgfs_utils_check_flags_validity(int flags);

#endif /* CGFS_UTILS_H_ */
