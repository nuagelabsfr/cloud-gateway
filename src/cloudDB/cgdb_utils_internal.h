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

#ifndef CLOUD_GATEWAY_UTILS_INTERNAL_H_
#define CLOUD_GATEWAY_UTILS_INTERNAL_H_

int cgdb_get_inode_instance_from_row(cgdb_row const * row,
                                     cgdb_inode_instance ** out);

int cgdb_get_inode_from_row(cgdb_row const * row,
                            cgdb_inode ** out);

int cgdb_get_entry_from_row(cgdb_row const * row,
                            cgdb_entry ** out);

int cgdb_get_delayed_expunge_entry_from_row(cgdb_row const * row,
                                            cgdb_delayed_expunge_entry ** out);

#endif /* CLOUD_GATEWAY_UTILS_INTERNAL_H_ */
