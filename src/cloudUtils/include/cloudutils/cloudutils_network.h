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

#ifndef CLOUD_UTILS_NETWORK_H_
#define CLOUD_UTILS_NETWORK_H_

#include <stdbool.h>
#include <netdb.h>

#include <cloudutils/cloudutils_compiler_specifics.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_network_validate_addr(char const * address);
int cgutils_network_get_addr_family(char const * address,
                                    int * family);

int cgutils_network_get_addr_storage(char const * address,
                                     char const * port,
                                     char const * protocol,
                                     struct addrinfo ** storage);

int cgutils_network_get_addr_storage_listen(char const * address,
                                            char const * port,
                                            char const * protocol,
                                            struct addrinfo ** storage);

int cgutils_network_get_addrinfo_from_unix_path(char const * unix_path,
                                                struct addrinfo ** binding);

int cgutils_network_connect_to_socket(struct addrinfo * remote,
                                      bool non_blocking,
                                      int * sock);

int cgutils_network_listen_on_socket(struct addrinfo * binding,
                                     int defer_accept_timeout,
                                     int backlog,
                                     bool nonblocking,
                                     int * sock);

int cgutils_network_prepare_socket_for_listening(struct addrinfo * binding,
                                                 bool nonblocking,
                                                 int * sock);

int cgutils_network_listen_on_prepared_socket(int sock,
                                              struct addrinfo * binding,
                                              int defer_accept_timeout,
                                              int backlog);

int cgutils_network_set_deferred_accept(int socket_fd,
                                        int timeout);

int cgutils_network_set_reuse_addr(int socket_fd,
                                   int reuse);

int cgutils_network_accept(int fd,
                           int * new_fd);

int cgutils_network_send_data(int sock,
                              bool non_blocking,
                              void const * data,
                              size_t data_size,
                              size_t * sent);

int cgutils_network_read_data(int sock,
                              bool non_blocking,
                              void * buffer,
                              size_t buffer_size,
                              size_t * got);

int cgutils_network_check_socket_usability(int sock,
                                           bool * usable);

int cgutils_network_socket_has_data(int sock,
                                    bool * data_available);

int cgutils_network_socket_peek_at_data(int sock,
                                        char ** buffer_out,
                                        size_t * buffer_out_size);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_NETWORK_H_ */
