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
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "cloudutils/cloudutils.h"
#include "cloudutils/cloudutils_file.h"
#include "cloudutils/cloudutils_network.h"

static int cgutils_network_get_protocol_type_from_name(char const * const protocol,
                                                       int * const type)
{
    static struct
    {
        char const * const name;
        int const type;
    } const protocols[] =
          {
              { "UDP", SOCK_DGRAM },
              { "TCP", SOCK_STREAM },
          };
    static size_t const protocols_count = sizeof protocols / sizeof *protocols;

    int result = ENOENT;
    assert(protocol != NULL);
    assert(type != NULL);

    for (size_t idx = 0;
         idx < protocols_count &&
             result == ENOENT;
         idx++)
    {
        if (strcasecmp(protocol, protocols[idx].name) == 0)
        {
            result = 0;
            *type = protocols[idx].type;
        }
    }

    return result;
}

int cgutils_network_get_addr_family(char const * address,
                                    int * const family)
{
    int result = EINVAL;

    if (address != NULL &&
        family != NULL)
    {
        struct addrinfo * storage = NULL;
        struct addrinfo hints =
            {
                .ai_family = AF_UNSPEC,
                .ai_flags = AI_NUMERICHOST,
                .ai_socktype = 0,
            };

        result = getaddrinfo(address, 0, &hints, &storage);

        if (result == 0)
        {
            *family = storage->ai_family;
            freeaddrinfo(storage), storage = NULL;
        }
        else
        {
            result = EINVAL;
        }
    }

    return result;
}

int cgutils_network_validate_addr(char const * const address)
{
    int result = EINVAL;

    if (address != NULL)
    {
        int family = AF_UNSPEC;

        result = cgutils_network_get_addr_family(address,
                                                 &family);
    }

    return result;
}

int cgutils_network_get_addr_storage(char const * const address,
                                     char const * const port,
                                     char const * const protocol,
                                     struct addrinfo ** const storage)
{
    int result = EINVAL;

    if (address != NULL && port != NULL && protocol != NULL && storage != NULL)
    {
        int socktype = -1;

        result = cgutils_network_get_protocol_type_from_name(protocol,
                                                             &socktype);

        if (result == 0)
        {
            struct addrinfo hints =
                {
                    .ai_family = AF_UNSPEC,
                    .ai_flags = AI_NUMERICHOST,
                    .ai_socktype = socktype
                };

            result = getaddrinfo(address, port, &hints, storage);

            if (result != 0)
            {
                result = EINVAL;
            }
        }
    }

    return result;
}

int cgutils_network_get_addr_storage_listen(char const * const address,
                                            char const * const port,
                                            char const * const protocol,
                                            struct addrinfo ** const storage)
{
    int result = EINVAL;

    if (port != NULL && protocol != NULL && storage != NULL)
    {
        int socktype = -1;

        result = cgutils_network_get_protocol_type_from_name(protocol,
                                                             &socktype);

        if (result == 0)
        {
            struct addrinfo hints =
                {
                    .ai_family = AF_UNSPEC,
                    .ai_flags = AI_PASSIVE | AI_NUMERICHOST,
                    .ai_socktype = socktype
                };

            result = getaddrinfo(address, port, &hints, storage);

            if (result != 0)
            {
                result = EINVAL;
            }
        }
    }

    return result;
}

int cgutils_network_get_addrinfo_from_unix_path(char const * const unix_path,
                                                struct addrinfo ** const binding)
{
    int result = EINVAL;

    if (unix_path != NULL && binding != NULL)
    {
        size_t const socklen = sizeof (struct sockaddr_un);
        result = 0;

        CGUTILS_MALLOC(*binding, 1, sizeof **binding + socklen);

        if (*binding != NULL)
        {
            (**binding) = (struct addrinfo) { 0 };

            (*binding)->ai_family = AF_LOCAL;
            (*binding)->ai_socktype = SOCK_STREAM;

            (*binding)->ai_addr = (void*) (*binding + 1);

            struct sockaddr_un * sa_un = (struct sockaddr_un *) (*binding)->ai_addr;
            sa_un->sun_family = AF_UNIX;
            (*binding)->ai_addr->sa_family = AF_UNIX;
            strncpy(sa_un->sun_path, unix_path, sizeof(sa_un->sun_path) - 1);
            sa_un->sun_path[sizeof(sa_un->sun_path)-1] = '\0';
            (*binding)->ai_addrlen = (socklen_t) socklen;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_network_connect_to_socket(struct addrinfo * const remote,
                                      bool const non_blocking,
                                      int * const sock)
{
    int result = EINVAL;

    if (remote != NULL && sock != NULL)
    {
        *sock = socket(remote->ai_family, remote->ai_socktype, 0);

        if (*sock >= 0)
        {
            result = cgutils_file_set_closeonexec(*sock);

            if (result == 0)
            {
                if (non_blocking == true)
                {
                    result = cgutils_file_set_non_block(*sock);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Unable to set socket to non blocking mode: %d", result);
                    }
                }

                if (result == 0)
                {
                    result = connect(*sock, remote->ai_addr, remote->ai_addrlen);

                    if (result != 0)
                    {
                        result = errno;

                        if (result != EINPROGRESS)
                        {
                            CGUTILS_ERROR("Error connecting socket: %d", result);
                            cgutils_file_close(*sock), *sock = -1;
                        }
                        else
                        {
                            result = 0;
                        }
                    }
                }
            }
            else
            {
                CGUTILS_ERROR("Error setting socket to non-blocking: %d", result);
            }
        }
        else
        {
            result = errno;
            CGUTILS_ERROR("Error creating socket: %d", result);
        }
    }

    return result;
}

int cgutils_network_prepare_socket_for_listening(struct addrinfo * const binding,
                                                 bool const nonblocking,
                                                 int * const sock)
{
    int result = EINVAL;

    if (binding != NULL && sock != NULL)
    {
        *sock = socket(binding->ai_family, binding->ai_socktype, 0);

        if (*sock != -1)
        {
            result = cgutils_file_set_closeonexec(*sock);

            if (result == 0)
            {
                if (nonblocking == true)
                {
                    result = cgutils_file_set_non_block(*sock);
                }

                if (result == 0)
                {
                    result = cgutils_network_set_reuse_addr(*sock, 1);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Unable to set reuse_addr flag: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Unable to set non block flag: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Unable to set close on exec flag: %d", result);
            }

            if (result != 0)
            {
                cgutils_file_close(*sock), *sock = -1;
            }
        }
        else
        {
            result = errno;
            CGUTILS_ERROR("Error while creating socket: %d", result);
        }
    }

    return result;
}

int cgutils_network_listen_on_prepared_socket(int const sock,
                                              struct addrinfo * const binding,
                                              int const defer_accept_timeout,
                                              int const backlog)
{
    int result = EINVAL;

    if (binding != NULL &&
        sock != -1)
    {
        result = bind(sock, binding->ai_addr, binding->ai_addrlen);

        if (result == 0)
        {
            if (binding->ai_socktype == SOCK_STREAM)
            {
                /* SOMAXCONN is a dynamic value on Linux since Linux 2.4.25,
                   and value greater than SOMAXCONN are silently truncated
                   to that value so we do not want to hardcode it.
                */
                result = listen(sock, backlog);

                if (result == 0)
                {
                    if (defer_accept_timeout != 0)
                    {
                        result = cgutils_network_set_deferred_accept(sock, defer_accept_timeout);

                        if (result != 0)
                        {
                            CGUTILS_ERROR("Unable to set deferred accept option on socket: %d", result);
                        }
                    }
                }
                else
                {
                    result = errno;
                    CGUTILS_ERROR("Unable to listen on socket: %d", result);
                }
            }
        }
        else
        {
            result = errno;
            CGUTILS_ERROR("Unable to bind: %d", result);
        }
    }

    return result;
}

int cgutils_network_listen_on_socket(struct addrinfo * const binding,
                                     int const defer_accept_timeout,
                                     int const backlog,
                                     bool const nonblocking,
                                     int * const sock)
{
    int result = EINVAL;

    if (binding != NULL && sock != NULL)
    {
        result = cgutils_network_prepare_socket_for_listening(binding,
                                                              nonblocking,
                                                              sock);

        if (result == 0)
        {
            result = cgutils_network_listen_on_prepared_socket(*sock,
                                                               binding,
                                                               defer_accept_timeout,
                                                               backlog);
        }
    }

    return result;
}

int cgutils_network_set_deferred_accept(int const socket_fd,
                                        int const timeout)
{
    int result = setsockopt(socket_fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, sizeof timeout);

    if (result == -1)
    {
        result = errno;
    }

    return result;
}

int cgutils_network_set_reuse_addr(int const socket_fd,
                                   int const reuse)
{
    int result = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);

    if (result == -1)
    {
        result = errno;
    }

    return result;
}

int cgutils_network_accept(int const fd,
                           int * const new_fd)
{
    int result = EINVAL;

    if (fd >= 0 && new_fd != NULL)
    {
        *new_fd = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);

        if (*new_fd >= 0)
        {
            result = 0;
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_network_send_data(int const sock,
                              bool const non_blocking,
                              void const * data,
                              size_t data_size,
                              size_t * const sent)
{
    int result = EINVAL;

    if (sock >= 0 && data != NULL && sent != NULL && data_size > 0)
    {
        *sent = 0;

        do
        {
            result = 0;
            ssize_t res = write(sock, data, data_size);

            if (res < 0)
            {
                result = errno;
            }
            else
            {
                if (SIZE_MAX - (size_t) res > *sent)
                {
                    *sent += (size_t) res;
                    data = ((char *) data) + res;
                    data_size -= (size_t) res;
                }
                else
                {
                    result = EFBIG;
                }
            }
        }
        while(data_size > 0 &&
              (result == 0 ||
               result == EINTR ||
               (non_blocking &&
                (result == EWOULDBLOCK ||
                 result == EAGAIN))));
    }

    return result;
}

int cgutils_network_read_data(int const sock,
                              bool const non_blocking,
                              void * buffer,
                              size_t buffer_size,
                              size_t * const got)
{
    int result = EINVAL;

    if (sock >= 0 && buffer != NULL && buffer_size > 0 && got != NULL)
    {
        *got = 0;
        bool eof = false;

        do
        {
            result = 0;

            ssize_t res = read(sock, buffer, buffer_size);

            if (res < 0)
            {
                result = errno;
            }
            else if (res > 0)
            {
                if (SIZE_MAX - (size_t) res > *got)
                {
                    *got += (size_t) res;
                    buffer = ((char *) buffer) + res;
                    buffer_size -= (size_t) res;
                }
                else
                {
                    result = EFBIG;
                }
            }
            else
            {
                eof = true;
            }
        }
        while(eof == false &&
              (buffer_size > 0) &&
              (result == 0 ||
               result == EINTR ||
               (non_blocking &&
                (result == EWOULDBLOCK ||
                 result == EAGAIN))));

    }

    return result;
}

int cgutils_network_check_socket_usability(int const sock,
                                           bool * const usable)
{
    int result = 0;

    if (COMPILER_LIKELY(sock >= 0 &&
                        usable != NULL))
    {
        char buf[1] = "\0";
        size_t const buf_size = sizeof buf;

        /* We try to read some bytes from the socket,
           setting :
           - MSG_PEEK so data is still available to the next reader
           - MSG_DONTWAIT so we don't block if no data is available
        */
        do
        {
            ssize_t got = recv(sock, buf, buf_size, MSG_PEEK|MSG_DONTWAIT);

            if (got > 0)
            {
                /* socket is usable, data is waiting */
                *usable = true;
            }
            else if (got == 0)
            {
                /* socket is closed */
                *usable = false;
            }
            else
            {
                result = errno;

                if (COMPILER_LIKELY(result == EAGAIN ||
                                    result == EWOULDBLOCK))
                {
                    /* socket is usable, no data waiting */
                    *usable = true;
                    result = 0;
                }
                else
                {
                    /* any other case except EINTR (handled below)
                       means that the socket is not usable */
                    *usable = false;

                    if (result == ECONNRESET ||
                        result == EPIPE)
                    {
                        /* connection closed */
                        result = 0;
                    }
                }
            }

        }
        while (result == EINTR);
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgutils_network_socket_has_data(int const sock,
                                    bool * const data_available)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(sock >= 0 &&
                        data_available != NULL))
    {
        char buf[1] = "\0";
        size_t const buf_size = sizeof buf;

        result = 0;
        /* We try to read some bytes from the socket,
           setting :
           - MSG_PEEK so data is still available to the next reader
           - MSG_DONTWAIT so we don't block if no data is available
        */
        do
        {
            ssize_t got = recv(sock, buf, buf_size, MSG_PEEK|MSG_DONTWAIT);

            if (got > 0)
            {
                /* socket is usable, data is waiting */
                *data_available = true;
            }
            else if (got == 0)
            {
                /* socket is closed */
                *data_available = false;
            }
            else
            {
                result = errno;

                if (result == EAGAIN || result == EWOULDBLOCK)
                {
                    /* socket is usable, no data waiting */
                    *data_available = false;
                    result = 0;
                }
                else
                {
                    /* any other case except EINTR (handled below)
                       means that the sock  is not usable */
                    *data_available = false;
                }
            }

        }
        while (result == EINTR);
    }

    return result;
}

int cgutils_network_socket_peek_at_data(int const sock,
                                        char ** const buffer_out,
                                        size_t * const buffer_out_size)
{
    int result = EINVAL;

    if (sock >= 0 &&
        buffer_out != NULL &&
        buffer_out_size != NULL)
    {
        char buf[1] = "\0";
        size_t const buf_size = sizeof buf;

        result = 0;
        /* We try to read some bytes from the socket,
           setting :
           - MSG_PEEK so data is still available to the next reader
           - MSG_DONTWAIT so we don't block if no data is available
        */
        do
        {
            ssize_t got = recv(sock, buf, buf_size, MSG_PEEK|MSG_DONTWAIT);

            if (got > 0)
            {
                *buffer_out_size = (size_t) got;

                CGUTILS_MALLOC(*buffer_out, *buffer_out_size, 1);

                if (*buffer_out != NULL)
                {
                    got = recv(sock, *buffer_out, *buffer_out_size, MSG_PEEK|MSG_DONTWAIT);

                    if (got > 0)
                    {
                        *buffer_out_size = (size_t) got;
                    }
                    else if (got == 0)
                    {
                        /* should not happen, but anyway */
                        result = ECONNRESET;
                    }
                    else
                    {
                        result = errno;
                    }

                    if (result != 0)
                    {
                        CGUTILS_FREE(*buffer_out);
                        *buffer_out_size = 0;
                    }
                }
                else
                {
                    result = ENOMEM;
                    *buffer_out_size = 0;
                }
            }
            else if (got == 0)
            {
                /* socket is closed */
                result = ECONNRESET;
            }
            else
            {
                result = errno;
            }
        }
        while (result == EINTR);
    }

    return result;
}
