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
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <arpa/inet.h>
#include <grp.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

/* See http://sourceforge.net/p/predef/wiki/OperatingSystems/ */
#ifdef __linux__
/* Routing sockets */
#include <netlink/addr.h>
#include <netlink/cache.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/link/vlan.h>
#include <netlink/route/route.h>
#include <netlink/socket.h>

#define CLOUDUTILS_SYSTEM_NETWORK_DEFAULT_ROUTING_TABLE (RT_TABLE_MAIN)
#endif /* __linux__ */

#include <sys/sysinfo.h>

#include <cloudutils/cloudutils_system.h>

#include <cloudutils/cloudutils_file.h>

#define MAC_ADDRESS_SIZE 18

struct cgutils_system_network_interface
{
    char * name;
    char * mac;
    unsigned int flags;
    unsigned int operstate;
};

struct cgutils_system_network_address
{
    char * interface;
    char * addr;
    char * mask;
    int family;
};

struct cgutils_system_uname_info
{
    struct utsname info;
};

#ifdef __linux__

static int cgutils_system_network_interface_init(char const * const if_name,
                                                 char * if_addr,
                                                 unsigned int const flags,
                                                 unsigned int const operstate,
                                                 cgutils_system_network_interface ** const itf)
{
    int result = ENOMEM;
    assert(if_name != NULL);
    assert(itf != NULL);


    CGUTILS_ALLOCATE_STRUCT(*itf);

    if (*itf != NULL)
    {
        cgutils_system_network_interface * this = *itf;

        this->name = cgutils_strdup(if_name);

        if (this->name != NULL)
        {
            this->mac = if_addr;

            result = 0;
            this->flags = flags;
            this->operstate = operstate;
        }

        if (result != 0)
        {
            cgutils_system_network_interface_free(*itf), *itf = NULL;
        }
    }
    else
    {
        result = ENOMEM;
    }


    return result;
}

static int cgutils_system_network_link_get_mac(struct rtnl_link * const nl_link,
                                               char ** const mac)
{
    int result = 0;
    CGUTILS_ASSERT(nl_link != NULL);
    CGUTILS_ASSERT(mac != NULL);

    struct nl_addr * addr = rtnl_link_get_addr(nl_link);

    if (addr != NULL)
    {
        char buffer[MAC_ADDRESS_SIZE + 1];
        size_t const buffer_size = sizeof buffer;

        nl_addr2str(addr,
                    buffer,
                    buffer_size);

        buffer[buffer_size - 1] = '\0';

        *mac = cgutils_strdup(buffer);

        if (*mac == NULL)
        {
            result = ENOMEM;
        }
    }
    else
    {
        result = ENOENT;
    }

    return result;
}

static int cgutils_system_network_add_if(cgutils_vector * const interfaces,
                                         struct rtnl_link * const nl_link)
{
    int result = 0;
    CGUTILS_ASSERT(interfaces != NULL);
    CGUTILS_ASSERT(nl_link != NULL);
    unsigned int const if_flags = rtnl_link_get_flags(nl_link);
    unsigned int const if_operstate = rtnl_link_get_operstate(nl_link);
    char const * const if_name = rtnl_link_get_name(nl_link);

    if (if_name != NULL)
    {
        char * if_addr = NULL;

        result = cgutils_system_network_link_get_mac(nl_link,
                                                     &if_addr);

        if (result == ENOENT)
        {
            result = 0;
        }

        if (result == 0)
        {
            cgutils_system_network_interface * itf = NULL;

            result = cgutils_system_network_interface_init(if_name,
                                                           if_addr,
                                                           if_flags,
                                                           if_operstate,
                                                           &itf);

            if (result == 0)
            {
                result = cgutils_vector_add(interfaces,
                                            itf);

                if (result != 0)
                {
                    CGUTILS_ERROR("Error adding interface to vector: %d", result);
                    cgutils_system_network_interface_free(itf), itf = NULL;
                }
            }
            else
            {
                CGUTILS_ERROR("Error in interface init: %d", result);
                CGUTILS_FREE(if_addr);
            }
        }
        else
        {
            CGUTILS_ERROR("Error getting MAC for link %s: %d",
                          if_name,
                          result);
        }
    }
    else
    {
        CGUTILS_WARN("Skipping interface with no name!");
    }

    return result;
}

int cgutils_system_network_get_all_interfaces(cgutils_vector ** const interfaces_out)
{
    int result = EINVAL;

    if (interfaces_out != NULL)
    {
        struct nl_sock * nl_socket = nl_socket_alloc();

        if (nl_socket != NULL)
        {
            result = nl_connect(nl_socket, NETLINK_ROUTE);

            if (result == 0)
            {
                struct nl_cache * cache = NULL;

                result = rtnl_link_alloc_cache(nl_socket,
                                               AF_UNSPEC,
                                               &cache);

                if (result == 0)
                {
                    int const count_int = nl_cache_nitems(cache);

                    if (count_int > 0)
                    {
                        result = cgutils_vector_init((size_t) count_int,
                                                     interfaces_out);

                        if (result == 0)
                        {
                            struct rtnl_link * nl_link = (struct rtnl_link *) nl_cache_get_first(cache);

                            while(nl_link != NULL &&
                                  result == 0)
                            {
                                result = cgutils_system_network_add_if(*interfaces_out,
                                                                       nl_link);

                                nl_link = (struct rtnl_link *) nl_cache_get_next((struct nl_object *) nl_link);
                            }

                            if (result != 0)
                            {
                                cgutils_vector_deep_free(interfaces_out,
                                                         &cgutils_system_network_interface_delete);
                            }

                        }
                        else
                        {
                            CGUTILS_ERROR("Error creating interfaces vector: %d", result);
                        }
                    }
                    else
                    {
                        result = ENOENT;
                    }

                    nl_cache_free(cache), cache = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error getting netlink cache: %d", -result);
                }

                nl_close(nl_socket);
            }
            else
            {
                CGUTILS_ERROR("Error connecting netlink socket: %d", -result);
            }

            nl_socket_free(nl_socket), nl_socket = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error getting netlink socket");
        }
    }

    return result;
}

#if 0
/* Whoops, SIOCGIFCONF doesn't report IPv6 addr on Linux */

static int cgutils_system_network_get_socket(int * const sockout)
{
    int result = 0;
    assert(sockout != NULL);

    *sockout = socket(AF_INET, SOCK_DGRAM, 0);

    if (*sockout < 0)
    {
        result = errno;
    }

    return result;
}

static int cgutils_system_network_get_if_conf(int const sock,
                                              struct ifconf * const if_conf)
{
    int result = 0;
    char * buf = NULL;
    size_t buflen = 0;
    size_t lastlen = 0;
    bool success = false;
    assert(if_conf != NULL);
    assert(sock >= 0);

    *if_conf = (struct ifconf) { 0 };

    /* We cannot know how much interfaces are present, so
       we have to try with an arbitrary size.
       We check how much was used, and we retry with a
       slighty bigger one. If the used size is the same, we
       are fine. Otherwise we grow and try again.
       See Unix Network Programming, R. Stevens,
       section 17.6.
    */
    buflen = 10 * sizeof (struct ifreq);

    while (result == 0 &&
           success == false &&
           buflen < INT_MAX)
    {
        CGUTILS_MALLOC(buf, 1, buflen);

        if (buf != NULL)
        {
            if_conf->ifc_buf = buf;
            if_conf->ifc_len = (int) buflen;

            result = ioctl(sock, SIOCGIFCONF, if_conf);

            if (result == -1)
            {
                result = errno;

                if (result == EINVAL && lastlen == 0)
                {
                    result = 0;
                }
                else
                {
                    CGUTILS_ERROR("Error in ioctl: %d", result);
                }
            }
            else
            {
                result = 0;

                if (if_conf->ifc_len >= 0)
                {
                    result = 0;

                    if ((size_t) if_conf->ifc_len == lastlen)
                    {
                        success = true;
                    }
                    else
                    {
                        lastlen = (size_t) if_conf->ifc_len;
                    }
                }
                else
                {
                    result = EINVAL;
                    CGUTILS_ERROR("Invalid len after ioctl: %d", result);
                }
            }

            if (success == false)
            {
                CGUTILS_FREE(buf);
                if_conf->ifc_buf = NULL;
            }
        }
        else
        {
            result = ENOMEM;
            CGUTILS_ERROR("Error allocating %zu bytes for if config: %d", buflen, result);
        }
    }

    return result;
}

int cgutils_system_network_get_all_interfaces(cgutils_llist ** const interfaces_out)
{
    int result = EINVAL;

    if (interfaces_out != NULL)
    {
        int sock = -1;

        result = cgutils_system_network_get_socket(&sock);

        if (result == 0)
        {
            struct ifconf if_conf = (struct ifconf) { 0 };

            result = cgutils_system_network_get_if_conf(sock,
                                                        &if_conf);

            if (result == 0)
            {
                size_t const if_conf_len = if_conf.ifc_len;

                for (size_t pos = 0;
                     result == 0 && pos < if_conf_len;
                    )
                {
                    struct ifreq const * const if_req = if_conf.buf + pos;
                    size_t const next_pos = sizeof (if_req->ifr_name) +
                        ( sizeof (struct sockaddr) > if_req->ifr_addr.sa_len ?
                          sizeof (struct sockaddr) : if_req->ifr_addr.sa_len);


                    pos += next_pos;

                }

                CGUTILS_FREE(if_conf.if_buf);
            }
            else
            {
                CGUTILS_ERROR("Error getting if config: %d", result);
            }

            close(sock), sock = -1;
        }
        else
        {
            CGUTILS_ERROR("Error getting socket:  %d", result);
        }
    }

    return result;
}

#endif /* 0 */
#endif /* __linux__ */

static int cgutils_system_network_address_init(int const family,
                                               char const * const if_name,
                                               char const * const if_addr,
                                               char const * const if_mask,
                                               cgutils_system_network_address ** const out)
{
    int result = ENOMEM;
    assert(if_name != NULL);
    assert(if_addr != NULL);
    assert(if_mask != NULL);
    assert(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(*out);

    if (*out != NULL)
    {
        cgutils_system_network_address * this = *out;

        this->interface = cgutils_strdup(if_name);

        if (this->interface != NULL)
        {
            this->addr = cgutils_strdup(if_addr);

            if (this->addr != NULL)
            {
                this->mask = cgutils_strdup(if_mask);

                if (this->mask != NULL)
                {
                    this->family = family;

                    result = 0;
                }
            }
        }

        if (result != 0)
        {
            cgutils_system_network_address_free(*out), *out = NULL;
        }
    }
    else
    {
        result = ENOMEM;
    }


    return result;
}

static int cgutils_system_network_add_addr(cgutils_llist * const addresses,
                                           int const family,
                                           char const * const if_name,
                                           char const * const if_addr,
                                           char const * const if_mask)
{
    int result = 0;
    cgutils_system_network_address * addr = NULL;
    assert(addresses != NULL);
    assert(if_name != NULL);
    assert(if_addr != NULL);
    assert(if_mask != NULL);

    result = cgutils_system_network_address_init(family,
                                                 if_name,
                                                 if_addr,
                                                 if_mask,
                                                 &addr);

    if (result == 0)
    {
        result = cgutils_llist_insert(addresses, addr);

        if (result != 0)
        {
            CGUTILS_ERROR("Error adding address to list: %d", result);
            cgutils_system_network_address_free(addr), addr = NULL;
        }
    }
    else
    {
        CGUTILS_ERROR("Error in address init: %d", result);
    }

    return result;
}

int cgutils_system_network_get_all_addresses(cgutils_llist ** const addrs_out)
{
    int result = EINVAL;

    if (addrs_out != NULL)
    {
        struct ifaddrs * addrs = NULL;

        result = getifaddrs(&addrs);

        if (result == 0)
        {
            result = cgutils_llist_create(addrs_out);

            if (result == 0)
            {
                for (struct ifaddrs * current = addrs;
                     result == 0 && current != NULL;
                     current = current->ifa_next)
                {
                    if (current->ifa_addr != NULL)
                    {
                        int const family = current->ifa_addr->sa_family;

                        if (family == AF_INET ||
                            family == AF_INET6)
                        {
                            char addr[NI_MAXHOST];

                            result = getnameinfo(current->ifa_addr,
                                                 (family == AF_INET ?
                                                  sizeof (struct sockaddr_in) :
                                                  sizeof (struct sockaddr_in6)),
                                                 addr,
                                                 sizeof addr,
                                                 NULL,
                                                 0,
                                                 NI_NUMERICHOST);
                            if (result == 0)
                            {
                                char mask[NI_MAXHOST];

                                result = getnameinfo(current->ifa_netmask,
                                                     (family == AF_INET ?
                                                      sizeof (struct sockaddr_in) :
                                                      sizeof (struct sockaddr_in6)),
                                                     mask,
                                                     sizeof mask,
                                                     NULL,
                                                     0,
                                                     NI_NUMERICHOST);
                                if (result == 0)
                                {
                                    result = cgutils_system_network_add_addr(*addrs_out,
                                                                             family,
                                                                             current->ifa_name,
                                                                             addr,
                                                                             mask);

                                    if (result != 0)
                                    {
                                        CGUTILS_ERROR("Error adding addr to list: %d", result);
                                    }
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error in getnameinfo: %s(%d)",
                                                  gai_strerror(result), result);
                                }
                            }
                            else
                            {
                                CGUTILS_ERROR("Error in getnameinfo: %s(%d)",
                                              gai_strerror(result), result);
                            }
                        }
                    }
                }

                if (result != 0)
                {
                    cgutils_llist_free(addrs_out, &cgutils_system_network_address_delete);
                }
            }
            else
            {
                CGUTILS_ERROR("Error creating addresses list: %d", result);
            }

            freeifaddrs(addrs);
        }
        else
        {
            CGUTILS_ERROR("Error getting interface addresses: %d", result);
        }
    }

    return result;
}

char const * cgutils_system_network_interface_get_name(cgutils_system_network_interface const * const this)
{
    char const * result = NULL;

    if (this != NULL)
    {
        result = this->name;
    }

    return result;
}

char const * cgutils_system_network_interface_get_mac(cgutils_system_network_interface const * const this)
{
    char const * result = NULL;

    if (this != NULL)
    {
        result = this->mac;
    }

    return result;
}

bool cgutils_system_network_interface_is_up(cgutils_system_network_interface const * const this)
{
    bool result = false;

    if (this != NULL)
    {
        result = this->flags & IFF_UP;
    }

    return result;
}

bool cgutils_system_network_interface_is_lower_up(cgutils_system_network_interface const * const this)
{
    bool result = false;

    if (this != NULL)
    {
        result = this->flags & IFF_LOWER_UP;
    }

    return result;
}

bool cgutils_system_network_interface_is_running(cgutils_system_network_interface const * const this)
{
    bool result = false;

    if (this != NULL)
    {
        /* RFC2863 OPER_UP */
        result = this->flags & IFF_RUNNING;
    }

    return result;
}

char const * cgutils_system_network_interface_get_oper_state_str(cgutils_system_network_interface const * const this)
{
    char const * result = NULL;

    if (this != NULL)
    {
        static char const * const states[] =
            {
                "Unknown",
                "Not-present",
                "Down",
                "Lower-layer-down",
                "Testing",
                "Dormant",
                "Up"
            };
        static size_t const states_count = sizeof states / sizeof *states;

        if (this->operstate < states_count)
        {
            result = states[this->operstate];
        }
    }

    return result;
}

bool cgutils_system_network_interface_is_oper_unknown(cgutils_system_network_interface const * const this)
{
    bool result = false;

    if (this != NULL)
    {
        result = this->operstate == IF_OPER_UNKNOWN;
    }

    return result;
}

bool cgutils_system_network_interface_is_oper_up(cgutils_system_network_interface const * const this)
{
    bool result = false;

    if (this != NULL)
    {
        result = this->operstate == IF_OPER_UP;
    }

    return result;
}

bool cgutils_system_network_interface_is_loopback(cgutils_system_network_interface const * const this)
{
    bool result = false;

    if (this != NULL)
    {
        result = this->flags & IFF_LOOPBACK;
    }

    return result;
}

void cgutils_system_network_interface_free(cgutils_system_network_interface * this)
{
    if (this != NULL)
    {
        if (this->name != NULL)
        {
            CGUTILS_FREE(this->name);
        }

        if (this->mac != NULL)
        {
            CGUTILS_FREE(this->mac);
        }

        CGUTILS_FREE(this);
    }
}

char const * cgutils_system_network_address_get_interface_name(cgutils_system_network_address const * const this)
{
    char const * result = NULL;

    if (this != NULL)
    {
        result = this->interface;
    }

    return result;
}

char const * cgutils_system_network_address_get_addr(cgutils_system_network_address const * const this)
{
    char const * result = NULL;

    if (this != NULL)
    {
        result = this->addr;
    }

    return result;
}

char const * cgutils_system_network_address_get_mask(cgutils_system_network_address const * const this)
{
    char const * result = NULL;

    if (this != NULL)
    {
        result = this->mask;
    }

    return result;
}

int cgutils_system_network_address_get_family(cgutils_system_network_address const * const this)
{
    int result = 0;

    if (this != NULL)
    {
        result = this->family;
    }

    return result;
}

void cgutils_system_network_address_free(cgutils_system_network_address * this)
{
    if (this != NULL)
    {
        if (this->interface != NULL)
        {
            CGUTILS_FREE(this->interface);
        }

        if (this->addr != NULL)
        {
            CGUTILS_FREE(this->addr);
        }

        if (this->mask != NULL)
        {
            CGUTILS_FREE(this->mask);
        }

        this->family = false;

        CGUTILS_FREE(this);
    }
}

int cgutils_system_get_uname_info(cgutils_system_uname_info ** const out)
{
    int result = EINVAL;

    if (out != NULL)
    {
        struct utsname info = (struct utsname) { 0 };

        result = uname(&info);

        if (result == 0)
        {
            CGUTILS_ALLOCATE_STRUCT(*out);

            if (*out != NULL)
            {
                (*out)->info = info;
            }
            else
            {
                result = ENOMEM;
            }
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

#define CGUTILS_SYSTEM_UNAME_GET(name)                                  \
char const * cgutils_system_uname_get_ ## name(cgutils_system_uname_info const * const this) \
{                                                                       \
    char const * result = NULL;                                         \
                                                                        \
    if (this != NULL)                                                   \
    {                                                                   \
        result = this->info.name;                                       \
    }                                                                   \
                                                                        \
    return result;                                                      \
}
CGUTILS_SYSTEM_UNAME_GET(sysname)
CGUTILS_SYSTEM_UNAME_GET(nodename)
CGUTILS_SYSTEM_UNAME_GET(release)
CGUTILS_SYSTEM_UNAME_GET(version)
CGUTILS_SYSTEM_UNAME_GET(machine)
#undef CGUTILS_SYSTEM_UNAME_GET

void cgutils_system_uname_info_free(cgutils_system_uname_info * this)
{
    if (this != NULL)
    {
        CGUTILS_FREE(this);
    }
}

int cgutils_system_get_cpuinfo(char ** const procinfo,
                               size_t * const len)
{
    int result = EINVAL;

    if (procinfo != NULL && len != NULL)
    {
        result = cgutils_file_get_proc_content_sync("/proc/cpuinfo",
                                                    procinfo,
                                                    len);
    }

    return result;
}

int cgutils_system_get_meminfo(char ** const meminfo,
                               size_t * const len)
{
    int result = EINVAL;

    if (meminfo != NULL && len != NULL)
    {
        result = cgutils_file_get_proc_content_sync("/proc/meminfo",
                                                    meminfo,
                                                    len);
    }

    return result;
}

int cgutils_system_get_page_size(uint32_t * const out)
{
    int result = EINVAL;

    if (out != NULL)
    {
        long page_size = sysconf(_SC_PAGESIZE);

        if (page_size > 0)
        {
            if (page_size < UINT32_MAX)
            {
                result = 0;
                *out = (uint32_t) page_size;
            }
            else
            {
                result = E2BIG;
                *out = 0;
            }
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_system_setproctitle(char * const argv0,
                                char const * const new_title)
{
    int result = EINVAL;

    if (argv0 != NULL && new_title != NULL)
    {
        size_t const avail = strlen(argv0);
        strncpy(argv0, new_title, avail);
        argv0[avail] = '\0';
        result = 0;
    }

    return result;
}

int cgutils_system_get_mode_as_str(mode_t const mode,
                                   char ** const out,
                                   size_t * const out_size)
{
    int result = EINVAL;

    if (out != NULL &&
        out_size != NULL)
    {
        char str[] = "----------";
        size_t const str_size = sizeof str;

        CGUTILS_MALLOC(*out, str_size, 1);

        if (*out != NULL)
        {
            size_t idx = 0;

#define RIGHT(right, code)                      \
            if (mode & (right))                 \
            {                                   \
                str[idx] = (code);              \
            }                                   \
            idx++;

            RIGHT(S_IFDIR, 'd');

            RIGHT(S_IRUSR, 'r');
            RIGHT(S_IWUSR, 'w');
            RIGHT(S_IXUSR, 'x');

            RIGHT(S_IRGRP, 'r');
            RIGHT(S_IWGRP, 'w');
            RIGHT(S_IXGRP, 'x');

            RIGHT(S_IROTH, 'r');
            RIGHT(S_IWOTH, 'w');
            RIGHT(S_IXOTH, 'x');

#undef RIGHT

            if (mode & S_ISUID)
            {
                if (mode & S_IXUSR)
                {
                    str[3] = 'S';
                }
                else
                {
                    str[3] = 's';
                }
            }

            if (mode & S_ISGID)
            {
                if (mode & S_IXGRP)
                {
                    str[6] = 'S';
                }
                else
                {
                    str[6] = 's';
                }
            }

            if (mode & S_ISVTX)
            {
                if (mode & S_IXOTH)
                {
                    str[9] = 't';
                }
                else
                {
                    str[9] = 'T';
                }
            }

            memcpy(*out, str, str_size);
            *out_size = str_size;

            result = 0;

        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_system_get_uid_name(uid_t const uid,
                                char ** const out,
                                size_t * const out_size)
{
    int result = EINVAL;

    if (out != NULL &&
        out_size != NULL)
    {
        long const needed = sysconf(_SC_GETPW_R_SIZE_MAX);

        if (needed > 0)
        {
            char * buffer = NULL;

            CGUTILS_MALLOC(buffer, (size_t) needed, 1);

            if (buffer != NULL)
            {
                struct passwd pwd = (struct passwd) { 0 };
                struct passwd * ptr = NULL;

                result = getpwuid_r(uid,
                                    &pwd,
                                    buffer,
                                    (size_t) needed,
                                    &ptr);

                if (result == 0)
                {
                    size_t const len = strlen(pwd.pw_name);

                    CGUTILS_MALLOC(*out, len + 1, 1);

                    if (*out != NULL)
                    {
                        memcpy(*out, pwd.pw_name, len);
                        (*out)[len] = '\0';
                        *out_size = len;
                    }
                    else
                    {
                        result = ENOMEM;
                    }
                }

                CGUTILS_FREE(buffer);
            }
            else
            {
                result = ENOMEM;
            }
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_system_get_gid_name(gid_t const gid,
                                char ** const out,
                                size_t * const out_size)
{
    int result = EINVAL;

    if (out != NULL &&
        out_size != NULL)
    {
        long const needed = sysconf(_SC_GETGR_R_SIZE_MAX);

        if (needed > 0)
        {
            char * buffer = NULL;

            CGUTILS_MALLOC(buffer, (size_t) needed, 1);

            if (buffer != NULL)
            {
                struct group grp = (struct group) { 0 };
                struct group * ptr = NULL;

                result = getgrgid_r(gid,
                                    &grp,
                                    buffer,
                                    (size_t) needed,
                                    &ptr);

                if (result == 0)
                {
                    size_t const len = strlen(grp.gr_name);

                    CGUTILS_MALLOC(*out, len + 1, 1);

                    if (*out != NULL)
                    {
                        memcpy(*out, grp.gr_name, len);
                        (*out)[len] = '\0';
                        *out_size = len;
                    }
                    else
                    {
                        result = ENOMEM;
                    }
                }

                CGUTILS_FREE(buffer);
            }
            else
            {
                result = ENOMEM;
            }
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

#ifdef __linux__
static int cgutils_system_network_get_interface_stats_from_link(struct rtnl_link * const nl_link,
                                                                size_t const idx,
                                                                cgutils_system_network_itf_stats ** const out)
{
    int result = 0;

    CGUTILS_ASSERT(nl_link != NULL);
    CGUTILS_ASSERT(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(*out);

    if (*out != NULL)
    {
        cgutils_system_network_itf_stats * itf_stat = *out;

        char const * const link_name = rtnl_link_get_name(nl_link);
        size_t const link_name_len = strlen(link_name);
        size_t const to_copy = link_name_len > sizeof (itf_stat->name) ? sizeof (itf_stat->name) - 1 : link_name_len;
        memcpy(itf_stat->name, link_name, to_copy);
        itf_stat->name[to_copy] = '\0';

        itf_stat->rx_packets = rtnl_link_get_stat(nl_link, RTNL_LINK_RX_PACKETS);
        itf_stat->tx_packets = rtnl_link_get_stat(nl_link, RTNL_LINK_TX_PACKETS);
        itf_stat->rx_bytes = rtnl_link_get_stat(nl_link, RTNL_LINK_RX_BYTES);
        itf_stat->tx_bytes = rtnl_link_get_stat(nl_link, RTNL_LINK_TX_BYTES);
        itf_stat->rx_errors = rtnl_link_get_stat(nl_link, RTNL_LINK_RX_ERRORS);
        itf_stat->tx_errors = rtnl_link_get_stat(nl_link, RTNL_LINK_TX_ERRORS);

        itf_stat->index = idx;

        if (result != 0)
        {
            CGUTILS_FREE(*out);
        }
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

/* cgutils_vector of cgutils_system_network_itf_stats * */
int cgutils_system_network_get_interfaces_stats(cgutils_vector ** const out)
{
    int result = EINVAL;

    if (out != NULL)
    {
        struct nl_sock * nl_socket = nl_socket_alloc();

        if (nl_socket != NULL)
        {
            result = nl_connect(nl_socket, NETLINK_ROUTE);

            if (result == 0)
            {
                struct nl_cache * cache = NULL;

                result = rtnl_link_alloc_cache(nl_socket,
                                               AF_UNSPEC,
                                               &cache);

                if (result == 0)
                {
                    int const count_int = nl_cache_nitems(cache);

                    if (count_int > 0)
                    {
                        cgutils_vector * vector = NULL;

                        result = cgutils_vector_init((size_t) count_int,
                                                     &vector);

                        if (result == 0)
                        {
                            struct rtnl_link * nl_link = (struct rtnl_link *) nl_cache_get_first(cache);

                            while(nl_link != NULL)
                            {
                                cgutils_system_network_itf_stats * stats = NULL;

                                result = cgutils_system_network_get_interface_stats_from_link(nl_link,
                                                                                              (size_t) rtnl_link_get_ifindex(nl_link),
                                                                                              &stats);

                                if (result == 0)
                                {
                                    result = cgutils_vector_add(vector,
                                                                stats);

                                    if (result != 0)
                                    {
                                        CGUTILS_ERROR("Error adding to vector: %d",
                                                      result);

                                        CGUTILS_FREE(stats);
                                    }
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error getting stats from link: %d",
                                                  result);
                                }

                                nl_link = (struct rtnl_link *) nl_cache_get_next((struct nl_object *) nl_link);
//                                rtnl_link_put(link);
                            }

                            if (result == 0)
                            {
                                *out = vector;
                            }
                            else
                            {
                                cgutils_vector_deep_free(&vector,
                                                         &free);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error allocating vector: %d", result);
                        }
                    }
                    else
                    {
                        result = ENOENT;
                        CGUTILS_ERROR("No interface found: %d", result);
                    }

                    nl_cache_free(cache), cache = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error getting netlink cache: %d", -result);
                }

                nl_close(nl_socket);
            }
            else
            {
                CGUTILS_ERROR("Error connecting netlink socket: %d", -result);
            }

            nl_socket_free(nl_socket), nl_socket = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error getting netlink socket");
            result = -ENOMEM;
        }
    }

    return result;
}

int cgutils_system_network_interface_vlan_add(char const * const itf_name,
                                              char const * const new_itf_name,
                                              uint16_t const vlan_id)
{
    int result = EINVAL;

    if (itf_name != NULL &&
        new_itf_name != NULL &&
        vlan_id < 4096)
    {
        struct nl_sock * nl_socket = nl_socket_alloc();

        if (nl_socket != NULL)
        {
            result = nl_connect(nl_socket, NETLINK_ROUTE);

            if (result == 0)
            {
                struct nl_cache * cache = NULL;

                result = rtnl_link_alloc_cache(nl_socket,
                                               AF_UNSPEC,
                                               &cache);

                if (result == 0)
                {
                    int master_interface_idx = rtnl_link_name2i(cache,
                                                                itf_name);


                    if (master_interface_idx > 0)
                    {
                        struct rtnl_link * vlan_link = rtnl_link_vlan_alloc();

                        if (vlan_link != NULL)
                        {
                            rtnl_link_set_link(vlan_link,
                                                 master_interface_idx);

                            rtnl_link_set_name(vlan_link,
                                               new_itf_name);

                            result = rtnl_link_vlan_set_id(vlan_link,
                                                           vlan_id);

                            if (result == 0)
                            {
                                result = rtnl_link_add(nl_socket,
                                                       vlan_link,
                                                       NLM_F_CREATE);

                                if (result != 0)
                                {
                                    CGUTILS_ERROR("Error adding vlan ID %"PRIu16" to interface %s: %s",
                                                  vlan_id,
                                                  itf_name,
                                                  nl_geterror(result));
                                    result = EIO;
                                }
                            }
                            else
                            {
                                CGUTILS_ERROR("Error setting vlan ID %"PRIu16" to new vlan of interface %s: %s",
                                              vlan_id,
                                              itf_name,
                                              nl_geterror(result));

                                result = EIO;
                            }

                            rtnl_link_put(vlan_link), vlan_link = NULL;
                        }
                        else
                        {
                            result = ENOMEM;
                            CGUTILS_ERROR("Error allocating memory for VLAN link: %d", result);
                        }
                    }
                    else
                    {
                        result = ENOENT;
                        CGUTILS_ERROR("No interface named %s found: %d",
                                      itf_name,
                                      result);
                    }

                    nl_cache_free(cache), cache = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error getting netlink cache: %d", -result);
                }

                nl_close(nl_socket);
            }
            else
            {
                CGUTILS_ERROR("Error connecting netlink socket: %d", -result);
            }

            nl_socket_free(nl_socket), nl_socket = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error getting netlink socket");
            result = -ENOMEM;
        }
    }

    return result;
}

int cgutils_system_network_interface_del(char const * const itf_name)
{
    int result = EINVAL;

    if (itf_name != NULL)
    {
        struct nl_sock * nl_socket = nl_socket_alloc();

        if (nl_socket != NULL)
        {
            result = nl_connect(nl_socket, NETLINK_ROUTE);

            if (result == 0)
            {
                struct rtnl_link * vlan_link = rtnl_link_vlan_alloc();

                if (vlan_link != NULL)
                {
                    rtnl_link_set_name(vlan_link,
                                       itf_name);

                    result = rtnl_link_delete(nl_socket,
                                              vlan_link);

                    if (result != 0)
                    {
                        CGUTILS_ERROR("Error removing interface %s: %s",
                                      itf_name,
                                      nl_geterror(result));
                        result = EIO;
                    }

                    rtnl_link_put(vlan_link), vlan_link = NULL;
                }
                else
                {
                    result = ENOMEM;
                    CGUTILS_ERROR("Error allocating memory for VLAN link: %d", result);
                }

                nl_close(nl_socket);
            }
            else
            {
                CGUTILS_ERROR("Error connecting netlink socket: %d", -result);
            }

            nl_socket_free(nl_socket), nl_socket = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error getting netlink socket");
            result = -ENOMEM;
        }
    }

    return result;
}

int cgutils_system_network_interface_set_mtu(char const * const itf_name,
                                             uint16_t const mtu)
{
    int result = EINVAL;

    if (itf_name != NULL &&
        mtu > 0)
    {
        struct nl_sock * nl_socket = nl_socket_alloc();

        if (nl_socket != NULL)
        {
            result = nl_connect(nl_socket, NETLINK_ROUTE);

            if (result == 0)
            {
                struct nl_cache * cache = NULL;

                result = rtnl_link_alloc_cache(nl_socket,
                                               AF_UNSPEC,
                                               &cache);

                if (result == 0)
                {
                    struct rtnl_link * itf_link = rtnl_link_get_by_name(cache,
                                                                        itf_name);

                    if (itf_link != NULL)
                    {
                        struct rtnl_link * change = rtnl_link_alloc();

                        if (change != NULL)
                        {
                            rtnl_link_set_mtu(change,
                                              mtu);

                            result = rtnl_link_change(nl_socket,
                                                      itf_link,
                                                      change,
                                                      0);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error updating the MTU (%"PRIu16") of interface %s: %s",
                                              mtu,
                                              itf_name,
                                              nl_geterror(result));
                                result = EIO;
                            }

                            rtnl_link_put(change), change = NULL;
                        }
                        else
                        {
                            result = ENOMEM;
                            CGUTILS_ERROR("Error allocating memory for change link: %d", result);
                        }

                        rtnl_link_put(itf_link), itf_link = NULL;
                    }
                    else
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Error allocating memory for interface link: %d", result);
                    }

                    nl_cache_free(cache), cache = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error getting netlink cache: %d", -result);
                }

                nl_close(nl_socket);
            }
            else
            {
                CGUTILS_ERROR("Error connecting netlink socket: %d", -result);
            }

            nl_socket_free(nl_socket), nl_socket = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error getting netlink socket");
            result = -ENOMEM;
        }
    }

    return result;
}

int cgutils_system_network_interface_set_state(char const * const itf_name,
                                               bool const up)
{
    int result = EINVAL;

    if (itf_name != NULL)
    {
        struct nl_sock * nl_socket = nl_socket_alloc();

        if (nl_socket != NULL)
        {
            result = nl_connect(nl_socket, NETLINK_ROUTE);

            if (result == 0)
            {
                struct nl_cache * cache = NULL;

                result = rtnl_link_alloc_cache(nl_socket,
                                               AF_UNSPEC,
                                               &cache);

                if (result == 0)
                {
                    struct rtnl_link * itf_link = rtnl_link_get_by_name(cache,
                                                                        itf_name);

                    if (itf_link != NULL)
                    {
                        struct rtnl_link * change = rtnl_link_alloc();

                        if (change != NULL)
                        {
                            if (up == true)
                            {
                                rtnl_link_set_flags(change,
                                                    IFF_UP);
                            }
                            else
                            {
                                rtnl_link_unset_flags(change,
                                                      IFF_UP);
                            }

                            result = rtnl_link_change(nl_socket,
                                                      itf_link,
                                                      change,
                                                      0);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error setting the state (%s) of interface %s: %s",
                                              up == true ? "up" : "down",
                                              itf_name,
                                              nl_geterror(result));
                                result = EIO;
                            }

                            rtnl_link_put(change), change = NULL;
                        }
                        else
                        {
                            result = ENOMEM;
                            CGUTILS_ERROR("Error allocating memory for change link: %d", result);
                        }

                        rtnl_link_put(itf_link), itf_link = NULL;
                    }
                    else
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Error allocating memory for interface link: %d", result);
                    }

                    nl_cache_free(cache), cache = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error getting netlink cache: %d", -result);
                }

                nl_close(nl_socket);
            }
            else
            {
                CGUTILS_ERROR("Error connecting netlink socket: %d", -result);
            }

            nl_socket_free(nl_socket), nl_socket = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error getting netlink socket");
            result = -ENOMEM;
        }
    }

    return result;
}

int cgutils_system_network_interface_addr_add(char const * const itf_name,
                                              char const * const addr_mask)
{
    int result = EINVAL;

    if (itf_name != NULL &&
        addr_mask != NULL)
    {
        struct nl_sock * nl_socket = nl_socket_alloc();

        if (nl_socket != NULL)
        {
            result = nl_connect(nl_socket, NETLINK_ROUTE);

            if (result == 0)
            {
                struct nl_cache * cache = NULL;

                result = rtnl_link_alloc_cache(nl_socket,
                                               AF_UNSPEC,
                                               &cache);

                if (result == 0)
                {
                    int master_interface_idx = rtnl_link_name2i(cache,
                                                                itf_name);


                    if (master_interface_idx > 0)
                    {
                        struct rtnl_addr * addr = rtnl_addr_alloc();

                        if (addr != NULL)
                        {
                            struct nl_addr * nl_addr = NULL;

                            result = nl_addr_parse(addr_mask,
                                                   AF_UNSPEC,
                                                   &nl_addr);

                            if (result == 0)
                            {
                                result = rtnl_addr_set_local(addr, nl_addr);

                                if (result == 0)
                                {
                                    rtnl_addr_set_ifindex(addr,
                                                          master_interface_idx);

                                    result = rtnl_addr_add(nl_socket,
                                                           addr,
                                                           NLM_F_CREATE);

                                    if (result != 0)
                                    {
                                        CGUTILS_ERROR("Error adding address %s to interface %s: %s",
                                                      addr_mask,
                                                      itf_name,
                                                      nl_geterror(result));
                                        result = EIO;
                                    }
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error setting address %s to local RTNL: %s",
                                                  addr_mask,
                                                  nl_geterror(result));
                                    result = EINVAL;
                                }

                                nl_addr_put(nl_addr), nl_addr = NULL;
                            }
                            else
                            {
                                CGUTILS_ERROR("Error while parsing address %s: %s",
                                              addr_mask,
                                              nl_geterror(result));
                                result = EINVAL;
                            }

                            rtnl_addr_put(addr), addr = NULL;
                        }
                        else
                        {
                            result = ENOMEM;
                            CGUTILS_ERROR("Error allocating memory for addr: %d",
                                          result);
                        }
                    }
                    else
                    {
                        result = ENOENT;
                        CGUTILS_ERROR("Error getting index for interface %s: %d",
                                      itf_name,
                                      result);
                    }

                    nl_cache_free(cache), cache = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error getting netlink cache: %d", -result);
                }

                nl_close(nl_socket);
            }
            else
            {
                CGUTILS_ERROR("Error connecting netlink socket: %d", -result);
            }

            nl_socket_free(nl_socket), nl_socket = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error getting netlink socket");
            result = -ENOMEM;
        }
    }

    return result;
}

int cgutils_system_network_interface_addr_del(char const * const itf_name,
                                              char const * const addr_mask)
{
    int result = EINVAL;

    if (itf_name != NULL &&
        addr_mask != NULL)
    {
        struct nl_sock * nl_socket = nl_socket_alloc();

        if (nl_socket != NULL)
        {
            result = nl_connect(nl_socket, NETLINK_ROUTE);

            if (result == 0)
            {
                struct nl_cache * cache = NULL;

                result = rtnl_link_alloc_cache(nl_socket,
                                               AF_UNSPEC,
                                               &cache);

                if (result == 0)
                {
                    int master_interface_idx = rtnl_link_name2i(cache,
                                                                itf_name);


                    if (master_interface_idx > 0)
                    {
                        struct rtnl_addr * addr = rtnl_addr_alloc();

                        if (addr != NULL)
                        {
                            struct nl_addr * nl_addr = NULL;

                            result = nl_addr_parse(addr_mask,
                                                   AF_UNSPEC,
                                                   &nl_addr);

                            if (result == 0)
                            {
                                result = rtnl_addr_set_local(addr, nl_addr);

                                if (result == 0)
                                {
                                    rtnl_addr_set_ifindex(addr,
                                                          master_interface_idx);

                                    result = rtnl_addr_delete(nl_socket,
                                                              addr,
                                                              0);

                                    if (result != 0)
                                    {
                                        CGUTILS_ERROR("Error removing address %s from interface %s: %s",
                                                      addr_mask,
                                                      itf_name,
                                                      nl_geterror(result));
                                        result = EIO;
                                    }
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error setting address %s to local RTNL: %s",
                                                  addr_mask,
                                                  nl_geterror(result));
                                    result = EINVAL;
                                }

                                nl_addr_put(nl_addr), nl_addr = NULL;
                            }
                            else
                            {
                                CGUTILS_ERROR("Error while parsing address %s: %s",
                                              addr_mask,
                                              nl_geterror(result));
                                result = EINVAL;
                            }

                            rtnl_addr_put(addr), addr = NULL;
                        }
                        else
                        {
                            result = ENOMEM;
                            CGUTILS_ERROR("Error allocating memory for addr: %d",
                                          result);
                        }
                    }
                    else
                    {
                        result = ENOENT;
                        CGUTILS_ERROR("Error getting index for interface %s: %d",
                                      itf_name,
                                      result);
                    }

                    nl_cache_free(cache), cache = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error getting netlink cache: %d", -result);
                }

                nl_close(nl_socket);
            }
            else
            {
                CGUTILS_ERROR("Error connecting netlink socket: %d", -result);
            }

            nl_socket_free(nl_socket), nl_socket = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error getting netlink socket");
            result = -ENOMEM;
        }
    }

    return result;
}

int cgutils_system_network_interface_route_add_advanced(char const * const dest_net,
                                                        char const * const nh_addr,
                                                        char const * const dev_itf,
                                                        uint32_t const priority,
                                                        uint32_t const table)
{
    int result = EINVAL;

    if (dest_net != NULL &&
        (nh_addr != NULL || dev_itf != NULL) &&
        !(nh_addr != NULL && dev_itf != NULL))
    {
        struct nl_sock * nl_socket = nl_socket_alloc();

        if (nl_socket != NULL)
        {
            result = nl_connect(nl_socket, NETLINK_ROUTE);

            if (result == 0)
            {
                struct nl_cache * cache = NULL;

                result = rtnl_link_alloc_cache(nl_socket,
                                               AF_UNSPEC,
                                               &cache);

                if (result == 0)
                {
                    struct rtnl_route * route = rtnl_route_alloc();

                    if (route != NULL)
                    {
                        struct rtnl_nexthop * nh = rtnl_route_nh_alloc();

                        if (nh != NULL)
                        {
                            if (dev_itf != NULL)
                            {
                                int master_interface_idx = rtnl_link_name2i(cache,
                                                                            dev_itf);

                                if (master_interface_idx > 0)
                                {
                                    rtnl_route_nh_set_ifindex(nh,
                                                              master_interface_idx);
                                }
                                else
                                {
                                    result = ENOENT;
                                    CGUTILS_ERROR("Error, no interface named %s",
                                                  dev_itf);
                                }
                            }
                            else
                            {
                                struct nl_addr * addr = NULL;

                                result = nl_addr_parse(nh_addr,
                                                       AF_UNSPEC,
                                                       &addr);

                                if (result == 0)
                                {
                                    rtnl_route_nh_set_gateway(nh,
                                                              addr);
                                    nl_addr_put(addr), addr = NULL;
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error while parsing address %s: %s",
                                                  nh_addr,
                                                  nl_geterror(result));
                                    result = EINVAL;
                                }
                            }

                            if (result == 0)
                            {
                                struct nl_addr * dest_addr = NULL;

                                result = nl_addr_parse(dest_net,
                                                       AF_UNSPEC,
                                                       &dest_addr);

                                if (result == 0)
                                {
                                    result = rtnl_route_set_dst(route, dest_addr);

                                    if (result == 0)
                                    {
                                        rtnl_route_add_nexthop(route, nh);
                                        rtnl_route_set_table(route, table);
                                        rtnl_route_set_priority(route, priority);
                                        rtnl_route_set_protocol(route, RTPROT_BOOT);

                                        result = rtnl_route_add(nl_socket,
                                                                route,
                                                                0);

                                        if (result != 0)
                                        {
                                            CGUTILS_ERROR("Error adding route: %s",
                                                          nl_geterror(result));
                                            result = EIO;
                                        }

                                        nl_addr_put(dest_addr), dest_addr = NULL;
                                    }
                                    else
                                    {
                                        CGUTILS_ERROR("Error setting route destination: %s",
                                                      nl_geterror(result));
                                        result = EIO;
                                    }
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error while parsing route destination %s: %s",
                                                  dest_net,
                                                  nl_geterror(result));
                                    result = EIO;
                                }
                            }
                            else
                            {
                                rtnl_route_nh_free(nh), nh = NULL;
                            }
                        }
                        else
                        {
                            result = ENOMEM;
                            CGUTILS_ERROR("Error allocating memory for next hop entry: %d",
                                          result);
                        }

                        rtnl_route_put(route), route = NULL;
                    }
                    else
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Error allocating memory for route entry: %d",
                                      result);
                    }

                    nl_cache_free(cache), cache = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error getting netlink cache: %d", -result);
                }

                nl_close(nl_socket);
            }
            else
            {
                CGUTILS_ERROR("Error connecting netlink socket: %d", -result);
            }

            nl_socket_free(nl_socket), nl_socket = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error getting netlink socket");
            result = -ENOMEM;
        }
    }

    return result;
}

int cgutils_system_network_interface_route_add(char const * const dest_net,
                                               char const * const nh_addr,
                                               char const * const dev_itf)
{
    return cgutils_system_network_interface_route_add_advanced(dest_net,
                                                               nh_addr,
                                                               dev_itf,
                                                               0,
                                                               (CLOUDUTILS_SYSTEM_NETWORK_DEFAULT_ROUTING_TABLE));
}

int cgutils_system_network_interface_route_del_advanced(char const * const dest_net,
                                                        char const * const nh_addr,
                                                        char const * const dev_itf,
                                                        uint32_t const priority,
                                                        uint32_t const table)
{
    int result = EINVAL;

    if (dest_net != NULL &&
        (nh_addr != NULL || dev_itf != NULL) &&
        !(nh_addr != NULL && dev_itf != NULL))
    {
        struct nl_sock * nl_socket = nl_socket_alloc();

        if (nl_socket != NULL)
        {
            result = nl_connect(nl_socket, NETLINK_ROUTE);

            if (result == 0)
            {
                struct nl_cache * cache = NULL;

                result = rtnl_link_alloc_cache(nl_socket,
                                               AF_UNSPEC,
                                               &cache);

                if (result == 0)
                {
                    struct rtnl_route * route = rtnl_route_alloc();

                    if (route != NULL)
                    {
                        struct rtnl_nexthop * nh = rtnl_route_nh_alloc();

                        if (nh != NULL)
                        {
                            if (dev_itf != NULL)
                            {
                                int master_interface_idx = rtnl_link_name2i(cache,
                                                                            dev_itf);

                                if (master_interface_idx > 0)
                                {
                                    rtnl_route_nh_set_ifindex(nh,
                                                              master_interface_idx);
                                }
                                else
                                {
                                    result = ENOENT;
                                    CGUTILS_ERROR("Error, no interface named %s",
                                                  dev_itf);
                                }
                            }
                            else
                            {
                                struct nl_addr * addr = NULL;

                                result = nl_addr_parse(nh_addr,
                                                       AF_UNSPEC,
                                                       &addr);

                                if (result == 0)
                                {
                                    rtnl_route_nh_set_gateway(nh,
                                                              addr);
                                    nl_addr_put(addr), addr = NULL;
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error while parsing address %s: %s",
                                                  nh_addr,
                                                  nl_geterror(result));
                                    result = EINVAL;
                                }
                            }

                            if (result == 0)
                            {
                                struct nl_addr * dest_addr = NULL;

                                result = nl_addr_parse(dest_net,
                                                       AF_UNSPEC,
                                                       &dest_addr);

                                if (result == 0)
                                {
                                    result = rtnl_route_set_dst(route, dest_addr);

                                    if (result == 0)
                                    {
                                        rtnl_route_add_nexthop(route, nh);
                                        rtnl_route_set_table(route, table);
                                        rtnl_route_set_priority(route, priority);
                                        rtnl_route_set_protocol(route, RTPROT_BOOT);

                                        result = rtnl_route_delete(nl_socket,
                                                                   route,
                                                                   0);

                                        if (result != 0)
                                        {
                                            CGUTILS_ERROR("Error removing route: %s",
                                                  nl_geterror(result));
                                            result = EIO;
                                        }

                                        nl_addr_put(dest_addr), dest_addr = NULL;
                                    }
                                    else
                                    {
                                        CGUTILS_ERROR("Error setting route destination: %s",
                                                      nl_geterror(result));
                                        result = EIO;
                                    }
                                }
                                else
                                {
                                    CGUTILS_ERROR("Error while parsing route destination %s: %s",
                                                  dest_net,
                                                  nl_geterror(result));
                                    result = EIO;
                                }
                            }
                            else
                            {
                                rtnl_route_nh_free(nh), nh = NULL;
                            }
                        }
                        else
                        {
                            result = ENOMEM;
                            CGUTILS_ERROR("Error allocating memory for next hop entry: %d",
                                          result);
                        }

                        rtnl_route_put(route), route = NULL;
                    }
                    else
                    {
                        result = ENOMEM;
                        CGUTILS_ERROR("Error allocating memory for route entry: %d",
                                      result);
                    }

                    nl_cache_free(cache), cache = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error getting netlink cache: %d", -result);
                }

                nl_close(nl_socket);
            }
            else
            {
                CGUTILS_ERROR("Error connecting netlink socket: %d", -result);
            }

            nl_socket_free(nl_socket), nl_socket = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error getting netlink socket");
            result = -ENOMEM;
        }
    }

    return result;
}

int cgutils_system_network_interface_route_del(char const * const dest_net,
                                               char const * const nh_addr,
                                               char const * const dev_itf)
{
    return cgutils_system_network_interface_route_del_advanced(dest_net,
                                                               nh_addr,
                                                               dev_itf,
                                                               0,
                                                               (CLOUDUTILS_SYSTEM_NETWORK_DEFAULT_ROUTING_TABLE));
}

int cgutils_system_get_cpu_stats(cgutils_system_cpu_stats * stats)
{
    int result = EINVAL;

    if (stats != NULL)
    {
        char * buffer = NULL;
        size_t buffer_size = 0;

        result = cgutils_file_get_proc_content_sync("/proc/stat",
                                                    &buffer,
                                                    &buffer_size);

        if (result == 0)
        {
            static char const prolog[] = "cpu  ";
            static size_t const prolog_size = sizeof prolog - 1;

            if (buffer_size > prolog_size)
            {
                char const * ptr = buffer;
                CGUTILS_ASSERT(ptr != NULL);

                int const count = sscanf(ptr, "cpu  %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64,
                                         &(stats->user),
                                         &(stats->nice),
                                         &(stats->system),
                                         &(stats->idle),
                                         &(stats->iowait),
                                         &(stats->irq),
                                         &(stats->softirq),
                                         &(stats->steal));

                if (count == 8)
                {
                    result = 0;
                }
                else
                {
                    result = EIO;
                }
            }
            else
            {
                result = EIO;
            }

            CGUTILS_FREE(buffer);
        }
    }

    return result;
}

int cgutils_system_get_memory_stats(cgutils_system_memory_stats * stats)
{
    int result = EINVAL;

    if (stats != NULL)
    {
        struct sysinfo si = (struct sysinfo) { 0 };

        result = sysinfo(&si);

        if (result == 0)
        {
            stats->total = si.totalram;
            stats->free = si.freeram;
            stats->buffers = si.bufferram;
            stats->swap_total = si.totalswap;
            stats->swap_free = si.freeswap;
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

int cgutils_system_set_datetime(time_t const * const datetime)
{
    int result = EINVAL;

    if (datetime != NULL)
    {
        result = stime(datetime);

        if (result != 0)
        {
            result = errno;
        }
    }

    return result;
}

#endif /* __linux__ */
