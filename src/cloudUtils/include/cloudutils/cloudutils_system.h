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

#ifndef CLOUD_UTILS_SYSTEM_H_
#define CLOUD_UTILS_SYSTEM_H_

#include <netdb.h>
#include <time.h>

#include <cloudutils/cloudutils_compiler_specifics.h>

typedef struct cgutils_system_network_address cgutils_system_network_address;
typedef struct cgutils_system_network_interface cgutils_system_network_interface;
typedef struct cgutils_system_uname_info cgutils_system_uname_info;

#include <cloudutils/cloudutils_llist.h>
#include <cloudutils/cloudutils_vector.h>

#define CGUTILS_SYSTEM_NETWORK_ITF_NAME_SIZE (16)

typedef struct
{
    char name[CGUTILS_SYSTEM_NETWORK_ITF_NAME_SIZE];
    size_t index;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_errors;
    uint64_t tx_errors;
} cgutils_system_network_itf_stats;

typedef struct
{
    uint64_t user;
    uint64_t nice;
    uint64_t system;
    uint64_t idle;
    uint64_t iowait;
    uint64_t irq;
    uint64_t softirq;
    uint64_t steal;
} cgutils_system_cpu_stats;

typedef struct
{
    uint64_t total;
    uint64_t free;
    uint64_t buffers;
    uint64_t swap_total;
    uint64_t swap_free;
} cgutils_system_memory_stats;

COMPILER_BLOCK_VISIBILITY_DEFAULT

/* cgutils_vector of cgutils_system_network_itf_stats * */
int cgutils_system_network_get_interfaces_stats(cgutils_vector ** out);
int cgutils_system_get_cpu_stats(cgutils_system_cpu_stats * stats);
int cgutils_system_get_memory_stats(cgutils_system_memory_stats * stats);

int cgutils_system_network_get_all_interfaces(cgutils_vector ** interfaces_out);

char const * cgutils_system_network_interface_get_name(cgutils_system_network_interface const * this) COMPILER_PURE_FUNCTION;
char const * cgutils_system_network_interface_get_mac(cgutils_system_network_interface const * this) COMPILER_PURE_FUNCTION;
bool cgutils_system_network_interface_is_up(cgutils_system_network_interface const * this) COMPILER_PURE_FUNCTION;
bool cgutils_system_network_interface_is_lower_up(cgutils_system_network_interface const * this) COMPILER_PURE_FUNCTION;
bool cgutils_system_network_interface_is_running(cgutils_system_network_interface const * this) COMPILER_PURE_FUNCTION;
char const * cgutils_system_network_interface_get_oper_state_str(cgutils_system_network_interface const * this) COMPILER_PURE_FUNCTION;

bool cgutils_system_network_interface_is_oper_unknown(cgutils_system_network_interface const * this) COMPILER_PURE_FUNCTION;
bool cgutils_system_network_interface_is_oper_up(cgutils_system_network_interface const * this) COMPILER_PURE_FUNCTION;
bool cgutils_system_network_interface_is_loopback(cgutils_system_network_interface const * this) COMPILER_PURE_FUNCTION;

void cgutils_system_network_interface_free(cgutils_system_network_interface *);

static inline void cgutils_system_network_interface_delete(void * this)
{
    cgutils_system_network_interface_free(this);
}

int cgutils_system_network_get_all_addresses(cgutils_llist ** addrs_out);

char const * cgutils_system_network_address_get_interface_name(cgutils_system_network_address const * this) COMPILER_PURE_FUNCTION;
char const * cgutils_system_network_address_get_addr(cgutils_system_network_address const * this) COMPILER_PURE_FUNCTION;
char const * cgutils_system_network_address_get_mask(cgutils_system_network_address const * this) COMPILER_PURE_FUNCTION;
int cgutils_system_network_address_get_family(cgutils_system_network_address const * this) COMPILER_PURE_FUNCTION;

void cgutils_system_network_address_free(cgutils_system_network_address * this);

static inline void cgutils_system_network_address_delete(void * this)
{
    cgutils_system_network_address_free(this);
}

int cgutils_system_network_interface_vlan_add(char const * itf_name,
                                              char const * new_itf_name,
                                              uint16_t vlan_id);

int cgutils_system_network_interface_del(char const * itf_name);

int cgutils_system_network_interface_set_mtu(char const * const itf_name,
                                             uint16_t const mtu);

int cgutils_system_network_interface_set_state(char const * const itf_name,
                                               bool const up);

int cgutils_system_network_interface_addr_add(char const * itf_name,
                                              char const * addr_mask);

int cgutils_system_network_interface_addr_del(char const * itf_name,
                                              char const * addr_mask);

int cgutils_system_network_interface_route_add_advanced(char const * const dest_net,
                                                        char const * const nh_addr,
                                                        char const * const dev_itf,
                                                        uint32_t const priority,
                                                        uint32_t const table);

int cgutils_system_network_interface_route_add(char const * const dest_net,
                                               char const * const nh_addr,
                                               char const * const dev_itf);

int cgutils_system_network_interface_route_del_advanced(char const * const dest_net,
                                                        char const * const nh_addr,
                                                        char const * const dev_itf,
                                                        uint32_t const priority,
                                                        uint32_t const table);

int cgutils_system_network_interface_route_del(char const * const dest_net,
                                               char const * const nh_addr,
                                               char const * const dev_itf);

int cgutils_system_get_uname_info(cgutils_system_uname_info ** info);

char const * cgutils_system_uname_get_sysname(cgutils_system_uname_info const * this) COMPILER_PURE_FUNCTION;
char const * cgutils_system_uname_get_nodename(cgutils_system_uname_info const * this) COMPILER_PURE_FUNCTION;
char const * cgutils_system_uname_get_release(cgutils_system_uname_info const * this) COMPILER_PURE_FUNCTION;
char const * cgutils_system_uname_get_version(cgutils_system_uname_info const * this) COMPILER_PURE_FUNCTION;
char const * cgutils_system_uname_get_machine(cgutils_system_uname_info const * this) COMPILER_PURE_FUNCTION;

void cgutils_system_uname_info_free(cgutils_system_uname_info * this);

int cgutils_system_get_cpuinfo(char ** procinfo,
                               size_t * len);

int cgutils_system_get_meminfo(char ** meminfo,
                               size_t * len);

int cgutils_system_get_page_size(uint32_t * const out);

int cgutils_system_setproctitle(char * argv0,
                                char const * new_title);

int cgutils_system_get_mode_as_str(mode_t mode,
                                   char ** out,
                                   size_t * out_size);

int cgutils_system_get_uid_name(uid_t uid,
                                char ** out,
                                size_t * out_size);

int cgutils_system_get_gid_name(gid_t gid,
                                char ** out,
                                size_t * out_size);

int cgutils_system_set_datetime(time_t const * datetime);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_SYSTEM_H_ */
