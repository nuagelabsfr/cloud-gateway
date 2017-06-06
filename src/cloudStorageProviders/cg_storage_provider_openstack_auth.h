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

#ifndef CG_STORAGE_PROVIDER_OPENSTACK_AUTH_H_
#define CG_STORAGE_PROVIDER_OPENSTACK_AUTH_H_

bool cg_stp_openstack_auth_performed(cg_storage_provider_request * pv_request) COMPILER_PURE_FUNCTION;

bool cg_stp_openstack_auth_token_is_old(cg_stp_openstack_specifics const * specifics);

int cg_stp_openstack_auth_refresh(cg_stp_openstack_provider_data * pvd,
                                      cg_stp_openstack_specifics * specifics);


int cg_stp_openstack_auth_add(cg_storage_provider_request * pv_request,
                              cg_stp_openstack_specifics const * specifics,
                              cgutils_llist * headers);

#endif /* CG_STORAGE_PROVIDER_OPENSTACK_AUTH_H_ */
