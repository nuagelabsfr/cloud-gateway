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

#ifndef EXPORTS_TOOLS_H_
#define EXPORTS_TOOLS_H_

#include <cloudutils/cloudutils_xml_writer.h>

#ifdef NDEBUG
static char const exports_file_path[] = "/etc/exports";
#else
static char const exports_file_path[] = "/tmp/exports";
#endif

int exports_tools_convert_exports_to_xml(char const * str,
                                         size_t str_size,
                                         cgutils_xml_writer ** out);

int exports_tools_convert_xml_to_exports(cgutils_xml_writer const * writer,
                                         FILE * fp);

int exports_tools_save(cgutils_xml_writer const * writer);

int exports_tools_add_export_if_not_exists(cgutils_xml_writer * writer,
                                           char const * path);

int exports_tools_remove_export_if_exists(cgutils_xml_writer * writer,
                                          char const * path);

int exports_tools_add_export_client(cgutils_xml_writer * writer,
                                    char const * path,
                                    char const * host,
                                    char const * options);

int exports_tools_remove_export_client(cgutils_xml_writer * writer,
                                       char const * path,
                                       char const * host);

#endif /* EXPORT_TOOLS_H_ */
