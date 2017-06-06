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

#ifndef CLOUD_UTILS_XML_INTERNALS_H_
#define CLOUD_UTILS_XML_INTERNALS_H_

#include <libxml/tree.h>
#include <libxml/xpath.h>

int cgutils_xml_get_xpath_ctx(xmlNode * node,
                              xmlXPathContext ** ctx);

void cgutils_xml_xpath_ctx_free(xmlXPathContext * ctx);

int cgutils_xml_ctx_register_namespace(xmlXPathContext * ctx,
                                       char const * prefix,
                                       char const * namespace);

int cgutils_xml_ctx_extract_node(xmlXPathContext * ctx,
                                 char const * xpath_str,
                                 xmlNode ** object);

int cgutils_xml_ctx_extract_nodeset(xmlXPathContext * ctx,
                                    char const * xpath_str,
                                    xmlXPathObject ** object);

int cgutils_xml_ctx_extract_unsigned_integer(xmlXPathContext * ctx,
                                             char const * xpath,
                                             uint64_t * value);

int cgutils_xml_ctx_extract_integer(xmlXPathContext * ctx,
                                    char const * xpath,
                                    int64_t * value);

int cgutils_xml_ctx_extract_size(xmlXPathContext * ctx,
                                 char const * xpath,
                                 size_t * value);

int cgutils_xml_ctx_extract_string(xmlXPathContext * ctx,
                                   char const * xpath,
                                   char ** value);

int cgutils_xml_extract_node(xmlNode * node,
                             char const * xpath_str,
                             xmlNode ** object);

int cgutils_xml_extract_unsigned_integer(xmlNode * node,
                                         char const * xpath,
                                         uint64_t * value);

int cgutils_xml_extract_integer(xmlNode * node,
                                char const * xpath,
                                int64_t * value);

int cgutils_xml_extract_size(xmlNode * node,
                             char const * xpath,
                             size_t * value);

int cgutils_xml_extract_string(xmlNode * node,
                               char const * xpath,
                               char ** value);

int cgutils_xml_extract_nodeset(xmlNode * node,
                                char const * xpath_str,
                                xmlXPathObject ** object);

int cgutils_xml_get_c14n_string(xmlDoc * doc,
                                xmlNode * node,
                                char ** out,
                                size_t * out_len);

int cgutils_xml_reader_from_doc(xmlDoc * doc,
                                cgutils_xml_reader ** out);

int cgutils_xml_writer_to_doc(cgutils_xml_writer const * writer,
                              xmlDoc ** doc);

#endif /* CLOUD_UTILS_INTERNALS_XML_H_ */
