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
#include <limits.h>
#include <strings.h>

#include "cloudutils/cloudutils.h"
#include "cloudutils/cloudutils_xml_reader.h"
#include "cloudutils/cloudutils_file.h"
#include "cloudutils/cloudutils_xml.h"
#include "cloudutils/cloudutils_xml_internals.h"

#include <libxml/c14n.h>
#include <libxml/tree.h>

struct cgutils_xml_reader
{
    xmlDoc * doc;
    xmlNode * node;
    xmlXPathContext * ctx;
    cgutils_xml_reader * parent;
    size_t refs_count;
};

static int cgutils_xml_reader_from_node(xmlNode * const node,
                                        cgutils_xml_reader ** const out)
{
    assert(node != NULL);
    assert(out != NULL);

    int result = 0;

    CGUTILS_ALLOCATE_STRUCT(*out);

    if (*out != NULL)
    {
        result = cgutils_xml_get_xpath_ctx(node, &((*out)->ctx));

        if (result == 0)
        {
            (*out)->node = node;
        }
        else
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

int cgutils_xml_reader_init(void)
{
    return cgutils_xml_init();
}

void cgutils_xml_reader_destroy(void)
{
    cgutils_xml_destroy();
}

int cgutils_xml_reader_from_doc(xmlDoc * doc,
                                cgutils_xml_reader ** const out)
{
    int result = EINVAL;

    if (doc != NULL &&
        out != NULL)
    {
        xmlNode * root = xmlDocGetRootElement(doc);

        if (root != NULL)
        {
            result = cgutils_xml_reader_from_node(root, out);

            if (result == 0)
            {
                assert(*out != NULL);
                (*out)->doc = doc, doc = NULL;
            }
        }
        else
        {
            result = EIO;
        }

    }

    return result;
}

int cgutils_xml_reader_from_buffer(char const * const data,
                                   size_t const data_size,
                                   cgutils_xml_reader ** const out)
{
    int result = EINVAL;

    if (data != NULL && data_size > 0 && out != NULL && data_size <= INT_MAX)
    {
        xmlDoc * doc = xmlReadMemory(data, (int) data_size, "inmemory.xml", NULL, XML_PARSE_NONET);

        if (doc != NULL)
        {
            result = cgutils_xml_reader_from_doc(doc, out);

            if (result != 0 && doc != NULL)
            {
                xmlFreeDoc(doc), doc = NULL;
            }
        }
        else
        {
            result = EIO;
        }
    }

    return result;
}

int cgutils_xml_reader_from_file(char const * const file,
                                 cgutils_xml_reader ** const out)
{
    int result = EINVAL;

    if (file != NULL && out != NULL)
    {
        if (cgutils_file_exists(file))
        {
            xmlDoc * doc = xmlReadFile(file, NULL, XML_PARSE_NONET);

            if (doc != NULL)
            {
                xmlNode * root = xmlDocGetRootElement(doc);

                if (root != NULL)
                {
                    result = cgutils_xml_reader_from_node(root, out);

                    if (result == 0)
                    {
                        assert(*out != NULL);
                        (*out)->doc = doc;
                        doc = NULL;
                    }
                }
                else
                {
                    result = EIO;
                }

                if (result != 0 && doc != NULL)
                {
                    xmlFreeDoc(doc), doc = NULL;
                }
            }
            else
            {
                result = EIO;
            }
        }
        else
        {
            result = ENOENT;
        }
    }

    return result;
}

int cgutils_xml_reader_from_path(cgutils_xml_reader * const reader,
                                 char const * const path,
                                 cgutils_xml_reader ** const out)
{
    int result = EINVAL;

    if (reader != NULL && path != NULL && out != NULL)
    {
        assert(reader->ctx != NULL);

        xmlNode * target_node = NULL;

        result = cgutils_xml_ctx_extract_node(reader->ctx,
                                              path,
                                              (xmlNode **)&target_node);

        if (result == 0)
        {
            result = cgutils_xml_reader_from_node(target_node,
                                                  out);

            if (result == 0)
            {
                reader->refs_count++;
                (*out)->parent = reader;
            }
        }
    }

    return result;
}

int cgutils_xml_reader_get_all(cgutils_xml_reader * const reader,
                               char const * const path,
                               cgutils_llist ** const confs_list)
{
    int result = EINVAL;

    if (reader != NULL && path != NULL && confs_list != NULL)
    {
        assert(reader->ctx != NULL);

        xmlXPathObject * object = NULL;

        result = cgutils_xml_ctx_extract_nodeset(reader->ctx, path, &object);

        if (result == 0)
        {
            xmlNodeSet * nodeset = object->nodesetval;

            if (nodeset != NULL && nodeset->nodeNr > 0)
            {
                result = cgutils_llist_create(confs_list);

                if (result == 0)
                {
                    assert(*confs_list != NULL);

                    for(size_t idx = 0; result == 0 && idx < (size_t)nodeset->nodeNr; idx++)
                    {
                        xmlNode * const node = nodeset->nodeTab[idx];

                        if (node != NULL)
                        {
                            cgutils_xml_reader * node_reader = NULL;

                            result = cgutils_xml_reader_from_node(node,
                                                                   &node_reader);

                            if (result == 0)
                            {
                                assert(node_reader != NULL);

                                reader->refs_count++;
                                node_reader->parent = reader;

                                result = cgutils_llist_insert(*confs_list,
                                                              node_reader);

                                if (result != 0)
                                {
                                    cgutils_xml_reader_free(node_reader), node_reader = NULL;
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                result = ENOENT;
            }

            xmlXPathFreeObject(object), object = NULL;
        }
    }

    return result;
}

int cgutils_xml_reader_get_string(cgutils_xml_reader const * const reader,
                                  char const * const path,
                                  char ** const out)
{
    int result = EINVAL;

    if (reader != NULL && path != NULL && out != NULL)
    {
        assert(reader->ctx != NULL);

        result = cgutils_xml_ctx_extract_string(reader->ctx,
                                                path,
                                                out);
    }

    return result;
}


int cgutils_xml_reader_get_boolean(cgutils_xml_reader const * reader,
                                   char const * path,
                                   bool * out)
{
    int result = EINVAL;

    if (reader != NULL && path != NULL && out != NULL)
    {
        assert(reader->ctx != NULL);

        char * value = NULL;

        result = cgutils_xml_ctx_extract_string(reader->ctx,
                                                path,
                                                &value);

        if (result == 0)
        {
            assert(value != NULL);

            if (strcasecmp(value, "true") == 0)
            {
                *out = true;
            }
            else
            {
                *out = false;
            }

            CGUTILS_FREE(value);
        }
    }

    return result;
}


int cgutils_xml_reader_get_unsigned_integer(cgutils_xml_reader const * const reader,
                                            char const * const path,
                                            uint64_t * const out)
{
    int result = EINVAL;

    if (reader != NULL && path != NULL && out != NULL)
    {
        assert(reader->ctx != NULL);

        result = cgutils_xml_ctx_extract_unsigned_integer(reader->ctx,
                                                          path,
                                                          out);
    }

    return result;
}


int cgutils_xml_reader_get_integer(cgutils_xml_reader const * const reader,
                                   char const * const path,
                                   int64_t * const out)
{
    int result = EINVAL;

    if (reader != NULL && path != NULL && out != NULL)
    {
        assert(reader->ctx != NULL);

        result = cgutils_xml_ctx_extract_integer(reader->ctx,
                                                 path,
                                                 out);
    }

    return result;
}

int cgutils_xml_reader_get_size(cgutils_xml_reader const * const reader,
                                char const * const path,
                                size_t * const out)
{
    int result = EINVAL;

    if (reader != NULL && path != NULL && out != NULL)
    {
        assert(reader->ctx != NULL);

        result = cgutils_xml_ctx_extract_size(reader->ctx,
                                              path,
                                              out);
    }

    return result;
}

void cgutils_xml_reader_free(cgutils_xml_reader * reader)
{
    if (reader != NULL)
    {
        if (reader->refs_count == 0)
        {
            if (reader->parent != NULL)
            {
                cgutils_xml_reader_free(reader->parent), reader->parent = NULL;
            }

            if (reader->ctx != NULL)
            {
                cgutils_xml_xpath_ctx_free(reader->ctx), reader->ctx = NULL;
            }

            if (reader->doc != NULL)
            {
                xmlFreeDoc(reader->doc), reader->doc = NULL;
            }

            CGUTILS_FREE(reader);
        }
        else
        {
            reader->refs_count--;
        }
    }
}

void cgutils_xml_reader_delete(void * reader)
{
    cgutils_xml_reader_free(reader);
}

int cgutils_xml_reader_register_namespace(cgutils_xml_reader * const this,
                                          char const * const prefix,
                                          char const * const namespace)
{
    int result = EINVAL;

    if (this != NULL && prefix != NULL && namespace != NULL)
    {
        result = cgutils_xml_ctx_register_namespace(this->ctx, prefix, namespace);
    }

    return result;
}

int cgutils_xml_reader_get_c14n_string(cgutils_xml_reader const * const reader,
                                       char const * const path,
                                       char ** const out,
                                       size_t * const out_len)
{
    int result = EINVAL;

    if (reader != NULL && path != NULL && out != NULL && out_len != NULL)
    {
        assert(reader->ctx != NULL);
        assert(reader->doc != NULL);

        xmlNode * node = NULL;

        result = cgutils_xml_ctx_extract_node(reader->ctx,
                                              path,
                                              &node);
        if (result == 0)
        {
            result = cgutils_xml_get_c14n_string(reader->doc,
                                                 node,
                                                 out,
                                                 out_len);
        }
    }

    return result;
}
