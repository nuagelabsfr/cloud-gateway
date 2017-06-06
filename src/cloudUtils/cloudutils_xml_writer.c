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
#include <inttypes.h>
#include <strings.h>

#include "cloudutils/cloudutils.h"
#include "cloudutils/cloudutils_file.h"
#include "cloudutils/cloudutils_xml.h"
#include "cloudutils/cloudutils_xml_internals.h"

#include <libxml/c14n.h>
#include <libxml/tree.h>

#include <cloudutils/cloudutils_xml_writer.h>

struct cgutils_xml_writer
{
    xmlDoc * doc;
    char const * filename;
    cgutils_xml_writer_element * root_elt;
};

struct cgutils_xml_writer_element
{
    cgutils_xml_writer * doc;
    xmlNode * node;
};

int cgutils_xml_writer_new(cgutils_xml_writer ** const writer)
{
    int result = EINVAL;

    if (writer != NULL)
    {
        result = ENOMEM;

        CGUTILS_ALLOCATE_STRUCT(*writer);

        if (*writer != NULL)
        {
            (*writer)->doc = xmlNewDoc(BAD_CAST "1.0");

            if ((*writer)->doc)
            {
                result = 0;
            }

            if (result != 0)
            {
                CGUTILS_FREE(*writer);
            }
        }
    }

    return result;
}

int cgutils_xml_writer_create_root(cgutils_xml_writer * const writer,
                                   char const * const root_name,
                                   cgutils_xml_writer_element ** const node)
{
    int result = EINVAL;

    if (writer != NULL && root_name != NULL && node != NULL && writer->root_elt == NULL)
    {
        result = ENOMEM;
        xmlNode * xml_node = xmlNewDocRawNode(writer->doc,
                                              NULL,
                                              BAD_CAST root_name,
                                              NULL);

        if (xml_node != NULL)
        {
            CGUTILS_ALLOCATE_STRUCT(*node);

            if (*node != NULL)
            {
                result = 0;
                writer->root_elt = *node;
                xmlDocSetRootElement(writer->doc, xml_node);

                (*node)->node = xml_node;
                (*node)->doc = writer;
                xml_node = NULL;
            }

            if (result != 0)
            {
                xmlFreeNode(xml_node), xml_node = NULL;
            }
        }
    }

    return result;
}

int cgutils_xml_writer_from_file(char const * const file,
                                 cgutils_xml_writer ** const out)
{
    int result = EINVAL;

    if (file != NULL &&
        out != NULL)
    {
        if (cgutils_file_exists(file))
        {
            xmlDoc * doc = xmlReadFile(file, NULL, XML_PARSE_NONET);

            if (doc != NULL)
            {
                xmlNode * root = xmlDocGetRootElement(doc);

                if (root != NULL)
                {
                    cgutils_xml_writer * writer = NULL;

                    CGUTILS_ALLOCATE_STRUCT(writer);

                    if (writer != NULL)
                    {
                        writer->doc = doc;
                        doc = NULL;
                        writer->filename = file;

                        CGUTILS_ALLOCATE_STRUCT(writer->root_elt);

                        if (writer->root_elt != NULL)
                        {
                            result = 0;

                            *out = writer;

                            writer->root_elt->node = root;
                            writer->root_elt->doc = writer;
                        }
                        else
                        {
                            result = ENOMEM;
                        }

                        if (result != 0)
                        {
                            cgutils_xml_writer_free(writer), writer = NULL;
                            *out = NULL;
                        }
                    }
                    else
                    {
                        result = ENOMEM;
                        *out = NULL;
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

cgutils_xml_writer_element * cgutils_xml_writer_get_root(cgutils_xml_writer const * const writer)
{
    cgutils_xml_writer_element * result = NULL;

    if (writer != NULL)
    {
        result = writer->root_elt;
    }

    return result;
}

int cgutils_xml_writer_element_add_child(cgutils_xml_writer_element * const parent,
                                         char const * const node_name,
                                         char const * const node_value,
                                         cgutils_xml_writer_element ** const child)
{
    int result = EINVAL;

    if (parent != NULL && node_name != NULL && child != NULL)
    {
        result = ENOMEM;

        xmlNode * xml_child = xmlNewTextChild(parent->node,
                                              NULL,
                                              BAD_CAST node_name,
                                              BAD_CAST node_value);

        if (xml_child != NULL)
        {
            CGUTILS_ALLOCATE_STRUCT(*child);

            if (*child != NULL)
            {
                result = 0;
                (*child)->node = xml_child;
                (*child)->doc = parent->doc;
                xml_child = NULL;
            }

            if (result != 0)
            {
                xmlFreeNode(xml_child), xml_child = NULL;
            }
        }
    }

    return result;
}

int cgutils_xml_writer_element_add_size_child(cgutils_xml_writer_element * const parent,
                                              char const * const element_name,
                                              size_t const element_value,
                                              cgutils_xml_writer_element ** const child)
{
    int result = EINVAL;

    if (parent != NULL && element_name != NULL && child != NULL)
    {
        char * value_str = NULL;

        result = cgutils_asprintf(&value_str,
                                  "%zu",
                                  element_value);

        if (result == 0)
        {
            result = cgutils_xml_writer_element_add_child(parent, element_name,
                                                          value_str,
                                                          child);

            CGUTILS_FREE(value_str);
        }
    }

    return result;
}

int cgutils_xml_writer_element_add_integer_child(cgutils_xml_writer_element * const parent,
                                                 char const * const element_name,
                                                 int64_t const element_value,
                                                 cgutils_xml_writer_element ** const child)
{
    int result = EINVAL;

    if (parent != NULL && element_name != NULL && child != NULL)
    {
        char * value_str = NULL;

        result = cgutils_asprintf(&value_str,
                                  "%"PRId64,
                                  element_value);

        if (result == 0)
        {
            result = cgutils_xml_writer_element_add_child(parent, element_name,
                                                          value_str,
                                                          child);

            CGUTILS_FREE(value_str);
        }
    }

    return result;
}

int cgutils_xml_writer_element_add_unsigned_integer_child(cgutils_xml_writer_element * const parent,
                                                          char const * const element_name,
                                                          uint64_t const element_value,
                                                          cgutils_xml_writer_element ** const child)
{
    int result = EINVAL;

    if (parent != NULL && element_name != NULL && child != NULL)
    {
        char * value_str = NULL;

        result = cgutils_asprintf(&value_str,
                                  "%"PRIu64,
                                  element_value);

        if (result == 0)
        {
            result = cgutils_xml_writer_element_add_child(parent, element_name,
                                                          value_str,
                                                          child);

            CGUTILS_FREE(value_str);
        }
    }

    return result;
}

int cgutils_xml_writer_element_add_boolean_child(cgutils_xml_writer_element * const parent,
                                                 char const * const element_name,
                                                 bool const element_value,
                                                 cgutils_xml_writer_element ** const child)
{
    int result = EINVAL;

    if (parent != NULL && element_name != NULL && child != NULL)
    {
        result = cgutils_xml_writer_element_add_child(parent, element_name,
                                                      element_value == true ? "true" : "false",
                                                      child);

    }

    return result;
}

int cgutils_xml_writer_element_add_prop(cgutils_xml_writer_element * const elt,
                                        char const * const prop_name,
                                        char const * const prop_value)
{
    int result = EINVAL;

    if (elt != NULL && prop_name != NULL)
    {
        xmlAttr * attr = NULL;

        attr = xmlNewProp(elt->node,
                          BAD_CAST prop_name,
                          BAD_CAST prop_value);

        if (attr != NULL)
        {
            result = 0;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

static void cgutils_xml_writer_element_free(cgutils_xml_writer_element * element)

{
    if (element != NULL)
    {
        element->node = NULL;
        element->doc = NULL;
        CGUTILS_FREE(element);
    }
}

void cgutils_xml_writer_element_release(cgutils_xml_writer_element * element)
{
    if (element != NULL)
    {
        /* Don't release the root,
           it may leave a dangling pointer at the parent */
        if (element->doc == NULL ||
            element->doc->root_elt != element)
        {
            cgutils_xml_writer_element_free(element);
        }
    }
}

int cgutils_xml_writer_get_output(cgutils_xml_writer const * const writer,
                                  char ** const out,
                                  size_t * const size)
{
    int result = EINVAL;

    if (writer != NULL && out != NULL && size != NULL)
    {
        int int_size = 0;

        xmlDocDumpFormatMemory(writer->doc,
                               (xmlChar **) out,
                               &int_size,
                               1);

        if (int_size >= 0)
        {
            result = 0;
            *size = (size_t) int_size;
        }
        else
        {
            if (*out != NULL)
            {
                xmlFree(*out), *out = NULL;
            }

            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_xml_writer_save_to_file(cgutils_xml_writer const * const writer,
                                    char const * const file)
{
    int result = EINVAL;

    if (writer != NULL &&
        file != NULL)
    {
        result = xmlSaveFormatFile(file,
                                   writer->doc,
                                   1);

        if (result > 0)
        {
            result = 0;
        }
        else
        {
            result = EIO;
        }
    }

    return result;
}

int cgutils_xml_writer_save(cgutils_xml_writer const * const writer)
{
    int result = EINVAL;

    if (writer != NULL &&
        writer->filename != NULL)
    {
        result = cgutils_xml_writer_save_to_file(writer,
                                                 writer->filename);
    }

    return result;
}

void cgutils_xml_writer_string_free(char * string)
{
    if (string != NULL)
    {
        xmlFree(string), string = NULL;
    }
}

void cgutils_xml_writer_free(cgutils_xml_writer * writer)
{
    if (writer != NULL)
    {
        if (writer->filename != NULL)
        {
            writer->filename = NULL;
        }

        if (writer->root_elt != NULL)
        {
            cgutils_xml_writer_element_free(writer->root_elt);
            writer->root_elt = NULL;
        }

        if (writer->doc != NULL)
        {
            xmlFreeDoc(writer->doc), writer->doc = NULL;
        }

        CGUTILS_FREE(writer);
    }
}

void cgutils_xml_writer_delete(void * writer)
{
    cgutils_xml_writer_free(writer);
}

int cgutils_xml_writer_get_c14n_string(cgutils_xml_writer const * const writer,
                                       char const * const path,
                                       char ** const out,
                                       size_t * const out_len)
{
    int result = EINVAL;

    if (writer != NULL && path != NULL && out != NULL && out_len != NULL)
    {
        assert(writer->root_elt != NULL);
        assert(writer->doc != NULL);

        xmlNode * node = NULL;

        result = cgutils_xml_extract_node(writer->root_elt->node,
                                          path,
                                          &node);
        if (result == 0)
        {
            result = cgutils_xml_get_c14n_string(writer->doc,
                                                 node,
                                                 out,
                                                 out_len);
        }

    }

    return result;
}

int cgutils_xml_writer_element_set_ns(cgutils_xml_writer_element * const elt,
                                      char const * const href,
                                      char const * const prefix)
{
    int result = EINVAL;

    if (elt != NULL && href != NULL && prefix != NULL)
    {
        assert(elt->node != NULL);

        xmlNs * ns = xmlNewNs(elt->node,
                              BAD_CAST href,
                              BAD_CAST prefix);

        if (ns != NULL)
        {
            xmlSetNs(elt->node, ns);
            result = 0;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_xml_writer_set_element_value(cgutils_xml_writer * const writer,
                                         char const * const xpath,
                                         char const * const value)
{
    int result = EINVAL;

    if (writer != NULL &&
        xpath != NULL)
    {
        xmlXPathContext * ctx = NULL;

        assert(writer->root_elt != NULL);
        assert(writer->root_elt->node != NULL);

        result = cgutils_xml_get_xpath_ctx(writer->root_elt->node,
                                           &(ctx));

        if (result == 0)
        {
            xmlNode * target_node = NULL;

            result = cgutils_xml_ctx_extract_node(ctx,
                                                  xpath,
                                                  &target_node);

            if (result == 0)
            {
                xmlNodeSetContent(target_node, (xmlChar *) value);
            }

            cgutils_xml_xpath_ctx_free(ctx), ctx = NULL;
        }
    }

    return result;
}

int cgutils_xml_writer_get_element_from_path(cgutils_xml_writer * const writer,
                                             char const * const xpath,
                                             cgutils_xml_writer_element ** const out)
{
    int result = EINVAL;

    if (writer != NULL &&
        xpath != NULL &&
        out != NULL)
    {
        xmlXPathContext * ctx = NULL;

        assert(writer->root_elt != NULL);
        assert(writer->root_elt->node != NULL);

        result = cgutils_xml_get_xpath_ctx(writer->root_elt->node,
                                           &(ctx));

        if (result == 0)
        {
            xmlNode * target_node = NULL;

            result = cgutils_xml_ctx_extract_node(ctx,
                                                  xpath,
                                                  &target_node);

            if (result == 0)
            {
                cgutils_xml_writer_element * elt = NULL;

                CGUTILS_ALLOCATE_STRUCT(elt);

                if (elt != NULL)
                {
                    result = 0;

                    elt->node = target_node;
                    elt->doc = writer;

                    *out = elt;
                }
                else
                {
                    result = ENOMEM;
                }
            }

            cgutils_xml_xpath_ctx_free(ctx), ctx = NULL;
        }
    }

    return result;
}

int cgutils_xml_writer_element_get_from_path(cgutils_xml_writer_element * const this,
                                            char const * const xpath,
                                            cgutils_xml_writer_element ** const out)
{
    int result = EINVAL;

    if (this != NULL &&
        xpath != NULL &&
        out != NULL)
    {
        xmlXPathContext * ctx = NULL;

        assert(this->node != NULL);

        result = cgutils_xml_get_xpath_ctx(this->node,
                                           &(ctx));

        if (result == 0)
        {
            xmlNode * target_node = NULL;

            result = cgutils_xml_ctx_extract_node(ctx,
                                                  xpath,
                                                  &target_node);

            if (result == 0)
            {
                cgutils_xml_writer_element * elt = NULL;

                CGUTILS_ALLOCATE_STRUCT(elt);

                if (elt != NULL)
                {
                    result = 0;

                    elt->node = target_node;
                    elt->doc = this->doc;

                    *out = elt;
                }
                else
                {
                    result = ENOMEM;
                }
            }

            cgutils_xml_xpath_ctx_free(ctx), ctx = NULL;
        }
    }

    return result;
}

int cgutils_xml_writer_element_remove_from_tree(cgutils_xml_writer_element * this)
{
    int result = EINVAL;

    if (this != NULL)
    {
        xmlUnlinkNode(this->node);
        xmlFreeNode(this->node), this->node = NULL;
        cgutils_xml_writer_element_release(this), this = NULL;
        result = 0;
    }

    return result;
}

int cgutils_xml_writer_to_doc(cgutils_xml_writer const * const writer,
                              xmlDoc ** const doc)
{
    int result = EINVAL;

    if (writer != NULL &&
        writer->doc != NULL &&
        doc != NULL)
    {
        *doc = xmlCopyDoc(writer->doc,
                          1);

        if (*doc != NULL)
        {
            result = 0;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}
