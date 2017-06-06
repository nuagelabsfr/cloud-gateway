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

#include <ctype.h>
#include <errno.h>
#include <time.h>

#include "cloudutils/cloudutils.h"
#include "cloudutils/cloudutils_xml.h"
#include "cloudutils/cloudutils_xml_internals.h"

#include <libxml/c14n.h>
#include <libxml/xpathInternals.h>

int cgutils_xml_init(void)
{
    xmlInitParser();
    LIBXML_TEST_VERSION;

    return 0;
}

void cgutils_xml_destroy(void)
{
    xmlCleanupParser();
}

int cgutils_xml_get_xpath_ctx(xmlNode * const node,
                              xmlXPathContext ** const ctx)
{
    int result = EINVAL;

    if(node != NULL && ctx != NULL)
    {
        xmlDoc const * const doc = node->doc;
        *ctx = xmlXPathNewContext((xmlDoc *)doc);

        if (*ctx != NULL)
        {
            result = 0;
            (*ctx)->node = node;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

void cgutils_xml_xpath_ctx_free(xmlXPathContext * ctx)
{
    if (ctx != NULL)
    {
        xmlXPathFreeContext(ctx), ctx = NULL;
    }
}

int cgutils_xml_ctx_register_namespace(xmlXPathContext * const ctx,
                                       char const * const prefix,
                                       char const * const namespace)
{
    int result = EINVAL;

    if (ctx != NULL && prefix != NULL && namespace != NULL)
    {
        result = xmlXPathRegisterNs(ctx, BAD_CAST prefix, BAD_CAST namespace);

        if (result == -1)
        {
            result = EINVAL;
        }
    }

    return result;
}

int cgutils_xml_ctx_extract_node(xmlXPathContext * const ctx,
                                 char const * const xpath_str,
                                 xmlNode ** const object)
{
    int result = EINVAL;

    if (ctx != NULL && xpath_str != NULL && object != NULL)
    {
        xmlXPathObject * xpath_object = xmlXPathEvalExpression(BAD_CAST xpath_str, ctx);

        if (xpath_object != NULL)
        {
            xmlNodeSet * ns = xpath_object->nodesetval;

            if (ns != NULL)
            {
                if (ns->nodeNr == 1)
                {
                    result = 0;
                    *object = ns->nodeTab[0];
                }
                else if (ns->nodeNr == 0)
                {
                    result = ENOENT;
                }
                else
                {
                    result = EINVAL;
                }
            }
            else
            {
                result = ENOENT;
            }

            xmlXPathFreeObject(xpath_object), xpath_object = NULL;
        }
        else
        {
            result = ENOENT;
        }
    }

    return result;
}

int cgutils_xml_ctx_extract_nodeset(xmlXPathContext * const ctx,
                                    char const * const xpath_str,
                                    xmlXPathObject ** const object)
{
    int result = EINVAL;

    if (ctx != NULL && xpath_str != NULL && object != NULL)
    {
        *object = xmlXPathEvalExpression(BAD_CAST xpath_str, ctx);

        if (*object != NULL)
        {
            result = 0;
        }
        else
        {
            result = ENOENT;
        }
    }

    return result;
}

int cgutils_xml_ctx_extract_unsigned_integer(xmlXPathContext * const ctx,
                                             char const * const xpath,
                                             uint64_t * const value)
{
    int result = EINVAL;

    if (ctx != NULL && xpath != NULL && value != NULL)
    {
        xmlNode * object = NULL;

        result = cgutils_xml_ctx_extract_node(ctx,
                                              xpath,
                                              &object);

        if (result == 0)
        {
            double number = xmlXPathCastNodeToNumber(object);

            if (number >= 0 && number <= UINT64_MAX)
            {
                result = 0;
                *value = (uint64_t) number;
            }
            else
            {
                result = E2BIG;
            }
        }
    }

    return result;
}

int cgutils_xml_ctx_extract_integer(xmlXPathContext * const ctx,
                                    char const * const xpath,
                                    int64_t * const value)
{
    int result = EINVAL;

    if (ctx != NULL && xpath != NULL && value != NULL)
    {
        xmlNode * object = NULL;

        result = cgutils_xml_ctx_extract_node(ctx,
                                              xpath,
                                              &object);

        if (result == 0)
        {
            double number = xmlXPathCastNodeToNumber(object);

            if (number >= INT64_MIN && number <= INT64_MAX)
            {
                result = 0;
                *value = (int64_t) number;
            }
            else
            {
                result = E2BIG;
            }
        }
    }

    return result;
}

int cgutils_xml_ctx_extract_size(xmlXPathContext * const ctx,
                                 char const * const xpath,
                                 size_t * const value)
{
    int result = EINVAL;

    if (ctx != NULL && xpath != NULL && value != NULL)
    {
        xmlNode * object = NULL;

        result = cgutils_xml_ctx_extract_node(ctx,
                                              xpath,
                                              &object);

        if (result == 0)
        {
            double number = xmlXPathCastNodeToNumber(object);

            if (number >= 0 && number <= SIZE_MAX)
            {
                result = 0;
                *value = (size_t) number;
            }
            else
            {
                result = E2BIG;
            }
        }
    }

    return result;
}

int cgutils_xml_ctx_extract_string(xmlXPathContext * const ctx,
                                   char const * const xpath,
                                   char ** const value)
{
    int result = EINVAL;

    if (ctx != NULL && xpath != NULL && value != NULL)
    {
        xmlNode * object = NULL;

        result = cgutils_xml_ctx_extract_node(ctx,
                                              xpath,
                                              &object);

        if (result == 0)
        {
            *value = (char *) xmlXPathCastNodeToString(object);

            if (*value != NULL)
            {
                result = 0;
            }
            else
            {
                result = ENOENT;
            }
        }
    }
    return result;
}

int cgutils_xml_extract_node(xmlNode * const node,
                             char const * const xpath_str,
                             xmlNode ** const object)
{
    int result = EINVAL;

    if (node != NULL && xpath_str != NULL && object != NULL)
    {
        xmlXPathContext * xpath_ctx = NULL;
        result = cgutils_xml_get_xpath_ctx(node, &xpath_ctx);

        if (result == 0)
        {
            result = cgutils_xml_ctx_extract_node(xpath_ctx, xpath_str, object);
            cgutils_xml_xpath_ctx_free(xpath_ctx), xpath_ctx = NULL;
        }
    }

    return result;
}

int cgutils_xml_extract_nodeset(xmlNode * const node,
                                char const * const xpath_str,
                                xmlXPathObject ** const object)
{
    int result = EINVAL;

    if (node != NULL && xpath_str != NULL && object != NULL)
    {
        xmlXPathContext * xpath_ctx = NULL;
        result = cgutils_xml_get_xpath_ctx(node, &xpath_ctx);

        if (result == 0)
        {
            result = cgutils_xml_ctx_extract_nodeset(xpath_ctx, xpath_str, object);
            cgutils_xml_xpath_ctx_free(xpath_ctx), xpath_ctx = NULL;
        }
    }

    return result;
}

int cgutils_xml_extract_unsigned_integer(xmlNode * const node,
                                         char const * const xpath,
                                         uint64_t * const value)
{
    int result = EINVAL;

    if (node != NULL && xpath != NULL && value != NULL)
    {
        xmlXPathContext * xpath_ctx = NULL;
        result = cgutils_xml_get_xpath_ctx(node, &xpath_ctx);

        if (result == 0)
        {
            result = cgutils_xml_ctx_extract_unsigned_integer(xpath_ctx, xpath, value);
            cgutils_xml_xpath_ctx_free(xpath_ctx), xpath_ctx = NULL;
        }
    }

    return result;
}

int cgutils_xml_extract_integer(xmlNode * const node,
                                char const * const xpath,
                                int64_t * const value)
{
    int result = EINVAL;

    if (node != NULL && xpath != NULL && value != NULL)
    {
        xmlXPathContext * xpath_ctx = NULL;
        result = cgutils_xml_get_xpath_ctx(node, &xpath_ctx);

        if (result == 0)
        {
            result = cgutils_xml_ctx_extract_integer(xpath_ctx, xpath, value);
            cgutils_xml_xpath_ctx_free(xpath_ctx), xpath_ctx = NULL;
        }
    }

    return result;
}

int cgutils_xml_extract_size(xmlNode * const node,
                             char const * const xpath,
                             size_t * const value)
{
    int result = EINVAL;

    if (node != NULL && xpath != NULL && value != NULL)
    {
        xmlXPathContext * xpath_ctx = NULL;
        result = cgutils_xml_get_xpath_ctx(node, &xpath_ctx);

        if (result == 0)
        {
            result = cgutils_xml_ctx_extract_size(xpath_ctx, xpath, value);
            cgutils_xml_xpath_ctx_free(xpath_ctx), xpath_ctx = NULL;
        }
    }

    return result;
}

int cgutils_xml_extract_string(xmlNode * const node,
                               char const * const xpath,
                               char ** const value)
{
    int result = EINVAL;

    if (node != NULL && xpath != NULL && value != NULL)
    {
        xmlXPathContext * xpath_ctx = NULL;
        result = cgutils_xml_get_xpath_ctx(node, &xpath_ctx);

        if (result == 0)
        {
            result = cgutils_xml_ctx_extract_string(xpath_ctx, xpath, value);
            cgutils_xml_xpath_ctx_free(xpath_ctx), xpath_ctx = NULL;
        }
    }

    return result;
}

int cgutils_xml_get_c14n_string(xmlDoc * const doc,
                                xmlNode * const node,
                                char ** const out,
                                size_t * const out_len)
{
    int result = EINVAL;

    if (doc != NULL && node != NULL && out != NULL && out_len != NULL)
    {
        /* We create a temporary doc with the wanted node
           as the root in order not to have to list all nodes. */
        xmlDoc * tmp_doc = xmlNewDoc((xmlChar *) "1.0");

        if (tmp_doc != NULL)
        {
            /* Kids, don't do this at home. */
            xmlNode * next = node->next;
            node->next = NULL;
            xmlSetTreeDoc(node, tmp_doc);
            tmp_doc->children = node;
            tmp_doc->last = node;

            int res = xmlC14NDocDumpMemory(tmp_doc,
                                           NULL,
                                           XML_C14N_EXCLUSIVE_1_0,
                                           NULL,
                                           0,
                                           (xmlChar **) out);

            if (res > 0)
            {
                result = 0;
                *out_len = (size_t) res;
            }
            else
            {
                result = EIO;
            }

            /* Kids, don't do this at home. */
            node->next = next;
            xmlSetTreeDoc(node, doc);
            tmp_doc->children = NULL;
            tmp_doc->last= NULL;

            xmlFreeDoc(tmp_doc);
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_xml_time_from_str(char const * const str,
                              time_t * const out)
{
    int result = EINVAL;

    if (str != NULL && out != NULL)
    {
        struct tm tv = (struct tm) { 0 };

        char const * ptr = strptime(str,
                                    "%Y-%m-%dT%T",
                                    &tv);

        if (ptr != NULL)
        {
            if (*ptr == '.')
            {
                /* skip micro seconds in \.[0-9]* form, because who cares? */
                ptr++;

                while (isdigit(*ptr) != 0)
                {
                    ptr++;
                }
            }

            /* If we have a timezone, other than 'Z' */
            if (*ptr == '+' ||
                *ptr == '-')
            {
                bool const negative = (*ptr == '-');
                ptr++;
                size_t count = 0;
                ssize_t hours = 0;
                ssize_t min = 0;

                while (count < 2 && isdigit(*ptr) != 0)
                {
                    hours = hours * 10 + (ssize_t) (*ptr - '0');
                    ptr++;
                }

                if (*ptr == ':')
                {
                    ptr++;
                }

                count = 0;

                while (count < 2 && isdigit(*ptr) != 0)
                {
                    min = min * 10 + (ssize_t) (*ptr - '0');
                    ptr++;
                }

                if (negative == true)
                {
                    hours = -hours;
                    min = -min;
                }

                tv.tm_hour -= (int) hours;
                tv.tm_min -= (int) min;
            }

            *out = timegm(&tv);

            if (*out != (time_t) -1)
            {
                result = 0;
            }
        }
        else
        {
            result = EINVAL;
            *out = (time_t) -1;
        }
    }

    return result;
}

int cgutils_xml_reader_from_writer(cgutils_xml_writer const * const writer,
                                   cgutils_xml_reader ** const out)
{
    int result = EINVAL;

    if (writer != NULL &&
        out != NULL)
    {
        xmlDoc * doc = NULL;

        result = cgutils_xml_writer_to_doc(writer,
                                           &doc);

        if (result == 0)
        {
            result =  cgutils_xml_reader_from_doc(doc,
                                                  out);

            if (result != 0)
            {
                xmlFreeDoc(doc), doc = NULL;
            }
        }
    }

    return result;
}
