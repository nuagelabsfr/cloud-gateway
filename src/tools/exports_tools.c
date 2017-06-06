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

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_xml.h>
#include <cloudutils/cloudutils_xml_reader.h>
#include <cloudutils/cloudutils_xml_writer.h>

#include "exports_tools.h"

static int handle_options_list(cgutils_xml_writer_element * const parent,
                               char const * const str,
                               size_t const begin,
                               size_t const end)
{
    int result = 0;
    size_t options_len = end - begin;
    char * options = NULL;
    assert(parent != NULL);
    assert(str != NULL);
    assert(begin <= end);

    CGUTILS_MALLOC(options, options_len + 1, 1);

    if (options != NULL)
    {
        cgutils_xml_writer_element * options_elt = NULL;

        memcpy(options, str + begin, options_len);
        options[options_len] = '\0';

        result = cgutils_xml_writer_element_add_child(parent,
                                                      "Options",
                                                      options,
                                                      &options_elt);

        if (result == 0)
        {
            cgutils_xml_writer_element_release(options_elt), options_elt = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error adding options child: %d", result);
        }

        CGUTILS_FREE(options);
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static int parse_options(cgutils_xml_writer_element * const parent,
                         char const * const str,
                         size_t const str_size,
                         size_t * const position,
                         bool const default_options)
{
    int result = 0;
    bool finished = false;

    assert(str != NULL);
    assert(position != NULL);

    size_t pos = *position;

    for (;
         result == 0 &&
             pos < str_size;
         pos++)
    {
        char const value = str[pos];

        switch (value)
        {
        case '\\':
            pos++;
            break;
        case ')':
            finished = true;

            result = handle_options_list(parent,
                                         str,
                                         *position,
                                         pos);

            break;
        case '#':
            finished = true;
            break;
        case ' ':
            /* fall-through */
        case '\t':
        case '\n':
            if (default_options == true)
            {
                /* Special case for the infamous '-' case (default options). */
                finished = true;

                result = handle_options_list(parent,
                                             str,
                                             *position,
                                             pos);
                pos--;
            }
            break;
        default:
            break;
        }

        if (finished == true)
        {
            break;
        }
    }

    *position = pos;

    return result;
}

static int handle_new_client(cgutils_xml_writer_element * const clients,
                             char const * const str,
                             size_t const begin,
                             size_t const end,
                             cgutils_xml_writer_element ** const out)
{
    int result = 0;
    size_t host_len = end - begin;
    char * host = NULL;
    assert(clients != NULL);
    assert(str != NULL);
    assert(begin <= end);
    assert(out != NULL);

    CGUTILS_MALLOC(host, host_len + 1, 1);

    if (host != NULL)
    {
        memcpy(host, str + begin, host_len);
        host[host_len] = '\0';

        result = cgutils_xml_writer_element_add_child(clients,
                                                      "Client",
                                                      NULL,
                                                      out);
        if (result == 0)
        {
            cgutils_xml_writer_element * host_elt = NULL;

            result = cgutils_xml_writer_element_add_child(*out,
                                                          "Host",
                                                          host,
                                                          &host_elt);

            if (result == 0)
            {
                cgutils_xml_writer_element_release(host_elt), host_elt = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error adding client host child: %d", result);
            }
        }
        else
        {
            CGUTILS_ERROR("Error adding client child: %d", result);
        }

        CGUTILS_FREE(host);
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static int parse_clients(cgutils_xml_writer_element * const parent,
                         char const * const str,
                         size_t const str_size,
                         size_t * const position)
{
    int result = 0;

    assert(parent != NULL);
    assert(str != NULL);
    assert(position != NULL);

    size_t pos = *position;
    cgutils_xml_writer_element * clients = NULL;

    result = cgutils_xml_writer_element_add_child(parent,
                                                  "Clients",
                                                  NULL,
                                                  &clients);

    if (result == 0)
    {
        bool eol = false;
        bool in_comment = false;
        bool in_client_host = false;
        bool first_client = true;
        size_t client_host_pos = 0;

        for (;
             result == 0 &&
                 pos < str_size;
             pos++)
        {
            char const value = str[pos];

            if (in_comment == false)
            {
                cgutils_xml_writer_element * client = NULL;

                switch (value)
                {
                case '\n':
                    eol = true;
                    /* fall-through */
                case ' ':
                    /* fall-through */
                case '\t':
                    if (in_client_host == true)
                    {
                        first_client = false;

                         result = handle_new_client(clients,
                                                   str,
                                                   client_host_pos,
                                                   pos,
                                                   &client);

                        if (result == 0)
                        {
                            cgutils_xml_writer_element_release(client), client = NULL;
                        }

                        in_client_host = false;
                    }
                    break;
                case '\\':
                    pos++;
                    break;
                case '#':
                    in_comment = true;
                    break;
                case '(':
                    if (in_client_host == true)
                    {
                        first_client = false;

                        result = handle_new_client(clients,
                                                   str,
                                                   client_host_pos,
                                                   pos,
                                                   &client);
                        pos++;

                        if (result == 0)
                        {
                            result = parse_options(client,
                                                   str,
                                                   str_size,
                                                   &pos,
                                                   false);

                            cgutils_xml_writer_element_release(client), client = NULL;
                        }

                        in_client_host = false;
                    }
                    else
                    {
                        result = EINVAL;
                    }
                    break;
                case '-':
                    /* Special case, has to be the first client on the line
                       and does not have parenthesis around the options list.
                    */
                    if (first_client == true &&
                        in_client_host == false)
                    {
                        result = handle_new_client(clients,
                                                   str,
                                                   pos,
                                                   pos + 1,
                                                   &client);
                        first_client = false;
                        pos++;

                        if (result == 0)
                        {
                            result = parse_options(client,
                                                   str,
                                                   str_size,
                                                   &pos,
                                                   true);

                            cgutils_xml_writer_element_release(client), client = NULL;
                        }

                        in_client_host = false;
                        break;
                    }
                    /* fall-through */
                default:
                    if (in_client_host == false)
                    {
                        in_client_host = true;
                        first_client = false;
                        client_host_pos = pos;
                    }
                    break;
                }
            }
            else
            {
                if (value == '\n')
                {
                    eol = true;
                }
            }

            if (eol == true)
            {
                break;
            }
        }

        *position = pos;

        cgutils_xml_writer_element_release(clients), clients = NULL;
    }
    else
    {
        CGUTILS_ERROR("Error creating clients node: %d", result);
    }

    return result;
}

static int create_export(cgutils_xml_writer_element * const parent,
                         char const * const str,
                         size_t const begin,
                         size_t const end)
{
    int result = 0;
    assert(parent != NULL);
    assert(str != NULL);
    assert(end >= begin);
    size_t path_len = end - begin;
    char * path = NULL;

    CGUTILS_MALLOC(path, path_len + 1, 1);

    if (path != NULL)
    {
        cgutils_xml_writer_element * path_elt = NULL;

        memcpy(path, str + begin, path_len);
        path[path_len] = '\0';

        result = cgutils_xml_writer_element_add_child(parent,
                                                      "Path",
                                                      path,
                                                      &path_elt);
        if (result == 0)
        {
            cgutils_xml_writer_element_release(path_elt); path_elt = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error adding path child: %d", result);
        }

        CGUTILS_FREE(path);
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

static int parse_export(cgutils_xml_writer_element * const parent,
                        char const * const str,
                        size_t const str_size,
                        size_t * const position)
{
    int result = 0;
    bool eol = false;
    bool in_comment = false;

    assert(parent != NULL);
    assert(str != NULL);
    assert(position != NULL);

    size_t pos = *position;

    for (;
         result == 0 &&
             pos < str_size;
         pos++)
    {
        char const value = str[pos];

        if (in_comment == false)
        {
            switch (value)
            {
            case '\\':
                pos++;
                break;
            case '\n':
                eol = true;
                /* Empty clients list, just create this export */
                result = create_export(parent,
                                       str,
                                       *position,
                                       pos);
                break;
            case '#':
                in_comment = true;
                /* Empty clients list, just create this export */
                result = create_export(parent,
                                       str,
                                       *position,
                                       pos);
                break;
            case ' ':
                /* fall-through */
            case '\t':
                result = create_export(parent,
                                       str,
                                       *position,
                                       pos);
                if (result == 0)
                {
                    pos++;
                    result = parse_clients(parent,
                                           str,
                                           str_size,
                                           &pos);
                }

                eol = true;
                break;
            default:
                break;
            }
        }
        else
        {
            if (value == '\n')
            {
                eol = true;
            }
        }

        if (eol == true)
        {
            break;
        }
    }

    *position = pos;

    return result;
}

static int handle_export(cgutils_xml_writer_element * const parent,
                         char const * const str,
                         size_t const str_size,
                         size_t * const position)
{
    cgutils_xml_writer_element * export = NULL;
    int result = cgutils_xml_writer_element_add_child(parent,
                                                      "Export",
                                                      NULL,
                                                      &export);
    if (result == 0)
    {
        result = parse_export(export,
                              str,
                              str_size,
                              position);

        cgutils_xml_writer_element_release(export), export = NULL;
    }
    else
    {
        CGUTILS_ERROR("Error adding export child: %d", result);
    }

    return result;
}

static int parse_lines(char const * const str,
                       size_t const str_size,
                       cgutils_xml_writer_element * const root)
{
    int result = 0;
    enum
    {
        start_of_line = 0,
        comment = 1,
    } state = start_of_line;

    assert(str != NULL);
    assert(root != NULL);

    for (size_t pos = 0;
         result == 0 &&
             pos < str_size;
         pos++)
    {
        char const value = str[pos];

        if (state == start_of_line)
        {
            switch(value)
            {
            case ' ':
                /* fall-through */
            case '\t':
                break;
            case '\\':
                pos++;
                break;
            case '#':
                state = comment;
                break;
            case '\n':
                state = start_of_line;
                break;
            default:
                result = handle_export(root,
                                       str,
                                       str_size,
                                       &pos);
                break;
            }
        }
        else if (state == comment)
        {
            switch (value)
            {
            case'\n':
                state = start_of_line;
                break;
            default:
                break;
            }
        }
    }

    return result;
}

int exports_tools_convert_exports_to_xml(char const * const str,
                                         size_t const str_size,
                                         cgutils_xml_writer ** const out)
{
    int result = 0;

    assert(str != NULL);
    assert(out != NULL);

    result = cgutils_xml_writer_new(out);

    if (result == 0)
    {
        cgutils_xml_writer * writer = *out;
        cgutils_xml_writer_element * root = NULL;

        result = cgutils_xml_writer_create_root(writer,
                                                "Exports",
                                                &root);

        if (result == 0)
        {
            result = parse_lines(str,
                                 str_size,
                                 root);

            if (result != 0)
            {
                CGUTILS_ERROR("Error parsing lines: %d", result);
            }

            cgutils_xml_writer_element_release(root), root = NULL;
        }
        else
        {
            CGUTILS_ERROR("Error creating root: %d", result);
        }

        if (result != 0)
        {
            cgutils_xml_writer_free(*out), *out = NULL;
        }
    }

    return result;
}

static int convert_client_node_to_clients(cgutils_xml_reader const * const client,
                                          FILE * const fp)
{
    int result = 0;
    assert(client != NULL);
    assert(fp != NULL);

    char * host = NULL;

    result = cgutils_xml_reader_get_string(client,
                                           "./Host",
                                           &host);

    if (result == 0)
    {
        char * options = NULL;

        result = cgutils_xml_reader_get_string(client,
                                               "./Options",
                                               &options);

        if (result == 0)
        {
            if (strcmp(host, "-") == 0)
            {
                fprintf(fp, " -%s", options);
            }
            else
            {
                fprintf(fp, " %s(%s)", host, options);
            }

            CGUTILS_FREE(options);
        }
        else
        {
            CGUTILS_ERROR("Error getting options: %d", result);
        }

        CGUTILS_FREE(host);
    }
    else
    {
        CGUTILS_ERROR("Error getting host: %d", result);
    }

    return result;
}

static int convert_export_node_to_exports(cgutils_xml_reader * const export,
                                          FILE * const fp)
{
    int result = 0;
    assert(export != NULL);
    assert(fp != NULL);

    char * path = NULL;

    result = cgutils_xml_reader_get_string(export,
                                           "./Path",
                                           &path);

    if (result == 0)
    {
        cgutils_llist * clients = NULL;

        fprintf(fp, "%s", path);

        result = cgutils_xml_reader_get_all(export,
                                            "Clients/Client",
                                            &clients);

        if (result == 0)
        {
            for (cgutils_llist_elt * client_elt = cgutils_llist_get_first(clients);
                 client_elt != NULL &&
                     result == 0;
                 client_elt = cgutils_llist_elt_get_next(client_elt))
            {
                cgutils_xml_reader const * client = cgutils_llist_elt_get_object(client_elt);
                assert(client != NULL);

                result = convert_client_node_to_clients(client,
                                                        fp);
            }

            cgutils_llist_free(&clients, &cgutils_xml_reader_delete);
        }
        else if (result == ENOENT)
        {
            result = 0;
        }
        else
        {
            CGUTILS_ERROR("Error getting clients list: %d", result);
        }

        fputs("\n", fp);

        CGUTILS_FREE(path);
    }
    else
    {
        CGUTILS_ERROR("Error getting path: %d", result);
    }

    return result;
}

int exports_tools_convert_xml_to_exports(cgutils_xml_writer const * const writer,
                                         FILE * const fp)
{
    int result = 0;
    cgutils_xml_reader * reader = NULL;
    assert(writer != NULL);
    assert(fp != NULL);

    result = cgutils_xml_reader_from_writer(writer,
                                            &reader);

    if (result == 0)
    {
        cgutils_llist * exports = NULL;

        result = cgutils_xml_reader_get_all(reader,
                                            "Export",
                                            &exports);

        if (result == 0)
        {
            for (cgutils_llist_elt * export_elt = cgutils_llist_get_first(exports);
                 export_elt != NULL &&
                     result == 0;
                 export_elt = cgutils_llist_elt_get_next(export_elt))
            {
                cgutils_xml_reader * export = cgutils_llist_elt_get_object(export_elt);
                assert(export != NULL);

                result = convert_export_node_to_exports(export,
                                                        fp);
            }

            cgutils_llist_free(&exports, &cgutils_xml_reader_delete);
        }
        else if (result == ENOENT)
        {
            result = 0;
        }
        else
        {
            CGUTILS_ERROR("Error getting exports list: %d", result);
        }

        cgutils_xml_reader_free(reader), reader = NULL;
    }
    else
    {
        CGUTILS_ERROR("Error getting XML reader from writer: %d", result);
    }

    return result;
}

int exports_tools_save(cgutils_xml_writer const * const writer)
{
    int result = EINVAL;

    if (writer != NULL)
    {
#ifdef NDEBUG
        char template[] = "/etc/.exportsXXXXXX";
#else
        char template[] = "/tmp/.exportsXXXXXX";
#endif

        int fd = -1;

        result = cgutils_file_mkstemp(template,
                                      &fd);

        if (result == 0)
        {
            FILE * fp = NULL;

            result = cgutils_file_fdopen(fd, "w+", &fp);

            if (result == 0)
            {
                result = cgutils_file_fchown(fd,
                                             (uid_t) 0,
                                             (gid_t) 0);

                if (result == 0)
                {
                    result = cgutils_file_fchmod(fd,
                                                 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

                    if (result == 0)
                    {
                        result = exports_tools_convert_xml_to_exports(writer,
                                                                      fp);

                        if (result == 0)
                        {
                            cgutils_file_fflush(fp);

                            result = cgutils_file_rename(template,
                                                         exports_file_path);

                            if (result != 0)
                            {
                                CGUTILS_ERROR("Error overwriting /etc/exports file: %d", result);
                            }
                        }
                        else
                        {
                            CGUTILS_ERROR("Error converting back XML to exports: %d", result);
                        }
                    }
                    else
                    {
                        CGUTILS_ERROR("Error setting rights on temporary file: %d", result);
                    }
                }
                else
                {
                    CGUTILS_ERROR("Error setting ownership on temporary file: %d", result);
                }

                cgutils_file_fclose(fp), fp = NULL;
            }
            else
            {
                CGUTILS_ERROR("Error converting file descriptor to file pointer: %d", result);
                cgutils_file_close(fd), fd = -1;
            }

            if (result != 0)
            {
                cgutils_file_unlink(template);
            }
        }
        else
        {
            CGUTILS_ERROR("Error opening temporary file: %d", result);
        }
    }

    return result;
}

int exports_tools_add_export_if_not_exists(cgutils_xml_writer * const writer,
                                           char const * const path)
{
    int result = EINVAL;

    if (writer != NULL &&
        path != NULL)
    {
        char * xpath = NULL;

        result = cgutils_asprintf(&xpath,
                                  "/Exports/Export[Path='%s']",
                                  path);

        if (result == 0)
        {
            cgutils_xml_writer_element * export_elt = NULL;

            result = cgutils_xml_writer_get_element_from_path(writer,
                                                              xpath,
                                                              &export_elt);

            if (result == 0)
            {
                /* Export already exists */
                cgutils_xml_writer_element_release(export_elt), export_elt = NULL;
            }
            else if (result == ENOENT)
            {
                /* Export does not exist, creating it */
                cgutils_xml_writer_element * exports_elt = NULL;

                result = cgutils_xml_writer_get_element_from_path(writer,
                                                                  "/Exports",
                                                                  &exports_elt);

                if (result == 0)
                {
                    result = cgutils_xml_writer_element_add_child(exports_elt,
                                                                  "Export",
                                                                  NULL,
                                                                  &export_elt);

                    if (result == 0)
                    {
                        cgutils_xml_writer_element * path_elt = NULL;

                        result = cgutils_xml_writer_element_add_child(export_elt,
                                                                      "Path",
                                                                      path,
                                                                      &path_elt);

                        if (result == 0)
                        {
                            cgutils_xml_writer_element_release(path_elt), path_elt = NULL;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error creating Path element: %d", result);
                        }

                        if (result == 0)
                        {
                            cgutils_xml_writer_element * clients_elt = NULL;

                            result = cgutils_xml_writer_element_add_child(export_elt,
                                                                          "Clients",
                                                                          NULL,
                                                                          &clients_elt);

                            if (result == 0)
                            {
                                fputs("Export added.\n", stdout);

                                cgutils_xml_writer_element_release(clients_elt), clients_elt = NULL;
                            }
                            else
                            {
                                CGUTILS_ERROR("Error creating Clients element: %d", result);
                            }
                        }

                        cgutils_xml_writer_element_release(export_elt), export_elt = NULL;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating Export element: %d", result);
                    }

                    cgutils_xml_writer_element_release(exports_elt), exports_elt = NULL;
                }
                else
                {
                    CGUTILS_ERROR("Error looking for Exports element: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error looking for an export with a path of %s: %d",
                              path,
                              result);
            }

            CGUTILS_FREE(xpath);
        }
        else
        {
            CGUTILS_ERROR("Error allocating memory for xpath: %d", result);
        }
    }

    return result;
}

int exports_tools_remove_export_if_exists(cgutils_xml_writer * const writer,
                                          char const * const path)
{
    int result = EINVAL;

    if (writer != NULL &&
        path != NULL)
    {
        char * xpath = NULL;

        result = cgutils_asprintf(&xpath,
                                  "/Exports/Export[Path='%s']",
                                  path);

        if (result == 0)
        {
            cgutils_xml_writer_element * export_elt = NULL;

            result = cgutils_xml_writer_get_element_from_path(writer,
                                                              xpath,
                                                              &export_elt);

            if (result == 0)
            {
                /* Export exists */

                result = cgutils_xml_writer_element_remove_from_tree(export_elt);

                if (result == 0)
                {
                    fputs("Export removed.\n", stdout);
                }
                else
                {
                    CGUTILS_ERROR("Error removing export: %d", result);

                    cgutils_xml_writer_element_release(export_elt), export_elt = NULL;
                }
            }
            else if (result == ENOENT)
            {
                result = 0;
            }
            else
            {
                CGUTILS_ERROR("Error looking for an export with a path of %s: %d",
                              path,
                              result);
            }

            CGUTILS_FREE(xpath);
        }
        else
        {
            CGUTILS_ERROR("Error allocating memory for xpath: %d", result);
        }
    }

    return result;
}

int exports_tools_add_export_client(cgutils_xml_writer * const writer,
                                    char const * const path,
                                    char const * const host,
                                    char const * const options)
{
    int result = EINVAL;

    if (writer != NULL &&
        path != NULL &&
        host != NULL &&
        options != NULL)
    {
        char * xpath = NULL;

        result = cgutils_asprintf(&xpath,
                                  "/Exports/Export[Path='%s']",
                                  path);

        if (result == 0)
        {
            cgutils_xml_writer_element * export_elt = NULL;

            result = cgutils_xml_writer_get_element_from_path(writer,
                                                              xpath,
                                                              &export_elt);

            if (result == 0)
            {
                /* Export exists */
                cgutils_xml_writer_element * clients_elt = NULL;

                result = cgutils_xml_writer_element_get_from_path(export_elt,
                                                                  "Clients",
                                                                  &clients_elt);

                if (result == ENOENT)
                {
                    /* Clients node does not exist, creating it */
                    result = cgutils_xml_writer_element_add_child(export_elt,
                                                                  "Clients",
                                                                  NULL,
                                                                  &clients_elt);

                    if (result == 0)
                    {
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating Clients element: %d", result);
                    }
                }
                else if (result != 0)
                {
                    CGUTILS_ERROR("Error looking for clients node: %d", result);
                }

                if (result == 0)
                {
                    cgutils_xml_writer_element * client_elt = NULL;

                    result = cgutils_xml_writer_element_add_child(clients_elt,
                                                                  "Client",
                                                                  NULL,
                                                                  &client_elt);

                    if (result == 0)
                    {
                        cgutils_xml_writer_element * host_elt = NULL;

                        result = cgutils_xml_writer_element_add_child(client_elt,
                                                                      "Host",
                                                                      host,
                                                                      &host_elt);

                        if (result == 0)
                        {
                            cgutils_xml_writer_element * options_elt = NULL;

                            result = cgutils_xml_writer_element_add_child(client_elt,
                                                                          "Options",
                                                                          options,
                                                                          &options_elt);

                            if (result == 0)
                            {
                                cgutils_xml_writer_element_release(options_elt), options_elt = NULL;
                            }
                            else
                            {
                                CGUTILS_ERROR("Error creating Options element: %d", result);
                            }

                            cgutils_xml_writer_element_release(host_elt), host_elt = NULL;
                        }
                        else
                        {
                            CGUTILS_ERROR("Error creating Host element: %d", result);
                        }

                        cgutils_xml_writer_element_release(client_elt), client_elt = NULL;
                    }
                    else
                    {
                        CGUTILS_ERROR("Error creating Client element: %d", result);
                    }

                    cgutils_xml_writer_element_release(clients_elt), clients_elt = NULL;
                }

                cgutils_xml_writer_element_release(export_elt), export_elt = NULL;
            }
            else if (result == ENOENT)
            {
                fprintf(stderr, "There is no export for path %s.\n", path);
            }
            else
            {
                CGUTILS_ERROR("Error looking for an export with a path of %s: %d",
                              path,
                              result);
            }

            CGUTILS_FREE(xpath);
        }
        else
        {
            CGUTILS_ERROR("Error allocating memory for xpath: %d", result);
        }
    }

    return result;
}

int exports_tools_remove_export_client(cgutils_xml_writer * const writer,
                                       char const * const path,
                                       char const * const host)
{
    int result = EINVAL;

    if (writer != NULL &&
        path != NULL &&
        host != NULL)
    {
        char * xpath = NULL;

        result = cgutils_asprintf(&xpath,
                                  "/Exports/Export[Path='%s']/Clients/Client[Host='%s']",
                                  path,
                                  host);

        if (result == 0)
        {
            cgutils_xml_writer_element * client_elt = NULL;

            result = cgutils_xml_writer_get_element_from_path(writer,
                                                              xpath,
                                                              &client_elt);

            if (result == 0)
            {
                /* Client exists */
                result = cgutils_xml_writer_element_remove_from_tree(client_elt);

                if (result == 0)
                {
                    fputs("Client removed.\n", stdout);
                }
                else
                {
                    CGUTILS_ERROR("Error removing client: %d", result);

                    cgutils_xml_writer_element_release(client_elt), client_elt = NULL;
                }
            }
            else if (result == ENOENT)
            {
                result = 0;
            }
            else
            {
                CGUTILS_ERROR("Error looking for a client %s of export %s: %d",
                              host,
                              path,
                              result);
            }

            CGUTILS_FREE(xpath);
        }
        else
        {
            CGUTILS_ERROR("Error allocating memory for xpath: %d", result);
        }
    }

    return result;
}
