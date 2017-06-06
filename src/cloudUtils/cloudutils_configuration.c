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
#include <strings.h>

#include "cloudutils/cloudutils.h"
#include "cloudutils/cloudutils_configuration.h"
#include "cloudutils/cloudutils_file.h"
#include "cloudutils/cloudutils_xml.h"
#include "cloudutils/cloudutils_xml_reader.h"

struct cgutils_configuration
{
    cgutils_xml_reader * reader;
};

static int cgutils_configuration_from_xml_reader(cgutils_xml_reader * const reader,
                                                 cgutils_configuration ** const out)
{
    assert(reader != NULL);
    assert(out != NULL);

    int result = 0;

    CGUTILS_ALLOCATE_STRUCT(*out);

    if (*out != NULL)
    {
        (*out)->reader = reader;
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

int cgutils_configuration_init(void)
{
    return cgutils_xml_reader_init();
}

void cgutils_configuration_destroy(void)
{
    cgutils_xml_reader_destroy();
}

int cgutils_configuration_from_xml_file(char const * const file,
                                        cgutils_configuration ** const out)
{
    int result = EINVAL;

    if (file != NULL && out != NULL)
    {
        cgutils_xml_reader * reader = NULL;

        result = cgutils_xml_reader_from_file(file, &reader);

        if (result == 0)
        {
            result = cgutils_configuration_from_xml_reader(reader, out);

            if (result != 0)
            {
                cgutils_xml_reader_free(reader);
            }
        }
    }

    return result;
}

int cgutils_configuration_from_xml_memory(char const * const xml,
                                          size_t const xml_size,
                                          cgutils_configuration ** const out)
{
    int result = EINVAL;

    if (xml != NULL && xml_size > 0 && out != NULL)
    {
        cgutils_xml_reader * reader = NULL;

        result = cgutils_xml_reader_from_buffer(xml, xml_size, &reader);

        if (result == 0)
        {
            result = cgutils_configuration_from_xml_reader(reader, out);

            if (result != 0)
            {
                cgutils_xml_reader_free(reader);
            }
        }
    }

    return result;
}

int cgutils_configuration_from_path(cgutils_configuration const * const config,
                                    char const * const path,
                                    cgutils_configuration ** const out)
{
    int result = EINVAL;

    if (config != NULL && path != NULL && out != NULL)
    {
        assert(config->reader != NULL);
        cgutils_xml_reader * new_reader = NULL;

        result = cgutils_xml_reader_from_path(config->reader,
                                               path,
                                               &new_reader);

        if (result == 0)
        {
            result = cgutils_configuration_from_xml_reader(new_reader, out);

            if (result != 0)
            {
                cgutils_xml_reader_free(new_reader), new_reader = NULL;
            }
        }
    }

    return result;
}

int cgutils_configuration_get_all(cgutils_configuration const * const config,
                                  char const * const path,
                                  cgutils_llist ** const confs_list)
{
    int result = EINVAL;

    if (config != NULL && path != NULL && confs_list != NULL)
    {
        assert(config->reader != NULL);

        result = cgutils_llist_create(confs_list);

        if (result == 0)
        {
            cgutils_llist * readers = NULL;

            result = cgutils_xml_reader_get_all(config->reader, path, &readers);

            if (result == 0)
            {
                assert(readers != NULL);

                cgutils_llist_elt * elt = cgutils_llist_get_iterator(readers);

                while (result == 0 && elt != NULL)
                {
                    cgutils_xml_reader * const reader = cgutils_llist_elt_get_object(elt);
                    assert(reader != NULL);

                    cgutils_configuration * new = NULL;

                    result = cgutils_configuration_from_xml_reader(reader, &new);

                    if (result == 0)
                    {
                        result = cgutils_llist_insert(*confs_list, new);

                        if (result != 0)
                        {
                            cgutils_configuration_free(new), new = NULL;
                        }
                    }
                    else
                    {
                        cgutils_xml_reader_free(reader);
                    }

                    elt = cgutils_llist_elt_get_next(elt);
                }

                if (result != 0)
                {
                    while(elt != NULL)
                    {
                        cgutils_xml_reader * const reader = cgutils_llist_elt_get_object(elt);
                        assert(reader != NULL);

                        cgutils_xml_reader_free(reader);
                        elt = cgutils_llist_elt_get_next(elt);
                    }
                }

                cgutils_llist_free(&readers, NULL);
            }

            if (result != 0)
            {
                cgutils_llist_free(confs_list, &cgutils_configuration_delete);
            }
        }
    }

    return result;
}

int cgutils_configuration_get_string(cgutils_configuration const * const config,
                                     char const * const path,
                                     char ** const out)
{
    int result = EINVAL;

    if (config != NULL && path != NULL && out != NULL)
    {
        assert(config->reader != NULL);

        result = cgutils_xml_reader_get_string(config->reader,
                                               path,
                                               out);
    }

    return result;
}


int cgutils_configuration_get_boolean(cgutils_configuration const * config,
                                      char const * path,
                                      bool * out)
{
    int result = EINVAL;

    if (config != NULL && path != NULL && out != NULL)
    {
        assert(config->reader != NULL);

        result = cgutils_xml_reader_get_boolean(config->reader,
                                                path,
                                                out);
    }

    return result;
}


int cgutils_configuration_get_unsigned_integer(cgutils_configuration const * const config,
                                               char const * const path,
                                               uint64_t * const out)
{
    int result = EINVAL;

    if (config != NULL && path != NULL && out != NULL)
    {
        assert(config->reader != NULL);

        result = cgutils_xml_reader_get_unsigned_integer(config->reader,
                                                         path,
                                                         out);
    }

    return result;
}

int cgutils_configuration_get_size(cgutils_configuration const * const config,
                                   char const * const path,
                                   size_t * const out)
{
    int result = EINVAL;

    if (config != NULL && path != NULL && out != NULL)
    {
        assert(config->reader != NULL);

        result = cgutils_xml_reader_get_size(config->reader,
                                             path,
                                             out);
    }

    return result;
}

int cgutils_configuration_get_integer(cgutils_configuration const * const config,
                                      char const * const path,
                                      int64_t * const out)
{
    int result = EINVAL;

    if (config != NULL && path != NULL && out != NULL)
    {
        assert(config->reader != NULL);

        result = cgutils_xml_reader_get_integer(config->reader,
                                                 path,
                                                 out);
    }

    return result;
}

void cgutils_configuration_free(cgutils_configuration * config)
{
    if (config != NULL)
    {
        if (config->reader != NULL)
        {
            cgutils_xml_reader_free(config->reader);
        }

        CGUTILS_FREE(config);
    }
}

void cgutils_configuration_delete(void * config)
{
    cgutils_configuration_free(config);
}
