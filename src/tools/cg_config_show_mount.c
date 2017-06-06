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

/*
   -f --file Configuration File to update
*/

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_xml.h>
#include <cloudutils/cloudutils_xml_reader.h>

static void print_usage(void)
{
    fprintf(stderr, "Usage: CloudGatewayShowMount [OPTIONS]\n");
    fprintf(stderr, "Required options are:\n");
#define ITEM(longname, variable, shortname, xmlname, required, expl)     \
    if (required == true)                                       \
    {                                                           \
        fprintf(stderr, "\t-%c --%-35s %s\n", shortname, longname, expl);  \
    }
#include "cg_config_show_mount.itm"
#undef ITEM
    fprintf(stderr, "Please look at the product documentation for more information.\n");
}

static void print_mount(cgutils_xml_reader * const mount)
{
    static struct
    {
        char const * const print_name;
        char const * const xpath;
    }
    const values[] =
        {
            { "Filesystem Id", "FileSystemID"},
            { "Mount Point", "MountPoint"},
            { "Path Max", "PathMax"},
            { "Name Max", "NameMax"},
            { "Symlink Max", "SymlinkMax"},
            { "Retry Count", "RetryCount"},
            { "Dirtyness Delay", "DirtynessDelay"},
            { "NFS Export", "NFSExport"},
            { "Storage Manager Socket", "StorageManagerSocket"},
        };
    static size_t const values_count = sizeof values / sizeof *values;
    char * value = NULL;
    int res = 0;

    assert(mount != NULL);

    for (size_t idx = 0;
         idx < values_count;
         idx++)
    {
        res = cgutils_xml_reader_get_string(mount,
                                            values[idx].xpath,
                                            &value);

        if (res == 0)
        {
            fprintf(stdout, "%s: %s\n",
                    values[idx].print_name,
                    value);
            CGUTILS_FREE(value);
        }
        else if (res != ENOENT)
        {
            fprintf(stderr, "Error getting value for %s: %s\n",
                    values[idx].print_name,
                    strerror(res));
        }
    }
}

int main (int argc, char **argv)
{

#define ITEM(longname, variable, shortname, xmlname, required, expl) char * variable = NULL;
#include "cg_config_show_mount.itm"
#undef ITEM

    static struct option const long_options[] =
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl) { longname, required_argument, NULL, shortname },
#include "cg_config_show_mount.itm"
#undef ITEM
            { 0, 0, 0, 0 }
        };

    int result = 0;
    int indexptr = 0;

    opterr = 1;

    while ((result = getopt_long(argc,
                                 argv,
                                 "+f:",
                                 long_options,
                                 &indexptr)) != -1)
    {
        switch(result)
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl)  \
            case shortname:                                           \
                variable = optarg;                                    \
                break;
#include "cg_config_show_mount.itm"
#undef ITEM
        default:
            print_usage();
        }

    }

    if (optind == argc)
    {
        if (file != NULL)
        {
            cgutils_xml_reader * reader = NULL;

            cgutils_xml_init();

            result = cgutils_xml_reader_from_file(file,
                                                  &reader);

            if (result == 0)
            {
                cgutils_xml_reader * mount = NULL;

                result = cgutils_xml_reader_from_path(reader,
                                                      "/Configuration",
                                                      &mount);

                if (result == 0)
                {
                    print_mount(mount);

                    cgutils_xml_reader_free(mount), mount = NULL;
                }
                else if (result == ENOENT)
                {
                    fprintf(stderr, "This does not seem to be a valid mount point configuration file.\n");
                }
                else
                {
                    fprintf(stderr, "Error looking for a mount point configuration: %s\n",
                            strerror(result));
                }

                cgutils_xml_reader_free(reader), reader = NULL;
            }
            else
            {
                fprintf(stderr, "Error opening file %s: %s\n",
                        file,
                        strerror(result));
            }

            cgutils_xml_destroy();
        }
        else
        {
            result = EINVAL;
            fprintf(stderr, "File parameter is mandatory.\n");
            print_usage();
        }
    }
    else
    {
        result = EINVAL;
        fprintf(stderr, "Too many arguments\n");
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
