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
   -i --instance-name Instance Name (required)
   -f --file Configuration File to read
   -I --in Encrypted file to read
   -O --out Decrypted file
*/

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <cgsm/cg_storage_filter.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_configuration.h>
#include <cloudutils/cloudutils_crypto.h>
#include <cloudutils/cloudutils_file.h>

#define BUFFER_SIZE (16 * 1024)

static void print_usage(void)
{
    fprintf(stderr, "Usage: CloudGatewayDecryptFile [OPTIONS]\n");
    fprintf(stderr, "Required options are:\n");
#define ITEM(longname, variable, shortname, xmlname, required, expl)     \
    if (required == true)                                       \
    {                                                           \
        fprintf(stderr, "\t-%c --%-35s %s\n", shortname, longname, expl);  \
    }
#include "cg_decrypt_file.itm"
#undef ITEM
    fprintf(stderr, "Please look at the product documentation for more information.\n");
}

static int cg_config_decrypt_file_write_to_file(int const out_fd,
                                                char const * const buffer,
                                                size_t const buffer_size)
{
    int result = 0;
    size_t pos = 0;
    CGUTILS_ASSERT(out_fd != -1);
    CGUTILS_ASSERT(buffer != NULL);

    while (result == 0 &&
           pos < buffer_size)
    {
        size_t written = 0;

        result = cgutils_file_write(out_fd,
                                    buffer + pos,
                                    buffer_size - pos,
                                    &written);

        if (COMPILER_LIKELY(result == 0))
        {
            if (COMPILER_LIKELY(written > 0))
            {
                pos += (size_t) written;
            }
        }
        else if (result == EINTR)
        {
            result = 0;
        }
        else
        {
            fprintf(stderr, "Error while writing to file: %s\n",
                    strerror(result));
        }
    }

    return result;
}

static int cg_config_decrypt_file_do(cg_storage_filter * const filter,
                                     char const * const encrypted_file_path,
                                     char const * const decrypted_file_path)
{
    int result = 0;

    CGUTILS_ASSERT(filter != NULL);
    CGUTILS_ASSERT(encrypted_file_path != NULL);
    CGUTILS_ASSERT(decrypted_file_path != NULL);

    cg_storage_filter_ctx * ctx = NULL;

    result = cg_storage_filter_ctx_init(filter,
                                        cg_storage_filter_dec,
                                        &ctx);

    if (result == 0)
    {
        int in_fd = -1;

        result = cgutils_file_open(encrypted_file_path,
                                   O_RDONLY,
                                   0,
                                   &in_fd);

        if (result == 0)
        {
            int out_fd = -1;

            result = cgutils_file_open(decrypted_file_path,
                                       O_WRONLY|O_TRUNC|O_CREAT,
                                       S_IRUSR | S_IWUSR,
                                       &out_fd);

            if (result == 0)
            {
                char buffer[BUFFER_SIZE];
                size_t const buffer_size = sizeof buffer;
                char * out = NULL;
                size_t out_size = 0;
                bool finished = false;

                do
                {
                    size_t got = 0;

                    result = cgutils_file_read(in_fd,
                                               buffer,
                                               buffer_size,
                                               &got);

                    if (COMPILER_LIKELY(result == 0))
                    {
                        if (COMPILER_LIKELY(got > 0))
                        {
                            result = cg_storage_filter_do(ctx,
                                                          buffer,
                                                          got,
                                                          &out,
                                                          &out_size);

                            if (COMPILER_LIKELY(result == 0))
                            {
                                if (out_size > 0)
                                {
                                    result = cg_config_decrypt_file_write_to_file(out_fd,
                                                                                  out,
                                                                                  out_size);
                                }

                                CGUTILS_FREE(out);
                                out_size = 0;
                            }
                            else
                            {
                                fprintf(stderr, "Filter error: %s\n",
                                        strerror(result));
                            }
                        }
                        else if (got == 0)
                        {
                            finished = true;
                        }
                    }
                    else if (result != EINTR)
                    {
                        fprintf(stderr,
                                "Error while reading: %s\n",
                                strerror(result));
                    }
                    else
                    {
                        result = 0;
                    }
                }
                while (result == 0 &&
                       finished == false);

                if (result == 0)
                {
                    result = cg_storage_filter_finish(ctx,
                                                      &out,
                                                      &out_size);

                    if (result == 0)
                    {
                        if (out_size > 0)
                        {
                            result = cg_config_decrypt_file_write_to_file(out_fd,
                                                                          out,
                                                                          out_size);
                        }

                        CGUTILS_FREE(out);
                        out_size = 0;
                    }
                    else
                    {
                        fprintf(stderr,
                                "Error finishing filter: %s\n",
                                strerror(result));
                    }
                }

                cgutils_file_close(out_fd), out_fd = -1;
            }
            else
            {
                fprintf(stderr,
                        "Error opening file %s: %s\n",
                        decrypted_file_path,
                        strerror(result));
            }

            cgutils_file_close(in_fd), in_fd = -1;
        }
        else
        {
            fprintf(stderr,
                    "Error opening file %s: %s\n",
                    encrypted_file_path,
                    strerror(result));
        }

        cg_storage_filter_ctx_free(ctx), ctx = NULL;
    }
    else
    {
        fprintf(stderr,
                "Error in filter ctx init: %s\n",
                strerror(result));
    }

    return result;
}

int main (int argc, char **argv)
{

#define ITEM(longname, variable, shortname, xmlname, required, expl) char * variable = NULL;
#include "cg_decrypt_file.itm"
#undef ITEM

    static struct option const long_options[] =
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl) { longname, required_argument, NULL, shortname },
#include "cg_decrypt_file.itm"
#undef ITEM
            { 0, 0, 0, 0 }
        };

    int result = 0;
    int indexptr = 0;

    opterr = 1;

    while ((result = getopt_long(argc,
                                 argv,
                                 "+i:f:I:O:",
                                 long_options,
                                 &indexptr)) != -1)
    {
        switch(result)
        {
#define ITEM(longname, variable, shortname, xmlname, required, expl)  \
            case shortname:                                           \
                variable = optarg;                                    \
                break;
#include "cg_decrypt_file.itm"
#undef ITEM
        default:
            print_usage();
        }

    }

    if (optind == argc)
    {
        if (instance_name != NULL &&
            file != NULL &&
            in_file != NULL &&
            out_file != NULL)
        {
            cgutils_configuration * configuration = NULL;

            cgutils_crypto_init();
            cgutils_configuration_init();

            result = cgutils_configuration_from_xml_file(file,
                                                         &configuration);

            if (result == 0)
            {
                char * xpath = NULL;

                result = cgutils_asprintf(&xpath,
                                          "/Configuration/Instances/Instance[Name='%s']/Filters/Filter[Type='Encryption']/Specifics",
                                          instance_name);

                if (result == 0)
                {
                    char * filters_path = NULL;

                    result = cgutils_configuration_get_string(configuration,
                                                              "General/FiltersPath",
                                                              &filters_path);

                    if (result == 0)
                    {
                        cgutils_configuration * filter_specifics = NULL;

                        result = cgutils_configuration_from_path(configuration,
                                                                 xpath,
                                                                 &filter_specifics);

                        if (result == 0)
                        {
                            cg_storage_filter * filter = NULL;

                            result = cg_storage_filter_init("encryption",
                                                            filters_path,
                                                            filter_specifics,
                                                            &filter);

                            if (result == 0)
                            {
                                result = cg_config_decrypt_file_do(filter, in_file, out_file);

                                cg_storage_filter_free(filter), filter = NULL;
                            }
                            else
                            {
                                fprintf(stderr, "Error in filter initialization: %s\n",
                                        strerror(result));
                            }


                            cgutils_configuration_free(filter_specifics), filter_specifics = NULL;
                        }
                        else if (result == ENOENT)
                        {
                            fprintf(stderr, "There is no instance named %s with a valid encryption filter.\n",
                                    instance_name);
                        }
                        else
                        {
                            fprintf(stderr, "Error looking for an instance named %s with a valid encryption filter: %s\n",
                                    instance_name,
                                    strerror(result));
                        }

                        CGUTILS_FREE(xpath);
                    }
                    else
                    {
                        fprintf(stderr, "Error allocating memory for XPath expression: %s\n",
                                strerror(result));
                    }

                    CGUTILS_FREE(filters_path);
                }
                else
                {
                    fprintf(stderr, "Error looking for the 'General/FiltersPath' parameter in the configuration file: %s\n",
                            strerror(result));
                }

                cgutils_configuration_free(configuration), configuration = NULL;
            }
            else
            {
                fprintf(stderr, "Error opening file %s: %s\n",
                        file,
                        strerror(result));
            }

            cgutils_crypto_destroy();
            cgutils_configuration_destroy();
        }
        else
        {
            result = EINVAL;
            fprintf(stderr, "Name and file parameters are mandatory.\n");
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
