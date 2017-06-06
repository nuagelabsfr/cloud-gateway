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

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_regex.h>

#include <errno.h>
#include <sys/types.h>
#include <regex.h>

int cgutils_regex_validate(char const * const str,
                           char const * const pattern)
{
    int result = EINVAL;

    if (str != NULL &&
        pattern != NULL)
    {
        regex_t preg = (regex_t) { 0 };

        int const error_code = regcomp(&preg,
                                       pattern,
                                       REG_EXTENDED | REG_NOSUB);

        if (error_code == 0)
        {
            result = regexec(&preg,
                             str,
                             0,
                             NULL,
                             0);

            if (result != 0)
            {
                result = EINVAL;
            }

            regfree(&preg);
        }
        else
        {
            char static_buffer[128] = { 0 };
            static size_t const static_buffer_size = sizeof static_buffer;

            size_t needed = regerror(error_code, NULL, static_buffer, static_buffer_size);

            if (needed > static_buffer_size)
            {
                char * buffer = NULL;
                CGUTILS_MALLOC(buffer, needed, 1);

                if (buffer != NULL)
                {
                    regerror(result, NULL, buffer, needed);
                    CGUTILS_ERROR("Error compiling regex %s: %s",
                                  pattern,
                                  buffer);
                    CGUTILS_FREE(buffer);
                }
                else
                {
                    result = ENOMEM;
                }
            }
            else
            {
                CGUTILS_ERROR("Error compiling regex %s: %s",
                              pattern,
                              static_buffer);
            }
        }
    }

    return result;
}
