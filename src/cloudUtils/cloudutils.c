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
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cloudutils/cloudutils.h>

#if 0
int cgutils_init_all(void)
{
    int result = cgutils_crypto_init();

    if (result == 0)
    {
        result = cgutils_xml_init();

        if (result == 0)
        {
            result = cgutils_configuration_init();

            if (result == 0)
            {
                result = cgutils_http_init();
            }
        }
    }

    return result;
}

void cgutils_destroy_all(void)
{
    cgutils_http_destroy();
    cgutils_configuration_destroy();
    cgutils_xml_destroy();
    cgutils_crypto_destroy();
}
#endif /* 0 */

int cgutils_time_to_str(time_t const date,
                        char ** const out)
{
    int result = EINVAL;

    if (out != NULL)
    {
        static size_t const max_size = 255;

        CGUTILS_MALLOC(*out, max_size, 1);

        if (*out != NULL)
        {
            struct tm res = { 0 };

            localtime_r(&date, &res);

            size_t out_size = strftime(*out,
                                       max_size - 1,
                                       "%d/%m/%Y %H:%M:%S",
                                       &res);

            if (out_size > 0)
            {
                if (out_size < max_size)
                {
                    (*out)[out_size] = '\0';
                }

                result = 0;
            }
            else
            {
                result = EINVAL;
            }

            if (result != 0)
            {
                CGUTILS_FREE(*out);
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

int cgutils_get_local_date_str_buf(char * const str,
                                   size_t const str_size,
                                   size_t * const out_size)
{
    int result = EINVAL;

    if (str != NULL &&
        str_size > 0 &&
        out_size != NULL)
    {
        time_t cur_time = time(NULL);
        struct tm res = { 0 };

        localtime_r(&cur_time, &res);

        *out_size = strftime(str,
                             str_size - 1,
                             "%a %b %d %H:%M:%S %Y",
                             &res);

        if (*out_size > 0)
        {
            if (*out_size < str_size)
            {
                str[*out_size] = '\0';
            }

            result = 0;
        }
        else
        {
            result = EINVAL;
        }
    }

    return result;
}

int cgutils_get_local_date_str(char ** const str,
                               size_t * const str_len)
{
    int result = EINVAL;

    if (str != NULL && str_len != NULL)
    {
        static size_t const max_size = 255;

        CGUTILS_MALLOC(*str, max_size, 1);

        if (*str != NULL)
        {
            result = cgutils_get_local_date_str_buf(*str,
                                                    max_size,
                                                    str_len);
            if (result != 0)
            {
                CGUTILS_FREE(*str);
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

#define MIN_CTIME_SIZE 27

void cgutils_debugf_real(char const * file,
                         int const line,
                         char const * const function,
                         char const * level,
                         char const * const format,
                         ...)
{
    if (file != NULL && function != NULL && level != NULL && format != NULL)
    {
        size_t const file_len = strlen(file);

        char buffer[MIN_CTIME_SIZE];
        size_t buffer_size = 0;

        int result = cgutils_get_local_date_str_buf(buffer,
                                                    MIN_CTIME_SIZE,
                                                    &buffer_size);

        if (result == 0)
        {
            if (file_len > 0)
            {
                size_t file_pos = file_len - 1;

                while(file_pos > 0 && file[file_pos] != '/')
                {
                    file_pos--;
                }

                if (file_pos > 0)
                {
                    file += file_pos + 1;
                }
            }

            pid_t const pid = getpid();

            fprintf(stderr, "[%s] [%s] {%lld} [%s(%d) %s] ",
                    buffer, level, (long long) pid, file, line, function);

            va_list params;
            va_start(params, format);
            vfprintf(stderr, format, params);
            va_end(params);

            fputs("\n", stderr);
            fflush(stderr);
        }
    }
}

int cgutils_asprintf(char ** const strp,
                     char const * const fmt,
                     ...)
{
    assert(strp != NULL);
    assert(fmt != NULL);

    va_list params;
    va_start(params, fmt);
    int result = vasprintf(strp, fmt, params);
    va_end(params);

    if (result > -1)
    {
        result = 0;
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

int cgutils_str_tolower(char const * const str,
                        char ** const out)
{
    int result = EINVAL;

    if (str != NULL && out != NULL)
    {
        size_t const str_len = strlen(str);
        result = 0;

        if (str_len > 0)
        {
            CGUTILS_MALLOC(*out, str_len + 1, 1);

            if (*out != NULL)
            {
                for(size_t idx = 0; result == 0 && idx <= str_len; idx++)
                {
                    int const lower = tolower(str[idx]);

                    if (lower != EOF)
                    {
                        (*out)[idx] = (char) lower;
                    }
                    else
                    {
                        result = EINVAL;
                    }
                }

                if (result != 0)
                {
                    CGUTILS_FREE(*out);
                }
            }
            else
            {
                result = ENOMEM;
            }
        }
    }

    return result;
}

char * cgutils_strdup(char const * const str)
{
    char * result = NULL;

    if (str != NULL)
    {
        size_t const len = strlen(str);

        CGUTILS_MALLOC(result, len + 1, 1);

        if (result != NULL)
        {
            memcpy(result, str, len);
            result[len] = '\0';
        }
    }

    return result;
}

char * cgutils_strndup(char const * const str,
                       size_t const str_size)
{
    char * result = NULL;

    if (str != NULL && str_size > 0)
    {
        CGUTILS_MALLOC(result, str_size + 1, 1);

        if (result != NULL)
        {
            memcpy(result, str, str_size);
            result[str_size] = '\0';
        }
    }

    return result;
}

unsigned int cgutils_get_random_number_r(unsigned int * const seed,
                                         unsigned int const max)
{
    unsigned int const util_part_size = 1 + (max >= RAND_MAX ? 0 : (RAND_MAX - max) / (max + 1));
    unsigned int const max_useful_value = util_part_size * max + (util_part_size - 1);

    int alea = 0;

    do
    {
        alea = rand_r(seed);
    }
    while (alea > 0 && (unsigned int) alea > max_useful_value);

    return (unsigned int) alea / util_part_size;
}

int cgutils_get_date_str(char ** const str,
                         size_t * const str_len)
{
    int result = EINVAL;

    if (str != NULL && str_len != NULL)
    {
        static size_t const max_size = 255;

        CGUTILS_MALLOC(*str, max_size, 1);

        if (*str != NULL)
        {
            time_t cur_time = time(NULL);
            struct tm res = { 0 };

            gmtime_r(&cur_time, &res);

            *str_len = strftime(*str, max_size - 1,
                                "%a, %d %b %Y %H:%M:%S GMT",
                                &res);

            if (*str_len > 0)
            {
                if (*str_len < max_size)
                {
                    (*str)[*str_len] = '\0';
                }

                result = 0;
            }
            else
            {
                result = EINVAL;
                CGUTILS_FREE(*str);
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

size_t cgutils_get_next_log10(size_t const number)
{
    size_t result = 0;
    long double nb_double = number;

    long double res = log10l(nb_double);

    result = (size_t) res;
    result++;

    return result;
}

uint64_t cgutils_ntohll(uint64_t const from)
{
    uint64_t result = 0;
#if __BYTE_ORDER != __BIG_ENDIAN
    result = (((uint64_t) htonl((uint32_t)from)) << 32) + htonl((uint32_t) (from >> 32));
#else /* __BYTE_ORDER == __BIG_ENDIAN */
    result = from;
#endif /* __BYTE_ORDER == __BIG_ENDIAN */
    return result;
}

uint32_t cgutils_ntohl(uint32_t const from)
{
    return htonl(from);
}

uint16_t cgutils_ntohs(uint16_t const from)
{
    return ntohs(from);
}

uint64_t cgutils_htonll(uint64_t const from)
{
    return cgutils_ntohll(from);
}

uint32_t cgutils_htonl(uint32_t const from)
{
    return cgutils_ntohl(from);
}

uint16_t cgutils_htons(uint16_t const from)
{
    return cgutils_ntohs(from);
}

int cgutils_str_to_unsigned_int64(char const * const str_val,
                                  uint64_t * const out)
{
    int result = EINVAL;

    if (str_val != NULL && out != NULL)
    {
        long long int val = 0;
        char *endptr;

        errno = 0;
        val = strtoll(str_val, &endptr, 10);

        /* Check for various possible errors */
        if ((errno == ERANGE && (val == LLONG_MAX || val == LLONG_MIN))
            || (errno != 0 && val == 0))
        {
            result = ERANGE;
        }
        else if (endptr == str_val)
        {
            result = ENOENT;
        }
        else if (val < 0 || (unsigned long long) val > UINT64_MAX)
        {
            result = ENOENT;
        }
        else
        {
            result = 0;
            *out = (unsigned long long) val;
        }
    }

    return result;
}

int cgutils_time_from_str(char const * const str,
                          time_t * const out)
{
    int result = EINVAL;

    if (str != NULL && out != NULL)
    {
        uint64_t temp = 0;

        result = cgutils_str_to_unsigned_int64(str, &temp);

        if (result == 0)
        {
            *out = (time_t) temp;
        }
    }

    return result;
}

void cgutils_debug_printn(char const * const str,
                          size_t const str_size)
{
    if (str != NULL && str_size > 0)
    {
        for (size_t idx = 0;
             idx < str_size;
             idx++)
        {
            fprintf(stderr, "%c", str[idx]);
        }

        fputs("\n", stderr);
    }
}
