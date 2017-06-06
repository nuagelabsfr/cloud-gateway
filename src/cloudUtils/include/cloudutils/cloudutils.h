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

#ifndef CLOUD_UTILS_H_
#define CLOUD_UTILS_H_

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <cloudutils/cloudutils_compiler_specifics.h>

#define CGUTILS_INIT_STRUCT(pointer) *(pointer) = (typeof (*(pointer))) { 0 }

#define CGUTILS_FREE(pointer) free(pointer), (pointer) = NULL

#define CGUTILS_MALLOC(pointer, count, size) (pointer) = malloc((count) * (size))

#define CGUTILS_REALLOC(newpointer, oldpointer, count, size) (newpointer) = realloc((oldpointer), (count) * (size))

#define CGUTILS_ALLOCATE_STRUCT(pointer)        \
    do                                          \
    {                                           \
        (pointer) = malloc(sizeof *(pointer));  \
        if ((pointer) != NULL)                  \
        {                                       \
            CGUTILS_INIT_STRUCT(pointer);       \
        }                                       \
    }                                           \
    while (0)

#define CGUTILS_DEBUGF(level, ...)                                      \
    do {                                                                \
        cgutils_debugf_real(__FILE__, __LINE__, __func__, level, __VA_ARGS__); \
    }                                                                   \
    while(0)
#define CGUTILS_INFO(...)  CGUTILS_DEBUGF("info ", __VA_ARGS__)
#define CGUTILS_WARN(...)  CGUTILS_DEBUGF("warn ", __VA_ARGS__)
#define CGUTILS_ERROR(...) CGUTILS_DEBUGF("error", __VA_ARGS__)

#ifndef NDEBUG
#ifndef __clang_analyzer__
#define CGUTILS_ASSERT(cond)                            \
    do                                                  \
    {                                                   \
        if ((cond) == false)                            \
        {                                               \
            int * const cgutils_assert_ptr = NULL;              \
            CGUTILS_ERROR("Assertion failure: %s", #cond);      \
            *cgutils_assert_ptr = 1;                            \
        }                                                       \
    }                                                           \
    while (0);
#else /* __clang_analyzer__ */
#define CGUTILS_ASSERT(cond) assert(cond)
#endif /* __clang_analyzer__ */
#else /* NDEBUG */
#define CGUTILS_ASSERT(cond)
#endif /* NDEBUG */

#ifdef CGUTILS_DEBUG_ENABLE
#if CGUTILS_DEBUG_ENABLE
#define CGUTILS_DEBUG(...) CGUTILS_DEBUGF("debug", __VA_ARGS__)
#endif /* CGUTILS_DEBUG_ENABLE */
#endif /* CGUTILS_DEBUG_ENABLE */

#ifndef CGUTILS_DEBUG
#define CGUTILS_DEBUG(...)
#endif /* CGUTILS_DEBUG */

#ifdef CGUTILS_TRACE_ENABLE
#if CGUTILS_TRACE_ENABLE
#define CGUTILS_TRACE(...) CGUTILS_DEBUGF("trace", __VA_ARGS__)
#endif /* CGUTILS_TRACE_ENABLE */
#endif /* CGUTILS_TRACE_ENABLE */

#ifndef CGUTILS_TRACE
#define CGUTILS_TRACE(...)
#endif /* CGUTILS_TRACE */

#ifndef CGUTILS_TYPE_SIGNED
#define CGUTILS_TYPE_SIGNED(t) (! ((t) 0 < (t) -1))
#endif

#ifndef CGUTILS_TYPE_MINIMUM
#define CGUTILS_TYPE_MINIMUM(t) ((t) (CGUTILS_TYPE_SIGNED (t) \
                              ? ~ (t) 0 << (sizeof (t) * CHAR_BIT - 1) : (t) 0))
#endif

#ifndef CGUTILS_TYPE_MAXIMUM
#define CGUTILS_TYPE_MAXIMUM(t) ((t) (~ (t) 0 - CGUTILS_TYPE_MINIMUM (t)))
#endif

COMPILER_BLOCK_VISIBILITY_DEFAULT

void cgutils_debugf_real(char const * file,
                         int line,
                         char const * function,
                         char const * level,
                         char const * format,
                         ...) __attribute__ ((__format__(printf, 5, 6)));

typedef void (*cgutils_object_cleaner)(void *);

int cgutils_asprintf(char ** strp,
                     char const * fmt,
                     ...) __attribute__ ((__format__(printf, 2, 3)));



int cgutils_str_tolower(char const * str,
                        char ** out);

char * cgutils_strdup(char const * str);

char * cgutils_strndup(char const * str,
                       size_t str_size);

unsigned int cgutils_get_random_number_r(unsigned int * seed,
                                         unsigned int max);

int cgutils_get_local_date_str_buf(char * str,
                                   size_t str_size,
                                   size_t * out_size);

int cgutils_get_local_date_str(char ** str,
                               size_t * str_len);

int cgutils_get_date_str(char ** str,
                         size_t * str_len);

size_t cgutils_get_next_log10(size_t number);

uint64_t cgutils_ntohll(uint64_t from) COMPILER_CONST_FUNCTION;
uint32_t cgutils_ntohl(uint32_t from) COMPILER_CONST_FUNCTION;
uint16_t cgutils_ntohs(uint16_t from) COMPILER_CONST_FUNCTION;
uint64_t cgutils_htonll(uint64_t from) COMPILER_CONST_FUNCTION;
uint32_t cgutils_htonl(uint32_t from) COMPILER_CONST_FUNCTION;
uint16_t cgutils_htons(uint16_t from) COMPILER_CONST_FUNCTION;

int cgutils_str_to_unsigned_int64(char const * str_val,
                                  uint64_t * out);

int cgutils_time_from_str(char const * str,
                          time_t * out);

int cgutils_time_to_str(time_t date,
                        char ** out);

void cgutils_debug_printn(char const * str,
                          size_t str_size);

typedef enum
{
    CLOUDUTILS_ANSI_COLOR_ATTR_RESET=0,
    CLOUDUTILS_ANSI_COLOR_ATTR_BRIGHT=1,
    CLOUDUTILS_ANSI_COLOR_ATTR_DIM=2,
    CLOUDUTILS_ANSI_COLOR_ATTR_ITALIC=3,
    CLOUDUTILS_ANSI_COLOR_ATTR_UNDERLINE=4,
    CLOUDUTILS_ANSI_COLOR_ATTR_BLINK_SLOW=5,
    CLOUDUTILS_ANSI_COLOR_ATTR_BLINK_FAST=6,
    CLOUDUTILS_ANSI_COLOR_ATTR_REVERSE=7,
    CLOUDUTILS_ANSI_COLOR_ATTR_HIDDEN=8
} cloudutils_ansi_color_attr;

typedef enum
{
    CLOUDUTILS_ANSI_COLOR_BLACK=0,
    CLOUDUTILS_ANSI_COLOR_RED=1,
    CLOUDUTILS_ANSI_COLOR_GREEN=2,
    CLOUDUTILS_ANSI_COLOR_YELLOW=3,
    CLOUDUTILS_ANSI_COLOR_BLUE=4,
    CLOUDUTILS_ANSI_COLOR_MAGENTA=5,
    CLOUDUTILS_ANSI_COLOR_CYAN=6,
    CLOUDUTILS_ANSI_COLOR_WHITE=7
} cloudutils_ansi_color;

#define cgutils_set_color(fd, attr, fg, bg)             \
    fprintf(fd,                                         \
            "\x1b[%"PRIu8";%"PRIu8";%"PRIu8"m",         \
            attr,                                       \
            fg + 30,                                    \
            bg + 40                                     \
        );

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_H_ */
