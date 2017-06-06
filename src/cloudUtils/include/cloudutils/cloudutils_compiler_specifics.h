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

#ifndef CLOUD_UTILS_COMPILER_SPECIFICS_H_
#define CLOUD_UTILS_COMPILER_SPECIFICS_H_

# ifdef __clang__
#  define COMPILER_LIKELY(x)       __builtin_expect((x),1)
#  define COMPILER_UNLIKELY(x)     __builtin_expect((x),0)
#  define COMPILER_STV_HIDDEN  __attribute__ ((__visibility__ ("hidden")))
#  define COMPILER_STV_DEFAULT __attribute__ ((__visibility__ ("default")))
#  define COMPILER_PURE_FUNCTION __attribute__ ((pure))
#  define COMPILER_CONST_FUNCTION __attribute__ ((const))
#  define COMPILER_CONSTRUCTOR_FUNCTION __attribute__((constructor))
#  define COMPILER_DESTRUCTOR_FUNCTION __attribute__((destructor))
#  define COMPILER_PRAGMA(val) _Pragma(#val)
#  define COMPILER_BLOCK_VISIBILITY_DEFAULT COMPILER_PRAGMA(GCC visibility push(default))
#  define COMPILER_BLOCK_VISIBILITY_HIDDEN COMPILER_PRAGMA(GCC visibility push(hidden))
#  define COMPILER_BLOCK_VISIBILITY_END COMPILER_PRAGMA(GCC visibility pop)
#  define COMPILER_DIAG_OFF(val) COMPILER_PRAGMA(GCC diagnostic ignored val)
#  define COMPILER_DIAG_ON(val) COMPILER_PRAGMA(GCC diagnostic warning val)
#  define COMPILER_DIAG_PUSH COMPILER_PRAGMA(GCC diagnostic push)
#  define COMPILER_DIAG_POP COMPILER_PRAGMA(GCC diagnostic pop)
#  define COMPILER_FALLTHROUGH
#  if __has_extension(c_static_assert)
#   define COMPILER_STATIC_ASSERT(cond, msg) _Static_assert((cond), msg)
#  endif /* __has_feature(c_static_assert) */
# elif defined __GNUC__
#  if __GNUC__ > 2
#   define COMPILER_LIKELY(x)       __builtin_expect((x),1)
#   define COMPILER_UNLIKELY(x)     __builtin_expect((x),0)
#   define COMPILER_CONSTRUCTOR_FUNCTION __attribute__((constructor))
#   define COMPILER_DESTRUCTOR_FUNCTION __attribute__((destructor))
#   if __GNUC__ >= 4
#    define COMPILER_STV_HIDDEN  __attribute__ ((__visibility__ ("hidden")))
#    define COMPILER_STV_DEFAULT __attribute__ ((__visibility__ ("default")))
#    define COMPILER_PURE_FUNCTION __attribute__ ((pure))
#    define COMPILER_CONST_FUNCTION __attribute__ ((const))
#    define COMPILER_PRAGMA(val) _Pragma(#val)
#    define COMPILER_BLOCK_VISIBILITY_DEFAULT COMPILER_PRAGMA(GCC visibility push(default))
#    define COMPILER_BLOCK_VISIBILITY_HIDDEN COMPILER_PRAGMA(GCC visibility push(hidden))
#    define COMPILER_BLOCK_VISIBILITY_END COMPILER_PRAGMA(GCC visibility pop)
#    if (__GNUC__ > 4 || ( __GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#     define COMPILER_STATIC_ASSERT(cond, msg) _Static_assert((cond), msg)
/* Diag ON / OFF exists in GCC 4.2+, but is useless without push / pop */
#     define COMPILER_DIAG_OFF(val) COMPILER_PRAGMA(GCC diagnostic ignored val)
#     define COMPILER_DIAG_ON(val) COMPILER_PRAGMA(GCC diagnostic warning val)
#     define COMPILER_DIAG_PUSH COMPILER_PRAGMA(GCC diagnostic push)
#     define COMPILER_DIAG_POP COMPILER_PRAGMA(GCC diagnostic pop)
#    endif /* GCC >= 4.6 */
#   endif /* __GNUC__ >= 4 */
#  endif /* __GNUC__ > 2 */
#  if __GNUC__ >= 7
#   define COMPILER_FALLTHROUGH __attribute__ ((fallthrough))
#  else
#   define COMPILER_FALLTHROUGH
#  endif /* __GNUC__ >= 7 */
# endif /* __GNUC__ */

#define COMPILER_SYNC_VAL_COMPARE_AND_SWAP(ptr, oldval, newval) \
    __sync_val_compare_and_swap(ptr, oldval, newval)

#define COMPILER_SYNC_BOOL_COMPARE_AND_SWAP(ptr, oldval, newval) \
    __sync_bool_compare_and_swap(ptr, oldval, newval)

# ifndef COMPILER_LIKELY
#  define COMPILER_LIKELY(x)
# endif /* COMPILER_LIKELY */

# ifndef COMPILER_UNLIKELY
#  define COMPILER_UNLIKELY(x)
# endif /* COMPILER_UNLIKELY */

# ifndef CGUTILS_COMPILER_LIKELY
#  define CGUTILS_COMPILER_LIKELY(x) COMPILER_LIKELY(x)
# endif /* CGUTILS_COMPILER_LIKELY */

# ifndef CGUTILS_COMPILER_UNLIKELY
#  define CGUTILS_COMPILER_UNLIKELY(x) COMPILER_UNLIKELY(x)
# endif /* CGUTILS_COMPILER_UNLIKELY */

# ifndef COMPILER_STV_HIDDEN
#  define COMPILER_STV_HIDDEN
# endif /* COMPILER_STV_HIDDEN */

# ifndef COMPILER_STV_DEFAULT
#  define COMPILER_STV_DEFAULT
# endif /* COMPILER_STV_DEFAULT */

# ifndef COMPILER_PURE_FUNCTION
#  define COMPILER_PURE_FUNCTION
# endif /* COMPILER_PURE_FUNCTION */

# ifndef COMPILER_CONST_FUNCTION
#  define COMPILER_CONST_FUNCTION
# endif /* COMPILER_CONST_FUNCTION */

# ifndef COMPILER_CONSTRUCTOR_FUNCTION
#  define COMPILER_CONSTRUCTOR_FUNCTION
# endif /* COMPILER_CONSTRUCTOR_FUNCTION */

# ifndef COMPILER_DESTRUCTOR_FUNCTION
#  define COMPILER_DESTRUCTOR_FUNCTION
# endif /* COMPILER_DESTRUCTOR_FUNCTION */

# ifndef COMPILER_PURE_FUNCTION
#  define COMPILER_PURE_FUNCTION
# endif /* COMPILER_PURE_FUNCTION */

# ifndef COMPILER_PRAGMA
#  define COMPILER_PRAGMA(val)
# endif /* COMPILER_PRAGMA */

# ifndef COMPILER_BLOCK_VISIBILITY_DEFAULT
#  define COMPILER_BLOCK_VISIBILITY_DEFAULT
# endif /* COMPILER_BLOCK_VISIBILITY_DEFAULT */

# ifndef COMPILER_BLOCK_VISIBILITY_HIDDEN
#  define COMPILER_BLOCK_VISIBILITY_HIDDEN
# endif /* COMPILER_BLOCK_VISIBILITY_HIDDEN */

# ifndef COMPILER_BLOCK_VISIBILITY_END
#  define COMPILER_BLOCK_VISIBILITY_END
# endif /* COMPILER_BLOCK_VISIBILITY_END */

# ifndef COMPILER_STATIC_ASSERT
#  define COMPILER_STATIC_ASSERT(cond, msg)
# endif /* COMPILER_STATIC_ASSERT */

# ifndef COMPILER_DIAG_OFF
#  define COMPILER_DIAG_OFF(val)
# endif /* COMPILER_DIAG_OFF */

# ifndef COMPILER_DIAG_ON
#  define COMPILER_DIAG_ON(val)
# endif /* COMPILER_DIAG_ON */

# ifndef COMPILER_DIAG_POP
#  define COMPILER_DIAG_POP
# endif /* COMPILER_DIAG_POP */

# ifndef COMPILER_DIAG_PUSH
#  define COMPILER_DIAG_PUSH
# endif /* COMPILER_DIAG_PUSH */

#endif /* CLOUD_UTILS_COMPILER_SPECIFICS_H_ */
