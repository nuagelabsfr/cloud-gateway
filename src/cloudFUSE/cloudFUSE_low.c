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

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUSE_USE_VERSION 29
#include <fuse/fuse_lowlevel.h>

#include "cgfs_async.h"

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_event.h>
#include <cloudutils/cloudutils_file.h>
#include <cloudutils/cloudutils_process.h>

/* Used by the kernel to know for how long attributes can be cached.
   The cache is invalidated by fuse_invalidate_attr()
   on open / truncate / fallocate / read / write anyway.
   In seconds.
*/
#define CGFUSE_ATTR_TIMEOUT (60.0)
/* Same for the directory entries (dentry),
   invalidated by fuse_invalidate_entry_cache()
   on unlink / rmdir / rename / ..
   In seconds.
*/
#define CGFUSE_ENTRY_TIMEOUT (60.0)

static void cgfuse_init(void * const userdata,
                        struct fuse_conn_info * const conn)
{
    (void) userdata;
    (void) conn;
}

static void cgfuse_destroy(void * const userdata)
{
    (void) userdata;
}

static cgfs_file_handler * cgfuse_get_file_handler(struct fuse_file_info const * const fi)
{
    cgfs_file_handler * result = NULL;
    COMPILER_STATIC_ASSERT(sizeof(void *) <= sizeof(uint64_t),
                           "Pointer should fit in an unsigned 64 bits integer");
    CGUTILS_ASSERT(fi != NULL);

#if (SIZE_MAX == UINT32_MAX)
    result = (void *) (uint32_t) fi->fh;
#elif (SIZE_MAX == UINT64_MAX)
    result = (void *) fi->fh;
#else
#error "Sizeof (void *) is neither 32 nor 64"
#endif

    return result;
}

static void cgfuse_set_file_handler(struct fuse_file_info * const fi,
                                    cgfs_file_handler * const file_handler)
{
    COMPILER_STATIC_ASSERT(sizeof(void *) <= sizeof(uint64_t),
                           "Pointer should fit in an unsigned 64 bits integer");
    CGUTILS_ASSERT(fi != NULL);
#if (SIZE_MAX == UINT32_MAX)
    fi->fh = (uint64_t) ((uint32_t) file_handler);
#elif (SIZE_MAX == UINT64_MAX)
    fi->fh = (uint64_t) file_handler;
#else
#error "Sizeof (void *) is neither 32 nor 64"
#endif
}

static void cgfuse_fill_reply_entry(struct fuse_entry_param * const params,
                                    cgfs_inode * const inode)
{
    CGUTILS_ASSERT(params != NULL);

    if (inode != NULL)
    {
        params->ino = cgfs_inode_get_number(inode);
        params->attr = inode->attr;
    }
    else
    {
        params->ino = 0;
    }

    /* Generation number for this entry */
    params->generation = 1;
    /* Validity timeout (in seconds) for the attributes */
    params->attr_timeout = CGFUSE_ATTR_TIMEOUT;
    /* Validity timeout (in seconds) for the name */
    params->entry_timeout = CGFUSE_ENTRY_TIMEOUT;
}

static void cgfuse_reply_entry(fuse_req_t const req,
                               cgfs_inode * const inode)
{
    int result = 0;
    CGUTILS_ASSERT(req != NULL);

    struct fuse_entry_param params = (struct fuse_entry_param) { 0 };

    cgfuse_fill_reply_entry(&params,
                            inode);

    result = fuse_reply_entry(req,
                              &params);

    if (COMPILER_LIKELY(result == 0))
    {
        cgfs_inode_inc_lookup_count(inode);
    }
    else
    {
        fprintf(stderr,
                "%s: error while sending response for request %p: %d\n",
                __func__,
                req,
                -result);
    }
}

static void cgfuse_reply_entry_cb(void * const req,
                                  cgfs_inode * const inode)
{
    cgfuse_reply_entry(req, inode);
}

static void cgfuse_reply_create(fuse_req_t const req,
                                cgfs_inode * const inode,
                                struct fuse_file_info const * const fi)
{
    int result = 0;
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(inode != NULL);
    CGUTILS_ASSERT(fi != NULL);

    struct fuse_entry_param params = (struct fuse_entry_param) { 0 };

    cgfuse_fill_reply_entry(&params,
                            inode);

    result = fuse_reply_create(req,
                               &params,
                               fi);


    if (COMPILER_LIKELY(result == 0))
    {
        cgfs_inode_inc_lookup_count(inode);
    }
    else
    {
        fprintf(stderr,
                "%s: error while sending response for request %p: %d\n",
                __func__,
                req,
                -result);
    }
}

static void cgfuse_reply_create_cb(void * const req,
                                 cgfs_inode * const inode,
                                 cgfs_file_handler * const file_handler)
{
    CGUTILS_ASSERT(req != NULL);
    struct fuse_file_info fi = (struct fuse_file_info) { 0 };

    cgfuse_set_file_handler(&fi, file_handler);
    /* There is no content modification from outside of
       the mounted filesystem, so the content may be cached
       by the kernel. */
    fi.keep_cache = 1;

    cgfuse_reply_create(req,
                        inode,
                        &fi);
}

static void cgfuse_reply_err(fuse_req_t const req,
                             int const status)
{
    CGUTILS_ASSERT(req != NULL);

    int result = fuse_reply_err(req,
                                status);

    if (COMPILER_UNLIKELY(result != 0))
    {
        fprintf(stderr,
                "%s: error while sending status %d for request %p: %d\n",
                __func__,
                status,
                req,
                -result);
    }
}

static void cgfuse_err_cb(int const error,
                          void * const cb_data)
{
    cgfuse_reply_err(cb_data,
                     error);
}

static void cgfuse_reply_attr(fuse_req_t const req,
                              cgfs_inode * inode)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(inode != NULL);

    int result = fuse_reply_attr(req,
                                 &(inode->attr),
                                 CGFUSE_ATTR_TIMEOUT);

    if (COMPILER_LIKELY(result != 0))
    {
        fprintf(stderr,
                "%s: error while sending attr reply for request %p: %d\n",
                __func__,
                req,
                -result);
    }
}

static void cgfuse_reply_attr_cb(void * const req,
                                 cgfs_inode * const inode)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(inode != NULL);

    cgfuse_reply_attr(req, inode);
}

static void cgfuse_reply_none(fuse_req_t const req)
{
    CGUTILS_ASSERT(req != NULL);
    fuse_reply_none(req);
}

static void cgfuse_reply_open(fuse_req_t const req,
                              struct fuse_file_info const * const fi)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(fi != NULL);

    int result = fuse_reply_open(req,
                                 fi);

    if (COMPILER_UNLIKELY(result != 0))
    {
        fprintf(stderr,
                "%s: error while sending open reply for request %p: %d\n",
                __func__,
                req,
                -result);
    }
}

static void cgfuse_reply_open_cb(void * const req,
                                 cgfs_file_handler * const file_handler)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(file_handler != NULL);
    struct fuse_file_info fi = (struct fuse_file_info) { 0 };

    cgfuse_set_file_handler(&fi, file_handler);
    /* There is no content modification from outside of
       the mounted filesystem, so the content may be cached
       by the kernel. */
    fi.keep_cache = 1;

    cgfuse_reply_open(req, &fi);
}

static void cgfuse_reply_write(fuse_req_t const req,
                               size_t const count)
{
    CGUTILS_ASSERT(req != NULL);
    int result = fuse_reply_write(req,
                                  count);

    if (COMPILER_UNLIKELY(result != 0))
    {
        fprintf(stderr,
                "%s: error while sending write reply of %zu for request %p: %d\n",
                __func__,
                count,
                req,
                -result);
    }
}

static void cgfuse_reply_write_cb(void * const req,
                                  size_t const written)
{
    CGUTILS_ASSERT(req != NULL);
    cgfuse_reply_write(req, written);
}

static void cgfuse_reply_readlink(fuse_req_t const req,
                                  char const * const link_to)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(link_to != NULL);

    int result = fuse_reply_readlink(req,
                                     link_to);

    if (COMPILER_UNLIKELY(result != 0))
    {
        fprintf(stderr,
                "%s: error while sending readlink reply (%s) for request %p: %d\n",
                __func__,
                link_to,
                req,
                -result);
    }
}

static void cgfuse_reply_readlink_cb(void * const req,
                                     char const * const link_to)
{
    cgfuse_reply_readlink(req,
                          link_to);
}

#if 0
static void cgfuse_reply_xattr(fuse_req_t const req,
                               size_t const count)
{
    CGUTILS_ASSERT(req != NULL);

    int result = fuse_reply_xattr(req,
                                  count);

    if (COMPILER_UNLIKELY(result != 0))
    {
        fprintf(stderr,
                "%s: error while sending xattr reply (%zu) for request %p: %d\n",
                __func__,
                count,
                req,
                -result);
    }
}
#endif /* 0 */

static void cgfuse_reply_statfs(fuse_req_t const req,
                                struct statvfs const * const stbuf)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(stbuf != NULL);

    int result = fuse_reply_statfs(req,
                                   stbuf);

    if (COMPILER_UNLIKELY(result != 0))
    {
        fprintf(stderr,
                "%s: error while sending statfs reply for request %p: %d\n",
                __func__,
                req,
                -result);
    }
}

static void cgfuse_reply_statfs_cb(void * const req,
                                   struct statvfs const * const stbuf)
{
    cgfuse_reply_statfs(req, stbuf);
}

#if 0
/* Reply with data from a buffer, cannot be spliced. */
static void cgfuse_reply_buf(fuse_req_t const req,
                              char const * const buffer,
                              size_t const buffer_size)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(buffer != NULL);

}
#endif /* 0 */

static void cgfuse_reply_empty_buf(fuse_req_t const req)
{
    CGUTILS_ASSERT(req != NULL);

    fuse_reply_buf(req, NULL, 0);
}

#if 0
/* Reply with data from memory or FD, can be spliced. */
/* != fuse_reply_buf uses a memory buffer, cannot be spliced. */
static void cgfuse_reply_data_fd(fuse_req_t const req,
                                 int const fd,
                                 off_t const position,
                                 size_t const size)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(fd != -1);

    struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
    buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
    buf.buf[0].fd = fd;
    buf.buf[0].pos = position;

    int result = fuse_reply_data(req,
                                 &buf,
                                 FUSE_BUF_SPLICE_NONBLOCK);

    if (COMPILER_UNLIKELY(result != 0))
    {
        fprintf(stderr,
                "%s: error while sending data for request %p: %d\n",
                __func__,
                req,
                -result);
    }
}
#endif /* 0 */

static void cgfuse_reply_data_mem(fuse_req_t const req,
                                  void const * const data,
                                  size_t const size)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(data != NULL);

    struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
    buf.buf[0].mem = (char *) data;

    int result = fuse_reply_data(req,
                                 &buf,
                                 FUSE_BUF_SPLICE_NONBLOCK);

    if (COMPILER_UNLIKELY(result != 0))
    {
        fprintf(stderr,
                "%s: error while sending data for request %p: %d\n",
                __func__,
                req,
                -result);
    }
}

static void cgfuse_reply_data_mem_cb(void * const req,
                                     void * buffer,
                                     size_t const buffer_size)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(buffer != NULL || buffer_size == 0);

    cgfuse_reply_data_mem(req,
                          buffer,
                          buffer_size);
}

static void cgfuse_forget_internal(fuse_ino_t const ino,
                                   unsigned long const nlookup)
{
    /* this function should decrement the lookup count by nlookup.
       If zero is reached, the inode may be expunged from the cache. */
    CGUTILS_ASSERT(ino > 0);
    CGUTILS_ASSERT(nlookup > 0);

    cgfs_async_forget_inode(cgfs_get_data(),
                            ino,
                            nlookup);
}

static void cgfuse_lookup(fuse_req_t const req,
                          fuse_ino_t const parent,
                          char const * const name)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(parent > 0);
    CGUTILS_ASSERT(name != NULL);

    cgfs_async_lookup(cgfs_get_data(),
                      parent,
                      name,
                      &cgfuse_reply_entry_cb,
                      &cgfuse_err_cb,
                      req);
}

static void cgfuse_forget(fuse_req_t const req,
                          fuse_ino_t const ino,
                          unsigned long const nlookup)
{
    cgfuse_forget_internal(ino,
                           nlookup);

    cgfuse_reply_none(req);
}

static void cgfuse_forget_multi(fuse_req_t const req,
                                size_t const count,
                                struct fuse_forget_data * const forgets)
{
    for (size_t idx = 0;
         idx < count;
         idx++)
    {
        cgfuse_forget_internal(forgets[idx].ino,
                               forgets[idx].nlookup);
    }

    cgfuse_reply_none(req);
}

static void cgfuse_getattr(fuse_req_t const req,
                           fuse_ino_t const ino,
                           struct fuse_file_info * const fi)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(ino > 0);

    /* As of version 2.9.3, fi is always NULL: "Reserved for future use" */
    (void) fi;

    cgfs_async_getattr(cgfs_get_data(),
                       ino,
                       &cgfuse_reply_attr_cb,
                       &cgfuse_err_cb,
                       req);

}

static void cgfuse_setattr(fuse_req_t const req,
                           fuse_ino_t const ino,
                           struct stat * const attr,
                           int const to_set,
                           struct fuse_file_info * const fi)
{
    cgfs_file_handler * file_handler = NULL;
    int cgfs_to_set = 0;
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(ino > 0);
    CGUTILS_ASSERT(attr != NULL);

    if (COMPILER_UNLIKELY(fi != NULL))
    {
        /* If the setattr was invoked from the ftruncate() system call under Linux kernel versions 2.6.15 or later,
           the fi->fh will contain the value set by the open method or
           will be undefined if the open method didn't set any value.
           Otherwise (not ftruncate call, or kernel version earlier than 2.6.15) the fi parameter will be NULL. */

        file_handler = cgfuse_get_file_handler(fi);
    }

    /* In the 'attr' argument only members indicated by the 'to_set' bitmask contain valid values.
       Other members contain undefined values.

      to_set:
#define FUSE_SET_ATTR_MODE      (1 << 0)
#define FUSE_SET_ATTR_UID       (1 << 1)
#define FUSE_SET_ATTR_GID       (1 << 2)
#define FUSE_SET_ATTR_SIZE      (1 << 3)
#define FUSE_SET_ATTR_ATIME     (1 << 4)
#define FUSE_SET_ATTR_MTIME     (1 << 5)
#define FUSE_SET_ATTR_ATIME_NOW (1 << 7)
#define FUSE_SET_ATTR_MTIME_NOW (1 << 8)
    */

    /* FUSE_SET_ATTR_SIZE is equivalent to a truncate
       (ie, the cache file should be altered too, and the inode should be marked dirty). */

#define CONVERT_FUSE_TO_CGFS_ATTR_FLAGS(value) \
    if (to_set & FUSE_SET_ATTR_ ## value)       \
    {                                           \
        cgfs_to_set |= CGFS_SET_ATTR_ ## value; \
    }
CONVERT_FUSE_TO_CGFS_ATTR_FLAGS(MODE)
CONVERT_FUSE_TO_CGFS_ATTR_FLAGS(UID)
CONVERT_FUSE_TO_CGFS_ATTR_FLAGS(GID)
CONVERT_FUSE_TO_CGFS_ATTR_FLAGS(SIZE)
CONVERT_FUSE_TO_CGFS_ATTR_FLAGS(ATIME)
CONVERT_FUSE_TO_CGFS_ATTR_FLAGS(MTIME)
CONVERT_FUSE_TO_CGFS_ATTR_FLAGS(ATIME_NOW)
CONVERT_FUSE_TO_CGFS_ATTR_FLAGS(MTIME_NOW)
#undef CONVERT_FUSE_TO_CGFS_ATTR_FLAGS

    cgfs_async_setattr(cgfs_get_data(),
                       ino,
                       file_handler,
                       attr,
                       cgfs_to_set,
                       &cgfuse_reply_attr_cb,
                       &cgfuse_err_cb,
                       req);

}

#if 0
static void cgfuse_getxattr(fuse_req_t const req,
                            fuse_ino_t const ino,
                            char const * const xattr_name,
                            size_t const size)
{
    /*
      If size is zero, the size of the value should be sent with fuse_reply_xattr.

      If the size is non-zero, and the value fits in the buffer, the value should be sent with fuse_reply_buf.

      If the size is too small for the value, the ERANGE error should be sent.*/

    // (cgfuse_reply_buf)
    // cgfuse_reply_data
    // cgfuse_reply_xattr
    // cgfuse_reply_err
}
#endif /* 0 */

#if 0
static void cgfuse_listxattr(fuse_req_t const req,
                             fuse_ino_t const ino,
                             size_t const size)
{
    /*
       If size is zero, the total size of the attribute list should be sent with fuse_reply_xattr.

       If the size is non-zero, and the null character separated attribute list fits in the buffer, the list should be sent with fuse_reply_buf.

       If the size is too small for the list, the ERANGE error should be sent.*/

    // (cgfuse_reply_buf)
    // cgfuse_reply_data
    // cgfuse_reply_xattr
    // cgfuse_reply_err
}
#endif /* 0 */

#if 0
static void cgfuse_removexattr(fuse_req_t const req,
                               fuse_ino_t const ino,
                               char const * const name)
{
    // cgfuse_reply_err
}

#endif /* 0 */

#if 0
static void cgfuse_setxattr(fuse_req_t const req,
                            fuse_ino_t const ino,
                            char const * const xattr_name,
                            char const * const value,
                            size_t const value_size,
                            int const flags)
{
    /* flags:
       XATTR_CREATE: pure replace operation, which fails if the named attribute does not already exist (EEXIST);
       XATTR_REPLACE: pure replace operation, which fails if the named attribute does not already exist (ENOATTR).
    */

    // cgfuse_reply_err
}
#endif /* 0 */

static void cgfuse_create(fuse_req_t const req,
                          fuse_ino_t const parent,
                          char const * const name,
                          mode_t const mode,
                          struct fuse_file_info * const fi)
{
    /*
      Create and open a file

      If the file does not exist, first create it with the specified mode, and then open it.

      Open flags (with the exception of O_NOCTTY) are available in fi->flags.

      Filesystem may store an arbitrary file handle (pointer, index, etc) in fi->fh,
      and use this in other all other file operations (read, write, flush, release, fsync).

      There are also some flags (direct_io, keep_cache) which the filesystem may set in fi, to change the way the file is opened. See fuse_file_info structure in <fuse_common.h> for more details.
    */

    /* for flags, see man 2 open
     */
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(parent > 0);
    CGUTILS_ASSERT(name != NULL);
    CGUTILS_ASSERT(fi != NULL);
    struct fuse_ctx const * context = fuse_req_ctx(req);

    if (COMPILER_LIKELY(context != NULL))
    {
        uid_t const uid = context->uid;
        uid_t const gid = context->gid;
        mode_t const mask = context->umask;

        cgfs_async_create_and_open(cgfs_get_data(),
                                   parent,
                                   name,
                                   uid,
                                   gid,
                                   mode & ~mask,
                                   fi->flags,
                                   &cgfuse_reply_create_cb,
                                   &cgfuse_err_cb,
                                   req);
    }
    else
    {
        cgfuse_reply_err(req, EINVAL);
    }
}

static void cgfuse_open(fuse_req_t const req,
                        fuse_ino_t const ino,
                        struct fuse_file_info * const fi)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(ino > 0);
    CGUTILS_ASSERT(fi != NULL);

    /* Open flags (with the exception of O_CREAT, O_EXCL, O_NOCTTY and O_TRUNC) are available in fi->flags.  */

    cgfs_async_open(cgfs_get_data(),
                    ino,
                    fi->flags,
                    &cgfuse_reply_open_cb,
                    &cgfuse_err_cb,
                    req);
}

static void cgfuse_release(fuse_req_t const req,
                           fuse_ino_t const ino,
                           struct fuse_file_info * const fi)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(fi != NULL);

    /*
      Release is called when there are no more references to an open file: all file descriptors are closed and all memory mappings are unmapped.

      For every open call there will be exactly one release call.

      The filesystem may reply with an error, but error values are not returned to close() or
      munmap() which triggered the release.
    */

    cgfs_file_handler * file_handler = cgfuse_get_file_handler(fi);

    CGUTILS_ASSERT(file_handler != NULL);

    cgfs_async_file_handler_release(cgfs_get_data(),
                                    ino,
                                    file_handler);

    cgfuse_reply_err(req, 0);
}

static void cgfuse_read(fuse_req_t const req,
                        fuse_ino_t const ino,
                        size_t const size,
                        off_t const off,
                        struct fuse_file_info * const fi)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(ino > 0);
    CGUTILS_ASSERT(size > 0);
    CGUTILS_ASSERT(off >= 0);
    CGUTILS_ASSERT(fi != NULL);
    /*
       Read should send exactly the number of bytes requested except on EOF or error,
       otherwise the rest of the data will be substituted with zeroes.
    */

    cgfs_file_handler * file_handler = cgfuse_get_file_handler(fi);

    CGUTILS_ASSERT(file_handler != NULL);

    /* FIXME / TODO: we may be able to use cgfuse_reply_data_fd
       in order to allow zero-copy via splice(), but I am not
       sure that it works correctly with a non-blocking FD. */
    cgfs_async_read(cgfs_get_data(),
                    file_handler,
                    ino,
                    size,
                    off,
                    &cgfuse_reply_data_mem_cb,
                    &cgfuse_err_cb,
                    req);
}

static void cgfuse_write(fuse_req_t const req,
                         fuse_ino_t const ino,
                         char const * const buf,
                         size_t const size,
                         off_t const off,
                         struct fuse_file_info * const fi)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(ino > 0);
    CGUTILS_ASSERT(buf != NULL);
    CGUTILS_ASSERT(size > 0);
    CGUTILS_ASSERT(off >= 0);
    CGUTILS_ASSERT(fi != NULL);
    /* Write should return exactly the number of bytes requested except on error */

    cgfs_file_handler * file_handler = cgfuse_get_file_handler(fi);

    CGUTILS_ASSERT(file_handler != NULL);
    cgfs_async_write(cgfs_get_data(),
                     file_handler,
                     ino,
                     buf,
                     size,
                     off,
                     &cgfuse_reply_write_cb,
                     &cgfuse_err_cb,
                     req);
}

#if 0
    /* FIXME / TODO: we may be able to use fuse_buf_copy
       in order to allow zero-copy via splice(), but I am not
       sure that it works correctly with a non-blocking FD. */
#if FUSE_VERSION >= 29
static void cgfuse_write_buf(fuse_req_t const req,
                             fuse_ino_t const ino,
                             struct fuse_bufvec * const bufv,
                             off_t const off,
                             struct fuse_file_info * const fi)
{
    int result = 0;
    int fd = -1;
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(ino > 0);
    CGUTILS_ASSERT(bufv != NULL);
    CGUTILS_ASSERT(off >= 0);
    CGUTILS_ASSERT(fi != NULL);
    cgfs_file_handler * file_handler = cgfuse_get_file_handler(fi);

    CGUTILS_ASSERT(file_handler != NULL);
    result = cgfs_async_get_fd_for_writing(cgfs_get_data(),
                                           file_handler,
                                           ino,
                                           &fd);

    if (COMPILER_LIKELY(result == 0))
    {
        CGUTILS_ASSERT(fd != -1);
        struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(bufv));

        dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
        dst.buf[0].fd = fd;
        fd = -1;
        dst.buf[0].pos = off;

        ssize_t const res = fuse_buf_copy(&dst,
                                          bufv,
                                          FUSE_BUF_SPLICE_NONBLOCK);

        if (COMPILER_LIKELY(res > 0))
        {
            cgfuse_reply_write(req,
                               (size_t) res);
        }
        else
        {
            CGUTILS_ASSERT(res >= INT_MIN);
            CGUTILS_ASSERT(res <= INT_MAX);


            cgfuse_reply_err(req,
                             (int) res);
        }
    }
    else
    {
        cgfuse_reply_err(req,
                         result);
    }
}
#endif /* FUSE_VERSION >= 29 */
#endif /* 0 */

static void cgfuse_fsync(fuse_req_t const req,
                         fuse_ino_t const ino,
                         int const datasync,
                         struct fuse_file_info * const fi)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(ino > 0);
    CGUTILS_ASSERT(fi != NULL);

    cgfs_file_handler * file_handler = cgfuse_get_file_handler(fi);
    CGUTILS_ASSERT(file_handler != NULL);

    cgfs_async_fsync(cgfs_get_data(),
                     file_handler,
                     ino,
                     datasync != 0 ? O_DSYNC : O_SYNC,
                     &cgfuse_err_cb,
                     &cgfuse_err_cb,
                     req);
}

static void cgfuse_unlink(fuse_req_t const req,
                          fuse_ino_t const parent,
                          char const * const name)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(parent > 0);
    CGUTILS_ASSERT(name != NULL);

    /* the inode should remain in the local cache until
       the inode's lookup count is zero
    */

    cgfs_async_unlink(cgfs_get_data(),
                      parent,
                      name,
                      &cgfuse_err_cb,
                      &cgfuse_err_cb,
                      req);
}

static void cgfuse_rename(fuse_req_t const req,
                          fuse_ino_t const parent,
                          char const * const name,
                          fuse_ino_t const newparent,
                          char const * const newname)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(parent > 0);
    CGUTILS_ASSERT(name != NULL);
    CGUTILS_ASSERT(newparent > 0);
    CGUTILS_ASSERT(newname != NULL);

    /*
       If the target exists it should be atomically replaced.
       If the target's inode's lookup count is non-zero,
       the file system is expected to postpone any removal of the inode
       until the lookup count reaches zero (see description of the forget function).
    */

    cgfs_async_rename(cgfs_get_data(),
                      parent,
                      name,
                      newparent,
                      newname,
                      &cgfuse_err_cb,
                      &cgfuse_err_cb,
                      req);
}

static void cgfuse_hardlink(fuse_req_t const req,
                            fuse_ino_t const ino,
                            fuse_ino_t const newparent,
                            char const * const newname)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(ino > 0);
    CGUTILS_ASSERT(newparent > 0);
    CGUTILS_ASSERT(newname != NULL);

    cgfs_async_hardlink(cgfs_get_data(),
                        ino,
                        newparent,
                        newname,
                        &cgfuse_reply_entry_cb,
                        &cgfuse_err_cb,
                        req);
}

static void cgfuse_mkdir(fuse_req_t const req,
                         fuse_ino_t const parent,
                         char const * const name,
                         mode_t mode)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(parent > 0);
    CGUTILS_ASSERT(name != NULL);

    struct fuse_ctx const * context = fuse_req_ctx(req);

    if (COMPILER_LIKELY(context != NULL))
    {
        uid_t const uid = context->uid;
        uid_t const gid = context->gid;
        mode_t const mask = context->umask;

        /* Fix mode as the kernel does not play nicely. */
        mode |= S_IFDIR;

        cgfs_async_mkdir(cgfs_get_data(),
                         parent,
                         name,
                         uid,
                         gid,
                         mode & ~mask,
                         &cgfuse_reply_entry_cb,
                         &cgfuse_err_cb,
                         req);
    }
    else
    {
        cgfuse_reply_err(req, EINVAL);
    }
}

static void cgfuse_rmdir(fuse_req_t const req,
                         fuse_ino_t const parent,
                         char const * const name)
{
    /*
       If the directory's inode's lookup count is non-zero, the file system is expected to
       postpone any removal of the inode until the lookup count reaches zero (see description of the forget function).
    */
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(parent > 0);
    CGUTILS_ASSERT(name != NULL);

    cgfs_async_rmdir(cgfs_get_data(),
                     parent,
                     name,
                     &cgfuse_err_cb,
                     &cgfuse_err_cb,
                     req);
}

static void cgfuse_opendir(fuse_req_t const req,
                           fuse_ino_t const ino,
                           struct fuse_file_info * const fi)
{
    /*
      Filesystem may store an arbitrary file handle (pointer, index, etc) in fi->fh,
      and use this in other all other directory stream operations (readdir, releasedir, fsyncdir).

      Filesystem may also implement stateless directory I/O and not store anything in fi->fh,
      though that makes it impossible to implement standard conforming directory stream operations in case the contents of the directory can change between opendir and releasedir.
    */

    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(ino > 0);
    (void) fi;

    /* TODO: use DB cursor (benchs show that we are fine even with a directory
       containing 500k+ entries, so this is not critical. */

    cgfs_async_opendir(cgfs_get_data(),
                       ino,
                       &cgfuse_reply_open_cb,
                       &cgfuse_err_cb,
                       req);
}

static void cgfuse_readdir(fuse_req_t const req,
                           fuse_ino_t const ino,
                           size_t const size,
                           off_t const off,
                           struct fuse_file_info * const fi)
{
    /*
      Send a buffer filled using fuse_add_direntry(), with size not exceeding the requested size. Send an empty buffer on end of stream.

      fi->fh will contain the value set by the opendir method, or will be undefined if the opendir method didn't set any value.
    */

    /*
      Returning a directory entry from readdir() does not affect its lookup count.
    */

    CGUTILS_ASSERT(off >= 0);

    size_t idx = (size_t) off;

    cgfs_data * const data = cgfs_get_data();
    cgfs_file_handler * const fh = cgfuse_get_file_handler(fi);

    size_t remaining_entries = cgfs_async_get_remaining_dir_entries_count(data,
                                                                          ino,
                                                                          fh,
                                                                          idx);

    if (remaining_entries > 0)
    {
        int result = 0;
        size_t remaining_entries_name_len = cgfs_async_get_remaining_dir_entries_name_len(data,
                                                                                          ino,
                                                                                          fh,
                                                                                          idx,
                                                                                          size);

        /* size of of an entry is roughly 32 + entry_name_len */
        size_t needed_size = (32 * remaining_entries) + remaining_entries_name_len;
        size_t const buffer_size = needed_size > size ? size : needed_size;
        void * buffer = NULL;

        CGUTILS_MALLOC(buffer, buffer_size, 1);

        if (COMPILER_LIKELY(buffer != NULL))
        {
            size_t position = 0;
            size_t remaining = buffer_size;
            bool finished = false;

            while (result == 0 &&
                   finished == false &&
                   remaining > 0)
            {
                char const * entry_name = NULL;
                struct stat const * entry_st = NULL;

                result = cgfs_async_get_dir_entry(data,
                                                  ino,
                                                  fh,
                                                  idx,
                                                  &entry_name,
                                                  &entry_st);

                if (COMPILER_LIKELY(result == 0))
                {
                    size_t got = fuse_add_direntry(req,
                                                   ((char *) buffer) + position,
                                                   remaining,
                                                   entry_name,
                                                   entry_st,
                                                   (off_t) idx + 1);

                    if (COMPILER_LIKELY(got <= remaining))
                    {
                        idx++;
                        position += got;
                        remaining -= got;
                    }
                    else
                    {
                        /* this entry would use more than we have,
                           we are done for now.
                        */
                        finished = true;
                    }
                }
                else if (result == ENOENT)
                {
                    result = 0;
                    finished = true;
                }
                else
                {
                    CGUTILS_ERROR("Error retrieving directory entry %zu: %d",
                                  idx,
                                  result);
                }
            }

            if (COMPILER_LIKELY(result == 0))
            {
                cgfuse_reply_data_mem(req,
                                      buffer,
                                      buffer_size - remaining);
            }

            CGUTILS_FREE(buffer);
        }

        if (COMPILER_UNLIKELY(result != 0))
        {
            cgfuse_reply_err(req,
                             result);
        }
    }
    else
    {
        /* No more entries, we send an empty buffer */
        cgfuse_reply_empty_buf(req);
    }
}

static void cgfuse_releasedir(fuse_req_t const req,
                              fuse_ino_t const ino,
                              struct fuse_file_info * const fi)
{
    /* For every opendir call there will be exactly one releasedir call. */

    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(ino > 0);
    CGUTILS_ASSERT(fi != NULL);
    cgfs_file_handler * const fh = cgfuse_get_file_handler(fi);

    cgfs_async_releasedir(cgfs_get_data(),
                          ino,
                          fh);

    cgfuse_reply_err(req,
                     0);
}

static void cgfuse_readlink(fuse_req_t const req,
                            fuse_ino_t const ino)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(ino > 0);

    cgfs_async_readlink(cgfs_get_data(),
                        ino,
                        &cgfuse_reply_readlink_cb,
                        &cgfuse_err_cb,
                        req);
}

static void cgfuse_symlink(fuse_req_t const req,
                           char const * const link,
                           fuse_ino_t const parent,
                           char const * const name)
{
    CGUTILS_ASSERT(req != NULL);
    CGUTILS_ASSERT(link != NULL);
    CGUTILS_ASSERT(parent > 0);
    CGUTILS_ASSERT(name != NULL);
    struct fuse_ctx const * context = fuse_req_ctx(req);

    if (COMPILER_LIKELY(context != NULL))
    {
        uid_t const uid = context->uid;
        uid_t const gid = context->gid;

        cgfs_async_symlink(cgfs_get_data(),
                           link,
                           parent,
                           name,
                           uid,
                           gid,
                           &cgfuse_reply_entry_cb,
                           &cgfuse_err_cb,
                           req);

    }
    else
    {
        cgfuse_reply_err(req, EINVAL);
    }
}

static void cgfuse_statfs(fuse_req_t const req,
                          fuse_ino_t const ino)
{
    CGUTILS_ASSERT(req != NULL);

    cgfs_async_statfs(cgfs_get_data(),
                      ino,
                      &cgfuse_reply_statfs_cb,
                      &cgfuse_err_cb,
                      req);
}

static struct fuse_lowlevel_ops const cgfuse_operations =
{
    .init         = cgfuse_init,
    .destroy      = cgfuse_destroy,

    .lookup       = cgfuse_lookup,
    .forget       = cgfuse_forget,
    .forget_multi = cgfuse_forget_multi,

    .opendir      = cgfuse_opendir,
    .readdir	  = cgfuse_readdir,
#if FUSE_VERSION >= 30
    .readdirplus  = cgfuse_readdirplus,
#endif /* FUSE_VERSION >= 30 */
    .releasedir   = cgfuse_releasedir,

    .getattr	  = cgfuse_getattr,
    .setattr	  = cgfuse_setattr,

    .create       = cgfuse_create,
    .release      = cgfuse_release,
    .open         = cgfuse_open,

    .read         = cgfuse_read,
    .write        = cgfuse_write,
    .fsync        = cgfuse_fsync,

    .link         = cgfuse_hardlink,

    .unlink       = cgfuse_unlink,
    .rename       = cgfuse_rename,

    .mkdir        = cgfuse_mkdir,
    .rmdir        = cgfuse_rmdir,

    .statfs       = cgfuse_statfs,

    .readlink     = cgfuse_readlink,
    .symlink      = cgfuse_symlink,

#if 0
#if FUSE_VERSION >= 29
    .write_buf    = cgfuse_write_buf,
#endif /* FUSE_VERSION >= 29 */
#endif /* 0 */
#if 0

    .getxattr	  = cgfuse_getxattr,
    .listxattr	  = cgfuse_listxattr,
    .removexattr  = cgfuse_removexattr,
    .setxattr	  = cgfuse_setxattr,

    .fallocate

#endif /* 0 */

    // .flock
    // .getlk
    // .setlk
    // .flush (useless, except if getlk/setlk is implemented)
    // .access (useless with default permissions flag)
    // .ioctl
    // .poll
    // .mknod (not supported)
    // .bmap (only for block device)
    // .retrieve_reply (only used with the kernel cache API)
};


static void cgfuse_fuse_event_cb(int const fd,
                                 short const flags,
                                 void * const cb_data)
{
    int result = 0;
    struct fuse_chan * chan = cb_data;
    cgfs_data * const data = cgfs_get_data();
    struct fuse_buf buf = (struct fuse_buf) { 0 };
    CGUTILS_ASSERT(chan != NULL);
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(fd != -1);
    CGUTILS_ASSERT(data->session != NULL);
    CGUTILS_ASSERT(data->buffer != NULL);
    CGUTILS_ASSERT(data->event_data != NULL);
    CGUTILS_ASSERT(data->buffer_size > 0);

    (void) fd;
    (void) flags;

    if (COMPILER_LIKELY(fuse_session_exited(data->session) == 0))
    {
        buf.mem = data->buffer;
        buf.size = data->buffer_size;

        do
        {
            result = fuse_session_receive_buf(data->session,
                                              &buf,
                                              &chan);
        }
        while(result == -EINTR);

        if (result > 0)
        {
            fuse_session_process_buf(data->session,
                                     &buf,
                                     chan);
        }
        else if (result < 0)
        {
            CGUTILS_ERROR("Error while receiving request: %d",
                          -result);
        }
    }
    else
    {
        cgutils_event_exit_loop(data->event_data);
    }
}

#define CGFUSE_SET_OPT(template, thest, field) { (template), offsetof(typeof(*thest), field), 1 }

static int cgfuse_parse_arguments(int const argc,
                                  char ** const argv,
                                  struct fuse_args * const args,
                                  cgfs_data * const data)
{
    CGUTILS_ASSERT(argv != NULL);
    CGUTILS_ASSERT(data != NULL);

    (void) argc;
    (void) argv;

    struct fuse_opt opts[] =
    {
        CGFUSE_SET_OPT("-s %s", data, cgsm_configuration_file),
        CGFUSE_SET_OPT("-i %s", data, fs_name),
        CGFUSE_SET_OPT("-p %s", data, pid_file),
        FUSE_OPT_END
    };

    int result = fuse_opt_parse(args, data, opts, NULL);

    return result;
}

static int cgfuse_load_configuration(cgfs_data * const data)
{
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(data->event_data != NULL);
    CGUTILS_ASSERT(data->cgsm_configuration_file != NULL &&
                   data->fs_name != NULL);

    return cgfs_data_load_configuration(data);
}

static void cgfuse_sighup_handler(int const sig,
                                  void * cb_data)
{
    (void) cb_data;
    (void) sig;

//    cgsm_reload_handler();
}

static void cgfuse_exit_signal_handler(int const sig,
                                       void * cb_data)
{
    cgfs_data * data = cb_data;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(data->event_data != NULL);

    (void) sig;

    cgutils_event_exit_loop(data->event_data);
}

static int cgfuse_set_one_signal_event(cgutils_event_data * const event_data,
                                       int const sig,
                                       cgutils_event ** const event,
                                       cgutils_event_signal_cb * const cb,
                                       cgfs_data * const cb_data)
{
    CGUTILS_ASSERT(event_data != NULL);
    CGUTILS_ASSERT(event != NULL);
    CGUTILS_ASSERT(cb != NULL);
    CGUTILS_ASSERT(cb_data != NULL);

    int result = cgutils_event_create_signal_event(event_data,
                                                   sig,
                                                   cb,
                                                   cb_data,
                                                   event);

    if (result == 0)
    {
        result = cgutils_event_enable(*event,
                                      NULL);

        if (result != 0)
        {
            CGUTILS_ERROR("Error enabling signal event for signal %d: %d",
                          sig,
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error creating signal event for signal %d: %d",
                      sig,
                      result);
    }

    return result;
}

static int cgfuse_set_signal_handlers(cgfs_data * const data)
{
    struct sigaction sa = (struct sigaction) { 0 };
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(data->event_data != NULL);

    int result = sigaction(SIGPIPE,
                           &sa,
                           NULL);
    if (result == 0)
    {
        result = cgfuse_set_one_signal_event(data->event_data,
                                             SIGINT,
                                             &(data->sigint_event),
                                             &cgfuse_exit_signal_handler,
                                             data);
    }

    if (result == 0)
    {
        result = cgfuse_set_one_signal_event(data->event_data,
                                             SIGTERM,
                                             &(data->sigterm_event),
                                             &cgfuse_exit_signal_handler,
                                             data);
    }

    if (result == 0)
    {
        result = cgfuse_set_one_signal_event(data->event_data,
                                             SIGHUP,
                                             &(data->sighup_event),
                                             &cgfuse_sighup_handler,
                                             data);
    }

    return result;
}

static int cgfuse_event_run(char const * const process_name,
                            cgfs_data * const data,
                            struct fuse_args * args)
{
    char * mountpoint = NULL;
    CGUTILS_ASSERT(process_name != NULL);
    CGUTILS_ASSERT(data != NULL);
    CGUTILS_ASSERT(args != NULL);
    int result = fuse_parse_cmdline(args,
                                    &mountpoint,
                                    NULL,
                                    NULL);

    if (result == 0)
    {
        CGUTILS_ASSERT(data->event_data != NULL);

        result = cgfuse_set_signal_handlers(data);

        if (result == 0)
        {
            struct fuse_chan * chan = fuse_mount(mountpoint,
                                                 args);

            if (chan != NULL)
            {
                data->session = fuse_lowlevel_new(args,
                                                  &cgfuse_operations,
                                                  sizeof cgfuse_operations,
                                                  NULL);

                if (data->session != NULL)
                {
                    fuse_session_add_chan(data->session, chan);
                    CGUTILS_ASSERT(fuse_chan_fd(chan) != -1);

                    data->buffer_size = fuse_chan_bufsize(chan);
                    CGUTILS_ASSERT(data->buffer_size > 0);

                    CGUTILS_MALLOC(data->buffer, 1, data->buffer_size);

                    if (data->buffer != NULL)
                    {
                        result = cgutils_event_create_fd_event(data->event_data,
                                                               fuse_chan_fd(chan),
                                                               &cgfuse_fuse_event_cb,
                                                               chan,
                                                               CGUTILS_EVENT_READ|CGUTILS_EVENT_PERSIST,
                                                               &(data->fuse_event));

                        if (result == 0)
                        {
                            result = cgutils_event_enable(data->fuse_event,
                                                          NULL);

                            if (result == 0)
                            {
                                cgutils_event_dispatch(data->event_data);
                            }
                            else
                            {
                                fprintf(stderr,
                                        "%s: error while enabling fuse event: %d\n",
                                        process_name,
                                        result);
                            }

                            cgutils_event_free(data->fuse_event), data->fuse_event = NULL;
                        }
                        else
                        {
                            fprintf(stderr,
                                    "%s: error while creating fuse event: %d\n",
                                    process_name,
                                    result);
                        }
                    }
                    else
                    {
                        result = ENOMEM;
                        fprintf(stderr,
                                "%s: error allocating IO buffer: %d\n",
                                process_name,
                                result);
                    }

                    fuse_session_remove_chan(chan);

                    fuse_session_destroy(data->session), data->session = NULL;
                }
                else
                {
                    result = errno;
                    fprintf(stderr,
                            "%s: error while creating new session: %d\n",
                            process_name,
                            result);
                }

                fuse_unmount(mountpoint, chan);
            }
            else
            {
                result = errno;
                fprintf(stderr,
                        "%s: error while creating new chan: %d\n",
                        process_name,
                        result);
            }

            cgutils_event_free(data->sighup_event), data->sighup_event = NULL;
            cgutils_event_free(data->sigint_event), data->sigint_event = NULL;
            cgutils_event_free(data->sigterm_event), data->sigterm_event = NULL;
        }
        else
        {
            fprintf(stderr,
                    "%s: error setting signal handlers: %d\n",
                    process_name,
                    result);
        }

        CGUTILS_FREE(mountpoint);
    }
    else
    {
        fprintf(stderr,
                "%s: error while parsing parameters: %d\n",
                process_name,
                result);
    }

    return result;
}

int main(int argc,
         char **argv)
{
    int result = cgfs_init();

    if (result == 0)
    {
        cgfs_data * data = cgfs_get_data();

        if (data != NULL)
        {
            struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
            *data = (cgfs_data) { 0 };

            result = cgfuse_parse_arguments(argc,
                                            argv,
                                            &args,
                                            data);

            if (result == 0)
            {
                if (data->cgsm_configuration_file != NULL &&
                    data->fs_name != NULL)
                {
                    result = cgutils_event_init(&(data->event_data));

                    if (result == 0)
                    {
                        result = cgutils_aio_init(data->event_data,
                                                  &(data->aio));

                        if (result == 0)
                        {
                            result = cgfuse_load_configuration(data);

                            if (result == 0)
                            {
                                if (data->pid_file != NULL)
                                {
                                    result = cgutils_process_write_pid(data->pid_file);
                                }

                                if (result == 0)
                                {
                                    result = cgfuse_event_run(argv[0],
                                                                  data,
                                                                  &args);
                                }
                                else
                                {

                                    fprintf(stderr,
                                            "%s: error writing pid file to %s: %d\n",
                                            argv[0],
                                            data->pid_file,
                                            result);
                                }

                                if (data->pid_file != NULL)
                                {
                                    cgutils_file_unlink(data->pid_file);
                                }
                            }
                            else
                            {
                                fprintf(stderr,
                                        "%s: error while loading configuration: %d\n",
                                        argv[0],
                                        result);
                            }
                        }
                        else
                        {
                            fprintf(stderr,
                                    "%s: error initializing AIO: %d\n",
                                    argv[0],
                                    result);
                        }
                    }
                    else
                    {
                        fprintf(stderr,
                                "%s: error initializing event: %d\n",
                                argv[0],
                                result);
                    }
                }
                else
                {
                    if (data->cgsm_configuration_file == NULL)
                    {
                        fprintf(stderr,
                                "%s: configuration file required\n",
                                argv[0]);
                    }
                    else if (data->fs_name == NULL)
                    {
                        fprintf(stderr,
                                "%s: filesystem name required\n",
                                argv[0]);
                    }

                    result = EINVAL;
                }

                fuse_opt_free_args(&args);
            }

            cgfs_data_clean(&data);
        }
        else
        {
            result = EXIT_FAILURE;
        }

        cgfs_destroy();
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
