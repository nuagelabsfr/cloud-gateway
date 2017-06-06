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

#ifndef CLOUD_UTILS_EVENT_H_
#define CLOUD_UTILS_EVENT_H_

#include <stdbool.h>
#include <sys/time.h>

typedef struct cgutils_event_data cgutils_event_data;
typedef struct cgutils_event cgutils_event;
typedef struct cgutils_buffered_event cgutils_buffered_event;

#define CGUTILS_EVENT_NONE    0x00
#define CGUTILS_EVENT_TIMEOUT 0x01 /* EV_TIMEOUT */
#define CGUTILS_EVENT_READ    0x02 /* EV_READ */
#define CGUTILS_EVENT_WRITE   0x04 /* EV_WRITE */
#define CGUTILS_EVENT_SIGNAL  0x08 /* EV_SIGNAL */
#define CGUTILS_EVENT_PERSIST 0x10 /* EV_PERSIST */

typedef uint8_t cgutils_event_flags;

typedef enum
{
    CGUTILS_EVENT_DISPATCH_NOFLAGS = 0x00,
    CGUTILS_EVENT_DISPATCH_ONCE = 0x01 /* EVLOOP_ONCE */,
    CGUTILS_EVENT_DISPATCH_NONBLOCK = 0x02 /* EVLOOP_NONBLOCK */
} cgutils_event_dispatch_flags;

typedef void (cgutils_event_event_cb)(int fd, short flags, void * cb_data);
typedef void (cgutils_event_timer_cb)(void * cb_data);
typedef void (cgutils_event_signal_cb)(int signal, void * cb_data);

#include <cloudutils/cloudutils_llist.h>

COMPILER_BLOCK_VISIBILITY_DEFAULT

int cgutils_event_create_fd_event(cgutils_event_data * data,
                                  int fd,
                                  cgutils_event_event_cb cb,
                                  void * cb_data,
                                  cgutils_event_flags flags,
                                  cgutils_event ** evout);

int cgutils_event_create_signal_event(cgutils_event_data * data,
                                      int signal,
                                      cgutils_event_signal_cb cb,
                                      void * cb_data,
                                      cgutils_event ** evout);


int cgutils_event_create_timer_event(cgutils_event_data * data,
                                     cgutils_event_flags const flags,
                                     cgutils_event_timer_cb cb,
                                     void * cb_data,
                                     cgutils_event ** evout);

int cgutils_event_pending(cgutils_event const * event,
                          cgutils_event_flags const flags,
                          bool * enabled);

void cgutils_event_free(cgutils_event * event);

int cgutils_event_enable(cgutils_event * event,
                         struct timeval const * timeout);

bool cgutils_event_is_enabled(cgutils_event * event) COMPILER_PURE_FUNCTION;
int cgutils_event_disable(cgutils_event * event);

int cgutils_event_change_action(cgutils_event * event,
                                cgutils_event_flags newflags);

int cgutils_event_reassign(cgutils_event * event,
                           cgutils_event_flags flags,
                           cgutils_event_event_cb cb);

int cgutils_event_dispatch(cgutils_event_data * data);
int cgutils_event_dispatch_ex(cgutils_event_data * data,
                              cgutils_event_dispatch_flags flags);

void cgutils_event_exit_loop(cgutils_event_data * data);
void cgutils_event_exit_after_loop(cgutils_event_data * data,
                                   struct timeval const * tv);

int cgutils_event_init(cgutils_event_data ** data);
int cgutils_event_clear(cgutils_event_data * data);
void cgutils_event_destroy(cgutils_event_data * data);

COMPILER_BLOCK_VISIBILITY_END

typedef struct cgutils_event_buffered_io cgutils_event_buffered_io;
typedef struct cgutils_event_buffered_io_elt cgutils_event_buffered_io_elt;

typedef enum
{
    cgutils_event_buffered_io_reading,
    cgutils_event_buffered_io_writing
} cgutils_event_buffered_io_action;

typedef struct cgutils_event_buffered_io_obj cgutils_event_buffered_io_obj;

typedef int (cgutils_event_buffered_io_cb)(cgutils_event_data * data,
                                           int status,
                                           int fd,
                                           cgutils_event_buffered_io_obj * obj);

struct cgutils_event_buffered_io_obj
{
    cgutils_event_buffered_io * io;
    void * object;
    size_t object_size;
    cgutils_event_buffered_io_cb * cb;
    void * cb_data;
    cgutils_event_buffered_io_action action;
    /* if this flag is set to true,
       the io_obj will not be freed internally
       after it has been dealt with.
    */
    bool do_not_free;
};

COMPILER_BLOCK_VISIBILITY_DEFAULT

void cgutils_event_buffered_io_free(cgutils_event_buffered_io * this);
void cgutils_event_buffered_io_release(cgutils_event_buffered_io * this);

int cgutils_event_buffered_io_init(cgutils_event_data * data,
                                   int fd,
                                   cgutils_event_buffered_io_action action,
                                   cgutils_event_buffered_io ** io);

int cgutils_event_buffered_io_add_obj(cgutils_event_buffered_io * this,
                                      cgutils_event_buffered_io_obj * obj);

int cgutils_event_buffered_io_add_one(cgutils_event_buffered_io * this,
                                      void * object,
                                      size_t object_size,
                                      cgutils_event_buffered_io_action action,
                                      cgutils_event_buffered_io_cb * cb,
                                      void * cb_data);

int cgutils_event_buffered_io_add_multi(cgutils_event_buffered_io * this,
                                        /* llist of cgutils_event_buffered_io_obj * */
                                        cgutils_llist * objs);

int cgutils_event_buffered_io_object_create(cgutils_event_buffered_io * this,
                                            void * object,
                                            size_t object_size,
                                            cgutils_event_buffered_io_action action,
                                            cgutils_event_buffered_io_cb * cb,
                                            void * cb_data,
                                            cgutils_event_buffered_io_obj ** obj);

size_t cgutils_event_buffered_io_remaining_objects_count(cgutils_event_buffered_io const * io);

int cgutils_event_buffered_io_get_error(cgutils_event_buffered_io const * io);

void cgutils_event_dump_events(cgutils_event_data * data,
                               FILE * fp);

COMPILER_BLOCK_VISIBILITY_END

#endif /* CLOUD_UTILS_EVENT_H_ */
