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
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "cloudutils/cloudutils.h"
#include "cloudutils/cloudutils_event.h"
#include "cloudutils_event_internal.h"

#include <event2/util.h>
#include <event2/event.h>

struct cgutils_event_data
{
    struct event_base * base;
};

typedef enum
{
    CGUTILS_EVENT_OBJ_SIGNAL,
    CGUTILS_EVENT_OBJ_FD,
    CGUTILS_EVENT_OBJ_TIMER,
} cgutils_event_obj_type;

struct cgutils_event
{
    cgutils_event_data * event_data;
    struct event * event;
    void * cb_data;
    /* could be an union */
    cgutils_event_event_cb * fd_cb;
    cgutils_event_signal_cb * sig_cb;
    cgutils_event_timer_cb * timer_cb;

    evutil_socket_t obj;
    cgutils_event_obj_type type;
    cgutils_event_flags flags;
    bool enabled;
};

int cgutils_event_init(cgutils_event_data ** const data)
{
    int result = EINVAL;

    if (data != NULL)
    {
        result = ENOMEM;

        CGUTILS_ALLOCATE_STRUCT(*data);

        if (*data != NULL)
        {
/*            event_enable_debug_mode(); */

            (*data)->base = event_base_new();

            if ((*data)->base != NULL)
            {
                result = 0;
            }
            else
            {
                CGUTILS_FREE(*data);
            }
        }
    }

    return result;
}

int cgutils_event_clear(cgutils_event_data * const data)
{
    int result = EINVAL;

    if (data != NULL)
    {
        if (data->base != NULL)
        {
            result = event_reinit(data->base);

            if (result != 0)
            {
                result = ENOMEM;
            }
        }
        else
        {
            data->base = event_base_new();

            if (data->base != NULL)
            {
                result = 0;
            }
            else
            {
                result = ENOMEM;
            }
        }

    }

    return result;
}

void cgutils_event_destroy(cgutils_event_data * data)
{
    if (data != NULL)
    {
        if (data->base != NULL)
        {
            event_base_free(data->base), data->base = NULL;
        }

        CGUTILS_FREE(data);
    }
}

static void cgutils_event_internal_event_cb(evutil_socket_t obj,
                                            short flags,
                                            void * cb_data)
{
    CGUTILS_ASSERT(cb_data != NULL);

    cgutils_event * const cgutils_ev = cb_data;

    CGUTILS_ASSERT(cgutils_ev->obj == obj || flags == EV_TIMEOUT);
    CGUTILS_ASSERT(flags == EV_SIGNAL || cgutils_ev->type != CGUTILS_EVENT_OBJ_SIGNAL);

    (void) obj;

    if (!(cgutils_ev->flags & CGUTILS_EVENT_PERSIST))
    {
        cgutils_ev->enabled = false;
    }

    if (COMPILER_LIKELY(cgutils_ev->type == CGUTILS_EVENT_OBJ_FD))
    {
        if (cgutils_ev->fd_cb != NULL)
        {
            (cgutils_ev->fd_cb)(cgutils_ev->obj, flags, cgutils_ev->cb_data);
        }
    }
    else if (cgutils_ev->type == CGUTILS_EVENT_OBJ_TIMER)
    {
        if (cgutils_ev->timer_cb != NULL)
        {
            (cgutils_ev->timer_cb)(cgutils_ev->cb_data);
        }
    }
    else if (cgutils_ev->type == CGUTILS_EVENT_OBJ_SIGNAL)
    {
        if (cgutils_ev->sig_cb != NULL)
        {
            (cgutils_ev->sig_cb)(cgutils_ev->obj, cgutils_ev->cb_data);
        }
    }

}

int cgutils_event_create_fd_event(cgutils_event_data * const data,
                                  evutil_socket_t const fd,
                                  cgutils_event_event_cb * const cb,
                                  void * const cb_data,
                                  cgutils_event_flags const flags,
                                  cgutils_event ** const evout)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(data != NULL && fd >= 0 && cb != NULL && evout != NULL))
    {
        CGUTILS_ASSERT(data->base != NULL);

        result = ENOMEM;

        CGUTILS_ALLOCATE_STRUCT(*evout);

        if (COMPILER_LIKELY(*evout != NULL))
        {
            (*evout)->event = event_new(data->base, fd, flags,
                                        &cgutils_event_internal_event_cb,
                                        *evout);

            if (COMPILER_LIKELY((*evout)->event != NULL))
            {
                (*evout)->event_data = data;
                (*evout)->cb_data = cb_data;
                (*evout)->fd_cb = cb;
                (*evout)->obj = fd;
                (*evout)->flags = flags;
                (*evout)->type = CGUTILS_EVENT_OBJ_FD;

                result = 0;
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_FREE(*evout);
            }
        }
    }

    return result;
}

int cgutils_event_create_timer_event(cgutils_event_data * const data,
                                     cgutils_event_flags const flags,
                                     cgutils_event_timer_cb * const cb,
                                     void * const cb_data,
                                     cgutils_event ** const evout)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(data != NULL && cb != NULL && evout != NULL))
    {
        CGUTILS_ASSERT(data->base != NULL);

        result = ENOMEM;

        CGUTILS_ALLOCATE_STRUCT(*evout);

        if (COMPILER_LIKELY(*evout != NULL))
        {
            (*evout)->event = event_new(data->base,
                                        -1,
                                        flags,
                                        &cgutils_event_internal_event_cb,
                                        *evout);

            if (COMPILER_LIKELY((*evout)->event != NULL))
            {
                (*evout)->event_data = data;
                (*evout)->cb_data = cb_data;
                (*evout)->timer_cb = cb;
                (*evout)->obj = -1;
                (*evout)->flags = flags;
                (*evout)->type = CGUTILS_EVENT_OBJ_TIMER;

                result = 0;
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_FREE(*evout);
            }
        }
    }

    return result;
}

int cgutils_event_create_signal_event(cgutils_event_data * const data,
                                      int const sig,
                                      cgutils_event_signal_cb * const cb,
                                      void * const cb_data,
                                      cgutils_event ** const evout)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(data != NULL && sig >= 0 && sig < NSIG && cb != NULL && evout != NULL))
    {
        CGUTILS_ASSERT(data->base != NULL);

        result = ENOMEM;

        CGUTILS_ALLOCATE_STRUCT(*evout);

        if (COMPILER_LIKELY(*evout != NULL))
        {
            /* events created with evsignal_new are persistent. */
            (*evout)->event = evsignal_new(data->base, sig,
                                           &cgutils_event_internal_event_cb,
                                           *evout);

            if (COMPILER_LIKELY((*evout)->event != NULL))
            {
                (*evout)->event_data = data;
                (*evout)->cb_data = cb_data;
                (*evout)->sig_cb = cb;
                (*evout)->obj = sig;
                (*evout)->type = CGUTILS_EVENT_OBJ_SIGNAL;

                result = 0;
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_FREE(*evout);
            }
        }
    }

    return result;
}

int cgutils_event_enable(cgutils_event * const event,
                         struct timeval const * const timeout)
{
    int result = 0;

    CGUTILS_ASSERT(event != NULL);
    CGUTILS_ASSERT(event->type == CGUTILS_EVENT_OBJ_SIGNAL ||
                   event->type == CGUTILS_EVENT_OBJ_FD ||
                   event->type == CGUTILS_EVENT_OBJ_TIMER);
    CGUTILS_ASSERT(event->event != NULL);

    if (COMPILER_LIKELY(event->enabled == false ||
                        timeout != NULL))
    {
        result = event_add(event->event, timeout);

        if (COMPILER_LIKELY(result == 0))
        {
            event->enabled = true;
        }
        else
        {
            result = EIO;
        }
    }
    else
    {
        CGUTILS_WARN("Doing nothing.");
        result = 0;
    }

    return result;
}

int cgutils_event_pending(cgutils_event const * const event,
                          cgutils_event_flags const flags,
                          bool * enabled)
{
    int result = 0;

    CGUTILS_ASSERT(event != NULL && enabled != NULL);
    short type = 0;

    switch(event->type)
    {
    case CGUTILS_EVENT_OBJ_SIGNAL:
        type = EV_SIGNAL;
        break;
    case CGUTILS_EVENT_OBJ_FD:
        type = flags;
        break;
    case CGUTILS_EVENT_OBJ_TIMER:
        type = EV_TIMEOUT;
        break;
    default:
        result = EINVAL;
    }

    if (result == 0)
    {
        *enabled = event_pending(event->event,
                                 type,
                                 NULL);

    }

    return result;
}

int cgutils_event_disable(cgutils_event * const event)
{
    int result = 0;

    CGUTILS_ASSERT(event != NULL);
    CGUTILS_ASSERT(event->type == CGUTILS_EVENT_OBJ_SIGNAL ||
                   event->type == CGUTILS_EVENT_OBJ_FD ||
                   event->type == CGUTILS_EVENT_OBJ_TIMER);

    CGUTILS_ASSERT(event->event != NULL);

    if (COMPILER_LIKELY(event->enabled == true))
    {
        result = event_del(event->event);
        event->enabled = false;

        if (COMPILER_UNLIKELY(result != 0))
        {
            result = EIO;
        }
    }

    return result;
}

bool cgutils_event_is_enabled(cgutils_event * const event)
{
    bool result = false;

    if (COMPILER_LIKELY(event != NULL))
    {
        result = event->enabled;
    }

    return result;
}

int cgutils_event_reassign(cgutils_event * const event,
                           cgutils_event_flags const flags,
                           cgutils_event_event_cb * const cb)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(event != NULL &&
                        cb != NULL &&
                        event->event != NULL &&
                        event->type == CGUTILS_EVENT_OBJ_FD))
    {
        result = 0;

        if (flags != event->flags ||
            cb != event->fd_cb)
        {
            bool was_enabled = event->enabled;

            CGUTILS_ASSERT(event->event_data != NULL);
            CGUTILS_ASSERT(event->event_data->base != NULL);

            cgutils_event_disable(event);

            result = event_assign(event->event,
                                  event->event_data->base,
                                  event->obj,
                                  flags,
                                  &cgutils_event_internal_event_cb,
                                  event);

            if (COMPILER_LIKELY(result == 0))
            {
                event->flags = flags;
                event->fd_cb = cb;

                if (was_enabled == true)
                {
                    result = cgutils_event_enable(event, NULL);
                }
            }
            else
            {
                result = EIO;
            }
        }
    }

    return result;
}

int cgutils_event_change_action(cgutils_event * const event,
                                cgutils_event_flags const flags)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(event != NULL &&
                        event->event != NULL &&
                        event->type == CGUTILS_EVENT_OBJ_FD))
    {
        result = 0;

        if (flags != event->flags)
        {
            result = cgutils_event_reassign(event,
                                            flags,
                                            event->fd_cb);
        }
    }

    return result;
}

void cgutils_event_free(cgutils_event * event)
{
    if (event != NULL)
    {
        if (event->event != NULL)
        {
            if (event->type == CGUTILS_EVENT_OBJ_SIGNAL ||
                event->type == CGUTILS_EVENT_OBJ_FD ||
                event->type == CGUTILS_EVENT_OBJ_TIMER)
            {
                event_free(event->event), event->event = NULL;
            }
        }

        CGUTILS_FREE(event);
    }
}

int cgutils_event_dispatch(cgutils_event_data * const data)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(data != NULL && data->base != NULL))
    {
        result = event_base_dispatch(data->base);

        if (result == -1)
        {
            result = EIO;
        }
        else if (result == 1)
        {
            result = 0;
        }
    }

    return result;
}

int cgutils_event_dispatch_ex(cgutils_event_data * const data,
                              cgutils_event_dispatch_flags const flags)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(data != NULL && data->base != NULL))
    {
        result = event_base_loop(data->base, flags);

        if (result == -1)
        {
            result = EIO;
        }
        else if (result == 1)
        {
            result = 0;
        }
    }

    return result;
}

void cgutils_event_exit_loop(cgutils_event_data * const data)
{
    if (data != NULL && data->base != NULL)
    {
        event_base_loopbreak(data->base);
    }
}

void cgutils_event_exit_after_loop(cgutils_event_data * const data,
                                   struct timeval const * const tv)
{
    if (data != NULL && data->base != NULL)
    {
        event_base_loopexit(data->base, tv);
    }
}

struct event_base * cgutils_event_get_base(cgutils_event_data * const data)
{
    struct event_base * result = NULL;

    if (data != NULL)
    {
        result = data->base;
    }

    return result;
}

void cgutils_event_dump_events(cgutils_event_data * const data,
                               FILE * const fp)
{
    if (data != NULL && fp != NULL)
    {
        event_base_dump_events(data->base, fp);
    }
}

struct cgutils_event_buffered_io
{
    cgutils_event_data * data;
    cgutils_llist * elements;
    cgutils_llist_elt * current_elt;
    cgutils_event * event;
    size_t position_in_element;
    int fd;
    int error;
    cgutils_event_buffered_io_action action;
    bool active;
    bool released;
    bool in_callback;
};

static void cgutils_event_buffered_io_obj_delete(void * obj)
{
    if (obj != NULL)
    {
        cgutils_event_buffered_io_obj * io_obj = obj;

        if (COMPILER_LIKELY(io_obj->do_not_free == false))
        {
            CGUTILS_FREE(obj);
        }
    }
}

static void cgutils_event_buffered_io_event_cb(int fd, short flags, void * cb_data) ;

static int cgutils_event_buffered_io_change_action(cgutils_event_buffered_io * const this,
                                                   cgutils_event_buffered_io_action const new_action)
{
    int result = 0;
    CGUTILS_ASSERT(this != NULL);

    if (this->action != new_action)
    {
        this->action = new_action;

        result = cgutils_event_change_action(this->event,
                                             (new_action == cgutils_event_buffered_io_reading ?
                                              CGUTILS_EVENT_READ :
                                              CGUTILS_EVENT_WRITE
                                                 )|CGUTILS_EVENT_PERSIST);

        if (COMPILER_UNLIKELY(result != 0))
        {
            this->active = false;
            CGUTILS_ERROR("Error creating new event: %d", result);
        }
    }

    return result;
}

static void cgutils_event_buffered_io_event_cb(int fd, short flags, void * cb_data)
{
    int result = 0;

    CGUTILS_ASSERT(fd >= 0);
    CGUTILS_ASSERT(cb_data != NULL);
    cgutils_event_buffered_io * io = cb_data;

    CGUTILS_ASSERT(io->elements != NULL);
    CGUTILS_ASSERT(io->current_elt != NULL);

    (void) flags;

    do
    {
        cgutils_event_buffered_io_obj * obj = cgutils_llist_elt_get_object(io->current_elt);
        CGUTILS_ASSERT(obj != NULL);

        ssize_t res = 0;

        if (io->action == cgutils_event_buffered_io_reading)
        {
            res = read(fd,
                       ((char *)obj->object) + io->position_in_element,
                       obj->object_size - io->position_in_element);
        }
        else
        {
            res = write(fd,
                        ((char const *)obj->object) + io->position_in_element,
                        obj->object_size - io->position_in_element);
        }

        if (COMPILER_LIKELY(res > 0))
        {
            io->position_in_element += (size_t) res;

            if (io->position_in_element == obj->object_size)
            {
                bool const delete = obj->do_not_free == false;
                io->position_in_element = 0;

                cgutils_llist_elt * next = cgutils_llist_elt_get_next(io->current_elt);

                int const remove_result = cgutils_llist_remove(io->elements,
                                                               io->current_elt);

                if (COMPILER_UNLIKELY(remove_result != 0))
                {
                    CGUTILS_ERROR("Error while removing list elt: %d",
                                  remove_result);

                    if (result == 0)
                    {
                        result = remove_result;
                    }
                }

                io->current_elt = next;

                if (io->current_elt != NULL)
                {
                    cgutils_event_buffered_io_obj * const next_obj = cgutils_llist_elt_get_object(io->current_elt);
                    CGUTILS_ASSERT(next_obj != NULL);

                    result = cgutils_event_buffered_io_change_action(io,
                                                                     next_obj->action);

                    if (COMPILER_UNLIKELY(result != 0))
                    {
                        CGUTILS_ERROR("Error changing action: %d", result);
                    }
                }
                else
                {
                    io->active = false;
                    cgutils_event_disable(io->event);
                }

                if (COMPILER_UNLIKELY(result != 0))
                {
                    cgutils_event_disable(io->event);

                    if (obj->cb != NULL)
                    {
                        io->in_callback = true;
                        (obj->cb)(io->data, result, fd, obj);
                        io->in_callback = false;
                    }

                    io->active = false;
                }
                else
                {
                    if (obj->cb != NULL)
                    {
                        io->in_callback = true;
                        result = (obj->cb)(io->data, 0, fd, obj);
                        io->in_callback = false;
                    }
                }

                if (delete == true)
                {
                    cgutils_event_buffered_io_obj_delete(obj), obj = NULL;
                }
            }
        }
        else if (res == -1)
        {
            result = errno;

            if (COMPILER_UNLIKELY(result != EINTR &&
                                  result != EAGAIN &&
                                  result != EWOULDBLOCK))
            {
                CGUTILS_ERROR("Error while %s %p of size %zu to FD %d: %d",
                              io->action == cgutils_event_buffered_io_reading ? "reading" : "writing",
                              obj->object,
                              obj->object_size,
                              fd,
                              result);

                if (obj->cb != NULL)
                {
                    io->error = result;
                    cgutils_event_disable(io->event);

                    io->in_callback = true;
                    (obj->cb)(io->data, result, fd, obj);
                    io->in_callback = false;

                    io->active = false;
                }
            }
        }
        else
        {
            /* res == 0 */
            result = EBADF;

            if (obj->cb != NULL)
            {
                io->error = result;
                cgutils_event_disable(io->event);

                io->in_callback = true;
                result = (obj->cb)(io->data, result, fd, obj);
                io->in_callback = false;

                io->active = false;
            }
        }
    }
    while(io->current_elt != NULL &&
          (result == 0 || result == EINTR)
        );

    if (io->released == true)
    {
        cgutils_event_buffered_io_free(io), io = NULL;
    }
}

void cgutils_event_buffered_io_free(cgutils_event_buffered_io * this)
{
    if (COMPILER_LIKELY(this != NULL))
    {
        if (this->elements != NULL)
        {
            cgutils_llist_free(&(this->elements), &cgutils_event_buffered_io_obj_delete);
        }

        if (this->event != NULL)
        {
            cgutils_event_free(this->event), this->event = NULL;
        }

        CGUTILS_FREE(this);
    }
}

void cgutils_event_buffered_io_release(cgutils_event_buffered_io * this)
{
    if (COMPILER_LIKELY(this != NULL))
    {
        if (this->in_callback == true)
        {
            this->released = true;
        }
        else
        {
            cgutils_event_buffered_io_free(this);
        }
    }
}

int cgutils_event_buffered_io_init(cgutils_event_data * const data,
                                   int fd,
                                   cgutils_event_buffered_io_action const action,
                                   cgutils_event_buffered_io ** const out)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(data != NULL && fd >= 0 && out != NULL))
    {
        cgutils_event_buffered_io * io = NULL;

        CGUTILS_ALLOCATE_STRUCT(io);

        if (COMPILER_LIKELY(io != NULL))
        {
            io->data = data;
            io->action = action;
            io->fd = fd;

            result = cgutils_llist_create(&(io->elements));

            if (COMPILER_LIKELY(result == 0))
            {

                result = cgutils_event_create_fd_event(data,
                                                       fd,
                                                       &cgutils_event_buffered_io_event_cb,
                                                       io,
                                                       (action == cgutils_event_buffered_io_reading ?
                                                        CGUTILS_EVENT_READ :
                                                        CGUTILS_EVENT_WRITE
                                                       )|CGUTILS_EVENT_PERSIST,
                                                       &(io->event));

                if (COMPILER_LIKELY(result == 0))
                {
                    *out = io;
                }
                else
                {
                    CGUTILS_ERROR("Error while creating fd event: %d", result);
                }
            }
            else
            {
                CGUTILS_ERROR("Error while creating elements list: %d", result);
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                cgutils_event_buffered_io_free(io), io = NULL;
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}


int cgutils_event_buffered_io_add_obj(cgutils_event_buffered_io * const this,
                                      cgutils_event_buffered_io_obj * const obj)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(this != NULL &&
                        this->error == 0 &&
                        obj != NULL &&
                        obj->object != NULL &&
                        obj->object_size > 0))
    {
        if (obj->io == NULL)
        {
            obj->io = this;
        }

        result = cgutils_llist_insert(this->elements, obj);

        if (COMPILER_LIKELY(result == 0))
        {
            if (this->current_elt == NULL)
            {
                cgutils_llist_elt * list_elt = cgutils_llist_get_iterator(this->elements);
                CGUTILS_ASSERT(list_elt != NULL);

                this->current_elt = list_elt;
            }
        }
        else
        {
            CGUTILS_ERROR("Unable to add element: %d", result);
        }

        if (result == 0 &&
            this->active == false)
        {
            result = cgutils_event_buffered_io_change_action(this, obj->action);

            if (COMPILER_LIKELY(result == 0))
            {
                this->active = true;

                result = cgutils_event_enable(this->event,
                                              NULL);

                if (COMPILER_UNLIKELY(result != 0))
                {
                    CGUTILS_ERROR("Error while enabling event: %d", result);
                    result = EIO;
                }
            }
            else
            {
                CGUTILS_ERROR("Error while enabling event: %d", result);
            }

            if (COMPILER_UNLIKELY(result != 0))
            {
                cgutils_llist_remove_by_object(this->elements, obj);
            }
         }
    }

    return result;
}

int cgutils_event_buffered_io_add_multi(cgutils_event_buffered_io * const this,
                                        cgutils_llist * const objs)
{
    int result = 0;

    if (COMPILER_LIKELY(this != NULL &&
                        this->error == 0 &&
                        objs != NULL))
    {
        cgutils_llist_elt * elt = cgutils_llist_get_iterator(objs);

        while(result == 0 &&
              elt != NULL)
        {
            cgutils_event_buffered_io_obj * new_io = cgutils_llist_elt_get_object(elt);
            CGUTILS_ASSERT(new_io != NULL);

            if (new_io->object != NULL && new_io->object_size > 0)
            {
                result = cgutils_event_buffered_io_add_obj(this, new_io);
            }
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgutils_event_buffered_io_add_one(cgutils_event_buffered_io * const this,
                                      void * const object,
                                      size_t const object_size,
                                      cgutils_event_buffered_io_action const action,
                                      cgutils_event_buffered_io_cb * const cb,
                                      void * const cb_data)
{
    int result = 0;

    if (COMPILER_LIKELY(this != NULL &&
                        this->error == 0 &&
                        object != NULL &&
                        object_size > 0))
    {
        cgutils_event_buffered_io_obj * io = NULL;

        result = cgutils_event_buffered_io_object_create(this,
                                                         object,
                                                         object_size,
                                                         action,
                                                         cb,
                                                         cb_data,
                                                         &io);

        if (COMPILER_LIKELY(result == 0))
        {
            CGUTILS_ASSERT(io != NULL);

            result = cgutils_event_buffered_io_add_obj(this, io);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_FREE(io), io = NULL;
            }
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

int cgutils_event_buffered_io_object_create(cgutils_event_buffered_io * const io,
                                            void * const object,
                                            size_t const object_size,
                                            cgutils_event_buffered_io_action const action,
                                            cgutils_event_buffered_io_cb * const cb,
                                            void * const cb_data,
                                            cgutils_event_buffered_io_obj ** const obj)
{
    int result = EINVAL;

    if (COMPILER_LIKELY(io != NULL &&
                        object != NULL &&
                        object_size > 0 &&
                        obj != NULL))
    {
        CGUTILS_ALLOCATE_STRUCT(*obj);

        if (COMPILER_LIKELY(*obj != NULL))
        {
            (*obj)->object = object;
            (*obj)->io = io;
            (*obj)->object_size = object_size;
            (*obj)->action = action;
            (*obj)->cb = cb;
            (*obj)->cb_data = cb_data;
            result = 0;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

size_t cgutils_event_buffered_io_remaining_objects_count(cgutils_event_buffered_io const * const io)
{
    size_t result = 0;

    if (COMPILER_LIKELY(io != NULL))
    {
        result = cgutils_llist_get_count(io->elements);
    }

    return result;
}

int cgutils_event_buffered_io_get_error(cgutils_event_buffered_io const * const io)
{
    int result = 0;

    if (COMPILER_LIKELY(io != NULL))
    {
        result = io->error;
    }

    return result;
}
