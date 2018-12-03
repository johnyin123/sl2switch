#ifndef __EVENT_H_
#define __EVENT_H_
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "debug.h"

#define EVENT_READ     0
#define EVENT_WRITE    1
#define EVENT_RW       2

typedef struct ev_loop_s ev_loop_t;
typedef struct ev_event_s ev_event_t;
typedef int (*ev_handler) (ev_event_t *ev);

struct ev_event_s
{
    int fd;
    ev_handler read_handler;
    ev_handler write_handler;
    ev_handler error_handler;
    void *ctx;
};

typedef struct
{
    const char *type;
    int (*create ) (ev_loop_t *loop);
    int (*destroy) (ev_loop_t *loop);
    int (*add    ) (ev_loop_t *loop, ev_event_t *ev, int events);
    int (*change ) (ev_loop_t *loop, ev_event_t *ev, int events);
    int (*del    ) (ev_loop_t *loop, ev_event_t *ev);
    int (*poll   ) (ev_loop_t *loop, long timeout);
} ev_impl_t;

struct ev_loop_s
{
    int size;
    struct
    {
        int efd;
        void *io;
    };
    ev_impl_t *actions;
};

struct event_operator
{
    sig_atomic_t tc_over;
    int         (*loop_init      )(ev_loop_t *loop, int size);
    int         (*loop_cycle     )(ev_loop_t *loop, long timeout);
    void        (*loop_final     )(ev_loop_t *loop);
    void        (*ev_init        )(ev_event_t *ev, int fd, ev_handler reader, ev_handler writer, ev_handler error, void *ctx);
    int         (*ev_add         )(ev_loop_t *loop, ev_event_t *ev, int events);
    int         (*ev_mod         )(ev_loop_t *loop, ev_event_t *ev, int events);
    int         (*ev_del         )(ev_loop_t *loop, ev_event_t *ev);
    void        (*ev_final       )(ev_event_t *ev);
    void *      (*ev_get_ctx     )(ev_event_t *ev);
    int         (*ev_timer_add   )(ev_loop_t *loop, ev_event_t *ev, long timer, ev_handler reader, void *ctx);
    void        (*ev_timer_update)(ev_event_t *ev, long timer);
    int         (*ev_timer_del   )(ev_loop_t *loop, ev_event_t *ev);
};
extern struct event_operator Event;

#endif
