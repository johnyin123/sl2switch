#include "event.h"
#include <stddef.h>
#include <stdlib.h>

#ifdef HAVE_EPOLL
extern ev_impl_t epoll_func;
#define impl_func  epoll_func
#else
#error  not impl!!!!!!!
ev_impl_t select_func =
{
    .type    = "SELECT",
    .create  = NULL,
    .destroy = NULL,
    .add     = NULL,
    .change  = NULL,
    .del     = NULL,
    .poll    = NULL,
};
#define impl_func  select_func
#endif

static int ev_loop_init(ev_loop_t *loop, int size)
{
    ev_impl_t *actions;
    ev_inner_log(DEBUG, "event(%s) init.", impl_func.type);
    actions = &impl_func;
    loop->actions = actions;
    loop->size = size;
    return actions->create(loop);
}
static int ev_loop_cycle(ev_loop_t *loop, long timeout)
{
    return loop->actions->poll(loop, timeout);
}
static void ev_loop_finish(ev_loop_t *loop)
{
    ev_impl_t *actions = loop->actions;
    if (actions != NULL)
    {
        /*destroy io module */
        actions->destroy(loop);
        loop->actions = NULL;
    }
}
static void ev_event_init(ev_event_t *ev, int fd, ev_handler reader, ev_handler writer, ev_handler error, void *data)
{
    ev_inner_log(INFO, "init event:%d", fd);
    assert(ev);
    memset(ev, 0, sizeof(ev_event_t));
    ev->fd = fd;
    ev->read_handler = reader;
    ev->write_handler = writer;
    ev->error_handler = error;
    ev->ctx = data;
}
static void ev_event_final(ev_event_t *ev)
{
    ev_inner_log(INFO, "final event:%d", ev->fd);
    assert(ev);
    ev->fd = -1;
    ev->read_handler = NULL;
    ev->write_handler = NULL;
    ev->error_handler = NULL;
    ev->ctx = NULL;
}
static int ev_event_add(ev_loop_t *loop, ev_event_t *ev, int events)
{
    return loop->actions->add(loop, ev, events);
}
static int ev_event_mod(ev_loop_t *loop, ev_event_t *ev, int events)
{
    return loop->actions->change(loop, ev, events);
}
static int ev_event_del(ev_loop_t *loop, ev_event_t *ev)
{
    return loop->actions->del(loop, ev);
}
#include <unistd.h>
#include <sys/timerfd.h>
static void ev_event_update_timer(ev_event_t *ev, long msec_timer)
{
    struct itimerspec new_value;
    new_value.it_value.tv_sec = (msec_timer / 1000); /* start time */
    new_value.it_value.tv_nsec = (msec_timer % 1000000);
    new_value.it_interval.tv_sec = 0; /* interval */
    new_value.it_interval.tv_nsec = 0;
    if (ev != NULL)
    {
        if(timerfd_settime(ev->fd, 0, &new_value, 0) == -1)
        {
            ev_inner_log(WARN, "timerfd_settime(%d) failed %s", ev->fd, strerror(errno));
        }
        ev_inner_log(DEBUG, "update timer(%p) %ld", ev, msec_timer);
    }
    else
    {
        ev_inner_log(WARN, "ev is null");
    }
}
static int ev_event_add_timer(ev_loop_t *loop, ev_event_t *ev, long msec_timer, ev_handler reader, void *ctx)
{
    struct itimerspec new_value;
    new_value.it_value.tv_sec = (msec_timer / 1000); /* start time */
    new_value.it_value.tv_nsec = (msec_timer % 1000000);
    new_value.it_interval.tv_sec = 0; /* interval */
    new_value.it_interval.tv_nsec = 0;
    assert(ev);
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if(fd > 0)
    {
        if(timerfd_settime(fd, 0, &new_value, 0) == 0)
        {
            ev_event_init(ev, fd, reader, NULL, NULL, ctx); 
            return ev_event_add(loop, ev, EVENT_READ);
        }
    }
    return EXIT_FAILURE;
}
static int ev_event_del_timer(ev_loop_t *loop, ev_event_t *ev)
{
    close(ev->fd);
    return ev_event_del(loop, ev);
}

static void *ev_event_get_ctx(ev_event_t *ev)
{
    return ev->ctx;
}

struct event_operator Event = {
    .tc_over         = 0,
    .loop_init       = ev_loop_init,
    .loop_cycle      = ev_loop_cycle,
    .loop_final      = ev_loop_finish,
    .ev_init         = ev_event_init,
    .ev_add          = ev_event_add,
    .ev_mod          = ev_event_mod,
    .ev_del          = ev_event_del,
    .ev_final        = ev_event_final,
    .ev_get_ctx      = ev_event_get_ctx,
    .ev_timer_add    = ev_event_add_timer,
    .ev_timer_update = ev_event_update_timer,
    .ev_timer_del    = ev_event_del_timer,
};
