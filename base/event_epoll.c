#include "event.h"
#include <sys/epoll.h>
#include <unistd.h>
#include <stdlib.h>

#define _INIT_EVAL  (EPOLLRDHUP | EPOLLERR)  // EPOLLHUP with this flag, bad performance !

static int mk_epoll_create(ev_loop_t *loop)
{
    assert(loop);
    if((loop->efd = epoll_create1(EPOLL_CLOEXEC)) == -1)
    {
        ev_inner_log(ERROR, "epoll_create1 %d, %s", errno, strerror(errno));
        return EXIT_FAILURE;
    }
    loop->io = NULL; /* epoll not use it */
    ev_inner_log(INFO, "epoll_create %d", loop->efd);
    return EXIT_SUCCESS;
}
static int mk_epoll_destroy(ev_loop_t *loop)
{
    ev_inner_log(INFO, "epoll_close %d", loop->efd);
    if (loop->efd)
    {
        close(loop->efd);
        loop->efd = -1;
    }
    return EXIT_SUCCESS;
}
static int mk_epoll_add(ev_loop_t *loop, ev_event_t *ev, int events)
{
    int ret;
    struct epoll_event event = { .events = _INIT_EVAL, .data.ptr = ev, };
    switch (events)
    {
    case EVENT_READ:
        event.events |= EPOLLIN;
        break;
    case EVENT_WRITE:
        event.events |= EPOLLOUT;
        break;
    case EVENT_RW:
        event.events |= EPOLLIN | EPOLLOUT;
        break;
    }
    ret = epoll_ctl(loop->efd, EPOLL_CTL_ADD, ev->fd, &event);
    if (ret < 0 && errno != EEXIST)
    {
        ev_inner_log(DEBUG, "[FD %i] epoll_ctl() %s", ev->fd, strerror(errno));
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
static int mk_epoll_change(ev_loop_t *loop, ev_event_t *ev, int events)
{
    struct epoll_event event = { .events = _INIT_EVAL, .data.ptr = ev, };
    switch (events)
    {
    case EVENT_READ:
        ev_inner_log(DEBUG, "[FD %i] EPoll changing mode to READ", ev->fd);
        event.events |= EPOLLIN;
        break;
    case EVENT_WRITE:
        ev_inner_log(DEBUG, "[FD %i] EPoll changing mode to WRITE", ev->fd);
        event.events |= EPOLLOUT;
        break;
    case EVENT_RW:
        ev_inner_log(DEBUG, "[FD %i] Epoll changing mode to READ/WRITE", ev->fd);
        event.events |= EPOLLIN | EPOLLOUT;
        break;
    }
    /* Update epoll fd events */
    if(epoll_ctl(loop->efd, EPOLL_CTL_MOD, ev->fd, &event) < 0)
    {
        ev_inner_log(DEBUG, "[FD %i] epoll_ctl() %s", ev->fd, strerror(errno));
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
static int mk_epoll_del(ev_loop_t *loop, ev_event_t *ev)
{
    int ret;
    struct epoll_event event;
    ret = epoll_ctl(loop->efd, EPOLL_CTL_DEL, ev->fd, &event);
    ev_inner_log(DEBUG, "Epoll, removing fd %d from efd %d", ev->fd, loop->efd);
    if(ret < 0)
    {
        ev_inner_log(DEBUG, "[FD %i] epoll_ctl() = %i, %s", ev->fd, ret, strerror(errno));
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
static int mk_epoll_polling(ev_loop_t *loop, long timeout)
{
    int i, num_fds;
    ev_event_t *ev;
    struct epoll_event events[1024];
    for(;;)
    {
        num_fds = epoll_wait(loop->efd, events, ARRAY_SIZE(events), timeout);
        if (Event.tc_over)
            return EXIT_SUCCESS;
        if(-1 == num_fds)
        {
            ev_inner_log(ERROR, "return -1");
            continue;
        }
        for(i=0; i<num_fds; i++)
        {
            ev = events[i].data.ptr;
            if (events[i].events & _INIT_EVAL)
            {
                if (ev->error_handler)
                {
                    ev_inner_log(INFO, "event fd(%d) error_handle", ev->fd);
                    ev->error_handler(ev); /*below not use ev, maybe delete in error_handle!!*/
                    /* if error, should not deal read/write events */
                    continue;
                }
            }
            if (events[i].events & EPOLLIN)
            {
                ev_inner_log(DEBUG, "event fd(%d) read_handle", ev->fd);
                if (ev->read_handler && ev->read_handler(ev) == EXIT_FAILURE)
                {
                    ev_inner_log(INFO, "event fd(%d) read_handle return failure.", ev->fd);
                }
            }
            if (events[i].events & EPOLLOUT)
            {
                ev_inner_log(DEBUG, "event fd(%d) write_handle", ev->fd);
                if (ev->write_handler && ev->write_handler(ev) == EXIT_FAILURE)
                {
                    ev_inner_log(INFO, "event fd(%d) write_handle return failure.", ev->fd);
                }
            }
        }
    }
    return EXIT_SUCCESS;
}

ev_impl_t epoll_func = {
    .type    = "EPOLL",
    .create  = mk_epoll_create,
    .destroy = mk_epoll_destroy,
    .add     = mk_epoll_add,
    .change  = mk_epoll_change,
    .del     = mk_epoll_del,
    .poll    = mk_epoll_polling,
};
