#include "event.h"
#include <unistd.h>
#include <stdlib.h>

struct pri_fds_t
{
    int fd;
    int event;
    void *data;
};

static int mk_select_create(ev_loop_t *loop)
{
    assert(loop);
    loop->efd = -1;
    if(loop->size > FD_SETSIZE)
    {
        ev_inner_log(ERROR, "loop size large than FD_SETSIZE(%d)", FD_SETSIZE);
        return EXIT_FAILURE;
    }
    loop->io = mem_calloc(loop->size, sizeof(struct pri_fds_t));
    return EXIT_SUCCESS;
}
static int mk_select_destroy(ev_loop_t *loop)
{
    struct pri_fds_t *fds = loop->io;
    mem_free(fds);
    return EXIT_SUCCESS;
}
static int mk_select_add(ev_loop_t *loop, ev_event_t *ev, int events)
{
    struct pri_fds_t *fds = loop->io;
    int i;
    for(i=0;i<loop->size;i++)
    {
        if((fds[i].fd == 0) && (fds[i].data == NULL) && (fds[i].event == 0))
        {
            fds[i].fd = ev->fd;
            fds[i].data = ev;
            fds[i].event = events;
            return EXIT_SUCCESS;
        }
    }
    return EXIT_FAILURE;
}
static int mk_select_change(ev_loop_t *loop, ev_event_t *ev, int events)
{
    ev_inner_log(DEBUG, "change %d", ev->fd);

    struct pri_fds_t *fds = loop->io;
    int i;
    for(i=0;i<loop->size;i++)
    {
        if((fds[i].fd == ev->fd) && (fds[i].data == ev))
        {
            fds[i].event = events;
            return EXIT_SUCCESS;
        }
    }
    return EXIT_FAILURE;
}
static int mk_select_del(ev_loop_t *loop, ev_event_t *ev)
{
    struct pri_fds_t *fds = loop->io;
    int i;
    for(i=0;i<loop->size;i++)
    {
        if((fds[i].fd == ev->fd) && (fds[i].data == ev))
        {
            fds[i].fd = 0;
            fds[i].data = NULL;
            fds[i].event = 0; 
            return EXIT_SUCCESS;
        }
    }
    return EXIT_FAILURE;
}
static int mk_select_polling(ev_loop_t *loop, long timeout)
{
    struct pri_fds_t *fds = loop->io;
    struct timeval tv;
    int nfds, i;
    ev_event_t *ev;
    fd_set rfds, wfds, efds;
    for(;;)
    {
        nfds = 0;
        tv.tv_sec = (long) (timeout / 1000);
        tv.tv_usec = (long) ((timeout % 1000) * 1000);
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&efds);
        for(i=0;i<loop->size;i++)
        {
            if((fds[i].fd != 0) && (fds[i].data != NULL))
            {
                /* Exception */
                FD_SET(fds[i].fd, &efds);
                if((fds[i].event == EVENT_READ) || (fds[i].event == EVENT_RW)) 
                    FD_SET(fds[i].fd, &rfds);
                if((fds[i].event == EVENT_WRITE) || (fds[i].event == EVENT_RW)) 
                    FD_SET(fds[i].fd, &wfds);
                nfds = nfds > fds[i].fd ? nfds : fds[i].fd;
            }
        }
        i = select(nfds + 1, &rfds, &wfds, &efds, &tv);
        if (Event.tc_over)
            return EXIT_SUCCESS;
        if (i < 0)
        {
            ev_inner_log(ERROR, "failed with error [%d] %s", errno, strerror(errno));
            continue;
        }
        for(i=0;i<loop->size;i++)
        {
            if((fds[i].fd != 0) && (fds[i].data != NULL))
            {
                ev = fds[i].data;
                if (FD_ISSET(fds[i].fd, &efds) && ev->error_handler)
                {
                    FD_CLR(fds[i].fd, &efds);
                    ev_inner_log(INFO, "event fd(%d) error_handle", ev->fd);
                    ev->error_handler(ev); /*below not use ev, maybe delete in error_handle!!*/
                    /* if error, should not deal read/write events */
                    continue;
                }

                if (FD_ISSET(fds[i].fd, &rfds) && ev->read_handler)
                {
                    FD_CLR(fds[i].fd, &rfds);
                    ev_inner_log(DEBUG, "event fd(%d) read_handle", ev->fd);
                    if (ev->read_handler(ev) == EXIT_FAILURE)
                    {
                        ev_inner_log(INFO, "event fd(%d) read_handle return failure.", ev->fd);
                        if(ev->error_handler)
                        {
                            ev->error_handler(ev);
                            continue;
                        }
                    }
                }

                if (FD_ISSET(fds[i].fd, &wfds) && ev->write_handler)
                {
                    FD_CLR(fds[i].fd, &wfds);
                    ev_inner_log(DEBUG, "event fd(%d) write_handle", ev->fd);
                    if (ev->write_handler(ev) == EXIT_FAILURE)
                    {
                        ev_inner_log(INFO, "event fd(%d) write_handle return failure.", ev->fd);
                        if(ev->error_handler)
                        {
                            ev->error_handler(ev);
                            continue;
                        }
                     }
                }
            }
        }
    }
    return EXIT_SUCCESS;
}

ev_impl_t select_func = {
    .type    = "SELECT",
    .create  = mk_select_create,
    .destroy = mk_select_destroy,
    .add     = mk_select_add,
    .change  = mk_select_change,
    .del     = mk_select_del,
    .poll    = mk_select_polling,
};
