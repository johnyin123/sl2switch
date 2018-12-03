#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include "conf.h"
#include "l2switch.h"

void mainloop(conf_t *cfg);

static void handle_signal(int sig)
{
    switch (sig)
    {
    case SIGQUIT:
    case SIGTERM:
    case SIGINT:
        Event.tc_over = 1;
        break;
    }
}

static int signal_init()
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGQUIT, handle_signal);
    return 0;
}

static void tun_init(conf_t *cfg, const char *name, const char *ifup, const char *nodename)
{
    //tun_name[0] = '\0';
    if (Tun.open(&cfg->tdev, name) == EXIT_FAILURE)
        exit(EXIT_FAILURE);
    uint64_t mac = Tun.getmac(&cfg->tdev);
    dump_hex(stderr, &mac, 8, "%s macaddress %Zx", Tun.getname(&cfg->tdev), mac);
    script_init_env(Tun.getname(&cfg->tdev), nodename);
    if (!run_script(ifup, true))
    {
        inner_log(ERROR, "interface initialization command '%s' failed.", ifup);
        exit(EXIT_FAILURE);
    }
    if (setnonblocking(Tun.getfd(&cfg->tdev)) < 0)
        inner_log(ERROR, "tun setnonblocking error");
}

#ifdef HAVE_TLS
static int tls_init(connection_t *c, conf_t *cfg)
{
    SSL_CTX *ctx;
    if ((ctx = tls_ctx_init()) == NULL)
        return -1;
    if (!tls_ctx_ca(ctx, cfg->ca))
        goto err;
    if (!tls_ctx_cert(ctx, cfg->cert))
        goto err;
    if (!tls_ctx_key(ctx, cfg->key))
        goto err;
    set_tls_ctx(c, ctx);
    return 0;
err:
    return -2;
}
#endif

int main(int argc, char *argv[])
{
    char ifup[PATH_MAX + NAME_MAX];
    signal_init();
    conf_t cfg;
    Conf.load_conf(&cfg, argc, argv);
    Conf.dump(&cfg);
    sprintf(ifup,"%s/%s", cfg.conf_path, cfg.ifup);
    tun_init(&cfg, cfg.devname, ifup, cfg.nodename);
    int ret1 = AsyncSocket.socket(&cfg.srv, PF_INET, SOCK_STREAM, IPPROTO_IP);
    int ret2 = Event.loop_init(&cfg.event_loop, cfg.maxfds);
#ifdef HAVE_TLS
    if (tls_init(&cfg.srv, &cfg) != 0)
    {
        inner_log(ERROR, "tls_init error");
        goto out;
    }
#endif
    if (ret1 == EXIT_FAILURE || ret2 == EXIT_FAILURE)
    {
        inner_log(ERROR, "event = %d, socket = %d\n", ret1, ret2);
        goto out;
    }
    /*add conf_t to tun private data */
    Tun.set_ctx(&cfg.tdev, &cfg);
    /*add conf_t to socket private data */
    AsyncSocket.set_ctx(&cfg.srv, &cfg);
    if (AsyncSocket.listen(&cfg.srv, cfg.port, 64) != EXIT_SUCCESS)
    {
        goto out;
    }
    mainloop(&cfg);
out:
#ifdef HAVE_TLS
    if (cfg.srv.tls_ctx)
        tls_ctx_free(cfg.srv.tls_ctx);
#endif
    Tun.close(&cfg.tdev);
    AsyncSocket.close(&cfg.srv);
    Event.loop_final(&cfg.event_loop);
    inner_log(INFO, "Event.loop_finish over");
    Conf.free_conf(&cfg);
    fprintf(stderr, "BYE\n");
    return EXIT_SUCCESS;
}
