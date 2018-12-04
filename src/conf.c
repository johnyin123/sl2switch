#include "conf.h"
#include "misc.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <getopt.h>

static void _destroy_conf(conf_t *conf)
{
    outgoing_t *out;
    list_for_each_entry(out, &conf->outgoing.link, link)
    {
        list_remove(&out->link);
        mem_free(out);
    }
}

static void default_conf(conf_t *conf)
{
    assert(conf);
    memset(conf, 0, sizeof(conf_t));
    conf->port = 8880;
    conf->maxfds = 64;
    conf->timer_tick = 1800*1000; /* msec */
    strcpy(conf->devname, "tunvpn0");
    gethostname(conf->nodename, sizeof(conf->nodename));
    get_abs_path(conf->conf_path, sizeof(conf->conf_path));
    //strcpy(, "/home/johnyin/ansible/tun/mvpn");
    strcpy(conf->ifup, "if-up");
    strcpy(conf->ca, "keys/ca");
    strcpy(conf->cert, "keys/cert"); 
    strcpy(conf->key, "keys/key");
    list_init(&(conf->peers.link));
    list_init(&(conf->outgoing.link));
}

static int _load_conf(conf_t *conf, int argc, char *argv[])
{
    default_conf(conf);
    struct option long_opts[] = {
        {"help", no_argument, NULL, 'h'},
        {"verbose", no_argument, NULL, 'v'},
        {"port", required_argument, NULL, 'p'},
        {"devname", required_argument, NULL, 'd'},
        {"nodename", required_argument, NULL, 'n'},
        {"ifup", required_argument, NULL, 's'},
        {"ca", required_argument, NULL, 'C'},
        {"cert", required_argument, NULL, 'c'},
        {"key", required_argument, NULL, 'k'},
        {"interval", required_argument, NULL, 't'},
        {0, 0, 0, 0},
    };
    const char *optstring = "h?v+p:d:n:s:C:c:k:t:";
    for (;;)
    {
        int idx = 1;
        int c = getopt_long(argc, argv, optstring, long_opts, &idx);
        if (c == -1)
            break;
        switch (c)
        {
        case 'h':
        case '?':
            printf("Usage: %s [-h?vpdnsCckt] [connect to peers]\n" "          \n\n", argv[0]);

            printf("Options:\n");
            printf("  -?, -h, --help    show this help screen\n");
            printf("  -v, --verbose     increase verbosity\n");

            printf("  -p, --port        listen port\n");
            printf("                    default: %d\n", conf->port);
            printf("  -d, --devname     tun/tap device name\n");
            printf("                    default: %s\n", conf->devname);
            printf("  -n, --nodename    local node name\n");
            printf("                    default: %s\n", conf->nodename);
            printf("  -s, --ifup        tun device ifup scripte\n");
            printf("                    default: %s\n", conf->ifup);
            printf("  -C, --ca          the ca chain file to use\n");
            printf("                    default: %s\n", "ca");
            printf("  -c, --cert        the client cert file to load\n");
            printf("                    default: %s\n", "cert");
            printf("  -k, --key         the the client key file to use\n");
            printf("                    default: %s\n", "key");
            printf("  -t, --interval    time interval(msec)\n");
            printf("                    default: %lu\n", conf->timer_tick);
            _destroy_conf(conf);
            exit(EXIT_SUCCESS);

        case 'v':
            log_level++;
            //conf->verbose++;
            break;
        case 'p':
            conf->port = atoi(optarg);
            break;
        case 'd':
            strcpy(conf->devname, optarg);
            break;
        case 'n':
            strcpy(conf->nodename, optarg);
            break;
        case 's':
            strcpy(conf->ifup, optarg);
            break;
        case 'C':
            strcpy(conf->ca, optarg);
            break;
        case 'c':
            strcpy(conf->cert, optarg);
            break;
        case 'k':
            strcpy(conf->key, optarg);
            break;
        case 't':
            conf->timer_tick = atoi(optarg);
            break;
        default:
            _destroy_conf(conf);
            fprintf(stderr, "unhandled option flag %#02x\n", c);
            exit(EXIT_FAILURE);
        }
    }
    for(; optind<argc; optind++)
    {
        char ip[1024], sport[1024];
        sscanf(argv[optind],"%15[^:]:%s", ip, sport);
        if(is_valid_ip(ip) && valid_digit(sport))
        {
            outgoing_t *out = mem_calloc(1, sizeof(outgoing_t));
            out->ipaddr = inet_addr(ip);
            out->port = atoi(sport);
            list_append(&(conf->outgoing.link), &out->link);
        }
        else
        {
            fprintf(stderr, "%s valid error %s,%s\n", argv[optind], ip, sport);
        }
    }
    return EXIT_SUCCESS;
}

static void _dump(conf_t * v)
{
    int cnt;
    char ipaddr[20];
    struct in_addr s;
    outgoing_t *out;
    fprintf(stderr, "configuration: \n");
    fprintf(stderr, "      port      =  %d\n", v->port);
    fprintf(stderr, "      maxfds    =  %d\n", v->maxfds);
    fprintf(stderr, "      devname   =  %s\n", v->devname);
    fprintf(stderr, "      nodename  =  %s\n", v->nodename);
    fprintf(stderr, "      ifup      =  %s\n", v->ifup);
    fprintf(stderr, "      ca        =  %s\n", v->ca);
    fprintf(stderr, "      cert      =  %s\n", v->cert);
    fprintf(stderr, "      key       =  %s\n", v->key);
    fprintf(stderr, "      log_level =  %d\n", log_level);
    cnt = 0;
    list_for_each_entry(out, &v->outgoing.link, link)
    {
        cnt++;
        s.s_addr = out->ipaddr;
        fprintf(stderr, "      [%.2d]      =  %X(%s):%d\n", cnt, out->ipaddr, inet_ntop(AF_INET, &s, ipaddr, 16), out->port);
    }
    fprintf(stderr, "-----------------------------------------\n");
}

struct conf_operator Conf =
{
    .load_conf = _load_conf,
    .free_conf = _destroy_conf,
    .dump      = _dump,
};

