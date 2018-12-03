#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>        // <-- This one
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <assert.h>
#include "tun_dev.h"

static int tun_open(tundev_t *tdev, const char *dev)
{
    struct ifreq ifr;
    assert(tdev);
    memset(tdev, 0, sizeof(tundev_t));
    if ((tdev->tfd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        tun_inner_log(ERROR, "tun '%s' open failed: %s", dev, strerror(errno));
        return EXIT_FAILURE;
    }
    memset(&ifr, 0, sizeof(ifr));
#if USE_TUN
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
#else
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
#endif
    if (*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (!ioctl(tdev->tfd, TUNSETIFF, (void *)&ifr))
    {
        strncpy(tdev->devname, ifr.ifr_name, IFNAMSIZ);
        return EXIT_SUCCESS;
    }
    tun_inner_log(ERROR, "tun '%s' ioctl failed: %s", dev, strerror(errno));
    close(tdev->tfd);
    memset(tdev, 0, sizeof(tundev_t));
    return EXIT_FAILURE;
}

static int tun_close(tundev_t *tdev)
{
    assert(tdev);
    int fd = tdev->tfd;
    memset(tdev, 0, sizeof(tundev_t));
    return close(fd);
}

static int tun_write(tundev_t * tdev, char *buf, int len)
{
    return write(tdev->tfd, buf, len);
}

static int tun_read(tundev_t * tdev, char *buf, int len)
{
    return read(tdev->tfd, buf, len);
}

static void *tun_get_data(tundev_t * tdev)
{
    return tdev->ctx;
}

static void tun_set_data(tundev_t * tdev, void *data)
{
    tdev->ctx = data;
}

static int tun_getfd(tundev_t * tdev)
{
    return tdev->tfd;
}

static const char *tun_getname(tundev_t * tdev)
{
    return tdev->devname;
}

static uint64_t tun_getmac(tundev_t *tdev)
{
    struct ifreq ifr;
    if(tdev->mac)
        return tdev->mac;
    memset(&ifr, 0, sizeof(ifr));
    if (!(ioctl(tdev->tfd, SIOCGIFHWADDR, (void *)&ifr)))
    {
        memcpy(&tdev->mac, ifr.ifr_hwaddr.sa_data, 6);
    }
    return tdev->mac;
}

struct tun_operator Tun =
{
    .open = tun_open,
    .close = tun_close,
    .write = tun_write,
    .read = tun_read,
    .getfd = tun_getfd,
    .getname = tun_getname,
    .getmac = tun_getmac,
    .get_ctx = tun_get_data,
    .set_ctx = tun_set_data,
};
