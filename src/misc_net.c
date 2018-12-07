#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include "misc.h"

#define IP_LENGTH    48

int settimeout(const int sockfd)
{
#define RECEIVE_TIMEOUT 30
#define SEND_TIMEOUT 5
    struct timeval timeout;
    timeout.tv_sec  = RECEIVE_TIMEOUT;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    timeout.tv_sec  = SEND_TIMEOUT;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    return EXIT_SUCCESS;
}
void setcloseexec(int fd)
{
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

int setreuseaddr(int socket)
{
    int status = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &status, sizeof(int)) == -1)
    {
        inner_log(ERROR, "setsockopt error %d", errno);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
int setreuseport(int fd)
{
    int flag = 1;
    int len = sizeof(flag);
    return setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &flag, len);
}
int getsockerror(int fd)
{
    int error;
    socklen_t len = sizeof(error);
    if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0)
    {
        return EXIT_SUCCESS;/* return 0, this fd is connected!! */
    }
    return EXIT_FAILURE;
}
int getsock_ip(int fd, char *ipaddr, socklen_t len, ushort *port)
{
    struct sockaddr_storage name;
    char sport[64];
    socklen_t namelen = sizeof(name);
    assert(fd >= 0);
    if(getsockname(fd,(struct sockaddr *) &name, &namelen) != 0)
    {
        inner_log(ERROR, "getsock_ip: getsockname() error: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    if(0 != getnameinfo((struct sockaddr *)&name, namelen, ipaddr, len, sport, sizeof(sport), NI_NUMERICHOST | NI_NUMERICSERV))
    {
        inner_log(ERROR, "getsock_ip: getnameinfo() error: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    *port = atoi(sport);
    return EXIT_SUCCESS;
}

/* return 1 if string contain only digits, else return 0 */
bool valid_digit(const char *str)
{
    while (*str) {
        if (*str >= '0' && *str <= '9')
            ++str;
        else
            return false;
    }
    return true;
}
#include <regex.h>
int regex_chk(const char *str, const char *pattern)
{
    int i, z; //status
    int cflags = 0; //compile flags
    regex_t reg; //compiled regular expression
    char ebuf[128]; //error buffer
    regmatch_t pm[10]; //pattern matches 0-9
    const size_t nmatch = 10; //The size of array pm[]
    /** //编译正则表达式
     * @param const char* pattern 将要被编译的正则表达式
     * @param regex_t* reg 用来保存编译结果
     * @param int cflags 决定正则表达式将如何被处理的细节
     *
     * @return success int 0 并把编译结果填充到reg结构中
     * fail int 非0
     */
    z = regcomp(&reg, pattern, cflags);

    if(z != 0) {
        regerror(z, &reg, ebuf, sizeof(ebuf));
        fprintf(stderr, "%s: pattern '%s'\n", ebuf, pattern);
        return 1;
    }
    //report the number of subexpressions
    if(!(cflags & REG_NOSUB))
        printf("There were %lu subexpression.\n", reg.re_nsub);
    /**
     * reg 指向编译后的正则表达式
     * str 指向将要进行匹配的字符串
     * pm str字符串中可能有多处和正则表达式相匹配， pm数组用来保存这些位置
     * nmacth 指定pm数组最多可以存放的匹配位置数
     *
     * @return 函数匹配成功后，str+pm[0].rm_so到str+pm[0].rm_eo是第一个匹配的子串
     * str+pm[1].rm_so到str+pm[1].rm_eo是第二个匹配的子串
     * ....
     */
    for(i=0; i<1000000; i++)
        z = regexec(&reg, str, nmatch, pm, 0);

    if(z == REG_NOMATCH)
        return 1;
    else if(z != 0) {
        regerror(z, &reg, ebuf, sizeof(ebuf));
        fprintf(stderr, "%s: regcomp('%s')\n", ebuf, str);
        return 2;
    }

    regfree(&reg);
    return 0;
}

/* return 1 if IP string is valid, else return 0 */
bool is_valid_ip(const char *ip_str)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip_str, &(sa.sin_addr));
    return result != 0;
}

#include <ctype.h>
#include <stdarg.h>

void dump_hex(FILE *fp, const void *vptr, int size, const char *fmt, ...)
{
    int i, j;
    char buffer[256], graph[32];
    const char *ptr = (const char*)vptr;

    va_list ap;
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);

    fprintf(fp, " DUMP %p[%d]\n", vptr, size);
    for (i = 0; i < size; i += 16)
    {
        for (j = 0; j < 16 && i + j < size; ++j)
        {
            sprintf(buffer + j * 3, "%02X ", ((unsigned char *)ptr)[i + j]);
            graph[j] = isprint(ptr[i + j])? ptr[i + j]: '.';
        }
        graph[j] = '\0';
        if (j > 8)
            buffer[23] = '-';
        fprintf(fp, "\t0x%04X:  %-47.47s  %.16s\n", i, buffer, graph);
    }
    fflush(fp);
}

