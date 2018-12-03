#include "misc.h"
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
void script_init_env(const char *ifname, const char *nodename)
{
    setenv("IFNAME", ifname, 1);
    setenv("MTU", "1500", 1);
    setenv("NODENAME", nodename, 1);
//    char buf[1024];
//    snprintf(buf, sizeof(buf), "fe:fd:80:00:%02x:%02x", conf->id >> 8, conf->id & 0xff);
//    setenv("MAC", buf, 1);
}

pid_t run_script(const char *script, bool wait)
{
    sigset_t oldset;
    if (wait)
    {
        sigset_t sigchld;
        sigemptyset(&sigchld);
        sigaddset(&sigchld, SIGCHLD);
        sigprocmask(SIG_BLOCK, &sigchld, &oldset);
    }
    pid_t pid = fork();
    if (pid == 0)
    {
        sigprocmask(SIG_SETMASK, &oldset, 0);
        execl("/bin/sh", "/bin/sh", "-c", script, (char *)0);
        exit(EXIT_FAILURE);
    }
    else if (pid > 0)
    {
        if (wait)
        {
            int status;
            int res = waitpid(pid, &status, 0);

            sigprocmask(SIG_SETMASK, &oldset, 0);

            if (res < 0)
            {
                inner_log(INFO, "waiting for an external command failed: %s.", strerror(errno));
                return 0;
            }
            else if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
            {
                inner_log(INFO, "external command returned with exit status %d (%04x).", WEXITSTATUS(status), status);
                return 0;
            }
        }
    }
    else
    {
        inner_log(INFO, "unable to fork, exiting: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return pid;
}
