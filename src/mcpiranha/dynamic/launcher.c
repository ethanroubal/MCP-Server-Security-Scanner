/* Trusted static launcher: seed only synthetic files, wait for the external tracer,
 * then replace this process with the server. No interpreter from the server image runs here.
 */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &signals, NULL) || argc < 2) return 120;
    const char *home = "/tmp/mcpiranha-home";
    const char *dirs[] = {"", "/.ssh", "/.aws", "/.config", "/.config/chromium",
                          "/.config/chromium/Default"};
    char path[256];
    for (unsigned i = 0; i < sizeof(dirs)/sizeof(dirs[0]); ++i) {
        snprintf(path, sizeof(path), "%s%s", home, dirs[i]);
        if (mkdir(path, 0700) && access(path, W_OK)) return 121;
    }
    const char *files[] = {"/.ssh/id_rsa", "/.aws/credentials", "/.env",
                           "/.config/chromium/Default/Cookies"};
    for (unsigned i = 0; i < sizeof(files)/sizeof(files[0]); ++i) {
        snprintf(path, sizeof(path), "%s%s", home, files[i]);
        FILE *file = fopen(path, "w");
        if (!file) return 122;
        fputs("MCPIRANHA_HONEYTOKEN_SYNTHETIC_ONLY\n", file);
        fclose(file);
    }
    FILE *canary = fopen("/tmp/mcpiranha-canary", "w");
    if (!canary) return 126;
    fputs("MCPIRANHA_TRAVERSAL_CANARY\n", canary);
    fclose(canary);
    snprintf(path, sizeof(path), "%s/workspace", home);
    if (mkdir(path, 0700) && access(path, W_OK)) return 127;
    setenv("HOME", home, 1);
    int ready = open("/tmp/mcpiranha-launcher-ready", O_WRONLY|O_CREAT, 0644);
    if (ready < 0) return 123;
    close(ready);
    int received;
    if (sigwait(&signals, &received)) return 124;
    sigprocmask(SIG_UNBLOCK, &signals, NULL);
    execvp(argv[1], &argv[1]);
    perror("mcpiranha launcher exec");
    return 125;
}
