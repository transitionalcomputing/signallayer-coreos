#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;

static void stop(int sig) {
    (void)sig;
    running = 0;
}

static void print_file(const char *label, const char *path) {
    char buffer[4096];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("%s_error=%s\n", label, strerror(errno));
        return;
    }
    ssize_t size = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (size < 0) {
        printf("%s_error=%s\n", label, strerror(errno));
        return;
    }
    buffer[size] = '\0';
    printf("[%s]\n%s", label, buffer);
    if (size == 0 || buffer[size - 1] != '\n')
        putchar('\n');
}

static void probe_write(void) {
    int fd = open("/etc/sl-phase1-container-write", O_WRONLY | O_CREAT, 0600);
    printf("privileged_write=%s\n", fd < 0 ? strerror(errno) : "UNEXPECTED_SUCCESS");
    if (fd >= 0) {
        close(fd);
        unlink("/etc/sl-phase1-container-write");
    }
}

static void probe_socket(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    int result = fd < 0 ? -1 : connect(fd, (struct sockaddr *)&address, sizeof(address));
    printf("socket:%s=%s\n", path,
           result == 0 ? "UNEXPECTED_CONNECTED" : strerror(errno));
    if (fd >= 0)
        close(fd);
}

int main(void) {
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    printf("uid=%ld euid=%ld gid=%ld egid=%ld pid=%ld\n",
           (long)getuid(), (long)geteuid(), (long)getgid(), (long)getegid(), (long)getpid());
    print_file("uid_map", "/proc/self/uid_map");
    print_file("gid_map", "/proc/self/gid_map");
    print_file("status", "/proc/self/status");
    print_file("selinux", "/proc/self/attr/current");
    print_file("cgroup", "/proc/self/cgroup");
    print_file("mountinfo", "/proc/self/mountinfo");
    probe_write();
    probe_socket("/run/podman/podman.sock");
    probe_socket("/run/systemd/private");
    fflush(stdout);
    while (running)
        pause();
    return 0;
}
