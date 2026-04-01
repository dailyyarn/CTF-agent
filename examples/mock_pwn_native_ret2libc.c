#include <stdio.h>
#include <unistd.h>
#include <string.h>

__attribute__((used))
static const char cmd[] = "/bin/sh -c \"printf '%s%s%s\\n' 'flag{' 'mock_native_' 'ret2libc}'\"";

__attribute__((used, naked))
static void pop_rdi_ret(void) {
    __asm__("pop %rdi; ret");
}

__attribute__((noinline))
static void leak(void *ptr) {
    write(1, "LEAK:", 5);
    write(1, ptr, 8);
}

__attribute__((noinline))
static void vuln(void) {
    char buf[64];
    puts("payload:");
    read(0, buf, 256);
    puts("done");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (cmd[0] == '\0') {
        write(1, cmd, 1);
    }
    vuln();
    return 0;
}
