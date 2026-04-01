#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((naked, noinline, used))
void rop_gadget(void) {
    __asm__("pop %rdi; ret");
}

static const char cmd[] =
    "/bin/sh -c \"printf '\\146\\154\\141\\147\\173\\155\\157\\143\\153\\137\\156\\141\\164\\151\\166\\145\\137\\163\\171\\163\\164\\145\\155\\162\\157\\160\\175\\n'\"";

__attribute__((noinline))
static void vuln(void) {
    char buf[64];
    puts("payload:");
    read(0, buf, 256);
    puts("done");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (getenv("CTF_AGENT_NEVER")) {
        system(cmd);
    }
    vuln();
    return 0;
}
