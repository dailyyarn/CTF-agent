#include <stdio.h>
#include <unistd.h>

__attribute__((noinline))
static void win(void) {
    puts("flag{mock_native_ret2win}");
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
    vuln();
    return 0;
}
