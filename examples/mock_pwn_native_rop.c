#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

__attribute__((naked, noinline, used))
void rop_gadget(void) {
    __asm__("pop %rdi; ret");
}

__attribute__((noinline))
static void win(unsigned long key) {
    static const unsigned char encoded[] = {
        0x34, 0x3e, 0x33, 0x35, 0x29, 0x3f, 0x3d, 0x31, 0x39,
        0x0d, 0x3c, 0x33, 0x26, 0x3b, 0x24, 0x37, 0x0d, 0x20,
        0x3d, 0x22, 0x2f
    };
    char out[sizeof(encoded) + 1];

    if (key != 0x1337133713371337ULL) {
        puts("nope");
        return;
    }
    for (size_t i = 0; i < sizeof(encoded); ++i) {
        out[i] = (char)(encoded[i] ^ 0x52);
    }
    out[sizeof(encoded)] = '\0';
    puts(out);
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
