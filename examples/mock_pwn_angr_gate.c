#include <stdio.h>

static int gate_open(const char *buf) {
    if (((unsigned char)buf[0] ^ 0x11u) != ((unsigned char)'R' ^ 0x11u)) {
        return 0;
    }
    if ((unsigned char)(buf[1] + 3) != (unsigned char)('2' + 3)) {
        return 0;
    }
    if ((unsigned char)(buf[2] - 5) != (unsigned char)('p' - 5)) {
        return 0;
    }
    if (((unsigned char)buf[3] ^ (unsigned char)buf[0]) != ((unsigned char)'!' ^ (unsigned char)'R')) {
        return 0;
    }
    if (((unsigned char)buf[4] ^ 0x55u) != ((unsigned char)'7' ^ 0x55u)) {
        return 0;
    }
    if ((unsigned char)(buf[5] - 1) != (unsigned char)('x' - 1)) {
        return 0;
    }
    if ((unsigned char)buf[6] != 0x21u) {
        return 0;
    }
    if (buf[7] != '\n' && buf[7] != '\0') {
        return 0;
    }
    return 1;
}

static void emit_flag(void) {
    unsigned char encoded[] = {
        0x25, 0x2f, 0x22, 0x24, 0x38, 0x2e, 0x2c, 0x20,
        0x28, 0x1c, 0x33, 0x34, 0x2d, 0x1c, 0x24, 0x22,
        0x37, 0x26, 0x3e
    };
    unsigned char key = 0x43u;
    char out[sizeof(encoded) + 1];
    size_t i;

    for (i = 0; i < sizeof(encoded); ++i) {
        out[i] = (char)(encoded[i] ^ key);
    }
    out[sizeof(encoded)] = '\0';
    puts(out);
}

int main(void) {
    char buf[32];

    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Gate key:");
    if (!fgets(buf, sizeof(buf), stdin)) {
        return 1;
    }

    if (!gate_open(buf)) {
        puts("Gate closed");
        return 1;
    }

    puts("Gate opened");
    emit_flag();
    return 0;
}
