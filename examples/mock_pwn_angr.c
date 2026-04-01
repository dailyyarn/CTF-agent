#include <stdio.h>
#include <string.h>

static int matches_secret(const char *buf) {
    return buf[0] == ('m' ^ 0x00) &&
           buf[1] == ('4' ^ 0x00) &&
           buf[2] == ('z' ^ 0x00) &&
           buf[3] == ('e' ^ 0x00) &&
           buf[4] == ('-') &&
           buf[5] == ('4') &&
           buf[6] == ('2') &&
           (buf[7] == '\n' || buf[7] == '\0');
}

static void emit_flag(void) {
    unsigned char encoded[] = {
        0x21, 0x2b, 0x26, 0x20, 0x3c, 0x2a, 0x28, 0x24,
        0x2c, 0x18, 0x37, 0x30, 0x29, 0x18, 0x26, 0x29,
        0x20, 0x35, 0x3a, 0x47
    };
    unsigned char key = 0x47;
    char out[sizeof(encoded)];
    size_t i;

    for (i = 0; i < sizeof(encoded); ++i) {
        out[i] = (char)(encoded[i] ^ key);
    }
    puts(out);
}

int main(void) {
    char buf[32];

    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Input token:");
    if (!fgets(buf, sizeof(buf), stdin)) {
        return 1;
    }

    if (!matches_secret(buf)) {
        puts("Access denied");
        return 1;
    }

    puts("Access granted");
    emit_flag();
    return 0;
}
