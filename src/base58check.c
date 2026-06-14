#include <string.h>
#include "sha256.c"


const char* BASE58_ALPHABET = "123456789"
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz";

static void base58(size_t s_size, uint8_t s[static s_size], size_t out_size, char out[static out_size]) {
    int c, i, n;

    out[n = out_size] = 0;
    while (n--) {
        for (c = i = 0; i < s_size; i++) {
            c = c * 256 + s[i];
            s[i] = c / 58;
            c %= 58;
        }
        out[n] = BASE58_ALPHABET[c];
    }
}

void base58check(size_t data_len, const uint8_t data[static data_len], size_t out_size, char out[static out_size]) {
    uint8_t buffer[data_len + 4];
    memcpy(buffer, data, data_len);

    uint8_t checksum[32];
    sha256(data_len, data, checksum);
    sha256(32, checksum, checksum);

    memcpy(buffer + data_len, checksum, 4);
    base58(data_len + 4, buffer, out_size, out);
}
