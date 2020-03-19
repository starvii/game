#include "utility.h"

size_t xor(const uint8_t *key, size_t key_size, const uint8_t *data, size_t data_size, uint8_t *out_buffer) {
    size_t i = 0;
    for (i = 0; i < data_size; i++) {
        out_buffer[i] = data[i] ^ key[i % key_size];
    }
    return i;
}

size_t hexlify(const uint8_t *raw, size_t size, char *out_buffer) {
    size_t i;
    bzero(out_buffer, (size << 2u) + 1u);
    for (i = 0; i < size; i++) {
        uint8_t byte = raw[i];
        out_buffer[i * 2] = HEX_CHARS[(byte >> 4u) & 0xfu];
        out_buffer[i * 2 + 1] = HEX_CHARS[byte & 0xfu];
    }
    return i * 2;
}
