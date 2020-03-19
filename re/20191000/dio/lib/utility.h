//
// Created by admin on 3/17/20.
//

#ifndef DIO_UTILITY_H
#define DIO_UTILITY_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include "const.h"

#define HEX_CHARS "0123456789ABCDEF"

// size_t xor (size_t key_size, const uint8_t* key_data, size_t data_size, const uint8_t* data, uint8_t* out_buffer);
size_t xor(const uint8_t *key, size_t key_size, const uint8_t *data, size_t data_size, uint8_t *out_buffer);

size_t hexlify(const uint8_t *raw, size_t size, char *out_buffer);

#endif //DIO_UTILITY_H
