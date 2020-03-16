#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mbstring.h>
#include <ctype.h>
#include <mbctype.h>
#include <sys\stat.h>
#include "const.h"

#pragma once
typedef struct {
    uint8_t* p_data;
    size_t len;
} BufferBlock;

typedef struct {
    uint8_t md5[16];
    uint8_t key[16];
    BufferBlock block;
} EndBlock;

size_t find_encrypted_data_from_end(const char* filename, uint8_t* out_buffer);
uint32_t get_uint32(const uint8_t* buffer);
size_t hexlify(const BufferBlock* data, uint8_t* out_buffer);
size_t xor (const BufferBlock* key, const BufferBlock* data, uint8_t* out_buffer);
