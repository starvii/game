#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mbstring.h>
#include <ctype.h>
#include <mbctype.h>
#include "utility.h"

#pragma once
typedef struct
{
    uint32_t total[2];
    uint32_t state[5];
    uint8_t buffer[64];
} SHA1_CTX;

void sha1(const BufferBlock* data, uint8_t out_buffer[20]);
void SHA1Init(SHA1_CTX* ctx);
void SHA1Update(SHA1_CTX* ctx, const uint8_t* input, const uint32_t length);
void SHA1Final(SHA1_CTX* ctx, uint8_t digest[20]);
