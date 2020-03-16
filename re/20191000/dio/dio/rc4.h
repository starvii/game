#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mbstring.h>
#include <ctype.h>
#include <mbctype.h>
#include "utility.h"

#pragma once
size_t rc4(const BufferBlock* key, const BufferBlock* data, uint8_t* out_buffer);
void RC4Init(uint8_t* sbox, const uint8_t* key, const size_t len);
size_t RC4Crypto(uint8_t* sbox, const uint8_t* data, const size_t len, uint8_t* out_buffer);
