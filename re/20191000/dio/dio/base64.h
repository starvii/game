#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mbstring.h>
#include <ctype.h>
#include <mbctype.h>

#pragma once

size_t base64_encode(const uint8_t* data, const size_t datasize, uint8_t* out_buffer);
size_t base64_decode(const uint8_t* data, const size_t datasize, uint8_t* out_buffer);
