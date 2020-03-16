#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mbstring.h>
#include <ctype.h>
#include <mbctype.h>
#include "crc32.h"


static uint32_t crc32tab[256];

uint32_t bitrev(uint32_t input, int bw)
{
    int i;
    uint32_t var;
    var = 0;
    for (i = 0; i < bw; i++)
    {
        if (input & 0x01)
        {
            var |= 1 << (bw - 1 - i);
        }
        input >>= 1;
    }
    return var;
}

void crc32_init(uint32_t poly)
{
    size_t i, j;
    uint32_t c;

    poly = bitrev(poly, 32);
    for (i = 0; i < 256; i++)
    {
        c = i;
        for (j = 0; j < 8; j++)
        {
            if (c & 1)
            {
                c = poly ^ (c >> 1);
            }
            else
            {
                c = c >> 1;
            }
        }
        crc32tab[i] = c;
    }
}

uint32_t crc32(const uint8_t* buf, size_t size)
{
    uint32_t crc = 0xFFFFFFFF;
    if (0 == crc32tab[0]) {
        crc32_init(0x4C11DB7);
    }
    for (size_t i = 0; i < size; i++) {
        crc = crc32tab[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}
