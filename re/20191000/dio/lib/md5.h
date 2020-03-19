//
// Created by admin on 3/17/20.
//

#ifndef DIO_MD5_H
#define DIO_MD5_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "const.h"
#include "utility.h"

#define R_memset(x, y, z) memset(x, y, z)
#define R_memcpy(x, y, z) memcpy(x, y, z)
#define R_memcmp(x, y, z) memcmp(x, y, z)

/* MD5 context. */
typedef struct {
    /* state (ABCD) */
    /*四个32bits数，用于存放最终计算得到的消息摘要。当消息长度〉512bits时，也用于存放每个512bits的中间结果*/
    uint32_t state[4];

    /* number of bits, modulo 2^64 (lsb first) */
    /*存储原始信息的bits数长度,不包括填充的bits，最长为 2^64 bits，因为2^64是一个64位数的最大值*/
    uint32_t count[2];

    /* input buffer */
    /*存放输入的信息的缓冲区，512bits*/
    uint8_t buffer[64];
} MD5_CTX;

void md5(const uint8_t *data, size_t size, uint8_t out_buffer[16]);

void MD5Init(MD5_CTX *);

void MD5Update(MD5_CTX *, const uint8_t *, size_t);

void MD5Final(MD5_CTX *, uint8_t[16]);

#endif //DIO_MD5_H
