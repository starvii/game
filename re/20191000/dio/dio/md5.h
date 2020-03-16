#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mbstring.h>
#include <ctype.h>
#include <mbctype.h>
#include "const.h"
#include "utility.h"

#pragma once

#define R_memset(x, y, z) memset(x, y, z)
#define R_memcpy(x, y, z) memcpy(x, y, z)
#define R_memcmp(x, y, z) memcmp(x, y, z)

/* MD5 context. */
typedef struct {
    /* state (ABCD) */
    /*�ĸ�32bits�������ڴ�����ռ���õ�����ϢժҪ������Ϣ���ȡ�512bitsʱ��Ҳ���ڴ��ÿ��512bits���м���*/
    uint32_t state[4];

    /* number of bits, modulo 2^64 (lsb first) */
    /*�洢ԭʼ��Ϣ��bits������,����������bits���Ϊ 2^64 bits����Ϊ2^64��һ��64λ�������ֵ*/
    uint32_t count[2];

    /* input buffer */
    /*����������Ϣ�Ļ�������512bits*/
    uint8_t buffer[64];
} MD5_CTX;

void md5(const BufferBlock* data, uint8_t out_buffer[16]);

void MD5Init(MD5_CTX*);
void MD5Update(MD5_CTX*, const uint8_t*, const size_t);
void MD5Final(MD5_CTX*, uint8_t[16]);
