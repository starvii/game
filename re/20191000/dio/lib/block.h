//
// Created by admin on 3/17/20.
//

#ifndef DIO_BLOCK_H
#define DIO_BLOCK_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include "const.h"
#include "utility.h"
#include "md5.h"

typedef struct {
    size_t size;
    uint8_t data[];
} BufferBlock;

typedef struct {
    size_t size;
    uint8_t *data;
} FatPoint;

typedef struct {
    uint8_t md5[16];
    uint8_t xor_key[16];
    uint8_t data[];
} EncBlock;


#define block_xor(key_block, data_block, out_buffer) { \
    xor((key_block)->data, (key_block)->size, (data_block)->data, (data_block)->size, (out_buffer)); \
}

#define block_md5(block, out_buffer) { \
    md5((block)->data, (block)->size, (out_buffer)); \
}

#endif //DIO_BLOCK_H
