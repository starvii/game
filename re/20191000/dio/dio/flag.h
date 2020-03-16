#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mbstring.h>
#include <ctype.h>
#include <mbctype.h>
#include <sys\stat.h>
#include "utility.h"

#pragma once

typedef struct {
    BufferBlock input;
    uint8_t func_index;
    uint8_t param_count;
    BufferBlock params[3];
} FlagBlock;

size_t flag_block_from(uint8_t* bytes, FlagBlock* out_flag_blocks, size_t* out_count);
