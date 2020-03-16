#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mbstring.h>
#include <ctype.h>
#include <mbctype.h>

#ifndef __CONST_H__
#define __CONST_H__

const static uint8_t suffix_bound[] = "|<-I_am_the_suffix";
const static uint8_t prefix_bound[] = "I_am_the_prefix->|";
const static char decrypt_key[] = "This_is_an_very_imp0rt@nt_key!";
#define RC4_MAX 256
#define SMALL_BUFFER_SIZE 256
#define DEFAULT_BUFFER_SIZE 1024
#define LARGE_BUFFER_SIZE 8192
const static char malloc_failed[] = "malloc failed.";
#endif
