#include "const.h"
#include "utility.h"
#include "crc32.h"
#include "md5.h"

uint32_t get_uint32(const uint8_t* buffer) {
    return buffer[0]
        | buffer[1] << 8
        | buffer[2] << 16
        | buffer[3] << 24;
}

size_t hexlify(const BufferBlock* data, uint8_t* out_buffer) {
    static uint8_t table[] = "0123456789abcdef";
    size_t i = 0;
    for (i = 0; i < data->len; i++) {
        out_buffer[i * 2] = table[(data->p_data[i] >> 4) & 0xf];
        out_buffer[i * 2 + 1] = table[data->p_data[i] & 0xf];
    }
    size_t n = i * 2;
    out_buffer[n] = '\0';
    return n;
}

size_t xor (const BufferBlock* key, const BufferBlock* data, uint8_t* out_buffer) {
    size_t i = 0;
    for (i = 0; i < data->len; i++) {
        out_buffer[i] = data->p_data[i] ^ key->p_data[i % key->len];
    }
    return i;
}

size_t search_from_end(const BufferBlock* small, const BufferBlock* large) {
    for (int64_t i = large->len - small->len; i >= 0; i--) {
        if (memcmp(small->p_data, &large->p_data[i], small->len)) {
            continue;
        }
        return (size_t)i;
    }
}

size_t find_encrypted_data_from_end(const char* filename, uint8_t* out_buffer) {
    //size_t max = sizeof(out_buffer);
    //printf("max = %d\n", max);
    // 获取文件大小
    struct _stat info;
    _stat(filename, &info);
    size_t filesize = info.st_size;

    uint8_t* buffer = (uint8_t*)calloc(1, filesize);
    if (NULL == buffer) {
        perror(malloc_failed);
        exit(-2);
    }
    // 全部读入内存
    FILE* fp = 0;
    fp = fopen(filename, "rb");
    if ((NULL == fp)) {
        //perror("debug: open file failed.");
        return 0;
    }
    //size_t readsize = fread_s(buffer, filesize, 1, filesize, fp);
    size_t readsize = fread(buffer, 1, filesize, fp);
    if (readsize != filesize) {
        //perror("debug: read file failed.");
        return 0;
    }
    fclose(fp);
    fp = NULL;
    // 查找相关数据
    BufferBlock file_block = { buffer, filesize };
    BufferBlock xfix = { suffix_bound, strlen(suffix_bound) };
    size_t suffix = search_from_end(&xfix, &file_block);
    if (0 == suffix) {
        //perror("debug: find suffix failed.");
        return 0;
    }
    xfix.len = strlen(prefix_bound);
    xfix.p_data = prefix_bound;
    size_t prefix = search_from_end(&xfix, &file_block);
    if (0 == prefix) {
        //perror("debug: find prefix failed.");
        return 0;
    }
    if (prefix + xfix.len + 32 >= suffix) {
        //perror("debug: encrypted data too short.");
        return 0;
    }
    size_t n = suffix - prefix - xfix.len;
    memcpy(out_buffer, &buffer[prefix + xfix.len], n);
    free(buffer);
    return n;
}
