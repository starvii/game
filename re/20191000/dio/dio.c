#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include "lib/const.h"
#include "lib/md5.h"
#include "lib/utility.h"
#include "lib/block.h"
#include "dio.h"

static char *g_filename = NULL;

static int check_pass_code(const char *pass_code);

static size_t find_encrypted_data_from_end(const char *filename, uint8_t *out_buffer);

int main(int argc, char **argv, char **envp) {
    g_filename = argv[0];
    char pass_code[DEFAULT_BUFFER_SIZE] = {0};
    printf("Please input pass code:");
    fgets(pass_code, DEFAULT_BUFFER_SIZE, stdin);
//    scanf("%s", pass_code);
    if (0 == check_pass_code(pass_code)) {
        puts("Congratulations!");
    } else {
        puts("Sorry. Please try again.");
    }
    return getchar() + getchar();
}

/*
返回0则表示正确，其他值为错误。
*/
static int check_pass_code(const char *pass_code) {
    uint8_t buffer[LARGE_BUFFER_SIZE];
    char md5_1[33]; // 转成16进制字符串进行比较，方便逆向理解
    char md5_2[33]; // 转成16进制字符串进行比较，方便逆向理解

    const size_t n = find_encrypted_data_from_end(g_filename, buffer);
    const size_t flag_length = n - 16 - 16;
    if (strlen(pass_code) != flag_length) {
        return -1;
    }

    FatPoint fp = {n, buffer};
    FatPoint pre_key = {strlen(decrypt_key), (uint8_t *) decrypt_key};

    // 解密步骤
    // 1. 预置密钥解密
    block_xor(&pre_key, &fp, buffer);
    // 2. 校验MD5
    EncBlock *efb = (EncBlock *) buffer;
    hexlify(efb->md5, sizeof(efb->md5), md5_1);

    FatPoint efp = {flag_length, efb->data};
    uint8_t md5buffer[16];
    block_md5(&efp, (uint8_t *) &md5buffer);
    hexlify(md5buffer, 16, md5_2);
    int ret = strcmp(md5_1, md5_2);
    if (0 != ret) {
        return ret;
    }
    // 3. 密钥加密pass_code，对比结果是否正确
    FatPoint pc = {strlen(pass_code), (uint8_t *) pass_code};
    FatPoint key = {sizeof(efb->xor_key), efb->xor_key};

    uint8_t *dec_buf = (uint8_t *) calloc(1, efp.size);
    if (NULL == dec_buf) {
        perror(malloc_failed);
        exit(-1);
    }
    xor(key.data, key.size, pc.data, pc.size, dec_buf);
    ret = memcmp(dec_buf, efb->data, flag_length);
    free(dec_buf);
    return ret;
}

/* test md5 */
//int test_md5() {
//    char x[] = "0123456789";
//    uint8_t buf[16];
//    md5(x, strlen(x), buf);
//    uint8_t hexbuf[1024];
//    hexlify(buf, 16, hexbuf);
//    puts(hexbuf);
//    return 0;
//}

/* test check_passcode */
//int test_sha1() {
//    char x[] = "0123456789";
//    uint8_t buf[20];
//    sha1(x, strlen(x), buf);
//    uint8_t hexbuf[1024];
//    hexlify(buf, 20, hexbuf);
//    puts(hexbuf);
//    return 0;
//}

/* test  */
//int main() {
//    tpl_node* tn;
//    int id = 0;
//    char* name, * names[] = { "joe", "bob", "cary" };
//
//    tn = tpl_map("A(is)", &id, &name);
//
//    for (name = names[0]; id < 3; name = names[++id]) {
//        tpl_pack(tn, 1);
//    }
//
//    tpl_dump(tn, TPL_FILE, "users.tpl");
//    tpl_free(tn);
//    return 0;
//}


size_t search_from_end(const FatPoint *small, const FatPoint *large) {
    for (int64_t i = large->size - small->size; i >= 0; i--) {
        if (0 != memcmp(small->data, &large->data[i], small->size)) {
            continue;
        }
        return (size_t) i;
    }
}

size_t find_encrypted_data_from_end(const char *filename, uint8_t *out_buffer) {
    //size_t max = sizeof(out_buffer);
    //printf("max = %d\n", max);
    // 获取文件大小
    struct stat info;
    stat(filename, &info);
    size_t file_size = info.st_size;

    uint8_t *file_image = (uint8_t *) calloc(1, file_size);
    if (NULL == file_image) {
        perror(malloc_failed);
        exit(-1);
    }
    // 全部读入内存
    FILE *fp = 0;
    fp = fopen(filename, "rb");
    if ((NULL == fp)) {
        perror("error: open file failed.");
        exit(-2);
    }
    size_t read_size = fread(file_image, 1, file_size, fp);
    if (read_size != file_size) {
        perror("error: read file failed.");
        exit(-2);
    }
    fclose(fp);
    fp = NULL;
    // 查找相关数据

    FatPoint file_point = {file_size, file_image};
    FatPoint fix_point = {strlen((const char *) suffix_bound), (uint8_t *) suffix_bound};
    size_t suffix = search_from_end(&fix_point, &file_point);
    if (0 == suffix) {
        perror("error: find data-suffix failed.");
        exit(-3);
    }
    fix_point.size = strlen((const char *) prefix_bound);
    fix_point.data = (uint8_t *) prefix_bound;
    size_t prefix = search_from_end(&fix_point, &file_point);
    if (0 == prefix) {
        perror("error: find data-prefix failed.");
        exit(-3);
    }
    if (prefix + fix_point.size + 32 >= suffix) {
        perror("error: data is too short.");
        exit(-3);
    }
    size_t n = suffix - prefix - fix_point.size;
    memcpy(out_buffer, &file_image[prefix + fix_point.size], n);
    free(file_image);
    return n;
}
