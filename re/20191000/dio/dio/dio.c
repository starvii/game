#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mbstring.h>
#include <ctype.h>
#include <mbctype.h>
#include <sys\stat.h>
#include "const.h"
#include "base64.h"
#include "md5.h"
#include "sha1.h"
#include "crc32.h"
#include "rc4.h"
#include "utility.h"


char* g_filename = NULL;

int check_passcode(const char* passcode);


int main(int argc, char** argv, char** envp)
{
    g_filename = argv[0];
    char passcode[DEFAULT_BUFFER_SIZE] = {0};
    printf("Please input passcode:");
    scanf("%s", passcode);
    if (check_passcode(passcode)) {
        puts("Congratulations!");
    }
    else {
        puts("Sorry. Please try again.");
    }
    return getchar() + getchar();
}

int check_passcode(char* passcode) {
    uint8_t buffer[LARGE_BUFFER_SIZE];
    uint8_t md5_1[SMALL_BUFFER_SIZE];
    uint8_t md5_2[SMALL_BUFFER_SIZE];

    size_t n = find_encrypted_data_from_end(g_filename, buffer);
    //size_t n = find_encrypted_data_from_end("C:\\home\\temp\\ctf\\dio\\dio.exe-flag.exe", buffer);
    if (0 == n) {
        //perror("debug: cannot find encrypted data in file.");
        return 0;
    }
    EndBlock ed;
    BufferBlock enc = { buffer, n };
    BufferBlock key = { decrypt_key, strlen(decrypt_key) };
    n = xor (&key, &enc, buffer);
    memcpy(ed.md5, buffer, 16);
    memcpy(ed.key, buffer + 16, 16);
    ed.block.len = n - 32;
    ed.block.p_data = buffer + 32;
    BufferBlock block = { ed.md5, 16 };
    hexlify(&block, md5_1);
    //printf("debug: expect md5 is {%s}\n", md5_1);
    uint8_t value_md5[16];
    block.p_data = buffer + 16;
    block.len = n - 16;
    md5(&block, value_md5);
    block.p_data = value_md5;
    block.len = 16;
    hexlify(&block, md5_2);
    //printf("debug: value md5 is {%s}\n", md5_2);
    if (strcmp(md5_1, md5_2)) {
        return 0;
    }
    key.len = 16;
    key.p_data = ed.key;
    block.len = strlen(passcode);
    block.p_data = passcode;

    n = xor (&key, &block, passcode);
    return !memcmp(passcode, ed.block.p_data, ed.block.len);
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

