#include "rc4.h"
#include "const.h"

size_t rc4(const BufferBlock* key, const BufferBlock* data, uint8_t* out_buffer) {
    uint8_t sbox[RC4_MAX] = { 0 };
    RC4Init(sbox, key->p_data, key->len);
    return RC4Crypto(sbox, data->p_data, data->len, out_buffer);
}

void RC4Init(uint8_t* sbox, const uint8_t* key, const size_t len)
{
    size_t j = 0;
    uint8_t t[RC4_MAX] = { 0 };
    uint8_t tmp = 0;
    for (int i = 0; i < RC4_MAX; i++)//初始化算法
    {
        sbox[i] = i;
        t[i] = key[i % len];
    }
    for (int i = 0; i < RC4_MAX; i++)//伪随机子密码生成算法
    {
        j = (j + sbox[i] + t[i]) % RC4_MAX;
        tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }
}

size_t RC4Crypto(uint8_t* sbox, const uint8_t* data, const size_t len, uint8_t* out_buffer)
{
    size_t i = 0, j = 0, k = 0;
    uint8_t tmp = 0;
    for (k = 0; k < len; k++)
    {
        i = (i + 1) % RC4_MAX;
        j = (j + sbox[i]) % RC4_MAX;
        tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
        int t = (sbox[i] + sbox[j]) % RC4_MAX;
        out_buffer[k] = data[i] ^ sbox[t];
    }
    return k;
}
