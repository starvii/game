/*base64.c*/
#include "base64.h"

uint8_t enc_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
uint8_t dec_table[] = {
            0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,62,0,0,0,
            63,52,53,54,55,56,57,58,
            59,60,61,0,0,0,0,0,0,0,0,
            1,2,3,4,5,6,7,8,9,10,11,12,
            13,14,15,16,17,18,19,20,21,
            22,23,24,25,0,0,0,0,0,0,26,
            27,28,29,30,31,32,33,34,35,
            36,37,38,39,40,41,42,43,44,
            45,46,47,48,49,50,51
};

size_t base64_encode(const uint8_t* data, size_t datasize, uint8_t* out_buffer)
{
    size_t out_len;
    unsigned char* res;
    int i, j;

    //计算经过base64编码后的字符串长度  
    if (datasize % 3 == 0)
        out_len = datasize / 3 * 4;
    else
        out_len = (datasize / 3 + 1) * 4;

    //以3个8位字符为一组进行编码  
    for (i = 0, j = 0; i < out_len - 2; j += 3, i += 4)
    {
        out_buffer[i] = enc_table[data[j] >> 2]; //取出第一个字符的前6位并找出对应的结果字符  
        out_buffer[i + 1] = enc_table[(data[j] & 0x3) << 4 | (data[j + 1] >> 4)]; //将第一个字符的后位与第二个字符的前4位进行组合并找到对应的结果字符  
        out_buffer[i + 2] = enc_table[(data[j + 1] & 0xf) << 2 | (data[j + 2] >> 6)]; //将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符  
        out_buffer[i + 3] = enc_table[data[j + 2] & 0x3f]; //取出第三个字符的后6位并找出结果字符  
    }

    switch (datasize % 3)
    {
    case 1:
        out_buffer[i - 2] = '=';
        out_buffer[i - 1] = '=';
        break;
    case 2:
        out_buffer[i - 1] = '=';
        break;
    }

    return out_len;
}

size_t base64_decode(const uint8_t* data, size_t datasize, uint8_t* out_buffer)
{
    long out_len;
    int i, j;

    //判断编码后的字符串后是否有=  
    if (strstr(data, "=="))
        out_len = datasize / 4 * 3 - 2;
    else if (strstr(data, "="))
        out_len = datasize / 4 * 3 - 1;
    else
        out_len = datasize / 4 * 3;

    //以4个字符为一位进行解码  
    for (i = 0, j = 0; i < out_len - 2; j += 3, i += 4)
    {
        out_buffer[j] = (dec_table[data[i]]) << 2 | ((dec_table[data[i + 1]]) >> 4); //取出第一个字符对应base64表的十进制数的前6位与第二个字符对应base64表的十进制数的后2位进行组合  
        out_buffer[j + 1] = ((dec_table[data[i + 1]]) << 4) | ((dec_table[data[i + 2]]) >> 2); //取出第二个字符对应base64表的十进制数的后4位与第三个字符对应bas464表的十进制数的后4位进行组合  
        out_buffer[j + 2] = ((dec_table[data[i + 2]]) << 6) | (dec_table[data[i + 3]]); //取出第三个字符对应base64表的十进制数的后2位与第4个字符进行组合  
    }

    return out_len;
}