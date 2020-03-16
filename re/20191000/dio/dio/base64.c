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

    //���㾭��base64�������ַ�������  
    if (datasize % 3 == 0)
        out_len = datasize / 3 * 4;
    else
        out_len = (datasize / 3 + 1) * 4;

    //��3��8λ�ַ�Ϊһ����б���  
    for (i = 0, j = 0; i < out_len - 2; j += 3, i += 4)
    {
        out_buffer[i] = enc_table[data[j] >> 2]; //ȡ����һ���ַ���ǰ6λ���ҳ���Ӧ�Ľ���ַ�  
        out_buffer[i + 1] = enc_table[(data[j] & 0x3) << 4 | (data[j + 1] >> 4)]; //����һ���ַ��ĺ�λ��ڶ����ַ���ǰ4λ������ϲ��ҵ���Ӧ�Ľ���ַ�  
        out_buffer[i + 2] = enc_table[(data[j + 1] & 0xf) << 2 | (data[j + 2] >> 6)]; //���ڶ����ַ��ĺ�4λ��������ַ���ǰ2λ��ϲ��ҳ���Ӧ�Ľ���ַ�  
        out_buffer[i + 3] = enc_table[data[j + 2] & 0x3f]; //ȡ���������ַ��ĺ�6λ���ҳ�����ַ�  
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

    //�жϱ������ַ������Ƿ���=  
    if (strstr(data, "=="))
        out_len = datasize / 4 * 3 - 2;
    else if (strstr(data, "="))
        out_len = datasize / 4 * 3 - 1;
    else
        out_len = datasize / 4 * 3;

    //��4���ַ�Ϊһλ���н���  
    for (i = 0, j = 0; i < out_len - 2; j += 3, i += 4)
    {
        out_buffer[j] = (dec_table[data[i]]) << 2 | ((dec_table[data[i + 1]]) >> 4); //ȡ����һ���ַ���Ӧbase64���ʮ��������ǰ6λ��ڶ����ַ���Ӧbase64���ʮ�������ĺ�2λ�������  
        out_buffer[j + 1] = ((dec_table[data[i + 1]]) << 4) | ((dec_table[data[i + 2]]) >> 2); //ȡ���ڶ����ַ���Ӧbase64���ʮ�������ĺ�4λ��������ַ���Ӧbas464���ʮ�������ĺ�4λ�������  
        out_buffer[j + 2] = ((dec_table[data[i + 2]]) << 6) | (dec_table[data[i + 3]]); //ȡ���������ַ���Ӧbase64���ʮ�������ĺ�2λ���4���ַ��������  
    }

    return out_len;
}