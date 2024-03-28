#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <curl/curl.h>
// 谢谢你，陌生人，你提供的思路让我得以在OpenWRT等嵌入式平台实现自动登录。
// 代码可能有点屎

// 用法：./program account password 网络接口
// 一口多号用 macvlan, 根本上杜绝多设备检测

// RC4加密算法
char *do_encrypt_rc4(char *src, char *passwd)
{
    int i, j, a, b, c;
    int key[256], sbox[256];
    int plen = strlen(passwd);
    int size = strlen(src);
    char *output = (char *)malloc(size * 2 + 1);

    // 初始化密钥key和状态向量sbox
    for (i = 0; i < 256; i++)
    {
        key[i] = passwd[i % plen];
        sbox[i] = i;
    }
    // 状态向量打乱
    j = 0;
    for (i = 0; i < 256; i++)
    {
        j = (j + sbox[i] + key[i]) % 256;
        int temp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = temp;
    }
    // 秘钥流的生成与加密
    a = 0, b = 0, c = 0;
    for (i = 0; i < size; i++)
    {
        // 子密钥生成
        a = (a + 1) % 256;
        b = (b + sbox[a]) % 256;
        int temp = sbox[a];
        sbox[a] = sbox[b];
        sbox[b] = temp;
        c = (sbox[a] + sbox[b]) % 256;
        // 明文字节由子密钥异或加密
        temp = src[i] ^ sbox[c];
        // 密文字节转换成hex，格式对齐修正（取最后两位，若为一位（[0x0，0xF]），则改成[00, 0F]）
        sprintf(output + i * 2, "%02X", temp);
    }
    output[size * 2] = '\0';
    return output;
}

int main(int argc, char *argv[])
{
    // 请求网址
    char *url = "http://1.1.1.2/ac_portal/login.php";
    // 请求头
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "X-Requested-With: XMLHttpRequest");
    headers = curl_slist_append(headers, "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36");
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded; charset=UTF-8");
    // 时间戳（提取ms单位）
    int tag = (int)(time(NULL) * 1000);
    // 利用RC4加密算法获取基于时间戳的密码
    char *account = argv[1];
    char *password = argv[2];
    char *interface = argv[3]; // 新增：网络接口
    char tag_str[20];
    sprintf(tag_str, "%d", tag);
    char *pwd = do_encrypt_rc4(password, tag_str);
    // 账号、密码、时间戳写入payload报文
    char payload[1024];
    sprintf(payload, "opr=pwdLogin&userName=%s&pwd=%s&auth_tag=%d&rememberPwd=1", account, pwd, tag);

    // 初始化curl
    CURL *curl = curl_easy_init();
    if (curl)
    {
        // 设置请求选项
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_INTERFACE, interface); // 新增：设置网络接口
        // 提交登录
        CURLcode res = curl_easy_perform(curl);
        // 输出登录结果
        if (res == CURLE_OK)
        {
            long status_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
            if (status_code == 200)
            {
                printf("\033[7;32;47m%s\033[0m\n", curl_easy_strerror(res));
            }
            else
            {
                printf("\033[7;31;47m%s\033[0m\n", curl_easy_strerror(res));
                printf("\033[7;31;47mLogin fail! Make sure input true account info!\033[0m\n");
            }
        }
        else
        {
            // 如果请求出错，大概率网络未连
            printf("\033[7;31;47mLogin Error！\tMaybe you need link wifi first?\033[0m\n");
            // 输出err
            printf("\033[7;33;40m%s\033[0m\n", curl_easy_strerror(res));
        }
        // 释放curl
        curl_easy_cleanup(curl);
    }
    // 释放headers
    curl_slist_free_all(headers);
    // 释放pwd
    free(pwd);
    return 0;
}
