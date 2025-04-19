## 固件鉴权的重要性

在嵌入式设备量产场景中，固件鉴权是保护知识产权和确保设备完整性的核心防线。

未经授权的固件可能引发硬件失效、数据泄露等问题。

本文介绍一种基于SHA256哈希的轻量级鉴权方案，已在STM32系列MCU实现量产验证。

## 非对称加密的可靠性

所谓的非对称加密，就是可以通过给定信息所处哈希值，但是无法通过哈希值反向得到给定信息，这在数学上有保证。

SHA256作为NIST认证的安全哈希算法，具备三大关键特性：

**抗碰撞性**：找到相同哈希值的不同输入在计算上不可行

**单向性**：无法通过哈希值逆向推导原始数据

**雪崩效应**：输入微小变化导致输出完全改变

## 基于ChipID的鉴权框架

1. 与硬件绑定的ChipID
STM32单片机在设计的时候由芯片原厂引入了和硬件绑定的ChipID，这个值是唯一的，出厂后无法通过技术手段更改，这为鉴权功能奠定了基础。

2. 代码读保护功能
STM32单片机自带读保护功能，分为Level 0（无保护）、Level 1（可软件解除的读保护）、Level 2（无法恢复的硬件读保护）
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/4931802fd84c4860bb1a0bdd9845e745.png)

3. 动态版本控制
开发者可以在软件设计时给固件自定义版本号，当固件升级时递增版本号，使旧版授权自动失效。

4. 用户密钥保护
用户可以自定义一个私钥，将私钥与ChipID、版本号同时作为输入信息给SHA256算法进行加密，得到公钥。

5. 鉴权流程
程序上电时会读取公钥信息，然后根据代码中存有的私钥、版本号以及芯片的ChipID计算得到公钥，比较两个公钥是否一致来进行鉴权

## 完整代码

```c
#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

void sha256_calculate(uint8_t *key1, uint32_t len1, uint8_t *key2, uint32_t len2, uint8_t *output);
```

```c
#include "sha256.h"

// SHA-256常量定义（网页8][8](@ref)
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define EP0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define EP1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t k[64] = {  // 预计算常量（网页8][8](@ref)
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    // ...（完整64个常量，参考RFC 6234）
};

void sha256_init(SHA256_CTX* ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;  // 初始哈希值
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_transform(SHA256_CTX* ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    // 消息扩展（网页8][8](@ref)
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3];
    for (; i < 64; ++i)
        m[i] = EP1(m[i - 2]) + m[i - 7] + EP0(m[i - 15]) + m[i - 16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2];
    d = ctx->state[3]; e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    // 压缩函数（网页8][8](@ref)
    for (i = 0; i < 64; ++i) {
        t1 = h + SIG1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = SIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    // 更新状态
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c;
    ctx->state[3] += d; ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_update(SHA256_CTX* ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        if (++ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX* ctx, uint8_t* hash) {
    uint32_t i = ctx->datalen;

    // 填充规则（网页8][8](@ref)
    ctx->data[i++] = 0x80;
    while (i < 56) ctx->data[i++] = 0x00;

    // 附加总比特长度（64位大端序）
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    // 输出大端序结果
    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0xFF;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xFF;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xFF;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xFF;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xFF;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xFF;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xFF;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xFF;
    }
}

// @input
// key1: pointer to key1
// len1: length of key1
// key2: pointer to key2
// len2: length of key2
// @output
// output: pointer to sha256, length is 32
void sha256_calculate(uint8_t *key1, uint32_t len1, uint8_t *key2, uint32_t len2, uint8_t *output)
{
    SHA256_CTX ctx;
    
    sha256_init(&ctx);
    sha256_update(&ctx, (uint8_t *)key1, len1);
    sha256_update(&ctx, (uint8_t *)key2, len2);
    sha256_final(&ctx, output);
}
```

```c
#define _CRT_SECURE_NO_WARNINGS
#include <string>
extern "C" {  // ���� C++ �������� C ���������
#include "sha256.h"
}

#pragma pack(push, 4)
typedef struct {
    uint32_t ver_num;
    uint32_t chipID[3];
} VersionInfo_t;
#pragma pack(pop)


VersionInfo_t VerInfo;
char user_local_key[] = "test";
const char VersionInfoName[] = "version.info";
const char AuthFileName[] = "license.lic";


int write_hash_to_file(const uint8_t* data, uint32_t len, const char* FileName)
{
    FILE* pFile = NULL;

    pFile = fopen(FileName, "wb+");
    if (!pFile)
    {
        printf("fopen error!\n");
        return -1;
    }
    int n = fwrite(data, sizeof(uint8_t), len, pFile);
    fclose(pFile);
}


int load_version_info(uint8_t* data, uint32_t len, const char* FileName)
{
    FILE* pFile = NULL;

    pFile = fopen(FileName, "rb");
    if (!pFile)
    {
        printf("fopen error!\n");
        return -1;
    }
    int n = fread(data, sizeof(uint8_t), len, pFile);
    fclose(pFile);
}


void main() {
    SHA256_CTX ctx;

    uint8_t output[32];

    load_version_info((uint8_t *)&VerInfo, sizeof(VersionInfo_t), "version.info");

    sha256_calculate((uint8_t *)&VerInfo, sizeof(VersionInfo_t), (uint8_t*)user_local_key, strlen(user_local_key), output);
    write_hash_to_file(output, 32, AuthFileName);
    printf("Generate license.lic done\r\n");
}
```
