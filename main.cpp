#define _CRT_SECURE_NO_WARNINGS
#include <string>
extern "C" {  // ���� C++ �������� C ���������
#include "sha256.h"
}

#pragma pack(push, 1)
typedef struct {
    uint8_t eth_en;
    uint8_t uart1_en;
    uint8_t uart2_en;
    uint8_t uart3_en;
    uint8_t can_en;
    uint8_t reserved[16-5];
} FuncTab_t;
#pragma pack(pop)
#pragma pack(push, 4)
typedef struct {
    uint32_t ver_num;
    uint32_t chipID[3];
} VersionInfo_t;
#pragma pack(pop)

VersionInfo_t VerInfo;
FuncTab_t FuncTab = {
    1,  // eth_en;
    1,  // uart1_en;
    1,  // uart2_en;
    1,  // uart3_en;
    1,  // can_en;
    {0} // reserved[16-5];
};
char user_local_key[] = "password";
const char VersionInfoName[] = "version.info";
const char AuthFileName[] = "license.lic";


int write_hash_to_file(const uint8_t* data1, uint32_t len1, const uint8_t* data2, uint32_t len2, const char* FileName)
{
    FILE* pFile = NULL;

    pFile = fopen(FileName, "wb+");
    if (!pFile)
    {
        printf("fopen error!\n");
        return -1;
    }
    fwrite(data1, sizeof(uint8_t), len1, pFile);
    fwrite(data2, sizeof(uint8_t), len2, pFile);
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

    uint8_t hash[32] = { 0 };

    load_version_info((uint8_t *)&VerInfo, sizeof(VersionInfo_t), "version.info");

    sha256_calculate((uint8_t*)&VerInfo, sizeof(VersionInfo_t), (uint8_t*)&FuncTab, sizeof(FuncTab_t), (uint8_t*)user_local_key, strlen(user_local_key), hash);
    write_hash_to_file((uint8_t *) & FuncTab, sizeof(FuncTab), hash, sizeof(hash), AuthFileName);
    printf("Generate license.lic done\r\n");
}