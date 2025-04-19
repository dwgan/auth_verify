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