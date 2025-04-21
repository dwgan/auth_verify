#include "auth.h"

FuncTab_t FuncTab;

VersionInfo_t VerInfo = {
    .ver_num = 0x20250101, // 2025年01系列产品01版本
};

FIL InfoFile;
FIL AuthFile;

char user_local_key[] = "password";
const char VersionInfoName[] = "version.info";
const char AuthFileName[] = "license.lic";




void get_chipid(uint8_t* id_buf) {
    uint32_t* id_ptr = (uint32_t*)CPU_ID_BASE_ADDR;
    memcpy(id_buf, id_ptr, 12);
}

int read_auth_file(uint8_t *data1, uint32_t len1, uint8_t *data2, uint32_t len2)
{
    UINT bytesRead;
    FIL *fp = &AuthFile;
    
    uint32_t size = len1 + len2;
    uint8_t *buf = malloc(size);
    
    if (f_open(fp, AuthFileName, FA_READ | FA_OPEN_EXISTING) != FR_OK)
    {
        return -1;
    }
    if (f_read(fp, buf, size, &bytesRead) != FR_OK && bytesRead == size)
    {
        return -1;
    }
    
    memcpy(data1, buf, len1);
    memcpy(data2, buf+len1, len2);
    
    free(buf);
    f_close(fp);
    return 0;
}

int generate_version_info()
{
    get_chipid((uint8_t *)&VerInfo.chipID);
    
    if (f_open(&InfoFile, VersionInfoName, FA_WRITE | FA_CREATE_ALWAYS) != FR_OK)
    {
        return -1;
    }
    
    UINT bytes_written;
    FRESULT res = f_write(&InfoFile, &VerInfo, sizeof(VersionInfo_t), &bytes_written);
    if (res == FR_OK && bytes_written == sizeof(VersionInfo_t))
    {
        f_close(&InfoFile);
        return 0;
    }
    else
    {
        return -2;
    }
}

int user_auth_verify()
{
    uint8_t hash[32]={0};
    uint8_t auth[32]={0};
    
    get_chipid((uint8_t *)&VerInfo.chipID);
    
    read_auth_file((uint8_t *)&FuncTab, sizeof(FuncTab_t), auth, sizeof(auth));
    
    sha256_calculate((uint8_t*)&VerInfo, sizeof(VersionInfo_t), (uint8_t*)&FuncTab, sizeof(FuncTab_t), (uint8_t*)user_local_key, strlen(user_local_key), hash);

    return memcmp(hash, auth, 32);
}
