#include "auth.h"



VersionInfo_t VerInfo = {
    .ver_num = 0x20250101,
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

int read_auth_file(uint8_t *auth)
{
    UINT bytesRead;
    FIL *fp = &AuthFile;
    
    if (f_open(fp, AuthFileName, FA_READ | FA_OPEN_EXISTING) != FR_OK)
    {
        return -1;
    }
    if (f_read(fp, auth, f_size(fp), &bytesRead) != FR_OK)
    {
        return -1;
    }
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
    uint8_t output[32]={0};
    uint8_t auth[32]={0};
    
    get_chipid((uint8_t *)&VerInfo.chipID);
    
    read_auth_file(auth);
    
    sha256_calculate((uint8_t *)&VerInfo, sizeof(VersionInfo_t), (uint8_t *)user_local_key, strlen(user_local_key), output);
    return memcmp(output, auth, 32);
}
