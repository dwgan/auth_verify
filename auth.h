#include "stdio.h"
#include "string.h"
#include "stm32f4xx_hal.h"
#include <string.h>
#include "indstorage.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sha256.h"


#define CPU_ID_BASE_ADDR (uint32_t*)(0x1FFF7A10)


#pragma pack(push, 4)
typedef struct {
    uint32_t ver_num;
    uint32_t chipID[3];
} VersionInfo_t;
#pragma pack(pop)


