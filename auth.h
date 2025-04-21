#ifndef __AUTH_H
#define __AUTH_H

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

extern FuncTab_t FuncTab;

extern int user_auth_verify();


#endif /* __AUTH_H */