#include <stdint.h>
#include <string.h>

typedef struct {  // 哈希计算上下文（网页8][8](@ref)
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

void sha256_calculate(uint8_t *key1, uint32_t len1, uint8_t *key2, uint32_t len2, uint8_t *output);
