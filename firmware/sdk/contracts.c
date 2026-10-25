#include "contracts.h"

static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int s3300_counter_decode(const uint8_t *input, size_t input_bytes,
                        struct s3300_cpu_counters *out)
{
    if (!input || !out || input_bytes < 24)
        return 0;
    out->hits = load_le32(input);
    out->misses = load_le32(input + 4);
    out->instructions = load_le32(input + 8);
    out->prefetch_hits = load_le32(input + 12);
    out->prefetch_misses = load_le32(input + 16);
    out->clocks = load_le32(input + 20);
    return 1;
}

uint32_t s3300_command_context_index(uint32_t context)
{
    if (context == 0x40) return 0;
    if (context == 0x50) return 1;
    if (context == 0xa0) return 2;
    if (context == 0xb0) return 5;
    return 8;
}

int s3300_command_id_parts(uint32_t value, uint32_t *category,
                          uint32_t *subindex)
{
    uint32_t group, base;
    if (!category || !subindex)
        return 0;
    if (value < 50) { group = 0; base = 0; }
    else if (value < 100) { group = 3; base = 50; }
    else if (value < 200) { group = 1; base = 100; }
    else if (value < 1000) { group = 4; base = 200; }
    else { group = 2; base = 1000; }
    *category = group;
    *subindex = value - base;
    return 1;
}

int s3300_settings_checksum(const uint8_t *store, size_t store_bytes,
                           uint8_t *out)
{
    uint32_t total = 0;
    size_t i;
    if (!store || !out || store_bytes < 0x1a0)
        return 0;
    for (i = 0; i < 0x19e; ++i)
        total += store[i];
    *out = (uint8_t)total;
    return 1;
}
