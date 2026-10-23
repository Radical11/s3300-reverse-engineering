#ifndef S3300_EXPERIMENT_SHADOW_LIFT_H
#define S3300_EXPERIMENT_SHADOW_LIFT_H

/* Host algorithm design only: this has no S3300 ABI, resource ID or hook.
 * Input is RGB8 in a full 0..255 domain. Do not pass a packed camera buffer.
 * Row-by-row operation requires only the caller's 256-byte table and 1 pixel
 * of scratch storage. src and dst may be identical or non-overlapping.
 */
#include <stddef.h>
#include <stdint.h>

static inline void shadow_lift_rgb8_row(const uint8_t *src, uint8_t *dst,
                                       size_t pixels, const uint8_t lut[256])
{
    size_t i;
    for (i = 0; i < pixels; ++i) {
        const uint32_t r = src[0], g = src[1], b = src[2];
        const uint32_t y = (77u*r + 150u*g + 29u*b + 128u) >> 8;
        const uint32_t target = lut[y];
        const uint32_t peak_rg = r > g ? r : g;
        const uint32_t peak = peak_rg > b ? peak_rg : b;
        uint32_t delta = target > y ? target - y : 0u;
        const uint32_t headroom = 255u - peak;
        if (delta > headroom) delta = headroom;
        dst[0] = (uint8_t)(r + delta);
        dst[1] = (uint8_t)(g + delta);
        dst[2] = (uint8_t)(b + delta);
        src += 3;
        dst += 3;
    }
}

#endif
