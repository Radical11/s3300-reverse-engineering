#include "looks.h"
#include "look_tables.h"

int s3300_look_row(uint8_t *rgb, size_t pixels, unsigned look)
{
    size_t i;
    if (look > S3300_MONO_GRIT || pixels > SIZE_MAX / 3 || (!rgb && pixels))
        return 0;
    if (look == S3300_ORIGINAL)
        return 1;
    if (look == S3300_MONO_GRIT) {
        for (i = 0; i < pixels; ++i, rgb += 3) {
            unsigned y = (77u * rgb[0] + 150u * rgb[1] + 29u * rgb[2] + 128u) >> 8;
            uint8_t mono = s3300_mono_table[y];
            rgb[0] = mono; rgb[1] = mono; rgb[2] = mono;
        }
    } else {
        const uint8_t (*table)[256] = s3300_colour_tables[look - 1];
        for (i = 0; i < pixels; ++i, rgb += 3) {
            rgb[0] = table[0][rgb[0]];
            rgb[1] = table[1][rgb[1]];
            rgb[2] = table[2][rgb[2]];
        }
    }
    return 1;
}

#ifdef S3300_LOOKS_REFERENCE
static uint8_t evaluate(unsigned value, unsigned look, unsigned channel)
{
    unsigned i, width;
    int tone, result;
    const struct s3300_reference_profile *profile = &s3300_reference_profiles[look - 1];
    for (i = 0; i < 5 && value > s3300_reference_x[i + 1]; ++i) {}
    width = s3300_reference_x[i + 1] - s3300_reference_x[i];
    tone = profile->tone[i] + (int)(((value - s3300_reference_x[i]) *
           (profile->tone[i + 1] - profile->tone[i]) + width / 2) / width);
    result = ((tone * profile->gain[channel] + 128) >> 8) + profile->offset[channel];
    return (uint8_t)(result < 0 ? 0 : result > 255 ? 255 : result);
}

int s3300_look_reference_row(uint8_t *rgb, size_t pixels, unsigned look)
{
    size_t i;
    if (look > S3300_MONO_GRIT || pixels > SIZE_MAX / 3 || (!rgb && pixels))
        return 0;
    if (look == S3300_ORIGINAL)
        return 1;
    for (i = 0; i < pixels; ++i, rgb += 3) {
        if (look == S3300_MONO_GRIT) {
            unsigned y = (77u * rgb[0] + 150u * rgb[1] + 29u * rgb[2] + 128u) >> 8;
            uint8_t mono = evaluate(y, look, 0);
            rgb[0] = mono; rgb[1] = mono; rgb[2] = mono;
        } else {
            rgb[0] = evaluate(rgb[0], look, 0);
            rgb[1] = evaluate(rgb[1], look, 1);
            rgb[2] = evaluate(rgb[2], look, 2);
        }
    }
    return 1;
}
#endif
