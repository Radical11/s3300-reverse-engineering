#ifndef S3300_CREATIVE_LOOKS_H
#define S3300_CREATIVE_LOOKS_H
#include <stddef.h>
#include <stdint.h>
#if defined(_WIN32) && defined(S3300_LOOKS_NATIVE_TEST)
#define S3300_LOOK_API __declspec(dllexport)
#else
#define S3300_LOOK_API
#endif

enum s3300_look {
    S3300_ORIGINAL = 0,
    S3300_FLASH_POP = 1,
    S3300_AMBER_DAYS = 2,
    S3300_COOL_NIGHT = 3,
    S3300_MONO_GRIT = 4
};

/* In-place interleaved RGB8 only. The caller owns >=3*pixels writable bytes.
 * Process one row/tile at a time. No allocation, floating point or OS calls.
 * Returns 0 for invalid arguments, leaving the buffer unchanged; 1 otherwise.
 * Camera ABI, colour domain and capture-buffer integration are unverified.
 */
S3300_LOOK_API int s3300_look_row(uint8_t *rgb, size_t pixels, unsigned look);

#ifdef S3300_LOOKS_REFERENCE
/* Host validation/benchmark only; excluded from the production module. */
S3300_LOOK_API int s3300_look_reference_row(uint8_t *rgb, size_t pixels, unsigned look);
#endif
#endif
