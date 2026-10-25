#ifndef S3300_SDK_CONTRACTS_H
#define S3300_SDK_CONTRACTS_H

#include <stddef.h>
#include <stdint.h>

/* Pure translations of reviewed static contracts. These helpers do not call
 * vendor code, touch registers, start DMA, submit commands or own buffers. */
struct s3300_cpu_counters {
    uint32_t hits;
    uint32_t misses;
    uint32_t instructions;
    uint32_t prefetch_hits;
    uint32_t prefetch_misses;
    uint32_t clocks;
};

/* Decode a copied 24-byte internal counter result. No live telemetry implied.
 * Returns zero without changing *out for NULL pointers or insufficient input.
 * The caller must supply actual readable/writable memory of the stated sizes.
 * Input and output storage must not overlap. */
int s3300_counter_decode(const uint8_t *input, size_t input_bytes,
                        struct s3300_cpu_counters *out);

/* Numeric lookup at vendor 0x8023c778: returns 0,1,2,5 or rejection bucket 8.
 * Context numbers are not assigned names such as still/live/playback here. */
uint32_t s3300_command_context_index(uint32_t context);

/* Reviewed unsigned command categorization, 0x801fe7f4/0x801fe82c.
 * On non-NULL outputs, category is 0,3,1,4,2 and subindex is value less
 * 0,50,100,200,1000 respectively. This does not validate an invocable command.
 * Returns zero for NULL outputs; output pointers must be distinct. */
int s3300_command_id_parts(uint32_t value, uint32_t *category,
                          uint32_t *subindex);

/* The reviewed store transaction passes N=0x19f to a helper that sums N-1
 * bytes. Thus store[0..0x19d] contribute; byte0x19e is excluded and the
 * transaction stores the checksum at0x19f. This helper only returns a byte;
 * it never edits the store or invokes the media writer. */
int s3300_settings_checksum(const uint8_t *store, size_t store_bytes,
                           uint8_t *out);

#endif
