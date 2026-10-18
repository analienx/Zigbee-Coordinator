/* Read-only host CLI. Input: private 704KiB P7U flash capture (never output).
 * Prints aggregate structural counts only. No storage/radio/write APIs.
 */
#include "nv4_readonly_admission.h"
#include <stdio.h>
#include <string.h>

#define FULL_FLASH_SIZE 0xB0000L
#define STOCK_NV_BASE   0xA6000L
static uint8_t private_media[R4_NV4_REGION_SIZE];

static int buffer_read(void *context, uint32_t off, uint8_t *to, uint32_t count)
{
    (void)context;
    if (off > sizeof(private_media) || count > sizeof(private_media) - off) return -1;
    memcpy(to, private_media + off, count);
    return 0;
}

static int file_read(void *context, uint32_t off, uint8_t *to, uint32_t count)
{
    FILE *f = (FILE *)context;
    if (fseek(f, STOCK_NV_BASE + (long)off, SEEK_SET) != 0) return -1;
    return fread(to, 1, count, f) == count ? 0 : -1;
}

int main(int argc, char **argv)
{
    FILE *input;
    long size;
    r4_nv4_result report;
    if (argc != 2) return 2;
    if (strcmp(argv[1], "--stdin-nv4") == 0) {
        if (fread(private_media, 1, sizeof(private_media), stdin) != sizeof(private_media) ||
            getchar() != EOF) return 5;
        report = r4_nv4_admit(buffer_read, NULL);
        memset(private_media, 0, sizeof(private_media));
    } else {
        input = fopen(argv[1], "rb");
        if (input == NULL) return 3;
        if (fseek(input, 0, SEEK_END) != 0 || (size = ftell(input)) != FULL_FLASH_SIZE) {
            fclose(input);
            return 4;
        }
        report = r4_nv4_admit(file_read, input);
        fclose(input);
    }
    printf("{\"code\":%u,\"records\":%u,\"active_records\":%u,"
           "\"reads\":%u,\"fault_offset\":%u,\"writes\":0,\"erases\":0,"
           "\"native_ti_recovery_validated\":false,\"flash_authorized\":false}\n",
           (unsigned)report.code, (unsigned)report.records,
           (unsigned)report.active_records, (unsigned)report.reads,
           (unsigned)report.fault_offset);
    return report.code == R4_NV4_READONLY_STRUCTURE_ACCEPTED ? 0 : 1;
}
