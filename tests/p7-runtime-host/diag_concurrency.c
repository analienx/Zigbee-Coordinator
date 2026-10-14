#include "../../firmware/slzb-06p7/ti832/g5/p7_crashdiag.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
static atomic_int start;
static void *writer(void *unused)
{
    (void)unused;
    while (!atomic_load(&start)) {}
    for (unsigned i = 0; i < 10000; ++i) p7_diag_record_isr(P7D_MT_RX, (uint16_t)i, i);
    return NULL;
}
int main(void)
{
    pthread_t task;
    uint8_t snapshot[256];
    p7_diag_init(1, 0, 0);
    assert(pthread_create(&task, NULL, writer, NULL) == 0);
    atomic_store(&start, 1);
    for (unsigned i = 0; i < 10000; ++i)
    {
        size_t length = p7_diag_snapshot(snapshot, sizeof(snapshot));
        if (length)
        {
            uint16_t crc = snapshot[length - 2] | ((uint16_t)snapshot[length - 1] << 8);
            assert(crc == p7_diag_crc16(snapshot, length - 2));
            assert(length == P7_DIAG_HDR + (size_t)snapshot[6] * sizeof(p7_diag_event_t) + 2);
        }
    }
    assert(pthread_join(task, NULL) == 0);
    puts("DIAGNOSTIC_CONCURRENT_WRITER_SNAPSHOT_PASS");
    return 0;
}
