/* R11 POD sizeof/offsetof proof artifact (hosted CI only). */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include "nv_r6_probe.h"
#include "r11_startup.h"
int main(void)
{
    printf("{\"first\":%u,\"current\":%u,\"snapshot\":%u,\"startup\":%u,\"ext\":%u,"
           "\"first_fault_id\":%u,\"first_requested\":%u,\"first_item\":%u,\"first_sub\":%u,"
           "\"first_api\":%u,\"first_sys\":%u,\"first_site\":%u,\"first_status\":%u,"
           "\"first_phase\":%u,\"first_known\":%u,"
           "\"cur_gen\":%u,\"cur_item\":%u,\"cur_sub\":%u,\"cur_api\":%u,"
           "\"cur_sys\":%u,\"cur_site\":%u,\"cur_known\":%u,"
           "\"snap_first\":%u,\"snap_current\":%u}\n",
           (unsigned)sizeof(T832R6NvFirst), (unsigned)sizeof(T832R6NvCurrent),
           (unsigned)sizeof(T832R6NvSnapshot), (unsigned)sizeof(T832R11Startup),
           (unsigned)sizeof(T832R11ExtState),
           (unsigned)offsetof(T832R6NvFirst, fault_id),
           (unsigned)offsetof(T832R6NvFirst, requested),
           (unsigned)offsetof(T832R6NvFirst, item_id),
           (unsigned)offsetof(T832R6NvFirst, sub_id),
           (unsigned)offsetof(T832R6NvFirst, api),
           (unsigned)offsetof(T832R6NvFirst, system_id),
           (unsigned)offsetof(T832R6NvFirst, site),
           (unsigned)offsetof(T832R6NvFirst, status),
           (unsigned)offsetof(T832R6NvFirst, phase_domain),
           (unsigned)offsetof(T832R6NvFirst, known_flags),
           (unsigned)offsetof(T832R6NvCurrent, generation),
           (unsigned)offsetof(T832R6NvCurrent, item_id),
           (unsigned)offsetof(T832R6NvCurrent, sub_id),
           (unsigned)offsetof(T832R6NvCurrent, api),
           (unsigned)offsetof(T832R6NvCurrent, system_id),
           (unsigned)offsetof(T832R6NvCurrent, site),
           (unsigned)offsetof(T832R6NvCurrent, known_flags),
           (unsigned)offsetof(T832R6NvSnapshot, first),
           (unsigned)offsetof(T832R6NvSnapshot, current));
    return 0;
}
