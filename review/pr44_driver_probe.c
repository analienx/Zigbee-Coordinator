/* Synthetic review fixture, real patched TI driver, no hardware or private data. */
#include "nvocmp.c"
#include <string.h>

static NVINTF_itemID_t item = {NVINTF_SYSID_ZSTACK, 14, 0};
static NVINTF_nvFuncts_t api;

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    NVOCMP_loadApiPtrsExt(&api);
    uint8_t init = api.initNV(NULL);
    if (init) return 20 + init;
    uint8_t payload[20], readback[20];
    memset(payload, 0xAA, sizeof(payload));
    if (!strcmp(argv[1], "read")) {
        uint8_t status = api.readItem(item, 0, sizeof(readback), readback);
        printf("{\"init_status\":%u,\"read_status\":%u,\"physical_operations\":%u}\n", init, status, nv_lab_operations);
        return 0;
    }
    if (api.createItem(item, sizeof(payload), payload)) return 40;
    if (!strcmp(argv[1], "seed")) return 0;
    if (strcmp(argv[1], "duplicate")) return 2;
    NVOCMP_itemHdr_t source = {.sysid=item.systemID, .itemid=item.itemID, .subid=item.subID};
    if (NVOCMP_findItem(&NVOCMP_nvHandle, NVOCMP_nvHandle.actPage,
                      NVOCMP_nvHandle.actOffset, &source, NVOCMP_FINDSTRICT, NULL)) return 41;
    uint8_t copied[27];
    NV_LINUX_read(source.hpage, source.hofs - source.len, copied, sizeof(copied));
    const uint8_t dst = 1;
    NVOCMP_changePageState(&NVOCMP_nvHandle, dst, NVOCMP_PGACT);
    NVOCMP_writeByte(dst, 6, NVOCMP_PGCDST);
    if (NV_LINUX_write(dst, NVOCMP_PGDATAOFS, copied, sizeof(copied))) return 42;
    NVOCMP_nvHandle.pageInfo[dst].mode = NVOCMP_PGCDST;
    NVOCMP_nvHandle.pageInfo[dst].offset = NVOCMP_PGDATAOFS + sizeof(copied);
    NVOCMP_itemHdr_t destination;
    const uint16_t dest_header = NVOCMP_PGDATAOFS + sizeof(payload);
    NVOCMP_readHeader(dst, dest_header, &destination, false);
    uint8_t corrupted = 0xA8; /* one NOR-legal payload bit cleared in source */
    if (NV_LINUX_write(source.hpage, source.hofs - source.len, &corrupted, 1)) return 43;
    uint8_t source_crc = NVOCMP_verifyCRC(source.hofs-source.len, source.len, source.crc8, source.hpage, false);
    uint8_t dest_crc = NVOCMP_verifyCRC(dest_header-destination.len, destination.len, destination.crc8, dst, false);
    int before = !!(destination.stats & NVOCMP_ACTIVEIDBIT);
    NVOCMP_recoverSettleDestination(&NVOCMP_nvHandle);
    NVOCMP_readHeader(dst, dest_header, &destination, false);
    int after = !!(destination.stats & NVOCMP_ACTIVEIDBIT);
    uint8_t status = api.readItem(item, 0, sizeof(readback), readback);
    printf("{\"source_crc_status\":%u,\"destination_crc_status\":%u,\"destination_active_before\":%s,\"destination_active_after\":%s,\"read_status_after\":%u}\n",
           source_crc, dest_crc, before?"true":"false", after?"true":"false", status);
    return 0;
}
