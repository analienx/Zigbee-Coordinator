/* Actual driver probe; physical operation count and immutable-image oracle. */
#include "nvocmp.c"
#include <string.h>
int main(int argc, char **argv) {
    if(argc != 2) return 2;
    NVINTF_nvFuncts_t api;
    NVINTF_itemID_t id = {NVINTF_SYSID_ZSTACK, 33, 0};
    uint8_t data[116], actual[116]; memset(data, 0xAA, sizeof(data));
    NVOCMP_loadApiPtrsExt(&api);
    uint8_t first = api.initNV(NULL), again = api.initNV(NULL);
    uint8_t write = 255, read = 255;
    if(!strcmp(argv[1], "seed")) {
        if(first || again || api.createItem(id, sizeof(data), data)) return 30;
    } else if(!strcmp(argv[1], "healthy")) {
        read = api.readItem(id, 0, sizeof(actual), actual);
        if(first || again || read || memcmp(data, actual, sizeof(data))) return 31;
    } else if(!strcmp(argv[1], "reject")) {
        write = api.writeItem(id, sizeof(data), data);
        read = api.readItem(id, 0, sizeof(actual), actual);
        if(!first || first != again || !write || !read || api.getFreeNV() || api.compactNV(0) == 0 || api.eraseNV() == 0 || nv_lab_operations) return 32;
    } else return 2;
    printf("{\"init_status\":%u,\"reinit_status\":%u,\"write_status\":%u,\"read_status\":%u,\"physical_operations\":%u}\n",
           first, again, write, read, nv_lab_operations);
    return 0;
}
