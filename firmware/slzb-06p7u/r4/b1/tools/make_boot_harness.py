"""Compile actual patched main() with synthetic board/task/RTOS boundaries."""
import argparse
from pathlib import Path
from patch_zdapp import extract_function

SCENARIOS = ("healthy", "nv_failure", "missing_api", "semaphore_failure")

PREAMBLE = r'''
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "b1_management.h"
#define USE_DEFAULT_USER_CFG 1
#define OTA_CLIENT_STANDALONE 1
#define NPI 1
#define ZNP_NPI 1
#define TRUE 1
#define VIMS_BASE 0u
#define VIMS_MODE_ENABLED 1u
#define VIMS_MODE_DISABLED 0u
#define APIMAC_SADDR_EXT_LEN 8u
#define NVINTF_SUCCESS 0u
#define EXTADDR_OFFSET 0u
static const uint8_t public_fixture_address[8] = {0};
#define FCFG1_BASE ((uintptr_t)public_fixture_address)
#define OsalPort_memcpy memcpy
static unsigned board_calls, nv_calls, stack_calls, npi_calls, bios_calls;
static unsigned sem_construct_calls, sem_handle_calls;
static unsigned inject_nv_failure, inject_missing_api, inject_sem_failure;
static unsigned cs_depth;
uintptr_t b1_management_test_disable(void) { assert(cs_depth==0); return cs_depth++; }
void b1_management_test_restore(uintptr_t key) { assert(cs_depth==key+1); cs_depth=(unsigned)key; }
typedef struct { int mode; } Semaphore_Params;
typedef struct { int value; } Semaphore_Struct;
static Semaphore_Struct npiInitializationMutex;
static void *npiInitializationMutexHandle;
#define ti_sysbios_knl_Semaphore_Mode_COUNTING 1
static void Semaphore_Params_init(Semaphore_Params *p) { p->mode=0; }
static void Semaphore_construct(Semaphore_Struct *s, int value, const Semaphore_Params *p) {
    assert(value==0 && p->mode==1); s->value=value; ++sem_construct_calls;
}
static void *Semaphore_handle(Semaphore_Struct *s) {
    ++sem_handle_calls; return inject_sem_failure?NULL:s;
}
static uint8_t fake_init(void *arg) { assert(arg==NULL); ++nv_calls; return inject_nv_failure?2:0; }
typedef struct { uint8_t (*initNV)(void *); } fake_nv_api;
static struct { uint8_t extendedAddress[8]; fake_nv_api nvFps; } zstack_user0Cfg;
static void NVOCMP_loadApiPtrs(fake_nv_api *api) { api->initNV=inject_missing_api?NULL:fake_init; }
static void VIMSConfigure(unsigned base, unsigned a, unsigned b) { (void)base; (void)a; (void)b; }
static void VIMSModeSet(unsigned base, unsigned mode) { (void)base; (void)mode; }
static void Board_initGeneral(void) { ++board_calls; }
static void stackTask_init(void *cfg) { assert(cfg==&zstack_user0Cfg); ++stack_calls; }
void NPITask_createTask(void) { ++npi_calls; }
static void BIOS_start(void) { ++bios_calls; }
'''

MAIN = r'''
int main(int argc, char **argv) {
    assert(argc==2); const char *s=argv[1];
    inject_nv_failure=strcmp(s,"nv_failure")==0;
    inject_missing_api=strcmp(s,"missing_api")==0;
    inject_sem_failure=strcmp(s,"semaphore_failure")==0;
    int result=b1_actual_main();
    assert(board_calls==1 && npi_calls==1 && sem_construct_calls==1 && sem_handle_calls==1);
    assert(nv_calls==(inject_missing_api?0u:1u));
    assert(stack_calls==((inject_nv_failure || inject_missing_api)?0u:1u));
    if(inject_sem_failure) assert(result==1 && bios_calls==0 && b1_management_get_hold_active());
    else assert(result==0 && bios_calls==1);
    if(inject_nv_failure || inject_missing_api) assert(b1_management_get_hold_active());
    if(!strcmp(s,"healthy")) assert(!b1_management_get_hold_active());
    assert(cs_depth==0);
    printf("B1_ACTUAL_MAIN_BOOT_HOSTED_SYNTHETIC_PASS %s stack_tasks=%u npi_tasks=%u bios=%u\n",s,stack_calls,npi_calls,bios_calls);
    return 0;
}
'''


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    body = extract_function(args.source.read_text(encoding="utf-8"), "int main()")
    if "goto b1_start_npi" not in body or body.count("NPITask_createTask();") != 1:
        raise RuntimeError("B1 original-owner boot path is missing or duplicated")
    args.output.write_text(PREAMBLE + body.replace("int main()", "int b1_actual_main()", 1) + MAIN)
    print("B1_ACTUAL_MAIN_BOOT_FUNCTION_EXTRACTED")


if __name__ == "__main__":
    main()
