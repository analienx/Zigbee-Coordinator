/* T832-DIAG-R0 host harness: SDK stub surface for the real recorder.
 *
 * Values below are verified against the pinned SDK 8.32.00.07 tree
 * (source/ti/zstack/mt/mt_rpc.h, source/ti/zstack/mt/mt.h).
 * The harness compiles the real ../t832_diag_impl.inc unchanged.
 */
#ifndef T832_HOST_SDK_H
#define T832_HOST_SDK_H
#define T832_DIAG_HOST 1

#include <stdint.h>

#define MT_RPC_CMD_TYPE_MASK 0xE0u
#define MT_RPC_CMD_SREQ      0x20u
#define MT_RPC_CMD_AREQ      0x40u
#define MT_RPC_CMD_SRSP      0x60u
#define MT_RPC_SUBSYSTEM_MASK 0x1Fu
#define MT_RPC_SYS_AF         0x04u
#define MT_RPC_SYS_DBG        0x08u
#define MT_RPC_POS_LEN        0u
#define MT_RPC_POS_CMD0       1u
#define MT_RPC_POS_CMD1       2u
#define MT_RPC_POS_DAT0       3u
#define MT_RPC_FRAME_HDR_SZ   3u
#define MTRPC_FRAME_HDR_SZ    3u
#define MTRPC_POS_LEN         0u
#define MTRPC_POS_CMD0        1u
#define MTRPC_POS_CMD1        2u
#define MT_DEBUG_MSG          0x80u

#define SYS_EVENT_MSG 0x8000u

/* Controllable host stand-ins (defined in t832_diag_host_test.c). */
uint32_t HostClock_getTicks(void);
uint32_t HostClock_getPeriodUs(void);
uint32_t HostCs_enter(void);
void HostCs_leave(uint32_t key);
int HostCs_depth(void);
void HostMdi_capture(uint8_t cmdType, uint8_t cmdId, uint8_t len,
                     const uint8_t *data);

/* Recorder-visible SDK symbols, backed by the host stand-ins. */
static inline uint32_t OsalPort_enterCS(void) { return HostCs_enter(); }
static inline void OsalPort_leaveCS(uint32_t key) { HostCs_leave(key); }
/* Defined in t832_diag_host_test.c (after the real recorder) so the
 * fail-allocation simulation can invoke the recorder's own hook. */
void MT_BuildAndSendZToolResponse(uint8_t cmdType, uint8_t cmdId,
                                  uint8_t dataLen, uint8_t *dataPtr);

#endif
