/* T832-DIAG-R0 host harness: MT AF command IDs.
 *
 * Values verified against pinned SDK 8.32.00.07
 * source/ti/zstack/mt/mt_af.c (MT_AfDataConfirm builds a 3-byte
 * [status, endpoint, transID] confirm; request IDs 0x01/0x02/0x03).
 */
#ifndef T832_STUB_MT_AF_H
#define T832_STUB_MT_AF_H

#define MT_AF_DATA_REQUEST         0x01u
#define MT_AF_DATA_REQUEST_EXT     0x02u
#define MT_AF_DATA_REQUEST_SRCRTG  0x03u
#define MT_AF_DATA_CONFIRM         0x80u

#endif
