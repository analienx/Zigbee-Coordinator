"""Physical limits of the pinned, settled four-page TI NVOCMP store.

One page is the compaction destination. Every stored item consumes a seven
byte header and at least one payload byte; neither history nor active-row
budgets may depend on today's particular network inventory.
"""
PAGE_BYTES = 8192
PAGE_HEADER_BYTES = 16
ITEM_HEADER_BYTES = 7
DATA_PAGES = 4 - 1
DATA_BYTES = DATA_PAGES * (PAGE_BYTES - PAGE_HEADER_BYTES)
MAX_RECORDS = DATA_PAGES * ((PAGE_BYTES - PAGE_HEADER_BYTES) // (ITEM_HEADER_BYTES + 1))
# Private pipe: 16-byte prefix, 7-byte per-row identity/length header (the
# same size as its physical TI header), then the 20-byte completion seal.
MAX_PRIVATE_OUTPUT = 16 + DATA_BYTES + 20
C_LIMITS = r'''
#define R4_NV4_DATA_PAGES (NVOCMP_NVPAGES - 1u)
#define R4_NV4_MAX_RECORDS (R4_NV4_DATA_PAGES * ((FLASH_PAGE_SIZE - NVOCMP_PGDATAOFS) / (NVOCMP_ITEMHDRLEN + 1u)))
_Static_assert(NVOCMP_NVPAGES == 4u && FLASH_PAGE_SIZE == 8192u &&
               NVOCMP_PGDATAOFS == 16u && NVOCMP_ITEMHDRLEN == 7u,
               "unqualified NV4 record geometry");
'''
