/* No RAM, CCFG, NVOCMP or library allocation is allowed. */
--entry_point=R4_Reset
--retain="*(.r4_vectors)"
--retain="*(.r4_handoff)"
MEMORY
{
    STAGE (RX) : origin = 0x000AC000, length = 0x2000
}
SECTIONS
{
    .r4_vectors : {} > STAGE
    .r4_handoff : {} > STAGE
}
