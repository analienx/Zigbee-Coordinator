# P7U board binding — source scaffold

Generic TI832 G2/G3/G4/G5/G6 code remains in `firmware/slzb-06p7/ti832`.
Future P7U overlays import those modules after verifying the separate P7U
contract. There is no copied stack implementation or board firmware overlay yet.

The accepted G6 native images use a TI LaunchPad reference. They are not P7U
images. The documented ESP GPIOs cannot select TI application DIOs; ROM BSL
UART pins also cannot establish application UART wiring.

R1 retains stock NV2 and requires board binding, vendor CCFG, stock USB/ZNP and
erase-policy evidence. R2 additionally requires complete G7/F07 and isolated
CAP192/NV5 persistence/capacity qualification. Both remain NOT_FLASHABLE.
