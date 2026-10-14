# Separate P7U board evidence

G6 PR64 was accepted into the P7 development feature at
`2ddcb4dbfcf757179046a62041817119270c601d`. Its genuine native builds remain
TI-reference software evidence. The original P7 board contract is unchanged.

This profile separates the [manufacturer ESPHome 06xU r1.73 reference](https://github.com/smlight-tech/slzb-esphome/blob/3397f6ffe7b0a58cf1546c8293bfa644235a9769/hw_defs/06xu/r1_73.yaml)
from the fitted P7U PCB and the TI application. TX17/RX18/CTS15/RTS14 are ESP
GPIOs. They establish no CC2652P7 DIO assignment. Neither ROM BSL UART pins nor
LaunchPad UART/RF defaults supply that assignment. No custom board overlay is
installed until that evidence exists.

`verify_board.py` allows unknown board claims under SOURCE_ONLY while rejecting
wrong models, SoCs, revision expectations and flash geometry. A declared
BOARD_FLASH_CANDIDATE requires all board-scoped evidence and the actual revision;
it never grants flash/physical/network qualification. The image/CCFG/erase-policy
verifier is a separate remaining gate, not implemented by this profile scaffold.

The user-supplied dashboard reports P7U, CC2652P7/ESP32-S3, stock metadata20240316,
core3.2.6.dev3 and USB Device mode. PCB revision, UART baud, exact bridge driver,
DTR/RTS semantics and live SYS_VERSION are unknown. Dashboard metadata does not
prove a live radio response. Private unit identifiers and network credentials
are excluded from this public profile.

All source verification runs on GitHub-hosted Actions. Flash, reset, erase,
radio/network commissioning and production migration remain separately gated.
