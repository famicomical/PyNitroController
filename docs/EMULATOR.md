# IS-NITRO-EMULATOR

What we know about the **IS-NITRO-EMULATOR** (Intelligent Systems' DS development box, USB
PID `0x0404`) and what PyNitroController does with it. Sources: Gericom's C#
`LibISNitroEmulator`, USB captures of the official **ISND** software (IS-NITRO-DEBUGGER: a
DS-firmware update, an NEC "Base Update" and a normal session), Lorenzooone's ISND
decompile, teod's analysis of the box's firmware, the community IS-NITRO register
document, and disassembly of the box's own V850E1 **Main Program** (version 3.52,
`0x160`). "Main+X" below is an NEC address inside the Main region (flash `0x10000`).

## Status

| Feature | Where | Tested on hardware |
|---|---|---|
| Identify (serial, device info, Main versions, IPL flash ID) | GUI *Identify*, `isnitro --version` | yes |
| NEC register reads, free-running counter | GUI *NEC Registers* | yes |
| DS reset | GUI *Reset DS*, `isnitro --reset` | yes |
| DS-IPL firmware dump / flash | GUI *Dump Firmware* / *Flash Firmware*, `ipl.dump_firmware`, `ipl.flash_firmware` | yes |
| Controller-flash dump (4 MiB) / Main extract | GUI *Dump NEC Flash*, *Extract Main Prog*, `nec.dump_nec_flash` | yes, byte-exact |
| Main Program reflash | GUI *Update Main Prog* | yes, re-dump identical |
| Full update (Main + LCA1/2/3 from a dump) | GUI *Full NEC Update* | yes (see "Region tails") |
| Device-info write (feature flags) | GUI *Write Device Info* | yes (video-out bit) |
| Alt-mode AGB + video Main patch | GUI *Special Mode Patch* (offline) | patched Main flashed and booted; current stub in self-tests |
| DS debugging (DS memory, registers, JTAG, breakpoints, ROM loading) | not ported; `LibISNitroEmulator` has it | — |

## USB transport

| | |
|---|---|
| VID / PID | `0x0F6E` / `0x0404` (rare early revision `0x0400`) |
| Endpoints | bulk OUT `0x01` (headers + write payloads), bulk IN `0x82` (read data); a third IN `0x83` is never used |
| Connect | set-configuration + claim; no vendor control transfers, no handshake needed |

Every command starts with a 16-byte little-endian header:

```
u16 command | u8 direction | u8 type | u32 address | u32 length | u32 0
```

- Direction `0x10` = write, `0x11` = read. ISND's first commands after power-up use
  `0x00`/`0x01`; meaning of bit 4 unknown, `0x10`/`0x11` always works.
- `type` selects the address space for cmd `0x00` (emulation memory); otherwise 0.
- **Write:** header and payload in one OUT transfer if the payload is ≤ 8192 bytes,
  otherwise two. By convention the payload's first byte repeats the command.
- **Read:** header on OUT, then `length` bytes from IN.
- An oversized or mis-sized read can stall IN with "Overflow"; clear-halt on `0x82`
  recovers it, no power-cycle needed.
- macOS: after a previous libusb session, set-configuration can fail with errno 19
  although the device is fine (it is already configured); ignore it.

## Address spaces

| Space | Commands | What |
|---|---|---|
| NEC memory | `0x25`/`0x27` setup + `0x17` read, `0x26` write | the box's own V850 controller: its flash, RAM and every peripheral |
| DS memory | `0x83` setup + `0x81` read, `0x84` write | the target DS's address space |
| Emulation memory | `0x00`, `type` 1 or 2 | the emulated cartridge (= NEC `0x0FC00000`) |

NEC memory map (only the low 28 address bits are decoded, so it mirrors):

| Base | What |
|---|---|
| `0x00000000` | controller flash, 4 MiB (the CPU executes from it in place) |
| `0x00800000` | RAM (the update routine runs at `0x80E000`, its buffer is `0x810000`) |
| `0x08000000` | Nitro control, IPL SPI flash, video forward / video out (below) |
| `0x0C000000` | USB controller |
| `0x0C800000` | Sub-LCA (CPLD): `+0x10` LEDs, `+0x12` version, `+0x16`/`+0x18` flash WP# override (undocumented) |
| `0x0F800000` | AGB bus: 256 KB debug RAM, JTAG engine, GBA-slot protection bitmap |
| `0x0FC00000` | NDS bus: emulated-cartridge memory |
| `0xFFFFF406` | DIP switch port |

**NEC reads:** setup payload `[0x25, unit_size, u16 count, u32 address]`, then cmd
`0x17` returns `unit_size × count` bytes. Measured:

- `unit_size` must be 1, 2 or 4; larger values silently return wrong data. It sets the
  bus access width and is the main speed factor: 1 → ~0.4 MiB/s, 4 → ~2 MiB/s.
- `count` is 16 bits; each `0x17` needs its own setup (the address doesn't carry over).
- Keep each read a multiple of 512 bytes. PyNitroController reads 0x2000 at a time;
  larger reads work on some units and corrupt on others.
- `0x27` (no auto-increment) and `0x25` give identical results for block reads.

**NEC writes:** cmd `0x26`, payload `[0x26, unit_size, u16 count, u32 address] + data`.
Never write command words to the flash this way: the CPU runs from that flash, so even
a read-ID command hangs the box until a power-cycle. Flash writes go through cmd
`0x0001` (below).

## Command table

"C#" = used by `LibISNitroEmulator`; "capture" = seen from ISND only.

| Cmd | Dir | Purpose | Source |
|---|---|---|---|
| `0x00` | r/w | emulation memory (`type` 1/2) | C# |
| `0x0001` | w | controller-firmware update (below) | capture, port |
| `0x02`, `0x08`, `0x91`, `0xA7` | r | small status reads; unknown | capture |
| `0x13` | r | 10 bytes: the unit serial (8 ASCII digits, = device info +0x40) + `00 FF` | port |
| `0x17` / `0x1A` | r | NEC read data, incrementing / not | C#, port |
| `0x18` | r | 120-byte firmware status (below) | capture, port |
| `0x25` / `0x27` | w | NEC read setup | C#, port |
| `0x26` | w | NEC write | C#, port |
| `0x81` | r/w | DS memory read data; a 2-byte `0x81` write is the reset prep | C#, port |
| `0x83` / `0x84` | w | DS memory read setup / write | C# |
| `0x85` | w | continue | C# |
| `0x87` | w | execution mode (run / trace / step over) | C# |
| `0x88` / `0x89` | r | polled while ISND flashes the DS IPL; unknown | capture |
| `0x8A` | w | hold / release DS reset | C#, port |
| `0x8B` | r/w | select processor / processor state | C#, port |
| `0x8C` | r | register file (0xA4 bytes) | C# |
| `0x8D` / `0xA3` | r / w | JTAG stream result / run JTAG stream | C# |
| `0x95` | r | control-register readback (16 bytes) | capture, port |
| `0x96` | r | 4-byte status, read around updates | capture, port |
| `0xA0`, `0xA1` | w | register-read latch, set one register | C# |
| `0xA5` | r | 32-byte progress struct during an IPL flash (total `0x40000` + counter) | capture |
| `0xA8` | r | 8-byte status | C# |
| `0xAA` | w | FIQ pin | C# |
| `0xAD` | w | control register: payload `AD 00 00 00 \| u32 w1 \| u32 w2 \| 12 × 00` | C#, port |
| `0xAE` | w | per-processor setup during reset | C# |
| `0xB3`, `0xBD` | w | EmbeddedICE register, breakpoint block | C# |
| `0xC0`/`0xC1`/`0xC2`/`0x97` | r/w | encrypted exchange (open questions) | capture |

**DS reset** (what *Reset DS* sends): `0x81` prep, `0x8A` hold, `0xAD` with w1 = `0x09`,
`0x8A` release. No ROM is loaded.

**cmd `0x18` firmware status** (120 bytes, little-endian):

| Offset | Contents |
|---|---|
| `0x00`–`0x27` | (version, type) word pairs for Main, LCA1, LCA2, LCA3, LCA4 |
| `0x28` / `0x2C` | LCA3 hardware revision / board configuration |
| `0x3C`–`0x4C` | XOR-32 checksum of Main, LCA1, LCA2, LCA3, LCA4 (see "ISND's firmware check") |
| after | the version words again |

The checksums are computed by the box when asked; they are not stored in flash.

## Registers (`0x08000000`)

16-bit accesses, only the low 8 bits valid. Some addresses moved between hardware
revisions (the IPL SPI control register was at `0x08000018` on old units), so check
against your unit before writing.

| Address | Name | Notes |
|---|---|---|
| `0x08000000` | NITRO REG 0 | `reset` (0 = resetting), `cover` (lid), `debug_btn` |
| `0x08000002` | NITRO REG 1 | bit 0 IPL-flash write protection (**set = off**), `boot_complete` (JTAG works only when 0), `power` (1→0 power-cycles; read-modify-write this register) |
| `0x08000004` / `06` | IPL SPI control / data | direct SPI to the DS IPL flash (below) |
| `0x08000008` / `0A` / `0C` | forward enable / config / frame count | USB video forwarding: rate, colours, screens |
| `0x08000010`–`16` | video-out unlock | must hold `59 4F 4B 4F` ("YOKO") or the AV outputs stay off |
| `0x08000018`–`1C` | background R/G/B | border colour |
| `0x0800001E` | monitor state | bits 5–4 AV1, 1–0 AV2 (0 off, 1 top, 2 bottom, 3 both); bit 2 rotate, bit 3 rotate direction; bit 6 de-flicker, bit 7 de-flicker type |
| `0x08000022` / `24` / `26` | cursor RAM | index; RGB555 pixel lo / hi, bit 15 = transparent (16×16) |
| `0x08000028` / `2A` | counter lo / hi | free-running; a good liveness check |
| `0x0800002C` / `2E` | cursor X / Y | 255 / 255 hides it |
| `0x08000030` / `34` / `36` | screen select / data lo / hi | select bit 7 = AV1 (clear = AV2), low bits: 0 X, 1 X dual, 2 Y, 3 Y dual, 4 dual-screen gap, 5 video mode (0 interlaced, 1 progressive), 6 aspect correction (rev J) |

The firmware's boot code programs the video-out block in every mode, unless DIP 3 is on
or the device-info video-out bit is locked (then it writes the unlock and immediately
overwrites it).

AGB bus: JTAG bit count `0x0F844004`, TDI `0x0F845000`, TMS `0x0F846000`, TDO
`0x0F847000`, state `0x0F844002`; `0x0F843000` is a 512-byte bitmap of accessible 8 KB
GBA-slot blocks (bit set = open).

## DS-IPL firmware flash

### Direct SPI (what PyNitroController does)

`0x08000004` bit 7 = busy, bit 6 = chip select, bit 3 = transmit. Per byte: write `0x48`
to control, the byte to data, read data back for the received byte; `0x00` to control
ends the transaction. Busy polling can be skipped (a USB round trip takes far longer
than one SPI byte).

- The flash sits on the DS's ARM7 SPI bus, so it only answers while the DS is **out of
  reset** (held in reset, the JEDEC ID reads `00 00 00`).
- Writes need NITRO REG 1 bit 0 **set**. With it clear, write-enable still latches but
  erase and program silently do nothing.
- On the unit tested (Sanyo LE25FW203T, JEDEC `62 16 xx`) the 4 KB sector erases (`0x20`,
  `0xD7`) do nothing over this path; only chip erase `0xC7` works, so
  `flash_firmware` erases the whole chip and reprograms it (256-byte pages, `0x02`).
  64 KB erase (`0xD8`) is untested.
- A full 256 KB read takes about 100 s; erase + program with sampled verify about 40 s.
- A dump differs from another unit's image in the per-console Wi-Fi calibration data
  (roughly `0x2A`–`0x162`).

### How ISND does it

ISND never touches these registers. It loads a 13 KB ARM7 flasher into ARM7 IWRAM
(`0x037F8000`), a 16-byte control block at DS `0x02080000` (`59 10 59 10 08 93 08 93`,
source `0x02081000`, length `0x40000`) and the new image at `0x02081000`, then runs the
flasher, which talks back through a mailbox in the GBA-slot area (`0x09F80000`, "IS"
signature) and reports progress through cmd `0xA5`. The image is wrapped in a transport
cipher over little-endian u32 words:

```
state = 0x59108930
plain = cipher ^ state
state = ((state ^ (state >> 17)) * 0x1717) & 0xFFFFFFFF
```

The flasher checks the decrypted image with CRC-16/MODBUS before programming. The image
format itself (KEY1 Blowfish + LZ77 boot modules, compressed GUI parts) is what
`iplrepack.py` handles; see [`DUALMODE.md`](DUALMODE.md).

## Controller flash

A Sharp LH28F320BF: 4 MiB NOR, x16, Intel/Sharp command set, 64 KB blocks plus eight
8 KB parameter blocks at `0x3F0000`–`0x3FFFFF`.

| Address | Contents |
|---|---|
| `0x000000` | bootloader |
| `0x010000` | Main Program (0x20000) |
| `0x030000` / `0x060000` / `0x090000` / `0x0C0000` | LCA1 (AGB) / LCA2 (NTR) / LCA3 (monitor) / LCA4 (FPGA bitstreams, 0x30000 each; LCA4 empty on the units seen) |
| `0x100000` | mirror of `0x000000`–`0x0FFFFF` |
| `0x210000`–`0x2C0000` | backups of Main and LCA1–4, same spacing |
| `0x3FE000` | device info (8 KB parameter block) |

The register document puts device info at `0x2F0000` (NEC address `0x7FE000`); in a
straight dump of the chip it is at `0x3FE000`. `dump_nec_flash` finds it by its
signature.

**Region headers:** `INTELLIGENT SYSTEMS` at +0, region name at +0x20, version at +0x40,
type at +0x44, size at +0x50. The version is decimal-coded: `0x160` = 352 = 3.52. Only
the Main carries a build string (`Version 3.52 2009/11/17 14:18`).

**Block locks:** the bootloader and device-info blocks are locked down at every boot;
Main and the LCAs are only locked, so the update routine can unlock them.

**DIP-4 repair** copies the backups over Main and the LCAs. On the unit tested the backup
Main is an older factory version (3.18), so a repair downgrades the Main.

### Device info

| Offset | Contents |
|---|---|
| +0x00 | `INTELLIGENT SYSTEMS` |
| +0x20 | `IS-NITRO-EMULATOR` |
| +0x40 | serial, 8 ASCII digits |
| +0x80 | options: a **set** bit = extension *not* available. Bit 7 DIMM-1024, bit 5 DIMM-512, bit 3 wireless, bit 1 video out |
| +0xA0 | LCA3 hardware revision (`FF` A, `FE` B, `FD` C, `FB` D) |
| +0x50, +0xFC | blank (`FF`); the update path writes size / 0 there in other regions |

The block is written at the factory: there is no backup copy, and ISND never writes it.
A unit with options `0xF6` has wireless but no video out; clearing bit 1 (`0xF4`) enables
the AV outputs permanently. A bad write can only be repaired with an external chip
programmer, so keep a 4 MiB dump.

## Firmware update (cmd `0x0001`)

**Blob** = [0x2000-byte flash routine, region selector u32 at `0x1FF0`] + [payload =
region data + 0x100 bytes], all encrypted with a per-byte cipher. `i` restarts at 0 for
the routine and for the payload:

```
b = (i + 0x5A) ^ b
if n & 0x80: b += 0xA8     if n & 0x08: b ^= 0xA5
if n & 0x40: b += 0x89     if n & 0x04: b += 0xBD
if n & 0x20: b ^= 0x32     if n & 0x02: b ^= 0xEF
if n & 0x10: b += 0xAE     if n & 0x01: b += 0x1B      (all & 0xFF)
```

- `n` is one key byte per blob (ISND: 15-bit random, forced to `0xA5` if 0; only the
  low byte is used). It travels **unencrypted** at payload +0xFC.
- Payload +0x50 holds the region size, encrypted on its own with `i` restarting at 0.
  It ends up in the region header verbatim, so it must be the region's real size.
- ISND keeps its firmware byte-decremented (store = real − 1, including the routine
  inside `ISNITRO.dll`), so its cipher starts with `+1`. Encrypting a dump skips that.
- The routine is the box's official one (`nec_flash_routine.bin`, identical in every
  ISND blob except the selector). Selectors 0–4 = Main, LCA1–4; anything else does
  nothing, so no selector reaches the backups or device info.

**Sequence** (as ISND does it, reproduced by `send_firmware_update` /
`send_firmware_update_multi`):

1. **Arm:** `0xAD`(0, `0x0A`), `0x95`, `0xAD`(`0x0A`, 0), `0xAD`(0, `0x02`), `0x95`. Without
   it the box accepts the blob and ignores it.
2. Reads `0x96`, `0x18`, `0x96`.
3. The cmd-`0x0001` header, then the blob in 0x10000-byte chunks.
4. **Drain progress:** bare 8-byte IN reads with no command header. Byte 0 climbs `03`…`09`;
   `01` means done. The routine waits for each read before continuing, so a host that
   doesn't read stalls it before the erase (the box goes silent until power-cycled).
5. Reads `0x18`, `0x96` (×2); further blobs repeat 3–5.
6. **Disarm:** `0xAD`(0, `0x0A`), `0x95`, `0xAD`(0, `0x02`), `0x95`.

On the box, the Main decrypts the routine to `0x80E000` and size + 0x100 payload bytes
to `0x810000`, writes the size into buffer +0x50 and 0 into +0xFC, and runs the routine:
identify, unlock, erase, blank check, program, verify, relock. A second routine then
checks the LCA signatures. The box restarts by itself afterwards; re-dump to verify.

**Region tails.** The routine programs a fixed span per region (Main 0x20000, LCA
0x30000) from the RAM buffer, but only size + 0x100 bytes are decrypted into it. For an
LCA the rest of the span is whatever is left in RAM. ISND does the same (its blobs are
byte-identical in layout), so after any LCA update the bytes past the bitstream differ
from run to run. The bitstream itself is exact and the tail is padding; Main has no
tail.

**Device-info write.** Uses a patched copy of the routine: selector 0's jump-table entry
(`0x1B8`) points to a stub at `0xD00` that

1. asserts the flash WP# override: `0x5555`, `0xAAAA`, `0xFFFF` to `0x0C800018`, then 1
   to `0x0C800016` (found in the bootloader and the Main);
2. targets `0x3FE000`, size 0x2000;
3. sets buffer +0x50 and +0xFC back to `FFFFFFFF` so the header gaps stay blank;
4. jumps to the routine's common flash code.

Without step 1 the routine's unlock loops forever on the locked-down block. That happens
before the erase, so the block is unchanged; power-cycle to recover. Exactly one byte
changes when clearing the video bit, and it persists across power-cycles.

## ISND's firmware check

On connect ISND reads cmd `0x18` and compares each region's version **and** XOR-32 (the XOR
of every little-endian u32 over the full span: Main 0x20000, LCA 0x30000) with the
firmware it ships. Any mismatch makes it force an update, wiping a patched Main. The
stock 3.52 Main's XOR-32 is `0x93C5F6E3`.

XOR is easy to steer: `patch_main` XORs the patch's net change into one spare word in
free padding (Main+`0x11614`), so a patched Main reports the stock checksum. Keep the
version at `0x160` too.

## DIP switches

Port `0xFFFFF406`, active low (bit n−1 = DIP n, 0 = on).

| DIP | Function |
|---|---|
| 1 | serial debug output |
| 2 | special mode |
| 3 | skip FPGA initialisation |
| 4 | restore firmware from the backups on boot |
| 5 | wireless vs wired DS Wi-Fi |
| 6 | special mode |
| 7 | AV OUT1: both screens |
| 8 | AV OUT2: both screens |

## Alternate (cartridge) mode

With **DIP 1, 6 and 8 on** and 2, 3, 7 off (4 and 5 don't matter) the Main boots as a
near-retail unit: it skips the USB debug handshake, passes the NDS slot through, powers
the GBA slot, turns off the NTR serial link and enables LCA3 forwarding. Video out is
configured at boot as in normal mode. The stock debug IPL hangs in this mode; the
dual-mode IPL in [`DUALMODE.md`](DUALMODE.md) boots carts instead.

Stock alt mode leaves most of the GBA slot blocked (bitmap at `0x0F843000`), so GBA saves
don't fully work. **Special Mode Patch** (`altmode_video_patch.py`) fixes that and sets the video
output:

- **Hook:** the `jarl` at Main+`0x11952` (end of the alt-mode setup, so normal mode is
  untouched) is redirected to a stub in a 4 KB free run at Main+`0x10618`: an `NVSC`
  parameter table, then code at Main+`0x1063C`.
- **GBA slot:** the stub runs the original call, then opens the whole slot: eject state
  0, `0x0F843000` filled with `FF` × 0x200, AGB bus control set. It must not call
  `agb_setBusProtection(0)`: that clears the protection flag the firmware just set and
  breaks saves.
- **Video:** it writes the unlock, then both outputs' geometry, background, cursor and
  monitor state from the table.
- **Checksum:** the correction word keeps the XOR-32 at stock.

Default values: X `196`, X dual `344`, Y `46`, Y dual `46`, gap `8`, interlaced,
black background, cursor hidden, monitor state `0x16`. Flash the result with *Update
Main Prog*.

## Open questions

- An encrypted exchange ISND runs after booting the firmware menu: `0xC1` (8-byte
  challenge), `0x97` (read 256 B), `0xC0` (write 256 B), `0xC2` (16 B). Neither cipher
  above decrypts it; possibly an authentication check.
- Bit 4 of the direction byte; the layouts of `0xA5` and the rest of `0x18`; `0x02`,
  `0x08`, `0x88`/`0x89`, `0x91`, `0xA7`; the third endpoint `0x83`.
- A byte-exact LCA restore (a stub that decrypts the full span) is not built.
- Whether 64 KB erase (`0xD8`) works on the IPL flash over the SPI path.
