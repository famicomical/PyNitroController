# IS-NITRO-CAPTURE

What we know about the **IS-NITRO-CAPTURE** (Intelligent Systems' DS capture box, USB
PID `0x0403`) and what PyNitroController does with it. Everything here comes from USB
captures of the official software (**ISNP**, IS-NITRO-CAPTURE v2.15), Lorenzooone's
[cc3dsfs](https://github.com/Lorenzooone/cc3dsfs), and disassembly of the box's own
V850E1 **Main Program** (versions `0x1D6` and `0x1DE` = stock v2.15). Offsets below are
for v2.15 unless stated; "Main+X" is an offset inside the 0x20000-byte Main region.

## Status

| Feature | Where | Tested on hardware |
|---|---|---|
| Identify (serial, firmware/LCA1 version) | GUI *Identify*, `isnitro_capture.py info` | yes |
| Controller-flash dump (4 MiB) / Main extract | GUI *Dump NEC Flash*, *Extract Main Prog*, `isnitro_capture.py dump` | yes, byte-exact |
| Controller-firmware update (Main) | GUI *Update Main Prog* | yes, written + read back + verified |
| Video Config (built-in offsets, gaps, aspect fix, version) | GUI *Video Config* | write path yes; dialog via simulation |
| Built-in cursor editor | GUI *Video Config → Edit Built-in Cursor* | simulation only |
| Dump saved video configs as `.nvi` (into an `nvi_configs` folder) | GUI *Dump Video Configs* | yes |
| Frame capture | `isnitro_capture.py grab` | no |
| Auto-disconnect on unplug | GUI | yes |

## USB transport

Same VID (`0x0F6E`), endpoints (OUT `0x01`, IN `0x82`) and 16-byte header as the
EMULATOR (`u16 cmd, u8 dir, u8 type, u32 addr, u32 len, u32 pad`), but:

- direction byte `0x00` = write, `0x01` = read (EMULATOR: `0x10`/`0x11`);
- a write's header and payload are separate bulk transfers;
- every command is answered by a **16-byte status**, byte 0 = `1` for OK (the
  capture-DMA start is the one exception);
- connect needs only set-configuration + claim + clear-halt on both pipes.

Other IS devices for reference: EMULATOR `0x0404` (rare early revision `0x0400`),
IS-TWL-CAPTURE `0x0501`/`0x0502`.

## Command table

The Main's dispatcher (Main+0x54AC) takes `header.cmd & 0x7F` and picks the table by
direction bit: write handlers for `0x01`, `0x0B`–`0x30`, read handlers for
`0x01`–`0x07`, `0x0E`–`0x2A` (no access check). Commands seen or traced:

| Cmd | Read | Write |
|---|---|---|
| `0x00` (type 2) | capture DMA: length 1 = start, 0 = stop | |
| `0x01` | Main version/type + LCA1 version/type (4 × u32, from flash 0x10040/44, 0x30040/44) | **firmware update** (below) |
| `0x02` | product type / options (32 bytes) | |
| `0x03` | serial (ASCII, polled by ISNP every ~200 ms) | |
| `0x05` | DIP switch port | |
| `0x06` | shipment firmware version | |
| `0x0D` | | memory-read parameters `u16 unit_size, u16 count, u32 address` |
| `0x0E` | memory read: `count × unit_size` bytes, incrementing | memory write (not used) |
| `0x0F` | non-incrementing read (registers) | same parameters as `0x0D` |
| `0x12`–`0x15` | | forward rate / screens / colours / frame count (`0x4001` = permanent) |
| `0x18` | debug button | full restart |
| `0x19` | lid state (bit 0) | |
| `0x1C` | | forward restart |
| `0x1E` | DS-IPL flash read (4-byte prefix + data, after `0x1F`) | |
| `0x1F` | | DS-IPL read setup (`1f 55 56 76`, address, length) |
| `0x21` / `0x22` | | DS CPU reset on / off |
| `0x22` | load the saved video config | |
| `0x23`, `0x29` | | set cursor data / image (live) |
| `0x24` | 4-byte response to `0x2A` | IPL-access mode on/off (`24 01` / `24 00`) |
| `0x28` | | save current video config to flash |
| `0x2A` | | 8-byte challenge (ISNP checking the box) |
| `0x2F` | | set video config (the 0x29C-byte `MNTR` record), applied immediately |

If the memory-read parameters are rejected (unit size not 1/2/4) the box still says OK
and returns its USB buffer unchanged, i.e. your own request; `read_memory` reports that
as an error instead of saving it.

## Controller flash

The flash is mapped at address 0 of the V850, so `0x0D`/`0x0E` read it directly. Same
layout as the EMULATOR:

| Address | Contents |
|---|---|
| `0x000000` | boot block |
| `0x010000` | Main Program (0x20000; only the first 64 KB used) |
| `0x030000` | LCA1 (the only FPGA bitstream; no LCA2/3) |
| `0x060000`–`0x1EFFFF` | blank |
| `0x1F0000` | saved video configs (log, below) |
| `0x210000` / `0x230000` | backup Main / LCA1 (stock; what a DIP-4 repair restores) |
| `0x3FE000` | device info (`IS-NITRO-CAPTURE`, serial at +0x40, options at +0x80) |

Region headers: `INTELLIGENT SYSTEMS` at +0, region name at +0x20, version at +0x40,
size at +0x50; an update fills +0x50 with the region span and +0xFC with 0.

## Firmware update (cmd `0x01`)

Reproduced byte for byte against a USB capture of ISNP v2.15:

1. Blob = **[0x2000 CAPTURE flash routine, region selector u32 at 0x1FF0]** + **[the
   full region]** (Main 0x20000 / LCA1 0x30000, no trailing bytes), encrypted with the
   EMULATOR's update cipher (`nec_base_update_crypt.py`). The size field at payload
   +0x50 (= span) is encrypted separately with the index restarted; the key sits at
   +0xFC (ISNP uses a 15-bit random key; the cipher uses its low byte).
2. Header + payload in 0x10000-byte chunks, then the 16-byte status.
3. The RAM routine flashes the region, sending bare 8-byte progress words on EP 0x82:
   `03`…`09`, then `01` = done. The host must keep reading them.
4. **Then wait ~5 s and clear-halt both pipes** before the next command; without that
   the box doesn't answer (ISNP does exactly this). The box doesn't reboot: the new
   version reads back immediately.

ISNP writes LCA1 then Main, and only offers an update when the box's Main version is
**older** than its own (`0x1DE` for v2.15; it refuses to run on a newer box). The CAPTURE
routine is not the EMULATOR's (`isnc_flash_routine.bin` vs `nec_flash_routine.bin`).
A DIP-4 repair restores the backup copies, i.e. stock firmware, losing any patch.

## Video output at power-on

Traced through the v2.15 boot code:

1. **Built-in settings** (Main+0x25D2) are written straight to the video registers
   (select `0x08000030`, data `0x08000034`/`36`): AV1 registers `0x80` X, `0x81` X
   dual, `0x82` Y, `0x83` Y dual, `0x84` gap; AV2 registers `0x00`–`0x04`. X, X dual
   and Y come in pairs chosen by the **LCA1 type** (flash 0x30044, `cmov H`): type > 1
   uses the first value, otherwise the second. Stock: X `0xC4`/`0xB8`, X dual
   `0x158`/`0x138`, Y `0x2E`/`0x30`, Y dual `0x2E`, gap 8.
2. **Aspect-ratio "fix"**: if LCA1 type > 1, registers `0x86`/`0x06` are set to 1
   (Main+0x28CE). This is the only place besides step 5 that writes them, and nothing
   clears them.
3. DIP 3/6/7/8 handling and the **built-in cursor** (Main+0x32A0, below).
4. DIP port `0xFFFFF406` **bit 1 = DIP 2** (bit n−1 = DIP n). If on, the newest valid
   saved config is loaded and **applied over the built-in settings** (Main+0x3580).
5. That apply routine sets the aspect registers again under the same rule (Main+0x379E).

ISNP's cmd `0x2F` (sent on every connect) runs the same apply routine, so while ISNP is
connected its Options values drive the video output whatever DIP 2 says.

Consequences: built-in-setting edits only show with DIP 2 off (and ISNP not
overriding). Removing the aspect fix needs Main+0x28CE patched (`bnh` 0x93 → `br`
0x95); with DIP 2 on, both sites must be patched, so "DIP 2 on only" is most likely
ineffective. The Video Config editor follows all of this.

## DIP switches

From the CAPTURE manual (don't flip them with the power on):

| DIP | Function |
|---|---|
| 1 | unused, keep off |
| 2 | on: use the video settings saved in the box (3, 6–8 ignored) |
| 3 | show the touch position on the video output |
| 4 | firmware repair (restores the backup Main/LCA1) |
| 5 | DS wireless: off wired, on wireless (WIRELESS OPTION) |
| 6 | colour outside the LCD image: off black, on grey |
| 7 | AV OUT1: off top screen, on both screens |
| 8 | AV OUT2: off bottom screen, on both screens |

## Saved video configs and `.nvi` files

ISNP's *Option → TV* tab saves its settings as an `.nvi` file and writes the same
**0x29C-byte `MNTR` record** to the box (*Write settings to hardware*, cmd `0x28`).

**Log.** Records live in 0x400-byte slots of the 64 KB block at `0x1F0000`. Loading
(Main+0x9632) reads the slots in order and keeps the last valid record before the first
invalid (blank) slot; saving (Main+0x971C) writes into that first invalid slot and
erases the block when all 64 are used. Nothing points at the current record.

**Validity** (Main+0x94B6): `MNTR` at +0, non-zero version at +4, and a 16-bit
checksum at +6 = the sum of the halfwords at +0x08, +0x0C … +0x5C (step 4), +0x60 …
+0x25E (step 2), +0x260, +0x264, then by version: ≥2 +0x268, +0x26C; ≥3 +0x270 …
+0x280 (step 4); ≥4 +0x284, +0x288, +0x28C; ≥5 +0x290, +0x294, +0x298.

**Fields** (version 5). "Firmware" = read by the apply routine.

| Offset | Meaning | Basis |
|---|---|---|
| +0x08 … +0x24 | 8 flags, probably AV OUT1/2 screen and interlace | not read by the apply routine; unconfirmed |
| +0x28 / +0x2C / +0x30 | background colour R/G/B | firmware (border-colour registers `0x08000018`/`1A`) |
| +0x34 … +0x58 | per-AV geometry: X ×2, Y ×2, X dual ×2, Y dual ×2, gap ×2 | firmware (normal mode) |
| +0x5C | touch-point display flag | firmware (same variable DIP 3 sets) |
| +0x60 … +0x25F | user cursor, 16×16 RGB555 | firmware |
| +0x260 / +0x264 | cursor centre point X/Y (default 7/7) | firmware |
| +0x268 | use the user-defined cursor | firmware |
| +0x26C | penetration (transparent) colour, default `0x7C1F` | firmware |
| +0x270 | apply special functions (selects unified geometry) | firmware |
| +0x274 | probably de-flicker vs rotation | firmware reads it |
| +0x278 / +0x27C / +0x280 | unified geometry X / Y / gap (special functions) | firmware |
| +0x284 / +0x288 / +0x28C | image rotation; +0x28C picks 30/37 for register `0x0800001E` (likely direction) | firmware |
| +0x290 / +0x294 / +0x298 | rotation geometry: AV1 X = +0x290 + +0x298 + 0x120, AV2 X = +0x290, Y = +0x294 | firmware |

## Cursors

The video FPGA has a **16×16 cursor**: the firmware writes 256 pixels (index to
`0x08000022`, data to `0x08000024`/`26`), RGB555 with bit 15 = transparent.

- **Built-in cursor** (DIP 3, DIP 2 off): a 16×16 table at Main+0x8120, one byte per
  pixel (0 transparent, 1 white, ≥2 black), loaded at every boot (Main+0x32C0); hotspot
  7/7. Stock it is a crosshair. The Video Config cursor editor edits this table (it
  first checks that Main+0x32D8 still loads it).
- **User cursor** (DIP 2 on): the image inside the active saved record, copied when
  the record has +0x268 set. Each record carries its own image.

## Open questions

- The meaning of the `MNTR` flags at +0x08 … +0x24 and +0x274 (save `.nvi` files
  from ISNP changing one setting at a time and diff them).
- The polarity of the DIP 3 bit, and whether "aspect fix removed with DIP 2 on only"
  really does nothing on hardware.
- The CAPTURE DS-IPL dump (`0x1F`/`0x1E`) and an LCA1 write are not implemented.
