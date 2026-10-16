# Dual-mode IS-NITRO debug firmware

Turn the IS-NITRO-EMULATOR's **debug DS-IPL firmware** into a *dual-mode* image:

- **Normal NEC mode** — unchanged: still a debugger (load a ROM over USB, JTAG-debug it).
- **DIP "alternate" mode** (SW1 / SW6 / SW8 **ON**) — boots a **physical NDS cartridge**, behaving
  like a retail console: the cart appears in the menu and the firmware's own **Start-up: Auto / Manual**
  setting decides whether it auto-boots or waits for you to pick it.

Stock debug firmware hangs (or ignores the cart slot) in alternate mode; this patch fixes that without
disturbing the debugger. The change is a 4-byte-patch + 32-byte stub set, applied to the *decompressed*
ARM9/ARM7 IPL modules and repacked with the bundled pure-Python [`iplrepack.py`](../pynitro/ipl/iplrepack.py).

> **No Nintendo firmware is shipped here.** Anyone builds their own dual-mode image from *their own*
> dump, and **their IPL settings are preserved** — calibration, language, the Start-up Auto/Manual
> choice, Wi-Fi config and owner info are carried over untouched (`iplrepack.py` inherits the
> settings/wifi region from your dump verbatim; only the IPL boot code is repacked). The builder first
> rejects any dump whose firmware-header build timestamp isn't the supported `2006-02-20 20:59`, then
> verifies every patch site's exact bytes (and the dead-padding slots) so the offsets line up with the
> IS-NITRO debug IPL build `VIB2.11May 26 2005` — the same on every unit with this firmware, *not*
> unit-specific — and aborts cleanly on any mismatch, so it never produces a bad image.

## What it patches

| # | Module @offset (RAM) | Change | Effect |
|---|---|---|---|
| 1 | arm9boot `0x7ab2` (`0x2327ab2`) | `FE E7 → C0 46` | NOP the `IplInit` `while(1)` hang that freezes the debug IPL at boot in alt mode. |
| 2 | arm7boot `0x6e8` (`0x37faee8`) | `0D → 07` | Retarget the ARM7's `isOnDebugger` branch so alt mode runs its flash resource-load instead of skipping the resource-init block — lets the ARM7↔ARM9 boot handshake proceed. |
| 3 | arm9boot `0x78d0` (`0x23278d0`) | `3B D0 → C0 46` | NOP the `!isOnDebugger → return 0` early-exit in `IplCheckCardBootSkipUI`, so alt mode runs card detection (`SYSM_IsExistCard`) and the boot state-machine (`IplUpdateBootStatus`) instead of bailing straight to the GUI. |
| 4 | arm9boot `0x7922` (`0x2327922`) | `bl IplSetBootFlag → bl stub` | Redirect the **auto-boot trigger** to the stub — placed *after* detection + state-2 (which sets the card-present flag) but *before* the boot fires. |
| 5 | arm9boot `0x104f8` (`0x23304f8`) | 32-byte stub | `isOnDebugger != 0` (normal/debugger): set `BOOT_NITRO_CARD` and continue the boot — debugger auto-boot preserved exactly. `isOnDebugger == 0` (alt): jump to the function's own return-0 epilogue (`0x232794a`) → fall through to the GUI menu. |

Net effect in alt mode: the firmware runs the cart-detection it normally skips, then drops into the
menu with the cart selectable; the stock auto-start logic (DS user-settings **bit 6**, "Autostart
Cartridge") then drives auto-boot vs. manual. Every patch is either alt-mode-only or gated on
`isOnDebugger`, so normal NEC/debugger mode is unchanged.

## Why v7: passing the firmware check

The 5 patches above are the functional change (they are the original "v6" patch set). ISND — the host
debugger — validates the DS-IPL by its **CRC-16/MODBUS**: the firmware header stores one joint CRC over
`arm9boot || arm7boot` at offset `0x06`, and a patched IPL whose CRC no longer matches is rejected and
force-reflashed. (This is *not* the XOR-32 check used for the NEC Main program — the DS-IPL gate is a
plain CRC.)

So **v7** applies the identical patch set, then writes one 16-byte correction word into genuinely dead
arm9boot padding (`0x10518`, RAM `0x2330518`, in the tail of the same dead run the stub lives in) chosen
so the stored joint CRC again equals the stock `0xB4DD`. No code or behaviour changes versus v6 — only
the CRC is brought back on-stock. The correction is solved as a GF(2) XOR-basis over the padding bits;
because CRC is affine and invertible in its seed, adjusting arm9boot alone can hit any joint target, so
arm7boot is left byte-identical except for its single functional `0x6e8` patch (it has no safe padding —
its large zero run is a live zero-initialised RAM block, not dead space).

## Build it

**Pure Python — no C toolchain, no `arm-none-eabi` assembler.** `iplrepack.py` is a self-contained port
of the IPL unpacker/repacker (LZSS + DS KEY1/Blowfish + the part3/4/5 huffman decoder), and the boot
stub is pre-assembled and embedded in `build_dualmode_v7.py`. You only need Python 3 and the two scripts
side by side.

You always build from a **dump of your own unit** — the patch is applied to your image, so your
settings/wifi region is carried over untouched. Two ways:

**GUI (easiest — the build itself is offline, no device needed):**
1. *Connect*, then **Dump Firmware…** to save a dump of your unit (or reuse one you already have).
2. Click **Build DualMode IPL…**, pick that dump as the input, and choose where to save the result.
   The button is enabled whether or not a unit is connected.

**CLI** (from the repository root):

```sh
# 1) dump YOUR firmware (the "require a dump first" step)
python3 -m pynitro.ipl.dump_firmware            # -> e.g. firmware_dump.bin

# 2) build the dual-mode image from your dump
python3 -m pynitro.ipl.build_dualmode_v7 firmware_dump.bin dualmode_ipl_v7.bin
```

Requirements:
- Python 3.7+.
- `iplrepack.py` next to `build_dualmode_v7.py` (both ship in `pynitro/ipl/`).
- A firmware **dump from your own unit** running the supported IPL revision. The builder gates on this
  in two layers and **never produces a bad image**:
  - **Version guard (checked first):** the DS firmware header carries a 5-byte BCD **build timestamp**
    at offset `0x18`. The supported IPL revision reads **`2006-02-20 20:59`** (the same image
    carries IPL code build `VIB2.11May 26 2005` at arm9boot `0x101c4`). A dump whose header timestamp
    differs is refused up front — the GUI shows both timestamps and stops, the CLI exits non-zero —
    because the fixed patch offsets are only valid for that exact revision.
  - **Per-site verification:** it then checks the original bytes at every patch site and the joint CRC,
    aborting cleanly on any mismatch.

`iplrepack.py` also works standalone for inspecting/rebuilding any DS firmware:

```sh
python3 -m pynitro.ipl.iplrepack info   firmware_dump.bin
python3 -m pynitro.ipl.iplrepack unpack firmware_dump.bin out_dir/
python3 -m pynitro.ipl.iplrepack repack base.bin out.bin --arm9 arm9boot.bin --arm7 arm7boot.bin
```

Replacing the GUI/wifi/gfx modules too (`--arm9gui` / `--arm7gui` / `--guidata`)
additionally needs **`part345enc.py`** (the huffman *encoder*) next to
`iplrepack.py`; it's imported only for that and the dual-mode build never uses
it. With it present, `iplrepack.py` is a full byte-for-byte replacement for the
C `iplrepack` tool.

## Flash it

> ⚠️ **Flash only in normal NEC mode, after a verified backup.** The DS IPL has **no DIP-4 recovery**
> (only the NEC controller firmware does), so a bad DS-IPL flash is unrecoverable without external means.

```sh
python3 -m pynitro.ipl.flash_firmware dualmode_ipl_v7.bin
```

Then set the DIP switches (SW1/6/8 ON) and insert a cart to use alternate mode; flip them back for
normal debugger use.

## Notes

- The built `*.bin` (and your dump) are Nintendo-derived and are `.gitignore`d on purpose — keep them
  local; share only the recipe.
- `build_dualmode_v7.py`'s docstring documents the exact patch bytes, the CRC reasoning, and why the
  correction is arm9-only if you want to audit or port to another firmware build.
