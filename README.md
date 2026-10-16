# PyNitroController

A cross-platform (macOS / Linux / Windows) Python driver and GUI for Intelligent
Systems' Nintendo DS development hardware. It talks to the box **directly over USB via
libusb**, with no official driver required.

- **IS-NITRO-EMULATOR**: device control, NEC register access, DS-IPL firmware dump and
  flash, and updates of the box's own controller flash (Main Program reflash,
  device-info feature flags) done the way the official ISND updater does them. See
  [`docs/EMULATOR.md`](docs/EMULATOR.md).
- **IS-NITRO-CAPTURE**: identify, controller-flash dump, firmware update (byte-identical
  to ISNP v2.15's), and a Video Config editor (offsets, gaps, aspect-ratio fix,
  built-in cursor). See [`docs/CAPTURE.md`](docs/CAPTURE.md).
- **DS-IPL tooling** in pure Python: `iplrepack` (unpack/repack, byte-identical to the
  C tool) and a dual-mode debug-firmware builder. See [`docs/DUALMODE.md`](docs/DUALMODE.md).

Reverse-engineered from USB captures and Gericom's C# implementation; tested on real
hardware.

> ⚠️ **Destructive operations** all need an explicit confirmation; controller-flash
> writes offer a full backup first (the device-info write requires one).
> - **DS-IPL firmware flash**: a bad write leaves the DS non-booting until reflashed.
> - **Main Program** (EMULATOR or CAPTURE): recoverable with the DIP-switch-4 repair,
>   which restores the backup copy. On a CAPTURE that is stock firmware, so custom
>   settings are lost; keep a dump.
> - **EMULATOR device-info block**: no on-chip backup; a bad write needs an external
>   chip programmer. Keep the 4 MB backup.
>
> Everything else is read-only.

## Contents

<details>
<summary>Show files</summary>

| File | What |
|------|------|
| `gui.py` | Launcher: `python3 gui.py` (from the repository root) starts the GUI in `pynitro/gui.py`. |
| `pynitro/isnitro.py` | The driver: the `ISNitro` class (USB transport + all commands) plus a small CLI. Import this to build on top. |
| `pynitro/isnitro_capture.py` | Driver for the **IS-NITRO-CAPTURE** (PID `0x0403`), ported from Lorenzooone's [cc3dsfs](https://github.com/Lorenzooone/cc3dsfs): serial, lid / debug-button state, CPU reset, frame capture (raw 256×384 BGR), a dump of the box's own controller flash (NEC memory read, cmds `0x0D`/`0x0E`), the controller-firmware update (cmd `0x01`, byte-identical to ISNP v2.15's), and read/patch helpers for teod's video settings (offsets, gaps, aspect-ratio fix). CLI: `info`, `dump`, `grab out.ppm`. Flash dump and update tested on hardware; frame capture not yet. |
| `pynitro/gui.py` | A Tkinter GUI that auto-detects the box on Connect (an IS-NITRO-CAPTURE gets Identify, Reset DS, Dump NEC Flash, Extract Main Prog, Update Main Prog, **Video Config** — an editor for teod's video patch with teod's value ranges, plus a 16×16 text editor for the built-in (DIP 3) cursor — and **Dump Video Configs**, which saves every video config in the box's DIP2-on save log as an ISNP `.nvi` file): Connect, identify, NEC registers, counter, flash JEDEC ID, dump firmware, NEC-flash backup, **flash firmware**, **Write Device Info** (tick the device-info feature flags to enable), **Update Main Prog**, **Full NEC Update**, **Extract Main Prog**, **Build DualMode IPL** and **Special Mode Patch** (both offline — no device needed), reset. |
| `pynitro/ipl/dump_firmware.py` | Headless: dump the 256 KB IPL firmware flash, optionally diff against a reference image. |
| `pynitro/nec/dump_nec_flash.py` | Headless: read-only backup of the 4 MB **NEC controller flash** (the box's own firmware: bootloader, Main Program, LCA1-4 FPGA bitstreams + backups, device-info block), via the fast bulk read (`unit_size=4`, ~2 MiB/s — ~5× the old per-byte loop). `--parse` labels an existing image offline. |
| `pynitro/ipl/flash_firmware.py` | Headless: erase + program a DS IPL firmware image (destructive). |
| `pynitro/ipl/iplrepack.py` | Pure-Python **DS IPL firmware** unpacker/repacker: decompress/recompress (LZSS) + decrypt/encrypt (DS KEY1/Blowfish) the ARM9/ARM7 boot code, decode the part3/4/5 huffman GUI modules, fix up the header ROM addresses + CRC16s, and rebuild a flashable 256 KB image. **Byte-for-byte parity** with the C `iplrepack`. Has an `info` / `unpack` / `repack` CLI and an importable API. |
| `pynitro/ipl/part345enc.py` | Optional companion to `iplrepack.py`: the "part345" huffman **encoder**, needed only to *replace* the GUI/wifi/gfx modules (parts 3/4/5) on `repack`. Imported lazily — the dual-mode build and IPL-only repack never need it. |
| `pynitro/ipl/build_dualmode_v7.py` | Build a **dual-mode** IS-NITRO debug DS-IPL: a USB/JTAG debugger in normal NEC mode, and a physical-NDS-cartridge player in DIP alt-mode. Patches the decompressed ARM9/ARM7 IPL and repacks via `iplrepack.py`. Self-contained: the boot stub is pre-assembled, no toolchain needed. Refuses a wrong-version dump up front by checking the firmware-header **build timestamp**. Has a CLI and an importable `build()` (the GUI's *Build DualMode IPL…* button calls it). See `docs/DUALMODE.md`. |
| `pynitro/nec/nec_firmware_update.py` | Build NEC controller-flash **update blobs** (cmd `0x0001`): `build_devinfo_blob_wp()` (rewrite the device-info block — asserts the flash `WP#` override so the locked-down block can be written) and `build_main_blob()` (vanilla Main-Program reflash, identical to ISND). `read_options()` / `set_options()` read and rewrite the device-info options register (`0x3FE080`, the video / RAM / wireless feature flags). Holds the pre-assembled relocation stubs (`STUB_BYTES`, and `WP_STUB_BYTES` which adds the WP# assert). Self-contained — no toolchain needed. |
| `pynitro/nec/altmode_video_patch.py` | Build a patched **Main Program** image that, in DIP **alt-mode**, powers the AGB cart bus and programs the video-out (AV-capture) registers (configurable screen geometry / background / cursor / monitor-state). The patch is **checksum-neutral**: it reproduces the stock Main's XOR-32 integrity word — which ISND reads via cmd `0x18` and compares against its bundled firmware — so ISND can't tell the Main was modified and won't force-reflash it. Pairs with `build_main_blob()` to reflash. |
| `pynitro/nec/nec_base_update_crypt.py` | The per-byte position+key cipher ISND wraps each update blob in (solved/reproduced). |
| `pynitro/nec/nec_flash_routine.bin` | A **verbatim, unmodified** copy of the box's *own* official RAM-resident V850E1 flash routine, pinned by SHA-256 and verified before any blob is built. |
| `pynitro/nec/isnc_flash_routine.bin` | The IS-NITRO-CAPTURE's own official flash routine (as embedded in ISNP v2.15), unmodified apart from a zeroed region selector; pinned by SHA-256. |
| `docs/EMULATOR.md` | The IS-NITRO-EMULATOR: USB protocol and command table, NEC memory and registers, DS-IPL flashing, the controller flash and its update path, ISND's firmware check, DIP switches and alternate mode, open questions. |
| `docs/DUALMODE.md` | The dual-mode DS-IPL firmware: what it patches, why, and how to build + flash it from your own dump. |
| `docs/CAPTURE.md` | The IS-NITRO-CAPTURE: USB protocol and command table, flash layout, firmware update, video output at power-on (built-in settings, DIP switches, saved configs), the `.nvi` format, cursors, open questions. |

</details>

## Setup

Requires Python 3.7+ and pyusb, plus a native **libusb-1.0** backend.

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` includes **`libusb-package`**, a wheel that bundles a
libusb-1.0 binary. `isnitro.py` auto-detects and uses it (falling back to a
system libusb if one is installed), so on **macOS and Linux** the pip install
above is all you need — no `brew`/`apt`.

If you'd rather rely on a system libusb (or `libusb-package` ships no wheel for
your platform), install it the usual way and drop `libusb-package` from
`requirements.txt`:

```sh
#   macOS:   brew install libusb
#   Debian:  sudo apt install libusb-1.0-0
```

**Windows** still needs a **WinUSB/libusb driver bound to the device with
[Zadig](https://zadig.akeo.ie/)** regardless: the bundled binary supplies the
libusb *library*, but libusb can only claim the device once a compatible driver
is attached to it.

### GUI / Tkinter note (macOS)
`gui.py` needs **Tk 8.6+**. macOS's *system* Python (`/usr/bin/python3`) ships the
old Tk 8.5, which doesn't repaint quick updates reliably. Use a Homebrew Python
with a modern Tk:

```sh
brew install python-tk@3.14
/opt/homebrew/bin/python3.14 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

The CLI tools (`pynitro.isnitro`, `pynitro.ipl.dump_firmware`, `pynitro.ipl.flash_firmware`) don't use
Tk and run on any Python 3.7+.

### Device permissions
- **macOS** — vendor devices are accessible to libusb directly; no kext needed.
- **Linux** — udev rule so you don't need root:
  ```
  # /etc/udev/rules.d/99-isnitro.rules
  SUBSYSTEM=="usb", ATTR{idVendor}=="0f6e", ATTR{idProduct}=="0404", MODE="0666"
  SUBSYSTEM=="usb", ATTR{idVendor}=="0f6e", ATTR{idProduct}=="0403", MODE="0666"
  ```
  then `sudo udevadm control --reload && sudo udevadm trigger`.
- **Windows** — use Zadig to bind WinUSB/libusb-win32 to the device.

## Usage

GUI:

```sh
python3 gui.py        # Connect, then pick an operation
```

CLI / library (run from the repository root; the tools are modules of the `pynitro` package):

```sh
python3 -m pynitro.isnitro --version          # print the box identify string
python3 -m pynitro.isnitro --reset            # reset the DS subsystem
python3 -m pynitro.ipl.dump_firmware -o dump.bin -d reference.bin   # dump + diff
python3 -m pynitro.ipl.flash_firmware image.bin   # DESTRUCTIVE: erase + program
python3 -m pynitro.nec.dump_nec_flash -o nec_flash.bin   # EMULATOR controller-flash backup
python3 -m pynitro.isnitro_capture info      # IS-NITRO-CAPTURE: serial, firmware, flash, lid
python3 -m pynitro.isnitro_capture grab frame.ppm --screens both   # save one frame
python3 -m pynitro.isnitro_capture dump isnc_flash.bin   # read-only controller-flash dump
```

DS-IPL firmware tooling (operates on image files, touches no hardware):

```sh
python3 -m pynitro.ipl.iplrepack info   firmware_dump.bin          # header, layout, CRC check
python3 -m pynitro.ipl.iplrepack unpack firmware_dump.bin out/     # header + decompressed modules
python3 -m pynitro.ipl.iplrepack repack base.bin out.bin --arm9 arm9boot.bin   # rebuild (also --arm7/--arm9gui/…)
# Build a dual-mode debug firmware from your own dump (see docs/DUALMODE.md), then flash it:
python3 -m pynitro.ipl.build_dualmode_v7 firmware_dump.bin dualmode_ipl_v7.bin
```

```python
from pynitro.isnitro import ISNitro
n = ISNitro.open()
print(n.version_string())             # e.g. "06125752"
print(n.spi_read_jedec_id().hex())    # flash chip JEDEC ID
data = n.dump_firmware()              # 256 KB
n.close()
```

Building a NEC controller-flash update blob (the GUI does this with a mandatory
backup + confirmation — prefer the GUI for the actual write):

```python
from pynitro.nec.nec_firmware_update import read_options, set_options, build_devinfo_blob_wp
block = open("nec_flash_backup.bin", "rb").read()[0x3FE000:0x400000]  # device-info block
cur = read_options(block)                      # options byte @0x3FE080 (a SET bit = NOT available)
block, info = set_options(block, cur & ~0x02)  # clear bit 1 to enable video-out
print(info)                                    # {'before': 0xF6, 'after': 0xF4, 'changed': True, ...}
blob = build_devinfo_blob_wp(block)            # cmd 0x0001 image (asserts the WP# override)
# ISNitro.send_firmware_update(blob)  <-- DESTRUCTIVE; back up first, power-cycle + re-dump to verify
```

Building an alt-mode AGB+video Main image (checksum-neutral, so ISND leaves it alone):

```python
from pynitro.nec import altmode_video_patch as avp
main = open("main_clean.bin", "rb").read()         # a STOCK 0x20000 Main region image
patched = avp.patch_main(main, {"single_x": 200, "monitor_state": 0x26})
assert avp.region_xor32(patched) == avp.STOCK_MAIN_XOR   # == the XOR ISND expects
# reflash via build_main_blob(patched) -> ISNitro.send_firmware_update(...)
```


## License

PyNitroController is licensed under the **MIT License** (see [`LICENSE`](LICENSE)),
**except** `pynitro/ipl/iplrepack.py` and `pynitro/ipl/part345enc.py`, which port code from Chishm's
**fwunpack** and are therefore licensed under the **GNU General Public License, version
2 or (at your option) any later version** (see [`LICENSE.GPL-2.0`](LICENSE.GPL-2.0)).

`build_dualmode_v7.py` imports `iplrepack.py`, and `gui.py` imports
`build_dualmode_v7.py`, so those two programs, as distributed, also fall under the GPL.
The library and the other tools (`isnitro.py`, `isnitro_capture.py`, `nec_firmware_update.py`,
`nec_base_update_crypt.py`, `dump_nec_flash.py`, `dump_firmware.py`, `flash_firmware.py`, `altmode_video_patch.py`)
don't use the GPL code and can be reused under MIT alone.

The USB driver is a Python reimplementation based on Gericom's `LibISNitroEmulator`
(C#/.NET). `iplrepack.py` also ports DarthNemesis's `CompressionManager.cs` (MIT; its
notice is kept in `iplrepack.py`).

`nec_flash_routine.bin` and `isnc_flash_routine.bin` are not covered by either license:
they are unmodified copies of the boxes' official flash routines.

## Credits

- **Gericom** — for **`LibISNitroEmulator`** (the C# program) and the
  **reverse-engineering of the IS-NITRO-EMULATOR** that this project is a Python
  port of. Full credit for the protocol and the original implementation is his.
- **teod (stickteo)** — for the reverse-engineering of the **IS-NITRO NEC Main-Program
  firmware**: subroutines decompiled to C (the `loadLCA1/2/3` FPGA-bitstream loaders,
  `init_1F018`, the `sendTLCA` keystream cipher) and the NEC hardware-register map, which
  the NEC-side firmware analysis is built on.
- **Lorenzooone** — for the **USB captures** (the DS firmware update *and* the NEC
  controller-firmware "Base Update") and the **ISND decompile** that the wire
  protocol, the firmware-flash analysis, and the controller-update payload cipher
  were reverse-engineered from; and for **cc3dsfs**, whose IS-NITRO-CAPTURE code
  `isnitro_capture.py` is ported from (MIT, notice kept in the file).
- **Garhoogin** — for the **IDA decompile of the debug DS-IPL's ARM9 boot module**
  (`0_arm9.bin.c`), which the dual-mode debug firmware (`build_dualmode_v7.py`) patch
  analysis was reverse-engineered against.
- **teod** — for the **IS-NITRO-CAPTURE video-adjustment patch** for ISNP
  (aspect-ratio-fix removal and video offsets), which the Video Config editor's offsets
  and value ranges are based on.
- **J4m13c** — for pinpointing the **device-info block's physical flash address**
  (`0x3FE000`, vs. the `0x7FE000` NEC-address view) and the **options byte at `0x3FE080`**
  (the Wi-Fi / video-out feature flags), spotted from a dump of a feature-less unit
  whose options byte reads `0xFF`.
- **Chishm** — **fwunpack** (GPLv2), the DS firmware unpacking tool that `iplrepack.py`
  is built on: its LZSS decompressor, DS KEY1/Blowfish, and the part3/4/5 huffman
  decoder are ported from it.
- **DarthNemesis** — the LZSS (de)compressor (`CompressionManager.cs`, MIT) ported for
  `iplrepack.py`'s IPL recompression (it fits the original slots and decodes
  byte-exactly like the DS BIOS).
