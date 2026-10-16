#!/usr/bin/env python3
"""
Dump the IS-NITRO's **NEC controller flash** (the box's own firmware) over USB.

READ-ONLY. This tool only issues NEC-memory *reads* (cmd 0x25 setup + 0x17 read,
via isnitro.read_nec_memory). It never writes to the flash, so it cannot brick
the box. Use it to back up the controller firmware before anything else.

The 4 MB flash is memory-mapped at NEC address 0x000000 (chip-select CS0). Its
layout (registers.pdf "NEC Memory Map") -- Main Program + LCA1-4 FPGA bitstreams,
their backups, and the Device Information block:

    0x000000 Bootloader            0x100000 mirror of 0x000000-0x0FFFFF
    0x010000 Main Program          0x210000 Main Program backup
    0x030000 LCA1 (AGB)            0x230000 LCA1 backup
    0x060000 LCA2 (NTR)            0x260000 LCA2 backup
    0x090000 LCA3 (Monitor)        0x290000 LCA3 backup
    0x0C0000 LCA4                  0x2C0000 LCA4 backup
                                   0x2F0000 Device Information

Usage:
    python3 -m pynitro.nec.dump_nec_flash [-o nec_flash.bin] [--start 0] [--length 0x400000] [--chunk 0x8000]
    python3 -m pynitro.nec.dump_nec_flash --parse <existing_dump.bin>     # offline: just parse/label
"""
import argparse
import re
import struct
import sys

FLASH_SIZE = 0x400000          # 4 MiB

# The Device Information block's offset VARIES between units / dump methods:
# a direct 4 MiB flash read has it at 0x3FE000 (last sector); the 192 MiB
# NEC-address-space dump had it at 0x2FE000. find_devinfo() locates it by its
# "INTELLIGENT SYSTEMS" + "IS-NITRO-EMULATOR" signature rather than guessing.
DEVINFO_CANDIDATES = (0x3FE000, 0x2FE000, 0x7FE000)
_SIG_MAKER = b"INTELLIGENT SYSTEMS"
_SIG_MODEL = b"IS-NITRO-"          # "IS-NITRO-EMULATOR" or "IS-NITRO-CAPTURE"

# Register 2.1 @ devinfo+0x80 (registers.pdf §2.2). A SET bit = extension NOT
# available. Bit positions verified against real units (wireless=3, video=1).
FLAG_BITS = [
    (7, "DIMM-1024 RAM extension"),
    (5, "DIMM-512 RAM extension"),
    (3, "Wireless extension"),
    (1, "Video-out extension"),
]
# LCA3 revision byte @ devinfo+0xA0 (signed): -1=(A) -2=(B) -3=(C) -5=(D)
LCA3_REV = {0xFF: "A", 0xFE: "B", 0xFD: "C", 0xFB: "D"}

REGIONS = [
    (0x000000, "Bootloader"),
    (0x010000, "Main Program"),
    (0x030000, "LCA1 (AGB)"),
    (0x060000, "LCA2 (NTR)"),
    (0x090000, "LCA3 (Monitor)"),
    (0x0C0000, "LCA4"),
    (0x0F0000, "(unused)"),
    (0x100000, "mirror of 0x000000-0x0FFFFF"),
    (0x200000, "(unused)"),
    (0x210000, "Main Program backup"),
    (0x230000, "LCA1 backup"),
    (0x260000, "LCA2 backup"),
    (0x290000, "LCA3 backup"),
    (0x2C0000, "LCA4 backup"),
    (0x2F0000, "Device Information"),
    (0x300000, "(undocumented / mirror)"),
]


def _ascii(b):
    return "".join(chr(x) if 0x20 <= x < 0x7F else "" for x in b)


def find_devinfo(data):
    """Locate the Device Information block by its maker+model signature.
    Returns its offset, or None. Distinct from the per-region headers (which
    start with the maker string but lack 'IS-NITRO-' at +0x20)."""
    for off in DEVINFO_CANDIDATES:           # fast path: known locations
        if off + 0x100 <= len(data) and \
           data[off:off + len(_SIG_MAKER)] == _SIG_MAKER and \
           data[off + 0x20:off + 0x20 + len(_SIG_MODEL)] == _SIG_MODEL:
            return off
    i = 0                                     # fallback: scan
    while True:
        j = data.find(_SIG_MAKER, i)
        if j < 0:
            return None
        if data[j + 0x20:j + 0x20 + len(_SIG_MODEL)] == _SIG_MODEL:
            return j
        i = j + 1


def report_devinfo(data, di, log=print, base_addr=None):
    """Log the Device Information fields (maker / model / serial / LCA3 rev /
    options flags) from `data`, whose devinfo signature starts at offset `di`.

    `base_addr` is the absolute flash address of that signature, used only to
    print the options register address; it defaults to `di` (correct for a full
    flash image, where the offset *is* the address). The GUI passes the live
    devinfo-block address since it reads just that block (di within it is 0).
    Shared by parse_dump and the GUI's Identify report."""
    if base_addr is None:
        base_addr = di
    serial = _ascii(data[di + 0x40:di + 0x48])
    flags = data[di + 0x80]
    lca3rev = data[di + 0xA0]
    log(f"  maker  : {_ascii(data[di:di + 0x20])!r}")
    log(f"  model  : {_ascii(data[di + 0x20:di + 0x40])!r}")
    log(f"  serial : {serial!r}")
    log(f"  LCA3 rev (0xA0): 0x{lca3rev:02X} ({LCA3_REV.get(lca3rev, '?')})")
    log(f"  options (0x{base_addr + 0x80:06X}) = 0x{flags:02X}  [bit set = NOT available]")
    for bit, name in FLAG_BITS:
        avail = not ((flags >> bit) & 1)
        log(f"     bit{bit} {name:24} {'ENABLED' if avail else 'not present'}")


# Embedded build stamp inside a Main Program region, e.g.
# " Version 3.52 2009/11/17 14:18 ". Sits in the region's string table at a
# build-dependent offset, so it's found by scanning rather than a fixed offset.
_BUILD_RE = re.compile(rb" Version (\d+\.\d+) (\d{4}/\d{2}/\d{2} \d{2}:\d{2}) ")


def parse_main_header(region):
    """Parse a Main Program region image (header at offset 0). Returns a dict
    {version, type, version_str} or None if the 'INTELLIGENT SYSTEMS' /
    'Main Program' header isn't present.

    The version is a u16 at +0x40 (e.g. 0x0160 -> "3.52"); +0x44 is the type."""
    if (len(region) < 0x46 or region[:len(_SIG_MAKER)] != _SIG_MAKER
            or region[0x20:0x2C] != b"Main Program"):
        return None
    ver = struct.unpack_from("<H", region, 0x40)[0]
    typ = struct.unpack_from("<H", region, 0x44)[0]
    return {"version": ver, "type": typ,
            "version_str": "%d.%02d" % (ver // 100, ver % 100)}


def find_build_string(region):
    """Return the embedded ' Version X.XX YYYY/MM/DD HH:MM ' build stamp text
    (stripped) from a Main Program region image, or None if not found."""
    m = _BUILD_RE.search(region)
    return m.group(0).strip().decode() if m else None


def parse_dump(data, log=print):
    """Report Device Information + a region summary (works on any >=3 MB image).
    `log` is any callable taking one string (defaults to print; the GUI passes
    its own logger)."""
    n = len(data)
    log(f"image size: 0x{n:X} ({n/1024/1024:.2f} MiB)")
    di = find_devinfo(data)
    if di is None:
        log("Device Information: not found (no INTELLIGENT SYSTEMS / IS-NITRO-EMULATOR signature)")
    else:
        log(f"Device Information @ 0x{di:06X}:")
        report_devinfo(data, di, log=log)
    log("Region map (first bytes / blank?):")
    for base, name in REGIONS:
        if base + 16 > n:
            continue
        head = data[base:base + 16]
        blank = all(x == 0xFF for x in head) or all(x == 0 for x in head)
        tag = _ascii(head[:12])
        log(f"  0x{base:06X} {name:28} {head[:8].hex()}"
            f"{'  [blank]' if blank else ''}"
            f"{('  ' + tag) if tag.strip() else ''}")


def read_flash(nec, start=0x0, length=FLASH_SIZE, unit_size=4, count=0x800,
               progress=None):
    """Read `length` bytes of NEC flash from `start` via an already-open ISNitro.
    READ-ONLY. Per-block 0x25/0x17 reads of `unit_size * count` bytes (default
    0x2000). The speed comes from unit_size=4 (~5x the old us=1 loop, ~2 MiB/s),
    staying within the 0x2000-per-read cap that's safe across units.
    `progress(done, total)` is optional. Returns bytes."""
    return nec.read_nec_memory_fast(start, length, unit_size=unit_size,
                                    count=count, progress=progress)


def dump_device(out_path, start, length, unit_size=4, count=0x800):
    from ..isnitro import ISNitro
    with ISNitro.open() as nec:
        print(f"connected: {nec.version_string()}")
        print(f"reading 0x{length:X} bytes from NEC 0x{start:06X} "
              f"(unit_size {unit_size}, count 0x{count:X} -> "
              f"0x{unit_size * count:X} B/read)")

        def prog(done, total):
            print(f"\r  read 0x{done:06X}/0x{total:06X} ({100*done/total:5.1f}%)",
                  end="", flush=True)

        data = read_flash(nec, start, length, unit_size=unit_size,
                          count=count, progress=prog)
        print()
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"wrote {out_path} (0x{len(data):X} bytes)")
    parse_dump(data)


def main(argv):
    ap = argparse.ArgumentParser(description="Dump the IS-NITRO NEC controller flash (read-only).")
    ap.add_argument("-o", "--out", default="nec_flash.bin")
    ap.add_argument("--start", type=lambda s: int(s, 0), default=0x0)
    ap.add_argument("--length", type=lambda s: int(s, 0), default=FLASH_SIZE)
    ap.add_argument("--unit-size", type=lambda s: int(s, 0), default=4,
                    help="bytes per unit (1/2/4; 4 = default, fastest. >4 corrupts)")
    ap.add_argument("--count", type=lambda s: int(s, 0), default=0x800,
                    help="units per 0x17 read (max 0xFFFF); bytes/read = unit_size*count "
                         "(default 0x2000; reads >0x2000 can artifact on some units)")
    ap.add_argument("--parse", metavar="FILE", help="offline: parse/label an existing dump and exit")
    args = ap.parse_args(argv[1:])

    if args.parse:
        parse_dump(open(args.parse, "rb").read())
        return 0
    dump_device(args.out, args.start, args.length, args.unit_size, args.count)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
