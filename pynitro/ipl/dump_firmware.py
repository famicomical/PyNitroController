#!/usr/bin/env python3
"""Dump the IS-NITRO DS IPL firmware flash over USB (read-only), optionally
diffing against a reference image.

    python3 -m pynitro.ipl.dump_firmware -o dump.bin -d /path/FW0B278F.BIN

Read-only: this only issues SPI READ-class opcodes; it never erases or programs.
"""
import argparse
import hashlib
import sys
import time

from ..isnitro import ISNitro, ISNitroError


def group_ranges(offsets):
    """Collapse a sorted list of ints into [start, end] contiguous ranges."""
    ranges = []
    for o in offsets:
        if ranges and o == ranges[-1][1] + 1:
            ranges[-1][1] = o
        else:
            ranges.append([o, o])
    return ranges


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-o", "--out", default="fw_live_dump.bin",
                   help="output file (default: fw_live_dump.bin)")
    ap.add_argument("-d", "--diff", help="reference image to diff against")
    ap.add_argument("--length", type=lambda x: int(x, 0), default=0x40000,
                   help="bytes to read (default: 0x40000)")
    args = ap.parse_args()

    try:
        n = ISNitro.open(timeout_ms=8000)
    except ISNitroError as e:
        print("error:", e)
        return 1
    try:
        print("Box identify:", n.version_string())
        print("JEDEC ID:", n.spi_read_jedec_id().hex())
        t0 = time.time()

        def prog(done, total):
            print("\r  %7d / %d  (%5.1f%%)  %4.0fs" %
                  (done, total, 100 * done / total, time.time() - t0),
                  end="", flush=True)

        data = n.dump_firmware(args.length, chunk=0x2000, progress=prog)
        print()
        with open(args.out, "wb") as f:
            f.write(data)
        print("wrote %d bytes to %s" % (len(data), args.out))
        print("dump md5:", hashlib.md5(data).hexdigest())

        if args.diff:
            ref = open(args.diff, "rb").read()
            print("ref  md5:", hashlib.md5(ref).hexdigest(), "(%s)" % args.diff)
            m = min(len(ref), len(data))
            if len(ref) != len(data):
                print("NOTE size differs: dump=%d ref=%d" % (len(data), len(ref)))
            diffs = [i for i in range(m) if data[i] != ref[i]]
            if not diffs:
                print("IDENTICAL over %d bytes" % m)
            else:
                print("%d differing bytes (%.4f%% of %d):" %
                      (len(diffs), 100 * len(diffs) / m, m))
                for a, b in group_ranges(diffs):
                    if b > a:
                        print("  0x%05X-0x%05X  (%d bytes)" % (a, b, b - a + 1))
                    else:
                        print("  0x%05X          (1 byte)" % a)
    finally:
        n.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
