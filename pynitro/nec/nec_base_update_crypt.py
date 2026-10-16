#!/usr/bin/env python3
"""
IS-NITRO NEC base-firmware *update* transport cipher (encrypt/decrypt).

This is the per-byte obfuscation the ISND host updater applies to each firmware
blob (Main Program / LCA1-4 FPGA bitstreams) sent over USB via command 0x0001
to reprogram the box's own NEC controller flash. It is distinct from the DS-IPL
transport cipher in docs/EMULATOR.md (that one is an XorShift PRNG;
this one is a position+key byte cipher).

Key (from captures/InfoUpdateFirmware.txt + Lorenzooone's decompile, cipher.png):

    n = (tick_count & 0x7FFF) ^ (rand() & 0x7FFF)   # sampled once per blob; ISND
                                                    # guarantees n != 0 before
                                                    # calling the cipher (forces
                                                    # n = 0xA5 if the sample is 0).

Per-byte transform at index i (i = position within the slice being transformed):

    byte = (byte + 1) & 0xFF        # ISND stores firmware pre-decremented
    byte = ((i + 0x5A) ^ byte) & 0xFF                # position XOR
    if n & 0x80: byte = (byte + 0xA8) & 0xFF
    if n & 0x40: byte = (byte + 0x89) & 0xFF
    if n & 0x20: byte ^= 0x32
    if n & 0x10: byte = (byte + 0xAE) & 0xFF
    if n & 0x08: byte ^= 0xA5
    if n & 0x04: byte = (byte + 0xBD) & 0xFF
    if n & 0x02: byte ^= 0xEF
    if n & 0x01: byte = (byte + 0x1B) & 0xFF

Three encryption phases, each restarting i at 0 (the index reset is provided by the
caller / builder transforming each slice on its own — these functions always start
at i=0):
    1. the 0x2000 RAM-resident V850 flash routine ("preamble").
    2. the payload = real firmware bytes + a 0x100 trailing tail.
    3. the 4-byte uint32 size field, written over the phase-2 ciphertext at
       payload+0x50. That size is the real-data length WITHOUT the trailing 0x100
       (Main 0x20000, each LCA 0x2C01C) — see InfoUpdateFirmware.txt "Sizes".

The "+1" maps ISND's internal (firmware-1) storage to the real firmware byte.
The byte that ends up in the NEC flash is the post-"+1" value, so when working
from a flash dump (true firmware) you skip the +1 (see `from_flash=`).

Verified against Base_Update.pcapng + a 192 MiB NEC memory dump: the four blobs'
selectors at preamble 0x1FF0 decrypt to 0/1/2/3 (Main/LCA1/LCA2/LCA3) and the
payloads match the flash regions (0x10000/0x30000/0x60000/0x90000) byte-for-byte.
The size field at data 0x50 also matches flash, but ONLY when decoded as its own
phase-3 pass with the index reset to 0: it is encrypted separately and overlaid on
the phase-2 ciphertext, so a single uniform decode of the payload (which hits 0x50
at i=0x50) yields garbage there and falsely looks like a mismatch — decode 0x50..0x53
at i=0 and it resolves to the real size. Bytes 0xFC-0xFF carry the raw key n on the
wire (host metadata); the resident overwrites buffer[0xFC]=0 before programming, so
those are genuinely not expected to equal the flash bytes.
"""
import struct
import sys

# Conditional ops keyed by the bits of n, MSB-first (the encrypt order).
_OPS = [(0x80, '+', 0xA8), (0x40, '+', 0x89), (0x20, '^', 0x32),
        (0x10, '+', 0xAE), (0x08, '^', 0xA5), (0x04, '+', 0xBD),
        (0x02, '^', 0xEF), (0x01, '+', 0x1B)]


def encrypt(data: bytes, n: int, from_flash: bool = True) -> bytes:
    """Firmware blob -> on-the-wire ciphertext. n is the per-blob key byte.
    from_flash=True: input is true firmware bytes (e.g. a flash dump), skip +1.
    from_flash=False: input is ISND's pre-decremented storage, apply +1."""
    n &= 0xFF
    out = bytearray(len(data))
    for i, b in enumerate(data):
        if not from_flash:
            b = (b + 1) & 0xFF
        b = ((i + 0x5A) ^ b) & 0xFF
        for bit, op, k in _OPS:
            if n & bit:
                b = (b + k) & 0xFF if op == '+' else (b ^ k)
        out[i] = b
    return bytes(out)


def decrypt(data: bytes, n: int, to_flash: bool = True) -> bytes:
    """On-the-wire ciphertext -> firmware blob (inverse of encrypt)."""
    n &= 0xFF
    out = bytearray(len(data))
    for i, b in enumerate(data):
        for bit, op, k in reversed(_OPS):
            if n & bit:
                b = (b - k) & 0xFF if op == '+' else (b ^ k)
        b = ((i + 0x5A) ^ b) & 0xFF
        if not to_flash:
            b = (b - 1) & 0xFF
        out[i] = b
    return bytes(out)


# Selector at preamble 0x1FF0 -> NEC flash region base.
REGION_BASE = {0: 0x010000, 1: 0x030000, 2: 0x060000, 3: 0x090000, 4: 0x0C0000,
               5: 0x210000, 6: 0x230000, 7: 0x260000, 8: 0x290000, 9: 0x2C0000,
               10: 0x2F0000}
SELECTOR_NAME = {0: "Main Program", 1: "LCA1 (AGB)", 2: "LCA2 (NTR)",
                 3: "LCA3 (Monitor)", 4: "LCA4", 5: "Main backup", 6: "LCA1 backup",
                 7: "LCA2 backup", 8: "LCA3 backup", 9: "LCA4 backup",
                 10: "Device Information"}


# The host transmits n raw (unencrypted) at this blob offset (= payload off 0xFC),
# in the ISND-written metadata block; the device reads it there before decrypting.
N_OFFSET = 0x20FC


def n_from_blob(blob: bytes) -> int:
    """Read the key n directly from where the host puts it (blob offset 0x20FC)."""
    return blob[N_OFFSET]


def recover_n(blob: bytes) -> int:
    """Brute-force n (no known plaintext needed): the right n makes the selector
    at 0x1FF0 a valid region index AND the preamble decode self-consistent.
    (For a full blob you can just use n_from_blob(); this is the fallback.)"""
    best = None
    for n in range(256):
        sel = decrypt(blob[0x1FF0:0x1FF1], n)[0] if False else _dec_byte(blob[0x1FF0], 0x1FF0, n)
        if sel in REGION_BASE:
            # tie-break: a correct n leaves the 0x2000 preamble mostly zero
            pre = decrypt(blob[:0x2000], n)
            zeros = pre.count(0)
            cand = (zeros, n, sel)
            if best is None or cand > best:
                best = cand
    return best[1] if best else 0


def _dec_byte(b, i, n):
    n &= 0xFF
    for bit, op, k in reversed(_OPS):
        if n & bit:
            b = (b - k) & 0xFF if op == '+' else (b ^ k)
    b = ((i + 0x5A) ^ b) & 0xFF
    return b


def _selftest():
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    # round-trip
    sample = bytes((i * 31 + 7) & 0xFF for i in range(5000))
    for n in (1, 0xBE, 0xFF):
        assert decrypt(encrypt(sample, n), n) == sample, f"round-trip failed n={n}"
    print("[ok] encrypt/decrypt round-trip for several n")
    # real blobs (cached by the analysis) + dump, if present
    dumpp = os.path.join(here, "dump.bin")
    cases = [("main", 0x10000, 0x20000, 0), ("lca1", 0x30000, 0x2C01C, 1),
             ("lca2", 0x60000, 0x2C01C, 2), ("lca3", 0x90000, 0x2C01C, 3)]
    dump = open(dumpp, "rb") if os.path.exists(dumpp) else None
    for name, foff, plen, want in cases:
        bp = f"/tmp/blob_{name}.bin"
        if not os.path.exists(bp):
            print(f"[skip] {bp} not cached"); continue
        blob = open(bp, "rb").read()
        n = recover_n(blob)
        sel = _dec_byte(blob[0x1FF0], 0x1FF0, n)
        line = f"[..] {name}: recovered n=0x{n:02X}, selector={sel} ({SELECTOR_NAME.get(sel)})"
        assert sel == want, f"selector {sel} != {want}"
        if dump:
            dump.seek(foff); P = dump.read(plen)
            dec = decrypt(blob[0x2000:0x2000 + plen], n)
            same = sum(a == b for a, b in zip(dec, P))
            line += f"; payload==flash {same}/{plen} ({100 * same / plen:.1f}%)"
        print(line)
    print("\nSELFTEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_selftest() if "--selftest" in sys.argv or len(sys.argv) == 1 else 0)
