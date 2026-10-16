#!/usr/bin/env python3
"""iplrepack.py - Nintendo DS IPL firmware unpacker / repacker, pure Python.

A self-contained Python port of the `iplrepack` C tool (companion to Chishm's
fwunpack). Where fwunpack only *extracts* the modules of a DS firmware image,
this can also *rebuild* one: it recompresses (LZSS type 0x10) and re-encrypts
(DS KEY1 / Blowfish) the ARM9 + ARM7 boot code ("the IPL"), fixes up the
firmware-header ROM addresses and CRC16/MODBUS, and writes a flashable image.

Layering of a DS firmware (GBATEK "DS Firmware Header"):
  part1  ARM9 boot code   LZ77 (type 0x10) + KEY1-encrypted   <- "IPL"
  part2  ARM7 boot code   LZ77 (type 0x10) + KEY1-encrypted   <- "IPL"
  part3  ARM9 GUI code    "part345" huffman
  part4  ARM7 wifi code   "part345" huffman
  part5  GUI data/gfx     "part345" huffman

Parts 1/2 we own end-to-end (decompress + recompress + encrypt + CRC). Parts
3/4/5 use an undocumented huffman variant ("part345"): the DECODER is here, and
repack can also swap them in via the optional companion module `part345enc.py`
(the huffman ENCODER), which is imported lazily only when a GUI part is being
replaced — unpacking and IPL-only repack never need it. Any module not replaced
is carried over verbatim, and the whole code region is re-laid-out tightly so a
grown module has room.

Public API
  load_keydata()                          -> bytes (the 0x1048-byte KEY1 table)
  crc16_modbus(data, init=0xFFFF)         -> int
  decode_layout(fw)                       -> Layout
  unpack(fw)                              -> dict(header, arm9boot, arm7boot,
                                                  arm9gui, arm7gui, gui_data, layout)
  part345_decompress(fw, off)             -> (data, blob_len)
  repack(base_fw, arm9=None, arm7=None,
         arm9gui=None, arm7gui=None, guidata=None) -> bytes (a fresh image)
         (replacing arm9gui/arm7gui/guidata also requires part345enc.py)

CLI
  python -m pynitro.ipl.iplrepack info   <firmware.bin>
  python -m pynitro.ipl.iplrepack unpack <firmware.bin> <outdir>
  python -m pynitro.ipl.iplrepack repack <base.bin> <out.bin> [--arm9 f] [--arm7 f]
                                 [--arm9gui f] [--arm7gui f] [--guidata f]

Ported from the fwunpack sources (Copyright 2007 Michael Chisholm, GPLv2 or
later) and DarthNemesis's CompressionManager.cs (MIT); offered under
GPL-2.0-or-later (text in LICENSE.GPL-2.0). The rest of the project is MIT.
"""
import base64
import os
import struct
import sys

# ---------------------------------------------------------------------------
# Firmware-header field offsets (GBATEK), and constants.
# ---------------------------------------------------------------------------
OFF_PART3_ROMADDR = 0x00
OFF_PART4_ROMADDR = 0x02
OFF_PART34_CRC16  = 0x04
OFF_PART12_CRC16  = 0x06
OFF_FW_IDENTIFIER = 0x08
OFF_PART1_ROMADDR = 0x0C
OFF_PART1_RAMADDR = 0x0E
OFF_PART2_ROMADDR = 0x10
OFF_PART2_RAMADDR = 0x12
OFF_SHIFT_AMOUNTS = 0x14
OFF_PART5_ROMADDR = 0x16
OFF_PART5_CRC16   = 0x26

FW_HEADER_SIZE    = 0x200
WIFI_REGION_START = 0x3FA00   # wifi access points / user settings begin here
KEYCODE_LEVEL     = 2
KEYCODE_MODULO    = 0x0C      # init_keycode level 2, modulo 0x0C (as in fwunpack)

# ---------------------------------------------------------------------------
# KEY1 Blowfish key table (0x1048 bytes), base64-embedded so this file stands
# alone. Identical to fwunpack's keydata[] (sha256 bedd20bd...8a34f08e).
# ---------------------------------------------------------------------------
_KEYDATA_B64 = """
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
58QYX631GQ==
"""


def load_keydata():
    """Return the 0x1048-byte KEY1 Blowfish key table."""
    data = base64.b64decode("".join(_KEYDATA_B64.split()))
    if len(data) != 0x1048:
        raise ValueError("keydata is %d bytes, expected 0x1048" % len(data))
    return data


# ---------------------------------------------------------------------------
# CRC-16/MODBUS (poly 0xA001, init 0xFFFF) - matches the firmware header CRCs.
# ---------------------------------------------------------------------------
_CRC16_TBL = []
for _b in range(256):
    _c = _b
    for _ in range(8):
        _c = (_c >> 1) ^ 0xA001 if (_c & 1) else _c >> 1
    _CRC16_TBL.append(_c)


def crc16_modbus(data, init=0xFFFF):
    c = init
    for b in data:
        c = (c >> 8) ^ _CRC16_TBL[(c ^ b) & 0xFF]
    return c & 0xFFFF


# ---------------------------------------------------------------------------
# DS KEY1 / Blowfish (port of fwunpack's encryption.cpp + keydata.cpp).
# ---------------------------------------------------------------------------
M32 = 0xFFFFFFFF


def _bswap32(v):
    return ((v & 0xFF) << 24 | (v >> 8 & 0xFF) << 16
            | (v >> 16 & 0xFF) << 8 | (v >> 24 & 0xFF)) & M32


class Key1:
    """The DS KEY1 (Blowfish-derived) cipher, keyed by a firmware id-code."""

    def __init__(self, idcode, level=KEYCODE_LEVEL, modulo=KEYCODE_MODULO):
        kd = load_keydata()
        # keybuf[]: 0x412 little-endian u32 words.
        self.keybuf = list(struct.unpack("<%dI" % (len(kd) // 4), kd))
        self.keycode = bytearray(12)
        self._init_keycode(idcode & M32, level, modulo)

    # crypt_64bit_up / _down operate on an 8-byte slice of `buf` at `off`.
    def crypt_up(self, buf, off):
        kb = self.keybuf
        x = struct.unpack_from("<I", buf, off + 4)[0]
        y = struct.unpack_from("<I", buf, off)[0]
        for i in range(0x10):
            z = kb[i] ^ x
            x = kb[0x012 + (z >> 24 & 0xFF)]
            x = (kb[0x112 + (z >> 16 & 0xFF)] + x) & M32
            x = kb[0x212 + (z >> 8 & 0xFF)] ^ x
            x = (kb[0x312 + (z & 0xFF)] + x) & M32
            x = y ^ x
            y = z
        struct.pack_into("<II", buf, off, (x ^ kb[0x10]) & M32, (y ^ kb[0x11]) & M32)

    def crypt_down(self, buf, off):
        kb = self.keybuf
        x = struct.unpack_from("<I", buf, off + 4)[0]
        y = struct.unpack_from("<I", buf, off)[0]
        for i in range(0x11, 0x01, -1):
            z = kb[i] ^ x
            x = kb[0x012 + (z >> 24 & 0xFF)]
            x = (kb[0x112 + (z >> 16 & 0xFF)] + x) & M32
            x = kb[0x212 + (z >> 8 & 0xFF)] ^ x
            x = (kb[0x312 + (z & 0xFF)] + x) & M32
            x = y ^ x
            y = z
        struct.pack_into("<II", buf, off, (x ^ kb[0x01]) & M32, (y ^ kb[0x00]) & M32)

    def _apply_keycode(self, modulo):
        kc = self.keycode
        self.crypt_up(kc, 4)
        self.crypt_up(kc, 0)
        scratch = bytearray(8)
        for i in range(0x12):
            word = struct.unpack_from("<I", kc, (i * 4) % modulo)[0]
            self.keybuf[i] ^= _bswap32(word)
        for i in range(0, 0x412, 2):
            self.crypt_up(scratch, 0)
            self.keybuf[i] = struct.unpack_from("<I", scratch, 4)[0]
            self.keybuf[i + 1] = struct.unpack_from("<I", scratch, 0)[0]

    def _init_keycode(self, idcode, level, modulo):
        kc = self.keycode
        struct.pack_into("<III", kc, 0, idcode, idcode // 2, (idcode * 2) & M32)
        if level >= 1:
            self._apply_keycode(modulo)
        if level >= 2:
            self._apply_keycode(modulo)
        k1 = (struct.unpack_from("<I", kc, 4)[0] * 2) & M32
        k2 = struct.unpack_from("<I", kc, 8)[0] // 2
        struct.pack_into("<II", kc, 4, k1, k2)
        if level >= 3:
            self._apply_keycode(modulo)


# ---------------------------------------------------------------------------
# Decrypt + LZ77-decompress an IPL part (parts 1/2). Mirrors fwunpack: the part
# is read as a stream of KEY1-decrypted 8-byte blocks, and the LZ77 stream (a
# standard DS BIOS type-0x10 block) is unwound from it.
# ---------------------------------------------------------------------------
class _DecryptReader:
    def __init__(self, key1, src, start):
        self.key1 = key1
        self.src = src
        self.ptr = start
        self.buf = bytearray(src[start:start + 8])
        self.key1.crypt_down(self.buf, 0)
        self.pos = 0

    def get_u8(self):
        if self.pos > 7:
            self.pos = 0
            self.ptr += 8
            self.buf = bytearray(self.src[self.ptr:self.ptr + 8])
            self.key1.crypt_down(self.buf, 0)
        b = self.buf[self.pos]
        self.pos += 1
        return b


def decrypt_decompress(key1, fw, rom_off):
    """Decrypt + LZ77-decompress the IPL part at `rom_off`. Returns raw bytes."""
    r = _DecryptReader(key1, fw, rom_off)
    typ = (r.get_u8() & 0xF0) >> 4
    size = r.get_u8() | (r.get_u8() << 8) | (r.get_u8() << 16)
    if typ != 1:
        raise ValueError("unsupported compression type %d in IPL part" % typ)

    out = bytearray()
    while len(out) < size:
        flags = r.get_u8()
        for bit in range(8):
            if len(out) >= size:
                break
            if flags & (0x80 >> bit):
                b0 = r.get_u8()
                b1 = r.get_u8()
                length = (b0 >> 4) + 3
                disp = ((b0 & 0x0F) << 8 | b1) + 1
                base = len(out) - disp
                for k in range(length):
                    out.append(out[base + k])
                    if len(out) >= size:
                        break
            else:
                out.append(r.get_u8())
    return bytes(out)


# ---------------------------------------------------------------------------
# DarthNemesis LZSS (type 0x10) - ported from CompressionManager.cs. Compresses
# about as well as Nintendo's encoder (so recompressed parts fit), and decodes
# byte-exactly like the DS BIOS. Used to (re)compress parts 1/2.
# ---------------------------------------------------------------------------
#
# CompressionManager.cs: Copyright (c) 2010 DarthNemesis. MIT License:
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ---------------------------------------------------------------------------
_LZ_WINDOW = 4096
_LZ_MIN_MATCH = 3
_LZ_MAX_MATCH = 18
_LZ_MIN_DIST = 2


def dn_compress_lzss(data):
    n = len(data)
    out = bytearray([0x10, n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF])
    pos = 0
    while pos < n:
        flag_pos = len(out)
        out.append(0)
        flag = 0
        for b in range(8):
            if pos >= n:
                break
            maxlen = min(n - pos, _LZ_MAX_MATCH)
            wstart = max(0, pos - _LZ_WINDOW)
            best_len, best_pos = 0, -1
            slast = pos - _LZ_MIN_DIST
            for s in range(wstart, slast + 1):
                if best_len < maxlen and data[s + best_len] != data[pos + best_len]:
                    continue                       # quick reject
                l = 0
                while l < maxlen and data[s + l] == data[pos + l]:
                    l += 1
                if l > best_len:
                    best_len, best_pos = l, s
            if best_len >= _LZ_MIN_MATCH:
                flag |= (0x80 >> b)
                off = (pos - best_pos) - 1          # 1..4095
                lenf = best_len - _LZ_MIN_MATCH     # 0..15
                out.append((lenf << 4) | ((off >> 8) & 0x0F))
                out.append(off & 0xFF)
                pos += best_len
            else:
                out.append(data[pos])
                pos += 1
        out[flag_pos] = flag
    return bytes(out)


def dn_decompress_lzss(comp, out_cap):
    if len(comp) < 4 or comp[0] != 0x10:
        return None
    size = comp[1] | (comp[2] << 8) | (comp[3] << 16)
    if size > out_cap:
        return None
    out = bytearray()
    cp = 4
    while len(out) < size and cp < len(comp):
        forward = 1
        flags = comp[cp]
        for i in range(8):
            if cp + forward >= len(comp) or len(out) >= size:
                break
            if (flags >> (7 - i)) & 1:
                length = _LZ_MIN_MATCH + ((comp[cp + forward] >> 4) & 0xF)
                copy_from = 1 + ((comp[cp + forward] & 0xF) << 8) + comp[cp + forward + 1]
                copy_pos = len(out) - copy_from
                for u in range(length):
                    src = copy_pos + (u % copy_from)
                    if src < 0 or src >= len(out):
                        return bytes(out)           # malformed
                    out.append(out[src])
                    if len(out) >= size:
                        break
                forward += 2
            else:
                out.append(comp[cp + forward])
                forward += 1
        cp += forward
    out.extend(b"\x00" * (size - len(out)))
    return bytes(out)


def compress_encrypt(key1, raw):
    """LZSS-compress + KEY1-encrypt an IPL part. Self-checks the LZSS round-trips
    before encrypting, so a corrupt stream is never produced. Returns bytes
    whose length is a multiple of 8 (the Blowfish block size)."""
    comp = bytearray(dn_compress_lzss(raw))
    chk = dn_decompress_lzss(comp, len(raw))
    if chk != raw:
        raise RuntimeError("LZSS self-check failed - refusing to emit corrupt IPL")
    while len(comp) % 8:
        comp.append(0)
    for i in range(0, len(comp), 8):
        key1.crypt_up(comp, i)
    return bytes(comp)


# ---------------------------------------------------------------------------
# part345 huffman decoder (port of fwunpack's part345_comp.cpp). Decodes parts
# 3/4/5; we use it both to recover the decompressed data (for the part3/4 and
# part5 header CRCs) and to measure each blob's exact in-ROM length so repack can
# pack the parts tightly. The matching ENCODER lives in the optional companion
# module part345enc.py (imported lazily, only when replacing a GUI part).
# ---------------------------------------------------------------------------
class _BitStreamBE:
    def __init__(self, data, start):
        self.data = data
        self.addr = start
        self.shift = 0
        self.bits = 0

    def _u32be(self):
        a = self.addr
        d = self.data
        v = (d[a] << 24) | (d[a + 1] << 16) | (d[a + 2] << 8) | d[a + 3]
        self.addr += 4
        return v & M32

    def get_bit(self):
        bit = (self.bits >> 31) & 1
        if self.shift == 31:
            self.bits = self._u32be()
            self.shift = 0
        else:
            self.bits = (self.bits << 1) & M32
            self.shift += 1
        return bit

    def get_bits(self, num):
        retval = (self.bits >> (32 - num)) & M32
        if self.shift + num == 32:
            self.bits = self._u32be()
            self.shift = 0
        elif self.shift + num < 32:
            self.bits = (self.bits << num) & M32
            self.shift += num
        else:                                       # 32 < shift+num < 64
            temp = self._u32be()
            retval |= temp >> (64 - (self.shift + num))
            self.shift += (num - 32)
            self.bits = (temp << self.shift) & M32
        return retval & M32


def _build_tree(bs, dat1, sym_bits):
    """Build one part345 huffman tree from `bs`; returns (leaf, inner, root)."""
    shape = []                       # the data_table_0 stack
    leaf = {}                        # data_table_1 / _3: node -> child node
    inner = {}                       # data_table_2 / _4: node -> child node
    data = dat1
    loop = True
    while loop:
        while bs.get_bit() != 0:
            shape.append(data | 0x8000)
            shape.append(data | 0x4000)
            data = (data + 1) & 0xFFFF
        bits = bs.get_bits(sym_bits)
        while True:
            temp = shape.pop()
            if (temp & 0x8000) == 0:
                leaf[temp & 0x3FFF] = bits & 0xFFFF
                break
            inner[temp & 0x3FFF] = bits & 0xFFFF
            bits = temp & 0x3FFF
            if not shape:
                loop = False
                break
    return leaf, inner, bits


def part345_decompress(fw, rom_off):
    """Decompress the part345 blob at `rom_off`. Returns (data, blob_len) where
    blob_len is the exact number of in-ROM bytes the two bitstreams consumed."""
    size = ((fw[rom_off + 4] << 24) | (fw[rom_off + 5] << 16)
            | (fw[rom_off + 6] << 8) | fw[rom_off + 7]) & 0x00FFFFFF
    offset = ((fw[rom_off + 8] << 24) | (fw[rom_off + 9] << 16)
              | (fw[rom_off + 10] << 8) | fw[rom_off + 11]) & M32

    bs0 = _BitStreamBE(fw, rom_off + 12)
    bs1 = _BitStreamBE(fw, rom_off + offset)
    bs0.get_bits(0x20)
    bs1.get_bits(0x20)

    leaf0, inner0, root0 = _build_tree(bs0, 0x200, 9)
    leaf1, inner1, root1 = _build_tree(bs1, 0x800, 11)

    out = bytearray()
    remaining = size
    while remaining > 0:
        node = root0
        while node >= 0x200:
            node = leaf0[node] if bs0.get_bit() == 0 else inner0[node]
        if node < 0x100:
            out.append(node)
            remaining -= 1
        else:
            dnode = root1
            while dnode >= 0x800:
                dnode = leaf1[dnode] if bs1.get_bit() == 0 else inner1[dnode]
            copy_length = node - 253
            src = len(out) - dnode - 1
            remaining -= copy_length
            for _ in range(copy_length):
                out.append(out[src])
                src += 1

    blob_len = max(bs0.addr, bs1.addr) - rom_off
    return bytes(out), blob_len


def _deflate345_checked(data, what):
    """Compress a replacement part345 (huffman) module, then self-check it
    against the decoder before it is written (matches the C tool's
    part345_deflate_checked). The encoder lives in the optional companion module
    `part345enc.py` and is imported lazily, so unpack / IPL-only repack never
    need it."""
    try:
        from .part345enc import part345_compress
    except ImportError:
        raise RuntimeError(
            "replacing a GUI part (arm9gui/arm7gui/gui_data) needs part345enc.py "
            "next to iplrepack.py; only the ARM9/ARM7 IPL parts can be rebuilt "
            "without it")
    blob = part345_compress(data)
    dec, _ = part345_decompress(blob + b"\x00" * 8, 0)  # pad for the word prefetch
    if dec != data:
        raise RuntimeError("part345 self-check failed for %s" % what)
    return blob


# ---------------------------------------------------------------------------
# Firmware-header layout (GBATEK).
# ---------------------------------------------------------------------------
class Layout:
    __slots__ = ("idcode", "shift_amounts", "shift1", "shift2", "shift3",
                 "shift4", "chipsize_128k", "part1_rom", "part1_ram",
                 "part2_rom", "part2_ram", "part3_rom", "part4_rom",
                 "part5_rom", "part12_crc16", "part34_crc16", "part5_crc16")


def _rd16(p, off):
    return p[off] | (p[off + 1] << 8)


def _rd32(p, off):
    return p[off] | (p[off + 1] << 8) | (p[off + 2] << 16) | (p[off + 3] << 24)


def decode_layout(fw):
    L = Layout()
    L.idcode = _rd32(fw, OFF_FW_IDENTIFIER)
    sh = _rd16(fw, OFF_SHIFT_AMOUNTS)
    L.shift_amounts = sh
    L.shift1 = sh & 7
    L.shift2 = (sh >> 3) & 7
    L.shift3 = (sh >> 6) & 7
    L.shift4 = (sh >> 9) & 7
    L.chipsize_128k = (sh >> 12) & 0xF

    L.part1_rom = _rd16(fw, OFF_PART1_ROMADDR) * (4 << L.shift1)
    L.part2_rom = _rd16(fw, OFF_PART2_ROMADDR) * (4 << L.shift3)
    L.part3_rom = _rd16(fw, OFF_PART3_ROMADDR) * 8
    L.part4_rom = _rd16(fw, OFF_PART4_ROMADDR) * 8
    L.part5_rom = _rd16(fw, OFF_PART5_ROMADDR) * 8

    L.part1_ram = 0x02800000 - _rd16(fw, OFF_PART1_RAMADDR) * (4 << L.shift2)
    base2 = 0x02800000 if (sh & 0x1000) else 0x03810000
    L.part2_ram = base2 - _rd16(fw, OFF_PART2_RAMADDR) * (4 << L.shift4)

    L.part12_crc16 = _rd16(fw, OFF_PART12_CRC16)
    L.part34_crc16 = _rd16(fw, OFF_PART34_CRC16)
    L.part5_crc16 = _rd16(fw, OFF_PART5_CRC16)
    return L


# ---------------------------------------------------------------------------
# unpack / repack
# ---------------------------------------------------------------------------
def unpack(fw):
    """Decode a firmware image into its modules. Returns a dict with the raw
    256-byte header, the decompressed arm9boot/arm7boot/arm9gui/arm7gui/gui_data,
    and the decoded Layout."""
    fw = bytes(fw)
    L = decode_layout(fw)
    key1 = Key1(L.idcode)
    a9 = decrypt_decompress(key1, fw, L.part1_rom)
    a7 = decrypt_decompress(key1, fw, L.part2_rom)
    g9, _ = part345_decompress(fw, L.part3_rom)
    g7, _ = part345_decompress(fw, L.part4_rom)
    gd, _ = part345_decompress(fw, L.part5_rom)
    return {
        "header": fw[:FW_HEADER_SIZE],
        "arm9boot": a9,
        "arm7boot": a7,
        "arm9gui": g9,
        "arm7gui": g7,
        "gui_data": gd,
        "layout": L,
    }


def _align_up(v, a):
    return (v + (a - 1)) & ~(a - 1)


def _wr16(buf, off, v):
    buf[off] = v & 0xFF
    buf[off + 1] = (v >> 8) & 0xFF


def repack(base_fw, arm9=None, arm7=None, arm9gui=None, arm7gui=None, guidata=None):
    """Rebuild a firmware image from `base_fw`, optionally swapping in fresh
    (decompressed) modules: arm9boot/arm7boot (LZSS+KEY1) and/or the huffman
    arm9gui/arm7gui/gui_data. Any module not given is carried over verbatim from
    `base_fw`; the wifi/user region is always inherited. The code region is
    re-laid-out tightly so a grown module has room. Returns a new bytes image the
    same length as `base_fw`; all ROM-address fields and the three header CRC16s
    are recomputed."""
    base_fw = bytes(base_fw)
    fw = bytearray(base_fw)
    L = decode_layout(base_fw)
    key1 = Key1(L.idcode)

    a9 = bytes(arm9) if arm9 is not None else decrypt_decompress(key1, base_fw, L.part1_rom)
    a7 = bytes(arm7) if arm7 is not None else decrypt_decompress(key1, base_fw, L.part2_rom)

    e9 = compress_encrypt(key1, a9)
    e7 = compress_encrypt(key1, a7)

    # Parts 3/4/5: for each part, either deflate a replacement (self-checked) or
    # carry the base blob over verbatim. We always recover the decompressed data
    # so the part3/4 and part5 header CRC16s can be recomputed. Snapshot the
    # base blobs before we start overwriting the buffer.
    def part345(rom, repl, what):
        if repl is not None:
            d = bytes(repl)
            blob = _deflate345_checked(d, what)
        else:
            d, n = part345_decompress(base_fw, rom)
            blob = base_fw[rom:rom + n]
        return d, blob, len(blob)

    d3, b3, len3 = part345(L.part3_rom, arm9gui, "arm9gui")
    d4, b4, len4 = part345(L.part4_rom, arm7gui, "arm7gui")
    d5, b5, len5 = part345(L.part5_rom, guidata, "gui_data")

    # Tight ROM-order layout: part1 fixed at its slot, every later part packed
    # right after the previous one (on its address granularity).
    p2_align = 4 << L.shift3
    p1 = L.part1_rom
    p2 = _align_up(p1 + len(e9), p2_align)
    p3 = _align_up(p2 + len(e7), 8)
    p4 = _align_up(p3 + len3, 8)
    p5 = _align_up(p4 + len4, 8)
    end = p5 + len5
    if end > WIFI_REGION_START:
        raise RuntimeError(
            "code region overflows: parts 1..5 end at 0x%06X but the wifi/user "
            "region starts at 0x%06X (over by 0x%X bytes)"
            % (end, WIFI_REGION_START, end - WIFI_REGION_START))

    fw[p1:p1 + len(e9)] = e9
    fw[p2:p2 + len(e7)] = e7
    fw[p3:p3 + len3] = b3
    fw[p4:p4 + len4] = b4
    fw[p5:p5 + len5] = b5
    if end < WIFI_REGION_START:                     # blank the reclaimed tail
        for i in range(end, WIFI_REGION_START):
            fw[i] = 0xFF

    _wr16(fw, OFF_PART2_ROMADDR, p2 // p2_align)
    _wr16(fw, OFF_PART3_ROMADDR, p3 // 8)
    _wr16(fw, OFF_PART4_ROMADDR, p4 // 8)
    _wr16(fw, OFF_PART5_ROMADDR, p5 // 8)

    _wr16(fw, OFF_PART12_CRC16, crc16_modbus(a9 + a7))
    _wr16(fw, OFF_PART34_CRC16, crc16_modbus(d3 + d4))
    _wr16(fw, OFF_PART5_CRC16, crc16_modbus(d5))
    return bytes(fw)


# ---------------------------------------------------------------------------
# CLI (parity with the C tool's info / unpack / repack --arm9/--arm7)
# ---------------------------------------------------------------------------
def _cmd_info(path):
    fw = open(path, "rb").read()
    L = decode_layout(fw)
    ident = fw[OFF_FW_IDENTIFIER:OFF_FW_IDENTIFIER + 4].decode("latin1")
    print("Firmware: %s" % path)
    print("  size           0x%06X (%d KiB)" % (len(fw), len(fw) // 1024))
    print('  identifier     "%s" (0x%08X)' % (ident, L.idcode))
    print("  shifts         s1=%d s2=%d s3=%d s4=%d (raw 0x%04X)"
          % (L.shift1, L.shift2, L.shift3, L.shift4, L.shift_amounts))
    print("  part1 ARM9boot rom 0x%06X -> ram 0x%08X  [LZ77+KEY1]" % (L.part1_rom, L.part1_ram))
    print("  part2 ARM7boot rom 0x%06X -> ram 0x%08X  [LZ77+KEY1]" % (L.part2_rom, L.part2_ram))
    print("  part3 ARM9gui  rom 0x%06X                [huffman]" % L.part3_rom)
    print("  part4 ARM7wifi rom 0x%06X                [huffman]" % L.part4_rom)
    print("  part5 gfx/data rom 0x%06X                [huffman]" % L.part5_rom)
    info = unpack(fw)
    crc = crc16_modbus(info["arm9boot"] + info["arm7boot"])
    print("  ARM9boot decompressed 0x%X bytes, ARM7boot 0x%X bytes"
          % (len(info["arm9boot"]), len(info["arm7boot"])))
    print("  part1/2 CRC16  header 0x%04X  recomputed 0x%04X  ->  %s"
          % (L.part12_crc16, crc, "MATCH" if crc == L.part12_crc16 else "MISMATCH"))
    return 0 if crc == L.part12_crc16 else 2


def _cmd_unpack(path, outdir):
    fw = open(path, "rb").read()
    os.makedirs(outdir, exist_ok=True)
    info = unpack(fw)
    L = info["layout"]
    for name in ("header", "arm9boot", "arm7boot", "arm9gui", "arm7gui", "gui_data"):
        with open(os.path.join(outdir, name + ".bin"), "wb") as f:
            f.write(info[name])
    with open(os.path.join(outdir, "manifest.txt"), "w") as m:
        m.write("source        %s\n" % path)
        m.write("identifier    %s\n" % fw[OFF_FW_IDENTIFIER:OFF_FW_IDENTIFIER + 4].decode("latin1"))
        m.write("arm9boot.bin  0x%06X bytes (part1, ram 0x%08X)\n" % (len(info["arm9boot"]), L.part1_ram))
        m.write("arm7boot.bin  0x%06X bytes (part2, ram 0x%08X)\n" % (len(info["arm7boot"]), L.part2_ram))
        m.write("arm9gui.bin   0x%06X bytes (part3, huffman)\n" % len(info["arm9gui"]))
        m.write("arm7gui.bin   0x%06X bytes (part4, huffman)\n" % len(info["arm7gui"]))
        m.write("gui_data.bin  0x%06X bytes (part5, huffman)\n" % len(info["gui_data"]))
    print("Unpacked to %s/ : header.bin, arm9boot.bin (0x%X), arm7boot.bin (0x%X),"
          % (outdir, len(info["arm9boot"]), len(info["arm7boot"])))
    print("  arm9gui.bin (0x%X), arm7gui.bin (0x%X), gui_data.bin (0x%X), manifest.txt"
          % (len(info["arm9gui"]), len(info["arm7gui"]), len(info["gui_data"])))
    return 0


def _cmd_repack(argv):
    base, out = argv[0], argv[1]
    flags = {"--arm9": None, "--arm7": None, "--arm9gui": None,
             "--arm7gui": None, "--guidata": None}
    i = 2
    while i < len(argv):
        if argv[i] in flags and i + 1 < len(argv):
            flags[argv[i]] = open(argv[i + 1], "rb").read(); i += 2
        else:
            sys.exit("unknown or incomplete arg %r" % argv[i])
    base_fw = open(base, "rb").read()
    img = repack(base_fw, arm9=flags["--arm9"], arm7=flags["--arm7"],
                 arm9gui=flags["--arm9gui"], arm7gui=flags["--arm7gui"],
                 guidata=flags["--guidata"])
    with open(out, "wb") as f:
        f.write(img)
    L = decode_layout(img)
    print("Repacked -> %s (%d bytes)" % (out, len(img)))
    print("  CRC16  part1/2=0x%04X  part3/4=0x%04X  part5=0x%04X"
          % (L.part12_crc16, L.part34_crc16, L.part5_crc16))
    return 0


def main(argv):
    if len(argv) >= 2 and argv[1] == "info":
        return _cmd_info(argv[2])
    if len(argv) >= 4 and argv[1] == "unpack":
        return _cmd_unpack(argv[2], argv[3])
    if len(argv) >= 4 and argv[1] == "repack":
        return _cmd_repack(argv[2:])
    print("iplrepack.py - Nintendo DS IPL firmware unpacker/repacker\n\n"
          "Usage:\n"
          "  python -m pynitro.ipl.iplrepack info   <firmware.bin>\n"
          "  python -m pynitro.ipl.iplrepack unpack <firmware.bin> <outdir>\n"
          "  python -m pynitro.ipl.iplrepack repack <base.bin> <out.bin> [--arm9 f] [--arm7 f]\n"
          "         [--arm9gui f] [--arm7gui f] [--guidata f]")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
