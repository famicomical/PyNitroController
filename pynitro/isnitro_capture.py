"""Driver for the IS-NITRO-CAPTURE (VID 0x0F6E / PID 0x0403) over USB.

Ported from Lorenzooone's cc3dsfs (``usb_is_device_communications.cpp`` and
``usb_is_nitro_acquisition_capture.cpp``). The NEC-memory read (cmds 0x0D/0x0E)
comes from the CAPTURE Main Program's own command table (read in the 0x1D6 and
0x1DE builds; same handlers in both). The firmware update (cmd 0x01) reproduces a
USB capture of ISNP v2.15 byte for byte. Both are confirmed on real hardware;
frame capture is not.

The CAPTURE uses the same endpoints (OUT 0x01 / IN 0x82) and 16-byte header as
the EMULATOR (see ``isnitro.py``), with three differences:
  - direction byte is 0x00 write / 0x01 read (EMULATOR: 0x10 / 0x11)
  - a write's header and payload go out as two separate bulk transfers
  - after each command the box sends a 16-byte status; byte 0 == 1 means OK
NEC memory (the box's V850 address space; its flash is mapped at 0) is read by
writing an 8-byte block ``u16 unit_size, u16 count, u32 address`` with cmd 0x0D,
then reading ``count * unit_size`` bytes with cmd 0x0E.

Frames are raw bulk-IN reads with no header: 256 px wide, top screen rows then
bottom screen rows, 3 bytes per pixel in B, G, R order.

CLI
  python -m pynitro.isnitro_capture info
  python -m pynitro.isnitro_capture dump nec_flash.bin [--start 0] [--length 0x400000]
  python -m pynitro.isnitro_capture grab out.ppm [--screens both|top|bottom] [--skip N]
  python -m pynitro.isnitro_capture --selftest
Firmware writes and the video-settings editor are in gui.py (with backup/verify).

cc3dsfs: Copyright (c) 2024 Lorenzooone. Its IS-device code is based on
Gericom's sample code, Copyright (c) 2024 Gericom. Both MIT License:

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import argparse
import hashlib
import os
import struct
import sys
import time

import usb.core
import usb.util

from .isnitro import (DEFAULT_TIMEOUT_MS, EP_IN, EP_OUT, ISNitro, ISNitroError,
                     _open_device)
from .nec.nec_base_update_crypt import encrypt

PID_CAPTURE = 0x0403

DIR_WRITE = 0x00
DIR_READ = 0x01

TYPE_COMMAND = 0
TYPE_DMA = 2

CMD_DMA = 0x00              # TYPE_DMA: read length 1 = start, 0 = stop
CMD_GET_FW_VERSION = 0x01   # Main version/type + LCA1 version/type (4 x u32)
CMD_GET_SERIAL = 0x03
CMD_SET_FWD_RATE = 0x12
CMD_SET_FWD_SCREENS = 0x13
CMD_SET_FWD_COLOURS = 0x14  # 0 = 24-bit
CMD_MEM_PARAMS = 0x0D       # write: u16 unit_size, u16 count, u32 address
CMD_MEM_READ = 0x0E         # read: count * unit_size bytes, address incrementing
CMD_SET_FWD_FRAMES = 0x15
CMD_DEBUG_BUTTON = 0x18     # read: debug button state; write: full restart
CMD_GET_LID = 0x19
CMD_SET_FWD_RESTART = 0x1C
CMD_RESET_CPU_ON = 0x21
CMD_RESET_CPU_OFF = 0x22

FWD_FRAMES_PERMANENT = 0x4001

SCREENS = {"both": 0, "top": 1, "bottom": 2}
RATE_FULL, RATE_HALF, RATE_THIRD, RATE_QUARTER = range(4)

FLASH_SIZE = 0x400000       # assumed: same 4 MiB part as the EMULATOR
FLASH_INFO_ADDR = 0x800988  # RAM globals (flash size, type, last block) in v2.10 firmware;
                            # other firmware builds may keep them elsewhere

WIDTH = 256
HEIGHT = 192            # per screen

# -- controller-firmware update (cmd 0x01) -------------------------------------
# Reproduces ISNP v2.15's update byte for byte (checked against a USB capture):
# blob = [0x2000 RAM flash routine, region selector at 0x1FF0] + [the full region],
# encrypted with the EMULATOR's update cipher; the size at +0x50 is the region span
# and the key sits at +0xFC. After the upload the box sends a 16-byte status, then
# the same 8-byte progress words as the EMULATOR (03..09, then 01 = done).

CMD_FW_UPDATE = 0x01
ROUTINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nec",
                            "isnc_flash_routine.bin")
ROUTINE_SHA256 = "5765637a6fcabdd15dcc7639f698caa7192bf8bce5fab0497ec3dd8eccdaba9b"
REGIONS = {0: (0x010000, 0x20000, b"Main Program"), 1: (0x030000, 0x30000, b"LCA1")}
CAPTURE_DESCRIPTOR = b"\x6e\x0f\x03\x04"   # VID 0F6E / PID 0403 inside a CAPTURE Main


def _routine():
    with open(ROUTINE_PATH, "rb") as f:
        raw = f.read()
    if hashlib.sha256(raw).hexdigest() != ROUTINE_SHA256:
        raise ISNitroError("isnc_flash_routine.bin is corrupt or modified (SHA-256 mismatch)")
    return raw


def build_update_blob(selector, image, n=0x5A):
    """Update blob for one region (0 = Main, 1 = LCA1) from its full region image."""
    if selector not in REGIONS:
        raise ValueError("selector must be 0 (Main) or 1 (LCA1)")
    _, span, tag = REGIONS[selector]
    if (len(image) != span or image[:19] != b"INTELLIGENT SYSTEMS"
            or image[0x20:0x20 + len(tag)] != tag):
        raise ValueError("not a 0x%X-byte %s region image" % (span, tag.decode()))
    if selector == 0 and CAPTURE_DESCRIPTOR not in image:
        raise ValueError("this Main Program is not IS-NITRO-CAPTURE firmware")
    if not (0 < n <= 0x7FFF and n & 0xFF):
        raise ValueError("key must be 1..0x7FFF with a non-zero low byte")
    routine = bytearray(_routine())
    struct.pack_into("<I", routine, 0x1FF0, selector)
    payload = bytearray(encrypt(bytes(image), n))
    payload[0x50:0x54] = encrypt(struct.pack("<I", span), n)   # cipher index restarts here
    payload[0xFC:0x100] = struct.pack("<I", n)
    return encrypt(bytes(routine), n) + bytes(payload)


# -- video settings (teod's ISNP patch) -----------------------------------
# At power-on the Main writes built-in video settings straight to the video
# registers (Main 0x125D2). Each entry gives the Main-region offset of the operand
# that holds a value: the imm16 of a `movea` (2 bytes) or the imm5 of a `mov`
# (gaps, 1 byte). X, X dual and Y come in pairs, picked by the LCA1 type in flash
# at 0x30044 (`cmov H`): type > 1 uses the first offset, type <= 1 the second.
# Bounds follow teod's ISNP-Patcher.CT. With DIP2 on the box then applies its saved
# config over these, and ISNP's cmd 0x2F does the same while it's connected.
VIDEO_FIELDS = (
    ("av1_x", 0x25E0, 0x25E4, 0xFF), ("av1_y", 0x2652, 0x2656, 0xFF),
    ("av1_x_dual", 0x261A, 0x261E, 0xFFFF), ("av1_y_dual", 0x2690, 0x2690, 0xFF),
    ("av1_gap", 0x26B0, 0x26B0, 31),
    ("av2_x", 0x26EC, 0x26F0, 0xFF), ("av2_y", 0x2758, 0x275C, 0xFF),
    ("av2_x_dual", 0x2722, 0x2726, 0xFFFF), ("av2_y_dual", 0x2792, 0x2792, 0xFF),
    ("av2_gap", 0x27B6, 0x27B6, 31),
)
# The aspect-ratio "fix" sets video registers 0x86/0x06 when LCA1 type > 1. Two
# `bnh` (0x93) guard it; `br` (0x95) skips it. 0x28CE runs on every boot (built-in
# settings); 0x379E only when a saved config or ISNP's settings are applied. Nothing
# ever clears those registers, so "dip2_on" alone most likely has no effect: with
# DIP2 on, only "always" removes the fix.
ASPECT_SITES = {"dip2_off": 0x28CE, "dip2_on": 0x379E}
ASPECT_MODES = ("keep", "dip2_off", "dip2_on", "always")


# The built-in cursor (shown with DIP3 when DIP2 is off): 16x16, one byte per
# pixel, copied to the video FPGA at every boot by Main 0x132C0, whose
# `mov 0x18120, r13` sits at region offset 0x32D8. Codes: 0 transparent, 1 white,
# 2 (anything >= 2) black; hotspot 7,7.
BUILTIN_CURSOR_OFF = 0x8120
BUILTIN_CURSOR_REF = 0x32D8
CURSOR_CHARS = ".#o"            # transparent, white, black
STOCK_CURSOR = (                # the crosshair in stock v2.15 (0x1DE) firmware
    "................", "......#o#.......", "......#o#.......", "......#o#.......",
    "......#o#.......", "......#o#.......", ".#####ooo#####..", ".oooooo.oooooo..",
    ".#####ooo#####..", "......#o#.......", "......#o#.......", "......#o#.......",
    "......#o#.......", "......#o#.......", "................", "................",
)


def _check_cursor_layout(main):
    h0, addr = struct.unpack_from("<HI", main, BUILTIN_CURSOR_REF)
    if h0 & 0xFFE0 != 0x0620 or addr != 0x10000 + BUILTIN_CURSOR_OFF:
        raise ValueError("unrecognised Main Program layout (built-in cursor table)")


def read_builtin_cursor(main):
    """The built-in cursor as 16 strings of 16 chars ('.' '#' 'o')."""
    _check_cursor_layout(main)
    t = main[BUILTIN_CURSOR_OFF:BUILTIN_CURSOR_OFF + 256]
    return ["".join(CURSOR_CHARS[min(c, 2)] for c in t[y * 16:y * 16 + 16]) for y in range(16)]


def patch_builtin_cursor(main, rows):
    """Copy of `main` with the built-in cursor replaced by 16 rows of 16 chars."""
    _check_cursor_layout(main)
    if len(rows) != 16 or any(len(r) != 16 or set(r) - set(CURSOR_CHARS) for r in rows):
        raise ValueError("cursor must be 16 rows of 16 '.', '#' or 'o'")
    out = bytearray(main)
    out[BUILTIN_CURSOR_OFF:BUILTIN_CURSOR_OFF + 256] = bytes(
        CURSOR_CHARS.index(c) for r in rows for c in r)
    return bytes(out)


def _video_offset(entry, lca1_type):
    _, first, second, _ = entry
    return first if lca1_type > 1 else second


# -- saved video configs (used with DIP2 on; ISNP's .nvi files are the same) -----
# The box keeps a log of 0x29C-byte "MNTR" records in 0x400-byte slots of one
# 64 KB flash block. At power-on it reads the slots in order and uses the last
# valid record before the first invalid one; a save goes into that first invalid
# slot, erasing the block when it is full (Main 0x19632 / 0x1971C / 0x194B6).

CONFIG_BASE = 0x1F0000
CONFIG_SIZE = 0x10000
CONFIG_SLOT = 0x400
MNTR_SIZE = 0x29C


def mntr_checksum(rec):
    """The firmware's 16-bit sum over a record's halfwords (stored at +6)."""
    h = lambda o: struct.unpack_from("<H", rec, o)[0]
    offs = list(range(0x08, 0x60, 4)) + list(range(0x60, 0x260, 2)) + [0x260, 0x264]
    for min_version, extra in ((2, (0x268, 0x26C)), (3, (0x270, 0x274, 0x278, 0x27C, 0x280)),
                               (4, (0x284, 0x288, 0x28C)), (5, (0x290, 0x294, 0x298))):
        if h(4) >= min_version:
            offs += extra
    return sum(h(o) for o in offs) & 0xFFFF


def mntr_valid(rec):
    return (len(rec) >= MNTR_SIZE and rec[:4] == b"MNTR"
            and struct.unpack_from("<H", rec, 4)[0] != 0
            and struct.unpack_from("<H", rec, 6)[0] == mntr_checksum(rec))


def saved_video_configs(block, base=CONFIG_BASE):
    """[(address, record)] in the order the box reads them; the last one is active."""
    out = []
    for off in range(0, len(block) - MNTR_SIZE + 1, CONFIG_SLOT):
        rec = bytes(block[off:off + MNTR_SIZE])
        if not mntr_valid(rec):
            break
        out.append((base + off, rec))
    return out


def _check_video_layout(main):
    for name, first, second, _ in VIDEO_FIELDS:
        for off in {first, second}:
            if name.endswith("_gap"):
                ok = main[off] < 0x20 and main[off + 1] & 0x07 == 0x02      # mov imm5, reg
            else:
                ok = main[off - 2] == 0x20 and main[off - 1] & 0x07 == 0x06  # movea imm16, r0
            if not ok:
                raise ValueError("unrecognised Main Program layout at +0x%X (%s); only "
                                 "v2.15-style CAPTURE firmware is supported" % (off, name))
    for off in ASPECT_SITES.values():
        if main[off] not in (0x93, 0x95) or main[off + 1] != 0x1D:
            raise ValueError("unrecognised Main Program layout at +0x%X (aspect fix)" % off)


def read_video_config(main, lca1_type=2):
    """Video settings (the set a box with this LCA1 type uses), aspect mode and
    version of a CAPTURE Main Program image."""
    _check_video_layout(main)
    cfg = {}
    for entry in VIDEO_FIELDS:
        off = _video_offset(entry, lca1_type)
        cfg[entry[0]] = main[off] if entry[0].endswith("_gap") else \
            struct.unpack_from("<H", main, off)[0]
    off_, on_ = (main[a] == 0x95 for a in ASPECT_SITES.values())
    cfg["aspect"] = ASPECT_MODES[off_ + 2 * on_]
    cfg["version"] = struct.unpack_from("<I", main, 0x40)[0]
    return cfg


def patch_video_config(main, cfg, lca1_type=2):
    """Copy of `main` with the settings in `cfg` (any subset of read_video_config's
    keys) written to the set a box with this LCA1 type uses."""
    _check_video_layout(main)
    out = bytearray(main)
    for entry in VIDEO_FIELDS:
        name, top, off = entry[0], entry[3], _video_offset(entry, lca1_type)
        if name in cfg:
            v = int(cfg[name])
            if not 0 <= v <= top:
                raise ValueError("%s must be 0..0x%X (got 0x%X)" % (name, top, v))
            if name.endswith("_gap"):
                out[off] = v
            else:
                struct.pack_into("<H", out, off, v)
    if "aspect" in cfg:
        i = ASPECT_MODES.index(cfg["aspect"])
        out[ASPECT_SITES["dip2_off"]] = 0x95 if i & 1 else 0x93
        out[ASPECT_SITES["dip2_on"]] = 0x95 if i & 2 else 0x93
    if "version" in cfg:
        v = int(cfg["version"])
        if not 0 <= v <= 0xFFFF:
            raise ValueError("version must be 0..0xFFFF (got 0x%X)" % v)
        struct.pack_into("<I", out, 0x40, v)
    return bytes(out)


def frame_size(screens="both"):
    """Bytes in one frame: 3 bytes per pixel, one or two 256x192 screens."""
    return WIDTH * HEIGHT * 3 * (2 if screens == "both" else 1)


def frame_to_ppm(frame):
    """Convert a raw B,G,R frame to a binary PPM (P6) image."""
    rgb = bytearray(frame)
    rgb[0::3], rgb[2::3] = frame[2::3], frame[0::3]
    height = len(frame) // (WIDTH * 3)
    return b"P6\n%d %d\n255\n" % (WIDTH, height) + bytes(rgb)


class ISNitroCapture:
    """High-level handle to an IS-NITRO-CAPTURE."""

    def __init__(self, device, timeout_ms=DEFAULT_TIMEOUT_MS):
        self.dev = device
        self.timeout = timeout_ms

    @classmethod
    def open(cls, timeout_ms=DEFAULT_TIMEOUT_MS):
        dev = _open_device(PID_CAPTURE, "IS-NITRO-CAPTURE")
        # cc3dsfs clears both pipes on connect for every IS-Nitro device.
        dev.clear_halt(EP_OUT)
        dev.clear_halt(EP_IN)
        return cls(dev, timeout_ms)

    def close(self):
        if self.dev is not None:
            usb.util.dispose_resources(self.dev)
            self.dev = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- low-level command protocol ----------------------------------------

    @staticmethod
    def _header(command, direction, ptype, length):
        # u16 cmd | u8 dir | u8 type | u32 addr | u32 len | u32 pad
        return struct.pack("<HBBIII", command, direction, ptype, 0, length, 0)

    def _status(self, command):
        status = bytes(self.dev.read(EP_IN, 16, self.timeout))
        if len(status) != 16 or status[0] != 1:
            raise ISNitroError("IS-NITRO-CAPTURE command 0x%02X failed (status %s)"
                               % (command, status.hex()))

    def _read(self, command, length, ptype=TYPE_COMMAND, data=True, status=True):
        self.dev.write(EP_OUT, self._header(command, DIR_READ, ptype, length),
                       self.timeout)
        out = b""
        if data and length:
            out = bytes(self.dev.read(EP_IN, length, self.timeout))
            if len(out) != length:
                raise ISNitroError("short read for command 0x%02X: %d of %d bytes"
                                   % (command, len(out), length))
        if status:
            self._status(command)
        return out

    def _write(self, command, payload=b""):
        self.dev.write(EP_OUT, self._header(command, DIR_WRITE, TYPE_COMMAND,
                                            len(payload)), self.timeout)
        if payload:
            self.dev.write(EP_OUT, payload, self.timeout)
        self._status(command)

    def _read_u32(self, command):
        return struct.unpack("<I", self._read(command, 4))[0]

    def _write_u32(self, command, value):
        self._write(command, struct.pack("<I", value))

    # -- info / control ------------------------------------------------------

    def serial(self):
        raw = self._read(CMD_GET_SERIAL, 10)
        return "".join(chr(b) for b in raw if 0x20 <= b < 0x7F) or raw.hex()

    version_string = serial     # the EMULATOR's "identify string" is its serial too

    def firmware_version(self):
        """(Main version, Main type, LCA1 version, LCA1 type) from the region headers."""
        return struct.unpack("<4I", self._read(CMD_GET_FW_VERSION, 16))

    def read_memory(self, address, length, unit_size=4, chunk=0x1000, progress=None):
        """Read NEC memory; the controller flash is mapped at address 0.
        `progress(done, total)` is optional."""
        # shortcut: 0x1000 per read; the box's USB buffer (0x80E000) likely fits
        # 0x2000 -- raise it once confirmed on hardware.
        out = bytearray()
        while len(out) < length:
            n = min(chunk, length - len(out))
            if n % unit_size:
                raise ValueError("length must be a multiple of unit_size")
            params = struct.pack("<HHI", unit_size, n // unit_size, address + len(out))
            self._write(CMD_MEM_PARAMS, params)
            data = self._read(CMD_MEM_READ, n)
            # If the box rejects the parameters (unit size not 1/2/4) it still
            # answers OK but sends its USB buffer back untouched: our request.
            if data[:8] == params:
                raise ISNitroError("the box ignored the memory read "
                                   "(cmd 0x0E returned the request unchanged)")
            out += data
            if progress:
                progress(len(out), length)
        return bytes(out)

    # -- same names as ISNitro, so gui.py / dump_nec_flash work on either box --

    def read_nec_memory(self, address, unit_size, count):
        return self.read_memory(address, unit_size * count, unit_size)

    def read_nec_memory_fast(self, address, length, unit_size=4, count=0x400,
                             progress=None):
        return self.read_memory(address, length, unit_size,
                                min(unit_size * count, 0x1000), progress)

    def reset_ds(self, log=print):
        log("  -> CPU reset on/off (cmds 0x21/0x22)")
        self.reset_cpu()

    def flash_info(self):
        """(size, type, last block address) as the firmware detected them."""
        return struct.unpack("<3I", self.read_memory(FLASH_INFO_ADDR, 12))

    def send_firmware_update(self, blob, log=None, progress=None, settle_s=5.0):
        """Upload one update blob (cmd 0x01) and wait while the box flashes it.
        DESTRUCTIVE. Returns (finished, progress_words)."""
        log = log or (lambda *a: None)
        progress = progress or (lambda *a: None)
        log("  firmware before: Main v0x%X, LCA1 v0x%X" % self.firmware_version()[::2])
        self.dev.write(EP_OUT, self._header(CMD_FW_UPDATE, DIR_WRITE, TYPE_COMMAND,
                                            len(blob)), self.timeout)
        for off in range(0, len(blob), 0x10000):            # ISNP's chunking
            self.dev.write(EP_OUT, blob[off:off + 0x10000], self.timeout)
            progress(5 + 35 * min(off + 0x10000, len(blob)) // len(blob), "uploading")
        self._status(CMD_FW_UPDATE)
        # Same progress stream as the EMULATOR's update; the drain only needs self.dev.
        words, finished = ISNitro._drain_progress(self, log, progress=progress)
        if finished:
            self._resync(log, settle_s)
        progress(100, "done" if finished else "stalled")
        return finished, words

    def _resync(self, log, settle_s, tries=5):
        """After an update the box only answers once both pipes are reset; ISNP
        waits ~5 s, resets them (seen in its USB capture), then reads the version."""
        log("  waiting %g s for the box to settle (as ISNP does)..." % settle_s)
        time.sleep(settle_s)
        saved, self.timeout = self.timeout, 1000
        try:
            for i in range(tries):
                if i:
                    time.sleep(1)
                try:
                    self.dev.clear_halt(EP_OUT)
                    self.dev.clear_halt(EP_IN)
                    log("  firmware after: Main v0x%X, LCA1 v0x%X" % self.firmware_version()[::2])
                    return
                except usb.core.USBError:
                    continue
        finally:
            self.timeout = saved
        raise ISNitroError("the box did not answer after the update; disconnect, "
                           "reconnect and check its firmware version")

    def lid_closed(self):
        return bool(self._read_u32(CMD_GET_LID) & 1)

    def debug_button(self):
        return bool(self._read_u32(CMD_DEBUG_BUTTON) & 1)

    def reset_cpu(self):
        self._write(CMD_RESET_CPU_ON)
        self._write(CMD_RESET_CPU_OFF)

    def full_restart(self):
        self._write(CMD_DEBUG_BUTTON)

    # -- capture -------------------------------------------------------------

    def start_capture(self, screens="both", rate=RATE_FULL):
        """Configure frame forwarding and start the capture DMA."""
        self._write_u32(CMD_SET_FWD_RATE, rate)
        self._write_u32(CMD_SET_FWD_SCREENS, SCREENS[screens])
        self._write_u32(CMD_SET_FWD_COLOURS, 0)
        self._write_u32(CMD_SET_FWD_FRAMES, FWD_FRAMES_PERMANENT)
        self._write_u32(CMD_SET_FWD_RESTART, 1)
        # Start has no data and no status; frames follow on EP_IN.
        self._read(CMD_DMA, 1, TYPE_DMA, data=False, status=False)

    def read_frame(self, screens="both"):
        size = frame_size(screens)
        frame = bytes(self.dev.read(EP_IN, size, self.timeout))
        if len(frame) != size:
            raise ISNitroError("short frame: %d of %d bytes" % (len(frame), size))
        return frame

    def stop_capture(self):
        self._read(CMD_DMA, 0, TYPE_DMA)


# -- self-test (no hardware) ---------------------------------------------------

class _FakeDev:
    """Records writes; serves queued reads."""

    def __init__(self, reads):
        self.writes, self.reads = [], list(reads)

    def write(self, ep, data, timeout):
        self.writes.append((ep, bytes(data)))

    def read(self, ep, size, timeout):
        assert ep == EP_IN
        return self.reads.pop(0)[:size]

    def clear_halt(self, ep):
        self.writes.append(("clear_halt", ep))


def _selftest():
    ok = b"\x01" + b"\x00" * 15

    d = _FakeDev([b"0123456789", ok])
    assert ISNitroCapture(d).serial() == "0123456789"
    assert d.writes == [(EP_OUT, struct.pack("<HBBIII", 0x03, 0x01, 0, 0, 10, 0))]

    d = _FakeDev([ok])
    ISNitroCapture(d)._write_u32(CMD_SET_FWD_FRAMES, FWD_FRAMES_PERMANENT)
    assert d.writes == [(EP_OUT, struct.pack("<HBBIII", 0x15, 0x00, 0, 0, 4, 0)),
                        (EP_OUT, b"\x01\x40\x00\x00")]

    d = _FakeDev([b"\x01\x00\x00\x00", b"\x00" * 16])
    try:
        ISNitroCapture(d).lid_closed()
        raise AssertionError("bad status not detected")
    except ISNitroError:
        pass

    d = _FakeDev([ok] * 5)
    ISNitroCapture(d).start_capture("top")
    assert d.writes[-1] == (EP_OUT, struct.pack("<HBBIII", 0x00, 0x01, 2, 0, 1, 0))
    assert d.reads == []            # start reads no status

    d = _FakeDev([ok, b"A" * 0x1000, ok, ok, b"B" * 8, ok])
    assert ISNitroCapture(d).read_memory(0x10000, 0x1008) == b"A" * 0x1000 + b"B" * 8
    assert d.writes[:3] == [
        (EP_OUT, struct.pack("<HBBIII", 0x0D, 0x00, 0, 0, 8, 0)),
        (EP_OUT, struct.pack("<HHI", 4, 0x400, 0x10000)),
        (EP_OUT, struct.pack("<HBBIII", 0x0E, 0x01, 0, 0, 0x1000, 0))]
    assert d.writes[4] == (EP_OUT, struct.pack("<HHI", 4, 2, 0x11000))

    params = struct.pack("<HHI", 4, 0x400, 0x10000)
    d = _FakeDev([ok, params + b"\x00" * 0xFF8, ok])
    try:
        ISNitroCapture(d).read_memory(0x10000, 0x1000)
        raise AssertionError("echoed request not detected")
    except ISNitroError:
        pass

    from .nec.nec_base_update_crypt import decrypt
    main = bytearray(b"\xff" * 0x20000)
    main[:19], main[0x20:0x2C] = b"INTELLIGENT SYSTEMS", b"Main Program"
    main[0x1000:0x1004] = CAPTURE_DESCRIPTOR
    for name, first, second, _ in VIDEO_FIELDS:
        if name.endswith("_gap"):
            main[first:first + 2] = b"\x08\x6a"             # mov 8, r13
        else:
            main[first - 2:first + 2] = b"\x20\x5e\xc4\x00"   # movea 0xC4, r0, r11
            if second != first:
                main[second - 2:second + 2] = b"\x20\x56\xb8\x00"   # movea 0xB8, r0, r10
    for off in ASPECT_SITES.values():
        main[off:off + 2] = b"\x93\x1d"                    # bnh
    cfg = read_video_config(main)
    assert cfg["av1_x"] == 0xC4 and cfg["av2_gap"] == 8 and cfg["aspect"] == "keep"
    new = patch_video_config(main, {"av1_x": 0xE4, "av1_x_dual": 0x160, "aspect": "always",
                                    "version": 0x1DF})
    cfg = read_video_config(new)
    assert (cfg["av1_x"], cfg["av1_x_dual"], cfg["aspect"], cfg["version"]) == \
        (0xE4, 0x160, "always", 0x1DF)
    assert sum(a != b for a, b in zip(main, new)) == 1 + 2 + 2 + 4   # x, x_dual, sites, version
    old = patch_video_config(main, {"av1_x": 0xA0}, lca1_type=1)   # older boards: 2nd value
    assert read_video_config(old, lca1_type=1)["av1_x"] == 0xA0
    assert read_video_config(old)["av1_x"] == 0xC4 and old[0x25E4] == 0xA0
    for bad in ({"av1_y": 0x100}, {"av1_gap": 32}, {"aspect": "sometimes"}):
        try:
            patch_video_config(main, bad)
            raise AssertionError("accepted %r" % bad)
        except ValueError:
            pass

    rec = bytearray(MNTR_SIZE)
    rec[:6] = b"MNTR\x05\x00"
    struct.pack_into("<I", rec, 0x34, 0xC4)
    struct.pack_into("<H", rec, 6, mntr_checksum(rec))
    assert mntr_valid(rec)
    block = bytearray(b"\xff" * CONFIG_SIZE)
    block[0:MNTR_SIZE] = rec
    block[CONFIG_SLOT:CONFIG_SLOT + MNTR_SIZE] = rec
    block[3 * CONFIG_SLOT:3 * CONFIG_SLOT + MNTR_SIZE] = rec    # after a blank slot: ignored
    assert [a for a, _ in saved_video_configs(block)] == [0x1F0000, 0x1F0400]
    rec[0x34] ^= 1                                               # bad checksum -> invalid
    assert not mntr_valid(rec)

    main[BUILTIN_CURSOR_REF:BUILTIN_CURSOR_REF + 6] = b"\x2d\x06" + struct.pack("<I", 0x18120)
    rows = read_builtin_cursor(main)
    assert rows[0] == "o" * 16                        # 0xFF fill reads as black
    assert read_builtin_cursor(patch_builtin_cursor(main, STOCK_CURSOR)) == list(STOCK_CURSOR)
    cross = ["." * 16] * 7 + ["...#####o####..."] + ["." * 16] * 8
    cur = patch_builtin_cursor(main, cross)
    assert read_builtin_cursor(cur) == cross and cur[BUILTIN_CURSOR_OFF + 7 * 16 + 3] == 1
    for bad in (cross[:15], cross[:15] + ["x" * 16]):
        try:
            patch_builtin_cursor(main, bad)
            raise AssertionError("bad cursor accepted")
        except ValueError:
            pass

    blob = build_update_blob(0, bytes(new), n=0x6D08)
    assert len(blob) == 0x22000
    assert struct.unpack_from("<I", decrypt(blob[:0x2000], 0x6D08), 0x1FF0)[0] == 0
    pl = decrypt(blob[0x2000:], 0x6D08)
    assert pl[0x100:] == bytes(new)[0x100:] and pl[:0x50] == bytes(new)[:0x50]
    assert decrypt(blob[0x2050:0x2054], 0x6D08) == struct.pack("<I", 0x20000)
    assert blob[0x20FC:0x2100] == struct.pack("<I", 0x6D08)
    emu = bytes(new).replace(CAPTURE_DESCRIPTOR, b"\x6e\x0f\x04\x04")
    try:
        build_update_blob(0, emu)
        raise AssertionError("EMULATOR Main accepted")
    except ValueError:
        pass

    words = [bytes([w]) + b"\x00" * 7 for w in (3, 4, 5, 6, 7, 8, 9, 1)]
    ver = b"\xde\x01\x00\x00" + b"\x00" * 12
    d = _FakeDev([ver, ok, ok] + words + [ver, ok])
    assert ISNitroCapture(d).send_firmware_update(blob, settle_s=0)[0]
    assert d.writes[1] == (EP_OUT, struct.pack("<HBBIII", 0x01, 0x00, 0, 0, 0x22000, 0))
    assert [len(w) for _, w in d.writes[2:5]] == [0x10000, 0x10000, 0x2000]
    assert d.writes[5:7] == [("clear_halt", EP_OUT), ("clear_halt", EP_IN)]   # resync
    assert d.reads == []

    assert frame_size("both") == 294912 and frame_size("top") == 147456
    ppm = frame_to_ppm(bytes([1, 2, 3]) * (WIDTH * HEIGHT))
    assert ppm.startswith(b"P6\n256 192\n255\n") and ppm.endswith(b"\x03\x02\x01")

    print("isnitro_capture selftest PASSED")


def _cli(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("info", help="print serial, firmware version, flash info, lid state")
    dm = sub.add_parser("dump", help="read the controller flash to a file (read-only)")
    dm.add_argument("out")
    dm.add_argument("--start", type=lambda v: int(v, 0), default=0)
    dm.add_argument("--length", type=lambda v: int(v, 0), default=FLASH_SIZE)
    g = sub.add_parser("grab", help="save one frame as a PPM image")
    g.add_argument("out")
    g.add_argument("--screens", choices=SCREENS, default="both")
    g.add_argument("--skip", type=int, default=0, help="frames to discard first")
    args = ap.parse_args(argv)

    if args.selftest:
        _selftest()
        return 0
    if args.cmd is None:
        ap.print_help()
        return 1

    try:
        cap = ISNitroCapture.open()
    except ISNitroError as e:
        print("error:", e)
        return 1

    with cap:
        if args.cmd == "info":
            print("serial:       %s" % cap.serial())
            print("firmware:     Main v0x%X type %d, LCA1 v0x%X type %d" % cap.firmware_version())
            print("flash:        size 0x%X, type 0x%X, last block 0x%X" % cap.flash_info())
            print("lid closed:   %s" % cap.lid_closed())
            print("debug button: %s" % cap.debug_button())
            return 0

        if args.cmd == "dump":
            def prog(done, total):
                if done % 0x40000 == 0 or done == total:
                    print("  0x%06X / 0x%06X" % (done, total))

            data = cap.read_memory(args.start, args.length, progress=prog)
            with open(args.out, "wb") as f:
                f.write(data)
            main = data[0x10000 - args.start:] if args.start <= 0x10000 else b""
            if main[:19] == b"INTELLIGENT SYSTEMS" and main[0x20:0x2C] == b"Main Program":
                print("Main Program header OK, version 0x%X" % struct.unpack_from("<I", main, 0x40))
            print("saved %s (%d bytes)" % (args.out, len(data)))
            return 0

        if cap.lid_closed():
            print("DS lid is closed: no frames to capture.", file=sys.stderr)
            return 1
        cap.start_capture(args.screens)
        try:
            for _ in range(args.skip):
                cap.read_frame(args.screens)
            frame = cap.read_frame(args.screens)
        finally:
            cap.stop_capture()
        with open(args.out, "wb") as f:
            f.write(frame_to_ppm(frame))
        print("saved %s" % args.out)
        return 0


if __name__ == "__main__":
    sys.exit(_cli())
