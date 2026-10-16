#!/usr/bin/env python3
"""
Build cmd-0x0001 update blobs for the IS-NITRO's NEC-controller flash.

Two builders, both producing a [0x2000 RAM-resident V850 flash routine][payload]
image the box decrypts and runs (see docs/EMULATOR.md):

  build_main_blob(main_image)        -- VANILLA Main-Program reflash, identical to
                                        the official ISND process: the unmodified
                                        flash routine, selector 0 -> erases+programs
                                        the Main region (0x10000, 0x20000). Main has
                                        a backup region + DIP-4 restore -> recoverable.

  build_devinfo_video_blob_wp(block) -- rewrites the device-info block (0x3FE000, 8KB)
                                        with bit1 of the options register cleared
                                        (enables video out), leaving every other byte
                                        identical. THIS IS THE WORKING DEVINFO BUILDER on
                                        real hardware (verified 2026-05-26): block 70 is
                                        factory LOCKED-DOWN, so the flash routine's
                                        clear-block-lock can't release it unless the flash
                                        WP# pin is driven high. The WP# pin is wired to the
                                        Sub-LCA CPLD; its 90-byte stub (WP_STUB_BYTES) first
                                        asserts WP# via the CPLD's guarded magic-key
                                        sequence, THEN does the block-70 repoint + header-
                                        slot restore, then runs the unlock/erase/program/
                                        verify. Result: exactly one byte changes (options
                                        0xF6->0xF4), persistent across power-cycle.

  build_devinfo_video_blob(block)    -- LEGACY: same idea with the 42-byte STUB_BYTES that
                                        does NOT assert WP#. This HANGS on hardware whose
                                        block 70 is locked-down (the unlock loop spins
                                        forever). Kept for reference; use the _wp builder.

This module is self-contained (no toolchain needed at runtime): the official routine
is committed as nec_flash_routine.bin (pinned by SHA-256 and verified before any blob
is built) and the stubs are pre-assembled (STUB_BYTES / WP_STUB_BYTES). Their assembly
source is in the comments above STUB_BYTES / WP_STUB_BYTES.

NOTHING here touches hardware. Sending a blob is ISNitro.send_firmware_update(), a
separate destructive step that must be preceded by a verified full backup.
"""
import hashlib, os, struct
from .nec_base_update_crypt import encrypt, decrypt

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROUTINE_PATH = os.path.join(_HERE, "nec_flash_routine.bin")

# The official flash routine is pinned by hash: a flash blob is built FROM it and
# then written to the box's controller, so an accidentally-modified/corrupt routine
# could brick hardware. _verified_routine() checks this before any blob is built.
ROUTINE_SIZE = 0x2000
EXPECTED_ROUTINE_SHA256 = "ca34af2ed33579da653335c33dcccc93bfb027854ed9cec059acd3ed998e60fa"

_routine_cache = None


def _verified_routine():
    """Return the official 0x2000 flash routine, verifying it is byte-for-byte the
    known-good capture-derived image. Raises RuntimeError on any size/hash mismatch
    (or FileNotFoundError if missing) — never build a flash blob from a tampered
    routine. Read lazily + cached, so importing this module for the read-only
    helpers (clear_video_lock) never touches or fails on the file."""
    global _routine_cache
    if _routine_cache is None:
        with open(_ROUTINE_PATH, "rb") as f:
            raw = f.read()
        if len(raw) != ROUTINE_SIZE:
            raise RuntimeError("nec_flash_routine.bin wrong size: 0x%X (expected 0x%X)"
                               % (len(raw), ROUTINE_SIZE))
        got = hashlib.sha256(raw).hexdigest()
        if got != EXPECTED_ROUTINE_SHA256:
            raise RuntimeError(
                "nec_flash_routine.bin FAILED integrity check — refusing to build a "
                "flash blob from a modified/corrupt routine.\n"
                "  expected sha256: %s\n  got      sha256: %s"
                % (EXPECTED_ROUTINE_SHA256, got))
        _routine_cache = raw
    return _routine_cache

# Pre-assembled relocation stub (v850-elf-as -mv850e1), placed at routine offset 0xD00:
#   mov 0x3FE000,r28 ; movhi 0x81,r0,r27 ; movea 0x2000,r0,r29 ; mov 2,r26
#   mov 0x810050,r10 ; mov -1,r11 ; st.w r11,0[r10]      # buffer[0x50] = 0xFFFFFFFF
#   mov 0x8100FC,r10 ; st.w r11,0[r10]                   # buffer[0xFC] = 0xFFFFFFFF
#   jr 0x1d0                                             # -> common flash code
STUB_BYTES = bytes.fromhex(
    "3c0600e03f0040de810020ee002002d22a06500081001f5a6a5f01002a06fc00"
    "81006a5f0100bf07aaf4"
)

# WP#-asserting stub (v850-elf-as -mv850e1), placed at 0xD00. Block 70 is factory
# LOCKED-DOWN, so clear-block-lock (0x60+0xD0) is ignored unless the flash WP# pin is
# high; WP# is driven by the Sub-LCA CPLD via an UNDOCUMENTED guarded register pair
# (found in the box firmware @ Main 0x21ace / bootloader 0x26d4). This stub asserts WP#
# first, then is identical to STUB_BYTES:
#   mov 0x0C800018,r10 ; st.h 0x5555 ; st.h 0xAAAA ; st.h 0xFFFF   # magic key -> arm
#   mov 0x0C800016,r10 ; st.h 1                                    # assert WP# HIGH
#   mov 0x3FE000,r28 ; movhi 0x81,r0,r27 ; movea 0x2000,r0,r29 ; mov 2,r26
#   mov 0x810050,r10 ; mov -1,r11 ; st.w r11,0[r10]               # buffer[0x50] = 0xFFFFFFFF
#   mov 0x8100FC,r10 ; st.w r11,0[r10]                            # buffer[0xFC] = 0xFFFFFFFF
#   jr 0x1d0                                                      # -> common flash code
# (No de-assert: the box hangs/power-cycles after a cmd-0x0001 and WP#'s pulldown +
# the firmware's boot-time re-lock-down restore protection.) Verified on hardware:
# the unlock clears DQ0 first try, full erase/program/verify runs, box stays alive.
WP_STUB_BYTES = bytes.fromhex(
    "2a061800800c2b06555500006a5f00002b06aaaa00006a5f00002b06ffff0000"
    "6a5f00002a061600800c015a6a5f00003c0600e03f0040de810020ee002002d2"
    "2a06500081001f5a6a5f01002a06fc0081006a5f0100bf077af4"
)

# routine patch geometry (see captures/ analysis)
STUB_OFF, CASE0_SW, SEL_OFF = 0x0D00, 0x01B8, 0x1FF0
DEVINFO_DEST, DEVINFO_SIZE  = 0x3FE000, 0x2000
MAIN_DEST,    MAIN_SIZE     = 0x010000, 0x20000

# device-info layout (relative to the maker-string base)
_MAKER, _MODEL = b"INTELLIGENT SYSTEMS", b"IS-NITRO-EMULATOR"
OPT_OFF, VIDEO_BIT = 0x80, 0x02          # options reg; bit1 = video-out lock (clear=enable)
DIMM1024_BIT = 0x80                       # options reg; bit7 = DIMM-1024 RAM extension (clear=enable)
_META_SLOTS = (0x50, 0xFC)               # firmware stuffs size/0 here; must be 0xFF in devinfo


def find_devinfo_base(block):
    i = block.find(_MAKER)
    if i < 0 or block[i+0x20:i+0x20+len(_MODEL)] != _MODEL:
        raise ValueError("not a device-info block (INTELLIGENT SYSTEMS / IS-NITRO-EMULATOR not found)")
    return i


def options_offset(block):
    return find_devinfo_base(block) + OPT_OFF


def read_options(block):
    """Return the options-register byte (devinfo+0x80) from a devinfo block/header.
    A SET bit = extension NOT available; a CLEAR bit = available/enabled."""
    return block[options_offset(block)]


def set_options(block, value):
    """Set the options register (devinfo+0x80) to `value` (absolute byte). Returns
    (new_block, info dict) with before/after/changed. Idempotent."""
    block = bytearray(block)
    off = options_offset(bytes(block))
    before = block[off]
    block[off] = value & 0xFF
    return bytes(block), {"offset": off, "before": before, "after": block[off],
                          "changed": before != block[off]}


def clear_option_bits(block, mask):
    """Clear option-register bits (devinfo+0x80) given by `mask`, enabling the
    corresponding extension(s) (a SET bit = NOT available). Returns
    (new_block, info dict). Idempotent."""
    block = bytearray(block)
    off = options_offset(bytes(block))
    before = block[off]
    block[off] = before & ~mask
    return bytes(block), {"offset": off, "before": before, "after": block[off],
                          "changed": before != block[off]}


def clear_video_lock(block):
    """Clear options bit1 (enable video-out extension). See clear_option_bits."""
    return clear_option_bits(block, VIDEO_BIT)


def clear_dimm1024_lock(block):
    """Clear options bit7 (enable DIMM-1024 RAM extension). See clear_option_bits.
    NOTE: this only flips the availability flag — the DIMM-1024 module(s) must be
    physically present for the extra RAM to actually work."""
    return clear_option_bits(block, DIMM1024_BIT)


def _build_update_blob(routine, payload_image, prog_size, n, trailing=None):
    """Assemble + encrypt a [routine][payload] cmd-0x0001 blob.

    `prog_size` is written (encrypted, index reset to 0) at payload+0x50; this is
    the region-header size field and it lands in NEC flash at <region>+0x50
    VERBATIM (proven on hardware: reflashing the box's LCA3 with prog_size=0x2C01C
    changed flash 0x090050 from its real 0x29500 to 0x2C01C). So `prog_size` MUST
    be the region's own +0x50 value, never a guessed constant.

    The payload the box programs is whatever the host sends, decrypted into the
    RAM buffer at 0x810000. The flash routine then erases+programs a FIXED span
    per selector (r29, hardcoded in the routine: Main=0x20000, each LCA=0x30000 —
    see captures/ disasm of nec_flash_routine.bin @0x80e1c2/0x80e282) out of that
    buffer. Any part of the span the host did NOT fill is programmed from STALE
    buffer RAM. Therefore `payload_image`+`trailing` MUST cover the full region
    span; build_region_blob passes region[:-0x100] + region[-0x100:] so the payload
    is exactly the span. (`trailing` is kept as a separate 0x100 arg only because
    build_main_blob / the devinfo builders predate this and still pass it
    explicitly; it defaults to 0xFF.)"""
    assert len(routine) == 0x2000
    if trailing is None:
        trailing = b"\xFF" * 0x100
    if len(trailing) != 0x100:
        raise ValueError("trailing must be exactly 0x100 bytes")
    payload_pt = bytes(payload_image) + bytes(trailing)         # +0x100 = next-region flash
    blob = bytearray(encrypt(bytes(routine), n, from_flash=True))
    pc = bytearray(encrypt(payload_pt, n, from_flash=True))
    pc[0x50:0x54] = encrypt(struct.pack("<I", prog_size), n, from_flash=True)  # size field (i=0)
    pc[0xFC] = n; pc[0xFD:0x100] = b"\x00\x00\x00"                # raw key at +0xFC
    return bytes(blob) + bytes(pc)


def _devinfo_routine(stub=STUB_BYTES):
    r = bytearray(_verified_routine())
    struct.pack_into("<I", r, SEL_OFF, 0)                         # selector 0 -> case 0
    struct.pack_into("<h", r, CASE0_SW, (STUB_OFF - CASE0_SW)//2) # repoint case 0 -> stub
    assert STUB_OFF + len(stub) < SEL_OFF, "stub overruns the selector word"
    assert set(r[STUB_OFF:STUB_OFF+len(stub)]) <= {0xFF}, "stub area not free"
    r[STUB_OFF:STUB_OFF+len(stub)] = stub
    return bytes(r)


def _check_devinfo_block(devinfo_block):
    if len(devinfo_block) != DEVINFO_SIZE:
        raise ValueError(f"device-info block must be 0x{DEVINFO_SIZE:X} bytes")
    find_devinfo_base(devinfo_block)                              # sanity: real devinfo
    for off in _META_SLOTS:
        if devinfo_block[off:off+4] != b"\xFF\xFF\xFF\xFF":
            raise ValueError(f"block[0x{off:X}] != 0xFFFFFFFF; size-stuffing would corrupt it")


def build_devinfo_video_blob_wp(devinfo_block, n=0x5A):
    """Build the WORKING device-info rewrite blob (asserts the flash WP# override so
    the locked-down block 70 can be unlocked). `devinfo_block` (8 KB) is the FULL desired
    flashed content (live block 70 with the video bit cleared). Verified on hardware."""
    _check_devinfo_block(devinfo_block)
    return _build_update_blob(_devinfo_routine(WP_STUB_BYTES), devinfo_block, DEVINFO_SIZE, n)


def build_devinfo_video_blob(devinfo_block, n=0x5A):
    """LEGACY (no WP# assert): hangs on hardware whose block 70 is locked-down — the
    unlock loop spins forever. Use build_devinfo_video_blob_wp(). Kept for reference."""
    _check_devinfo_block(devinfo_block)
    return _build_update_blob(_devinfo_routine(STUB_BYTES), devinfo_block, DEVINFO_SIZE, n)


# the WP#-override devinfo builder is bit-agnostic — it flashes whatever block you
# hand it. This alias reads correctly when clearing option bits other than video
# (e.g. the DIMM-1024 RAM bit). Same blob, same hardware-verified WP# unlock path.
build_devinfo_blob_wp = build_devinfo_video_blob_wp


def build_main_blob(main_image, n=0x5A, trailing=None):
    """Build a VANILLA Main-Program reflash blob (official routine, selector 0).
    `main_image` = the 0x20000 Main region image (header 'INTELLIGENT SYSTEMS' /
    'Main Program' + code), exactly as it should sit at flash 0x10000. Main's
    program span (routine r29) == its region size (0x20000), so a full-region
    image already fills the routine's buffer — this is the proven-on-hardware Main
    path (post-reflash == source, 0 diffs). `trailing` = the 0x100 flash bytes
    that FOLLOW Main (NEC 0x30000 = the LCA1 header); it only fills buffer past the
    programmed span, so its value is immaterial and it defaults to 0xFF."""
    if len(main_image) != MAIN_SIZE:
        raise ValueError("main_image must be 0x%X bytes (got 0x%X)" % (MAIN_SIZE, len(main_image)))
    if main_image[:len(_MAKER)] != _MAKER or main_image[0x20:0x2C] != b"Main Program":
        raise ValueError("not a Main Program region image (header mismatch)")
    routine = bytearray(_verified_routine())
    struct.pack_into("<I", routine, SEL_OFF, 0)
    return _build_update_blob(bytes(routine), main_image, MAIN_SIZE, n, trailing)


# Per-selector flash geometry for a vanilla "Base Update" (Main + LCA1/2/3 — the
# four regions the official ISND updater reflashes, captures/Base_Update.pcapng).
#   REGION_SPAN = bytes the routine ERASES+PROGRAMS for that selector. This is
#   hardcoded in the flash routine (r29; see disasm of nec_flash_routine.bin:
#   Main case @0x80e1c2 movhi 2 -> 0x20000; LCA cases @0x80e282.. movhi 3 ->
#   0x30000). The routine programs the WHOLE span out of the 0x810000 RAM buffer,
#   so the blob payload must cover the full span or the unfilled tail is flashed
#   from stale RAM (the bug that left LCA1/2/3 tails as 85ff75ee.. garbage).
#   NB: this is NOT the +0x50 size field — that is per-region and DERIVED from the
#   source image (e.g. the box's LCA3 is 0x29500, not 0x2C01C). LCA4 (selector 4)
#   is intentionally excluded — the official Base Update does not reflash it.
REGION_SPAN = {0: MAIN_SIZE, 1: 0x30000, 2: 0x30000, 3: 0x30000}
REGION_TAG = {0: b"Main Program", 1: b"LCA1", 2: b"LCA2", 3: b"LCA3"}
# Region base in the flash image, by selector (matches nec_base_update_crypt).
REGION_BASE = {0: 0x010000, 1: 0x030000, 2: 0x060000, 3: 0x090000}


def build_region_blob(selector, region_image, n=0x5A):
    """Build a vanilla cmd-0x0001 update blob for ONE NEC flash region.

    selector 0=Main, 1/2/3=LCA1/2/3. Uses the official routine unchanged except
    the region selector word at 0x1FF0 — byte-identical to how ISND streams every
    Base-Update blob. `region_image` is the region's full REGION_SPAN[selector]
    bytes (the GUI just passes dump[base:base+span]); the blob carries its
    declared size only.

    Two things, both proven by post-reflash diffs + the routine disasm:
      • The +0x50 size field is DERIVED from the image's own header
        (region_image[0x50:0x54]) and written back unchanged, so a reflash keeps
        the box's real value (LCA3 = 0x29500, NOT a guessed 0x2C01C).
      • The blob sends exactly `size`+0x100 payload bytes — IDENTICAL length to
        the captured ISND blobs. The resident decrypts only `size`+0x100 bytes
        into the RAM buffer (its decrypt bound IS the +0x50 size), then the routine
        erases+programs the FULL span out of that buffer, so the span tail past
        size+0x100 is programmed from stale RAM and CANNOT be set from here.
        (Sending the full span instead just leaves undecrypted bytes in the pipe
        -> mis-framed stream -> the box resets once per blob; do NOT do that.)
        Restoring the tail byte-exactly needs the Route-3A stub trick (decrypt the
        full span via a span-sized +0x50, then a stub rewrites buffer[0x50] to the
        real size before programming) — not done here."""
    if selector not in REGION_SPAN:
        raise ValueError("unsupported selector %r (0=Main, 1/2/3=LCA1/2/3)" % (selector,))
    span, tag = REGION_SPAN[selector], REGION_TAG[selector]
    if len(region_image) != span:
        raise ValueError("selector %d (%s) image must be the full 0x%X region span "
                         "(got 0x%X)" % (selector, tag.decode(), span, len(region_image)))
    if (region_image[:len(_MAKER)] != _MAKER
            or region_image[0x20:0x20 + len(tag)] != tag):
        raise ValueError("not a %s region image (header mismatch)" % tag.decode())
    prog_size = struct.unpack_from("<I", region_image, 0x50)[0]  # region's OWN size field
    if not 0 < prog_size <= span:
        raise ValueError("selector %d (%s) header size 0x%X out of range (region span 0x%X) "
                         "— refusing to flash a bad +0x50" % (selector, tag.decode(), prog_size, span))
    routine = bytearray(_verified_routine())
    struct.pack_into("<I", routine, SEL_OFF, selector)           # region selector
    # Capture-faithful payload: the declared `size` bytes + the 0x100 that follow.
    # For the LCAs size<span so the trailing comes from within the region; for Main
    # size==span so it falls past the region — pad with 0xFF (the routine programs
    # only buffer[0..span] for Main, so that 0x100 is inert; proven on hardware).
    image = region_image[:prog_size]
    trailing = region_image[prog_size:prog_size + 0x100]
    if len(trailing) < 0x100:
        trailing = trailing + b"\xFF" * (0x100 - len(trailing))
    return _build_update_blob(bytes(routine), image, prog_size, n, trailing)


def _selftest():
    """Round-trip both builders against the committed routine + a sample devinfo block."""
    assert hashlib.sha256(_verified_routine()).hexdigest() == EXPECTED_ROUTINE_SHA256
    print("routine integrity: sha256 OK (%s...)" % EXPECTED_ROUTINE_SHA256[:16])
    # synthesize a minimal devinfo block (maker/model/serial + options 0xF6) for the test
    blk = bytearray(b"\xFF" * DEVINFO_SIZE)
    blk[0:len(_MAKER)] = _MAKER; blk[0x20:0x20+len(_MODEL)] = _MODEL
    blk[0x40:0x48] = b"00000000"; blk[OPT_OFF] = 0xF6
    new, info = clear_video_lock(bytes(blk))
    assert info["before"] == 0xF6 and info["after"] == 0xF4 and info["changed"]
    for build, stub in ((build_devinfo_video_blob, STUB_BYTES),
                        (build_devinfo_video_blob_wp, WP_STUB_BYTES)):
        blob = build(new)
        assert len(blob) == 0x4100
        r = decrypt(blob[:0x2000], 0x5A)
        assert struct.unpack_from("<I", r, SEL_OFF)[0] == 0
        assert struct.unpack_from("<h", r, CASE0_SW)[0] == (STUB_OFF-CASE0_SW)//2
        assert r[STUB_OFF:STUB_OFF+len(stub)] == stub
        p = decrypt(blob[0x2000:0x4000], 0x5A)
        assert p[OPT_OFF] == 0xF4
        assert struct.unpack("<I", decrypt(blob[0x2050:0x2054], 0x5A))[0] == DEVINFO_SIZE
    print("devinfo builders (legacy + WP#) selftest OK")
    # main builder: header-valid full Main region with its own +0x50 size field.
    img = bytearray(b"\xFF" * MAIN_SIZE)
    img[0:len(_MAKER)] = _MAKER; img[0x20:0x2C] = b"Main Program"
    struct.pack_into("<I", img, 0x50, MAIN_SIZE)                   # region size field
    mblob = build_main_blob(bytes(img))
    assert len(mblob) == 0x2000 + MAIN_SIZE + 0x100               # legacy path: image + 0x100 trailing
    mr = decrypt(mblob[:0x2000], 0x5A)
    assert struct.unpack_from("<I", mr, SEL_OFF)[0] == 0
    assert mr[STUB_OFF:STUB_OFF+4] == b"\xFF\xFF\xFF\xFF"          # main routine UNmodified
    assert struct.unpack("<I", decrypt(mblob[0x2050:0x2054], 0x5A))[0] == MAIN_SIZE
    # region builder: full-region input, but the blob carries only `size`+0x100
    # (capture-faithful length); +0x50 DERIVED from the image's own header, routine
    # UNmodified but the selector. Use a per-region size smaller than the span
    # (like the real LCA3 0x29500) to exercise the derive-and-slice path.
    sizes = {0: MAIN_SIZE, 1: 0x2C01C, 2: 0x2C01C, 3: 0x29500}
    for sel in (0, 1, 2, 3):
        limg = bytearray(b"\xFF" * REGION_SPAN[sel])
        limg[0:len(_MAKER)] = _MAKER
        limg[0x20:0x20+len(REGION_TAG[sel])] = REGION_TAG[sel]
        struct.pack_into("<I", limg, 0x50, sizes[sel])            # region's OWN size field
        rblob = build_region_blob(sel, bytes(limg))
        assert len(rblob) == 0x2000 + sizes[sel] + 0x100          # capture-faithful length
        rr = decrypt(rblob[:0x2000], 0x5A)
        assert struct.unpack_from("<I", rr, SEL_OFF)[0] == sel
        assert rr[STUB_OFF:STUB_OFF+4] == b"\xFF\xFF\xFF\xFF"     # routine UNmodified
        # +0x50 written to flash == the image's own size field (derived, preserved)
        assert struct.unpack("<I", decrypt(rblob[0x2050:0x2054], 0x5A))[0] == sizes[sel]
        # payload body round-trips to the source region's first `size` bytes,
        # except the metadata slots the firmware stuffs (+0x50 size, +0xFC..+0xFF).
        pt = decrypt(rblob[0x2000:], 0x5A)
        meta = lambda i: (0x50 <= i < 0x54) or (0xFC <= i < 0x100)
        assert len(pt) == sizes[sel] + 0x100
        assert all(pt[i] == limg[i] for i in range(sizes[sel]) if not meta(i))
    print("region builder (Main + LCA1/2/3, capture-length + derived +0x50) selftest OK")
    print("nec_firmware_update selftest PASSED")


if __name__ == "__main__":
    _selftest()
