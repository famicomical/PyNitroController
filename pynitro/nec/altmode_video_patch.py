#!/usr/bin/env python3
"""Patch the IS-NITRO NEC Main Program so its DIP alt-mode (loc_11920) does a full
AGB-bus unlock AND configures the video-out (AV-capture) registers.

This supersedes the old AGB-only stub. The injected stub now, after the original
``sub_11A4C`` final-init and the AGB full-unlock, programs the 0x08000010-0x08000036
video-out register block: the YOKO write-enable magic, screen geometry for BOTH
AV-outs, background colour, the hardware cursor position, and the MONITOR-STATE
register. The YOKO write (0x08000010..16) unlocks the AV-out block and is written
UNCONDITIONALLY — the alt-mode patch always enables video out, independent of the
device-info video_out bit (0x7FE080). (It does not itself flip that device-info bit.)

Layout of the stub region (NEC 0x10618, a 4 KiB run of free 0xFF in the Main region):

    0x10618  +0x00  magic  "NVSC"            (4)   <- signature for detection
             +0x04  u8 version (=1)
             +0x05  u8 n_params (=len(TABLE_KEYS))
             +0x06  u16 reserved (0)
             +0x08  u16[n_params] LE param table   <- the GUI reads/edits this
             +0x22  u16 pad (0)
    0x1063C  code: prepare; jarl sub_11A4C; AGB unlock; video config; dispose/ret

AGB save-fix (2026-05-26): the stub no longer calls agb_setBusProtection(0). On the
alt-mode path loc_11920 has already powered the bus and set busProtected=1 before the
0x11952 redirect reaches us, so calling setBusProtection(0) was clearing busProtected
and wiping the 0xF843000 save-buffer marker -> GBA cart saves broke. The stub now just
memsets the save buffer to 0xFF (the harmless side effect) and leaves busProtected=1.

The cmd-0x0001 redirect at 0x11952 (originally ``jarl sub_11A4C``) is repointed to the
CODE start (0x1063C); execution skips the header/table data and runs the code, which
returns to ``lp`` (the ``br loc_1191A`` after the original call site) so normal NEC
mode is byte-behaviour-identical to stock — only the DIP alt-mode path (r29!=0) ever
reaches loc_11920 and therefore this stub.

The table is the single source of truth the GUI preloads from; `build_code` regenerates
the register-write code from the same params, so writing a config = rebuilding the
whole Main with new params and reflashing it (build_main_blob -> send_firmware_update).

All V850 encodings below were verified byte-for-byte against the firmware's own video
block in captures/firmware_6B0468_2025.asm (disassembled with rizin -a v850).

ISND integrity check (2026-05-27): ISND force-reflashes any Main whose per-region
XOR-32 checksum (the XOR of every little-endian u32 across the 0x20000 span, reported
in the cmd-0x18 status block) differs from the firmware ISND bundles -- even when the
version word matches. So a naive code patch trips it and the box gets wiped back to
stock. To stay invisible, ``patch_main`` is CHECKSUM-TRANSPARENT: after writing the
stub + redirect it XORs the net change into a single correction word (CKSUM_SLOT_NEC)
in the dedicated free run, so the patched Main's XOR-32 equals that of the equivalent
UNPATCHED Main. Apply this to a STOCK Main and do NOT bump the version word @0x40
(ISND also wants its exact bundled version) -> the result is indistinguishable from
stock to ISND. See docs/EMULATOR.md.

NOTHING here touches hardware; it only builds a patched Main image.
"""
import os
import struct
import sys

# --- geometry of the Main region / stub -------------------------------------
BASE        = 0x10000          # NEC addr of the Main region (file offset = addr - BASE)
MAIN_SIZE   = 0x20000
STUB_NEC    = 0x10618          # start of the 4 KiB free 0xFF run (header+table+code)
FREE_START  = 0x10618
FREE_END    = 0x11618          # exclusive; the free run is exactly 0x1000 bytes
REDIR_NEC   = 0x11952          # the `jarl sub_11A4C` at the end of loc_11920

MAGIC         = b"NVSC"        # "Nitro Video Stub Config"
STUB_VERSION  = 1
HEADER_LEN    = 0x24           # magic(4)+ver(1)+n(1)+rsv(2)+table(26)+pad(2)
CODE_NEC      = STUB_NEC + HEADER_LEN   # 0x1063C; the redirect jumps here

# Checksum-correction word: a single u32 at the END of the dedicated free run (well
# past the stub code), written LAST so the Main region's XOR-32 integrity checksum
# stays identical to the stock Main. 0xFF (blank) in vanilla.
CKSUM_SLOT_NEC = FREE_END - 4          # 0x11614

# Stock Main XOR-32 = region_xor32() of the UNMODIFIED v3.52 / 0x160 Main (main_clean.bin
# on the user's unit). This is the value ISND holds for its bundled firmware and compares
# the box's cmd-0x18 report against, verified == the bytes in captures/menucheck.pcapng.
# HARDCODED on purpose: re-deriving the target from the input (e.g. by blanking the stub
# region) is only correct when the input is pristine-stock-except-our-stub, and would
# silently produce the wrong value if the base Main has ANY other change (a bumped version
# word, a second patch, ...). A fixed constant makes the correction deterministic and the
# output reproducible regardless of input state. For a DIFFERENT firmware/unit, pass
# patch_main(..., target_xor=<that stock Main's region_xor32>).
STOCK_MAIN_XOR = 0x93C5F6E3

# helper entry points in the Main Program (NEC addrs), verified from the asm
SUB_11A4C            = 0x11a4c
AGB_SETEJECTSTATE    = 0x17064
AGB_16F0C            = 0x16f0c
AGB_MEMSET           = 0x19ebc   # memset(r6=dst, r7=val, r8=size)

# AGB save-fix: we deliberately do NOT call agb_setBusProtection (0x16f68) here.
# Our redirect sits at 0x11952 (the `jarl sub_11A4C` at the *end* of loc_11920),
# and on the DIP alt-mode path loc_11920 has ALREADY executed, in order:
#     0x11934  agb_setBusPowerState(1)   -> bus powered, busPowerState=1
#     0x1193a  agb_setBusProtection(1)   -> busProtected=1, save buffer initialised
# *before* control reaches our stub. The proven savefixed firmware ends in exactly
# that state (busPowerState=1, busProtected=1, buffer=0xFF). Calling
# agb_setBusProtection(0) from the stub would flip busProtected back to 0 and wipe
# the 0xF843000 buffer's `*0xF843000=1` marker -> GBA cart saves stop working.
# So we reproduce ONLY the harmless buffer-clear side effect with a direct memset,
# leaving the firmware's busProtected=1 untouched.
AGB_SRAM_BUF         = 0xf843000  # AGB SRAM / backup emulation buffer base
AGB_SRAM_FILL        = 0xff
AGB_SRAM_LEN         = 0x200

# video-out register block base (NEC space); individual regs are base + disp
VREG_BASE = 0x08000000

# --- parameter schema -------------------------------------------------------
# TABLE_KEYS[0:7] map 1:1 to the indirect screen-geometry register-select low bits
# (sel 0..6: single-X, dual-X, single-Y, dual-Y, spacing, video-mode, aspect).
# The remaining keys are the direct background / cursor / monitor-state registers.
TABLE_KEYS = [
    "single_x", "dual_x", "single_y", "dual_y", "spacing", "video_mode", "aspect",
    "bg_r", "bg_g", "bg_b", "cursor_x", "cursor_y", "monitor_state",
]

# (key, label, default, lo, hi) — order is the GUI display order (== table order).
PARAM_SPECS = [
    ("single_x",      "Single-screen X offset", 196,    0, 0xFFFF),
    ("dual_x",        "Dual-screen X offset",   344,    0, 0xFFFF),
    ("single_y",      "Single-screen Y offset", 46,     0, 0xFFFF),
    ("dual_y",        "Dual-screen Y offset",   46,     0, 0xFFFF),
    ("spacing",       "Dual-screen spacing",    8,      0, 0xFFFF),
    ("video_mode",    "Video mode (0=intl,1=prog)", 0,  0, 1),
    ("aspect",        "Aspect correction (rev J)",  0,  0, 0xFF),
    ("bg_r",          "Background R",           0,      0, 0xFF),
    ("bg_g",          "Background G",           0,      0, 0xFF),
    ("bg_b",          "Background B",           0,      0, 0xFF),
    ("cursor_x",      "Cursor X (255=hide)",    255,    0, 0xFF),
    ("cursor_y",      "Cursor Y (255=hide)",    255,    0, 0xFF),
    ("monitor_state", "Monitor state (0x16)",   0x16,   0, 0xFF),
]
DEFAULT_PARAMS = {k: d for (k, _, d, _, _) in PARAM_SPECS}
assert set(TABLE_KEYS) == set(DEFAULT_PARAMS) and len(TABLE_KEYS) == len(PARAM_SPECS)

ORIG_REDIR = bytes([0x80, 0xff, 0xfa, 0x00])   # jarl sub_11a4c, lp


# --- V850E1 instruction encoders (verified vs firmware_6B0468_2025.asm) ------
def jarl(target, pc):
    """jarl disp22, lp — e.g. 0x7992: 80 ff 80 04 = jarl 0x7e12 (disp 0x480)."""
    disp = (target - pc) & 0x3FFFFF        # 22-bit, must be even
    assert disp & 1 == 0
    hw0 = 0xFF80 | ((disp >> 16) & 0x3F)
    hw1 = disp & 0xFFFF
    return bytes([hw0 & 0xFF, hw0 >> 8, hw1 & 0xFF, hw1 >> 8])


def jarl_target(b, pc):
    """Inverse of jarl(): decode a 4-byte jarl disp22 back to its absolute target,
    or None if `b` is not a jarl disp22."""
    if len(b) < 4:
        return None
    hw0 = b[0] | (b[1] << 8)
    hw1 = b[2] | (b[3] << 8)
    if (hw0 & 0xFFC0) != 0xFF80:
        return None
    disp = ((hw0 & 0x3F) << 16) | hw1
    if disp & 0x200000:
        disp -= 0x400000
    return (pc + disp) & 0xFFFFFFFF


PREPARE_LP4    = bytes([0x88, 0x07, 0x21, 0x00])   # prepare {lp}, 4
DISPOSE_LP_RET = bytes([0x48, 0x06, 0x3f, 0x00])   # dispose 4, {lp}, [lp]  (return)


def mov_imm5_r6(imm):                  # mov imm5, r6  (e.g. 01 32 = mov 1,r6)
    return bytes([imm & 0x1F, 0x32])


def mov_imm32(imm, reg):               # mov imm32, reg1  (2f 06 10 00 00 08 = mov 0x8000010,r15)
    return bytes([0x20 | (reg & 0x1F), 0x06,
                  imm & 0xFF, (imm >> 8) & 0xFF, (imm >> 16) & 0xFF, (imm >> 24) & 0xFF])


def movea_r0(imm, reg):                # movea imm16, r0, reg2  (20 56 59 00 = movea 0x59,r0,r10)
    hw0 = ((reg & 0x1F) << 11) | 0x0620
    return bytes([hw0 & 0xFF, hw0 >> 8, imm & 0xFF, (imm >> 8) & 0xFF])


def st_h(reg2, disp, reg1):            # st.h reg2, disp16[reg1]  (6f 57 00 00 = st.h r10,0[r15])
    assert disp % 2 == 0 and 0 <= disp < 0x10000, "st.h disp must be even/16-bit"
    hw0 = ((reg2 & 0x1F) << 11) | 0x760 | (reg1 & 0x1F)
    return bytes([hw0 & 0xFF, hw0 >> 8, disp & 0xFF, (disp >> 8) & 0xFF])


# --- region integrity checksum (ISND's cmd-0x18 check) ----------------------
def region_xor32(buf, span=MAIN_SIZE):
    """The box's per-region integrity checksum: XOR of every 32-bit little-endian word
    across the region span (Main span = MAIN_SIZE = 0x20000). ISND reads this in the
    cmd-0x18 status block and force-reflashes the region if it differs from its bundled
    firmware's value -- so a patched Main must reproduce the stock XOR to be left alone."""
    x = 0
    for i in range(0, span - 3, 4):
        x ^= int.from_bytes(buf[i:i + 4], "little")
    return x


def unpatched_xor(main_img):
    """region_xor32 of `main_img` with our alt-mode stub removed (free run blanked +
    vanilla redirect restored if it points into the stub) — i.e. the XOR-32 the Main
    would have without our patch. Compare to STOCK_MAIN_XOR to tell whether the base is
    a pristine stock Main (if it differs, the base carries non-stock changes such as a
    bumped version word, and ISND may still reflash on that mismatch)."""
    van = bytearray(main_img)
    van[FREE_START - BASE:FREE_END - BASE] = b"\xFF" * (FREE_END - FREE_START)
    roff = REDIR_NEC - BASE
    tgt = jarl_target(bytes(van[roff:roff + 4]), REDIR_NEC)
    if tgt is not None and FREE_START <= tgt < FREE_END:
        van[roff:roff + 4] = ORIG_REDIR
    return region_xor32(van)


# --- stub construction ------------------------------------------------------
def _norm_params(params):
    p = dict(DEFAULT_PARAMS)
    if params:
        for k, v in params.items():
            if k in p:
                p[k] = int(v) & 0xFFFF
    return p


def build_header(params):
    p = _norm_params(params)
    h = bytearray()
    h += MAGIC
    h.append(STUB_VERSION)
    h.append(len(TABLE_KEYS))
    h += b"\x00\x00"
    for k in TABLE_KEYS:
        h += struct.pack("<H", p[k] & 0xFFFF)
    h += b"\x00" * (HEADER_LEN - len(h))
    assert len(h) == HEADER_LEN
    return bytes(h)


def build_code(params):
    """Emit the V850 code at CODE_NEC: original sub_11A4C, AGB full-unlock, then the
    video-out register configuration. r19 holds the 0x08000000 register base; r10 is
    the value scratch. All video writes happen AFTER the function calls so nothing is
    live across a call."""
    p = _norm_params(params)
    code = bytearray()

    def J(target):
        code.extend(jarl(target, CODE_NEC + len(code)))

    code += PREPARE_LP4
    J(SUB_11A4C)                                   # original final init
    code += mov_imm5_r6(0); J(AGB_SETEJECTSTATE)   # eject = 0 (cart inserted)
    # Clear the AGB save buffer to 0xFF directly, WITHOUT agb_setBusProtection(0):
    # loc_11920 already set busProtected=1; preserve it (see AGB_MEMSET note above).
    code += mov_imm32(AGB_SRAM_BUF, 6)             # r6 = dst  = 0xF843000
    code += movea_r0(AGB_SRAM_FILL, 7)             # r7 = val  = 0xFF
    code += movea_r0(AGB_SRAM_LEN, 8)              # r8 = size = 0x200
    J(AGB_MEMSET)                                  # memset(0xF843000, 0xFF, 0x200)
    code += mov_imm5_r6(1); J(AGB_16F0C)           # 0xF840004 tweak

    # --- video-out configuration ---
    code += mov_imm32(VREG_BASE, 19)               # r19 = 0x08000000 (reg base)

    def wr(disp, val):                             # write 8-bit-valid value to base+disp
        val &= 0xFFFF
        if val == 0:
            code.extend(st_h(0, disp, 19))         # st.h r0, disp[r19]
        else:
            code.extend(movea_r0(val, 10))         # movea val, r0, r10
            code.extend(st_h(10, disp, 19))        # st.h r10, disp[r19]

    # 0) YOKO write-enable magic ('Y','O','K','O' to 0x10/0x12/0x14/0x16) — written
    #    UNCONDITIONALLY: the alt-mode patch always enables video out (per user choice),
    #    independent of the device-info video_out bit. NOT user-configurable.
    for disp, ch in ((0x10, 0x59), (0x12, 0x4F), (0x14, 0x4B), (0x16, 0x4F)):
        wr(disp, ch)

    # 1) screen geometry: indirect select(0x30)+data(0x34 LSB / 0x36 MSB), both AV-outs
    #    (first pass select bit7=1, second bit7=0), sel 0..6 in TABLE order.
    for av in (0x80, 0x00):
        for sel in range(7):
            data = p[TABLE_KEYS[sel]] & 0xFFFF
            wr(0x30, av | sel)                     # select register
            wr(0x34, data & 0xFF)                  # data LSB
            wr(0x36, (data >> 8) & 0xFF)           # data MSB
    # 2) background colour (R/G/B)
    wr(0x18, p["bg_r"]); wr(0x1A, p["bg_g"]); wr(0x1C, p["bg_b"])
    # 3) cursor position (255,255 = parked off-screen)
    wr(0x2C, p["cursor_x"]); wr(0x2E, p["cursor_y"])
    # 4) MONITOR STATE
    wr(0x1E, p["monitor_state"])

    code += DISPOSE_LP_RET
    return bytes(code)


def build_stub(params=None):
    """Return (header_bytes, code_bytes) for the given params."""
    return build_header(params), build_code(params)


def parse_stub(main_img):
    """Read the video-config params out of a (full 0x20000) Main image's stub region.
    Returns a params dict if our signature is present and the layout matches, else None."""
    soff = STUB_NEC - BASE
    if bytes(main_img[soff:soff + 4]) != MAGIC:
        return None
    version = main_img[soff + 4]
    n = main_img[soff + 5]
    if version != STUB_VERSION or n != len(TABLE_KEYS):
        return None
    vals = struct.unpack_from("<%dH" % n, main_img, soff + 8)
    return {k: v for k, v in zip(TABLE_KEYS, vals)}


def stub_present(main_img):
    """True if the redirect at 0x11952 already points into the free stub region
    (an alt-mode stub of ours is installed), regardless of signature/version."""
    roff = REDIR_NEC - BASE
    tgt = jarl_target(bytes(main_img[roff:roff + 4]), REDIR_NEC)
    return tgt is not None and FREE_START <= tgt < FREE_END


def patch_main(main_img, params=None, fix_checksum=True, target_xor=None):
    """Apply the alt-mode AGB+video stub (with `params`, defaults filled in) to a full
    0x20000 Main Program image and return the patched image. Idempotent: works on a
    vanilla Main (redirect -> sub_11A4C) or on one that already has our stub (redirect
    -> free region) by clearing the 4 KiB free run and rewriting. Refuses if the
    redirect is something else (e.g. an unrelated hook) to avoid clobbering it.

    When `fix_checksum` (default True) the patch is made CHECKSUM-NEUTRAL: a single
    correction word in the free run (CKSUM_SLOT_NEC) is set so the patched Main's
    XOR-32 (region_xor32) equals `target_xor`, which defaults to the hardcoded
    STOCK_MAIN_XOR -- the value ISND expects for its bundled firmware. So ISND's
    cmd-0x18 integrity check passes. The correction is recomputed from the fully-built
    image, so it stays correct for ANY video-config params. Pass `target_xor` to match a
    different firmware/unit. NB: this only fixes the XOR; ISND also checks the version
    word @0x40, so keep the base a stock 0x160 Main (see unpatched_xor for a check)."""
    img = bytearray(main_img)
    if len(img) != MAIN_SIZE:
        raise ValueError("Main image must be 0x%X bytes (got 0x%X)" % (MAIN_SIZE, len(img)))
    if img[:19] != b"INTELLIGENT SYSTEMS" or img[0x20:0x2C] != b"Main Program":
        raise ValueError("not a Main Program region image (header mismatch)")

    roff = REDIR_NEC - BASE
    tgt = jarl_target(bytes(img[roff:roff + 4]), REDIR_NEC)
    header = build_header(params)
    code = build_code(params)
    blob = header + code
    if STUB_NEC + len(blob) > FREE_END:
        raise ValueError("stub (0x%X bytes) overruns the free region" % len(blob))

    if tgt == SUB_11A4C:
        # vanilla loc_11920 -> the bytes we will occupy must be blank
        soff = STUB_NEC - BASE
        if any(b != 0xFF for b in img[soff:soff + len(blob)]):
            raise ValueError("redirect is vanilla but the stub region is not blank; refusing")
    elif tgt is not None and FREE_START <= tgt < FREE_END:
        # an existing stub of ours -> clear the whole (dedicated) free run, rewrite
        img[FREE_START - BASE:FREE_END - BASE] = b"\xFF" * (FREE_END - FREE_START)
    else:
        raise ValueError(
            "redirect @0x11952 is neither vanilla (jarl sub_11A4C) nor a known alt-mode "
            "stub (jarl into 0x%05X-0x%05X); refusing to clobber it." % (FREE_START, FREE_END))

    soff = STUB_NEC - BASE
    img[soff:soff + len(blob)] = blob
    img[roff:roff + 4] = jarl(CODE_NEC, REDIR_NEC)

    if fix_checksum:
        coff = CKSUM_SLOT_NEC - BASE
        if (CODE_NEC - BASE) + len(code) > coff:
            raise ValueError("stub code overruns the checksum-correction slot")
        # Drive region_xor32 to the value ISND expects (stock by default), so its
        # cmd-0x18 integrity check passes. Hardcoded, not re-derived from the input.
        if target_xor is None:
            target_xor = STOCK_MAIN_XOR
        # The slot is in the (blank) free run; XOR the net delta into it.
        correction = region_xor32(img) ^ (target_xor & 0xFFFFFFFF)
        old = int.from_bytes(img[coff:coff + 4], "little")
        img[coff:coff + 4] = (old ^ correction).to_bytes(4, "little")
        assert region_xor32(img) == (target_xor & 0xFFFFFFFF)
    return bytes(img)


# --- self-test + CLI --------------------------------------------------------
def _selftest():
    # round-trip: build defaults onto a blank-but-valid Main, parse back, compare
    img = bytearray(b"\xFF" * MAIN_SIZE)
    img[0:19] = b"INTELLIGENT SYSTEMS"
    img[0x20:0x2C] = b"Main Program"
    img[REDIR_NEC - BASE:REDIR_NEC - BASE + 4] = ORIG_REDIR  # vanilla redirect

    patched = patch_main(bytes(img), DEFAULT_PARAMS)
    assert parse_stub(patched) == DEFAULT_PARAMS, "default round-trip failed"
    assert stub_present(patched)
    # redirect now points at CODE_NEC
    roff = REDIR_NEC - BASE
    assert jarl_target(patched[roff:roff + 4], REDIR_NEC) == CODE_NEC

    # custom params round-trip + idempotent re-patch (replace path)
    custom = dict(DEFAULT_PARAMS, single_x=200, dual_x=350, monitor_state=0x26, bg_b=0x10)
    again = patch_main(patched, custom)        # patched already has a stub -> replace
    assert parse_stub(again) == custom, "custom round-trip failed"
    # re-patching is stable
    assert patch_main(again, custom) == again, "re-patch not idempotent"

    # encoder ground-truth spot checks (vs firmware disasm)
    assert jarl(0x7e12, 0x7992) == bytes.fromhex("80ff8004")
    assert mov_imm32(0x8000010, 15) == bytes.fromhex("2f06100000 08".replace(" ", ""))
    assert movea_r0(0x59, 10) == bytes.fromhex("20565900")
    assert st_h(10, 0, 15) == bytes.fromhex("6f570000")
    assert st_h(11, 0x8c60, 4) == bytes.fromhex("645f608c")

    # memset(0xF843000, 0xFF, 0x200) arg encodings — byte-identical to the proven
    # savefixed stub embedded in ISNITRO_gamehookvideo_savefixed.dll
    assert mov_imm32(AGB_SRAM_BUF, 6) == bytes.fromhex("26060030840f")
    assert movea_r0(AGB_SRAM_FILL, 7) == bytes.fromhex("203eff00")
    assert movea_r0(AGB_SRAM_LEN, 8) == bytes.fromhex("20460002")

    # AGB save-fix invariants on the generated code: must memset the save buffer and
    # must NOT call agb_setBusProtection (0x16f68), which would clear busProtected.
    code = build_code(None)
    targets = set()
    for i in range(0, len(code) - 3, 2):
        t = jarl_target(code[i:i + 4], CODE_NEC + i)
        if t is not None:
            targets.add(t)
    assert 0x16f68 not in targets, "stub must NOT call agb_setBusProtection (save-fix)"
    assert AGB_MEMSET in targets, "stub must memset the AGB save buffer (save-fix)"
    assert {SUB_11A4C, AGB_SETEJECTSTATE, AGB_16F0C} <= targets, "missing expected AGB calls"

    # --- checksum correction ---
    van = bytearray(b"\xFF" * MAIN_SIZE)
    van[0:19] = b"INTELLIGENT SYSTEMS"
    van[0x20:0x2C] = b"Main Program"
    van[REDIR_NEC - BASE:REDIR_NEC - BASE + 4] = ORIG_REDIR
    van[0x2000:0x2000 + 64] = bytes(range(64))      # non-FF content (outside the free run) so xor is non-trivial
    vx = region_xor32(van)

    # default target is the HARDCODED stock xor, regardless of the input's own xor
    pd = patch_main(bytes(van), DEFAULT_PARAMS)
    assert region_xor32(pd) == STOCK_MAIN_XOR, "default target must be STOCK_MAIN_XOR"

    # with an explicit target the correction hits it, and is RECOMPUTED for changed
    # params (so editing video settings always updates the repair word)
    p1 = patch_main(bytes(van), DEFAULT_PARAMS, target_xor=vx)
    assert region_xor32(p1) == vx, "correction did not hit the target xor"
    p2 = patch_main(bytes(van), dict(DEFAULT_PARAMS, single_x=200, bg_b=0x10), target_xor=vx)
    assert region_xor32(p2) == vx, "correction not recomputed for changed params"
    assert p2 != p1, "changed params should change the build"
    p3 = patch_main(p1, DEFAULT_PARAMS, target_xor=vx)   # re-patch idempotent
    assert region_xor32(p3) == vx and p3 == p1, "re-patch not idempotent"

    # unpatched_xor recovers the base (stub removed); fix_checksum=False leaves it changed
    assert unpatched_xor(p1) == vx, "unpatched_xor should recover the base xor"
    p0 = patch_main(bytes(van), DEFAULT_PARAMS, fix_checksum=False)
    assert region_xor32(p0) != vx, "expected the un-corrected patch to change the checksum"
    # the correction lives only in the dedicated free run, never in the stub/redirect
    assert p1[:FREE_START - BASE] == p0[:FREE_START - BASE]
    assert p1[REDIR_NEC - BASE:REDIR_NEC - BASE + 4] == p0[REDIR_NEC - BASE:REDIR_NEC - BASE + 4]

    print("altmode_video_patch selftest PASSED (stub %d bytes: %d header + %d code; "
          "checksum-neutral, default target 0x%08X)"
          % (HEADER_LEN + len(build_code(None)), HEADER_LEN, len(build_code(None)),
             STOCK_MAIN_XOR))


def _cli(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Patch a Main Program image with the alt-mode AGB+video stub.")
    ap.add_argument("infile", nargs="?", help="input Main region image (0x20000 bytes)")
    ap.add_argument("outfile", nargs="?", help="output patched image")
    ap.add_argument("--selftest", action="store_true", help="run the round-trip self-test and exit")
    ap.add_argument("--no-fix-checksum", action="store_true",
                    help="do NOT make the patch checksum-transparent (will trip ISND's "
                         "cmd-0x18 XOR-32 integrity check and get the box reflashed)")
    for key, label, default, lo, hi in PARAM_SPECS:
        ap.add_argument("--" + key, type=lambda s: int(s, 0), default=None,
                        help="%s (default %d, range %d..%d)" % (label, default, lo, hi))
    args = ap.parse_args(argv)
    if args.selftest or not args.infile:
        _selftest()
        return
    params = {k: getattr(args, k) for (k, *_ ) in PARAM_SPECS if getattr(args, k) is not None}
    img = open(args.infile, "rb").read()
    fix = not args.no_fix_checksum
    out = patch_main(img, params, fix_checksum=fix)
    outfile = args.outfile or (os.path.splitext(args.infile)[0] + "_altmode.bin")
    open(outfile, "wb").write(out)
    p = parse_stub(out)
    print("patched %s -> %s" % (args.infile, outfile))
    print("  stub @ NEC 0x%05X (magic %s), code @ 0x%05X, redirect @ 0x%05X"
          % (STUB_NEC, MAGIC.decode(), CODE_NEC, REDIR_NEC))
    for key, label, *_ in PARAM_SPECS:
        print("    %-26s = %d (0x%X)" % (label, p[key], p[key]))
    ox = region_xor32(out)
    base = unpatched_xor(img)
    if not fix:
        print("  region XOR-32 = 0x%08X  (checksum NOT corrected -- ISND will force-reflash!)" % ox)
    else:
        print("  region XOR-32 = 0x%08X  (target stock 0x%08X: %s)"
              % (ox, STOCK_MAIN_XOR, "OK" if ox == STOCK_MAIN_XOR else "MISMATCH"))
        if base != STOCK_MAIN_XOR:
            print("  WARNING: base Main (stub removed) = 0x%08X != stock 0x%08X -- the input "
                  "is NOT a pristine stock 0x160 Main (e.g. a bumped version word). The XOR is "
                  "forced to stock, but ISND may still reflash on the version/content mismatch."
                  % (base, STOCK_MAIN_XOR))


if __name__ == "__main__":
    _cli(sys.argv[1:])
