#!/usr/bin/env python3
"""Build dualmode_ipl_v7.bin = the v6 dual-mode IS-NITRO DS-IPL
firmware, but with the part1/2 CRC16 restored to the STOCK value so it
passes ISND's check. Supports the IPL builds listed in REVISIONS (2006-02-20,
hardware-validated; 2004-10-05, ported by disassembly, see the table).

ISND validates the DS-IPL by its CRC (it does NOT use an xor32-style check here
-- that XOR-32 gate is the NEC Main). The v6 edits move the part1/2 CRC16 off
stock, so a patched IPL is rejected. v7 applies the identical v6 patch set, then
writes one correction word into arm9boot's dead padding so that the stored
part1/2 CRC16 again equals 0xB4DD. No code/behaviour change vs v6.

WHY arm9-only (NOT a per-module fix): the DS firmware header stores a SINGLE
part1/2 CRC -- the joint CRC-16/MODBUS over (arm9boot || arm7boot) at header
0x06. That joint value is the only CRC ISND can read for parts 1/2; there is no
separate arm7boot CRC anywhere. So restoring the joint to 0xB4DD is sufficient,
and it can be done entirely in arm9boot.

WHY NOT touch arm7boot: arm7boot has no safe dead padding. Its one large zero run
(0x0AC5F, 241 B) is NOT padding -- it is a zero-initialised RAM data block: 23
absolute pointer constants in arm7boot point into it (several straight into where
a correction word would go). Writing there would set the initial values of live
variables. arm9boot's 0x104f5 run, by contrast, is genuinely dead: 0 PC-relative
loads and 0 pointer constants target it, and the v6 stub already ran there on
hardware. The correction word goes in the tail of that run, after the stub.

Joint CRC = process(arm7', init = CRC16(arm9')), and CRC is affine/invertible in
the seed, so adjusting arm9boot alone can hit any joint target -- the solve is an
XOR-basis over the arm9 padding bits.

This is the self-contained (pure-Python) build: it depends only on iplrepack.py
(the IPL unpack/repack port) sitting next to it -- no C `iplrepack` binary and no
arm-none-eabi toolchain. The boot stub is pre-assembled and embedded below.

Usage:
  python -m pynitro.ipl.build_dualmode_v7 [stock_firmware.bin] [out.bin] [--slow-card]
    defaults: firmware_dump.bin -> dualmode_ipl_v7.bin
    --slow-card: alt-mode-only 4.2 MHz card clock for flashcarts (CARD_SLOW_STUB)
"""
import os
import sys

from . import iplrepack

BASE = 0x02320000               # arm9boot load address (ram)
CORR_LEN = 16                  # arm9 correction bytes (>=2 needed; 16 = ample margin)
ISONDEBUGGER = 0x027FF814      # SHARED_WORK isOnDebugger (same in every build)

# ---------------------------------------------------------------------------
# Per-IPL-revision patch offsets. The DS firmware header stores a 5-byte BCD
# build timestamp at 0x18 (minute, hour, day, month, year-2000); it selects the
# row. Every offset is into the *decompressed* arm9boot/arm7boot modules.
#   a9_hang   : IplInit `b .` (FE E7)                     -> NOP
#   a7_gate   : (offset, old, new) of the isOnDebugger `beq` displacement in
#               the ARM7 resource-init block -> retarget to the flash-load bl
#   a9_gate   : (offset, old bytes) of the `beq` in IplCheckCardBootSkipUI -> NOP
#   boot_off  : `bl IplSetBootFlag(BOOT_NITRO_CARD)` in IplCheckCardBootSkipUI
#   setbootflag, ret0 : IplSetBootFlag entry / IplCheckCardBootSkipUI return-0
#               epilogue (stub literals)
#   stub_off, run_end : 4-aligned start of the dead zero run that takes the
#               stub + CRC correction, and the run's end (exclusive)
# The 2004 row was derived from the 2006 one by matching the same functions
# in the older build (every site, callee and the IplLaunchNitroCard selector
# verified by disassembly); the 2004 build lacks the SYSMi_IsDebuggerBanner-
# ViewMode check and one ARM7 predicate, hence the different gate bytes.
OFF_BUILD_TS = 0x18
BUILD_TS_LEN = 5
REVISIONS = {
    bytes((0x59, 0x20, 0x20, 0x02, 0x06)): dict(      # 2006-02-20 20:59
        name="IPL VIB2.11 May 26 2005", hw_validated=True,
        a9_hang=0x7ab2, a7_gate=(0x6e8, 0x0D, 0x07), a9_gate=(0x78d0, b"\x3b\xd0"),
        boot_off=0x7922, setbootflag=0x7554, ret0=0x794a,
        stub_off=0x104f8, run_end=0x1054c),
    bytes((0x07, 0x11, 0x05, 0x10, 0x04)): dict(      # 2004-10-05 11:07
        name="IPL VIB2.11 Oct 5 2004", hw_validated=False,
        a9_hang=0x75e2, a7_gate=(0x64a, 0x09, 0x03), a9_gate=(0x742c, b"\x26\xd0"),
        boot_off=0x7454, setbootflag=0x70ac, ret0=0x747c,
        stub_off=0x10738, run_end=0x1078c),
}


def _bcd(b):
    hi, lo = b >> 4, b & 0xF
    if hi > 9 or lo > 9:
        raise ValueError("not BCD: 0x%02X" % b)
    return hi * 10 + lo


def read_build_timestamp(fw):
    """Return the 5 raw BCD bytes of the firmware-header build timestamp (0x18)."""
    if len(fw) < OFF_BUILD_TS + BUILD_TS_LEN:
        raise ValueError("file too small to be a DS firmware image (%d bytes)" % len(fw))
    return bytes(fw[OFF_BUILD_TS:OFF_BUILD_TS + BUILD_TS_LEN])


def format_build_timestamp(ts):
    """Format the 5 BCD bytes (minute, hour, day, month, year-2000) as a
    human-readable string; falls back to raw hex if they aren't valid BCD."""
    try:
        mi, hh, dd, mo, yy = (_bcd(b) for b in ts)
        return "20%02d-%02d-%02d %02d:%02d" % (yy, mo, dd, hh, mi)
    except ValueError:
        return ts.hex()

# ---------------------------------------------------------------------------
# The v6 boot stub, pre-assembled (arm-none-eabi-as -mthumb -mcpu=arm946e-s).
# Embedded so this script needs no toolchain. Source (Thumb), for provenance:
#
#     _start:
#         ldr  r1, =0x027FF814        @ isOnDebugger
#         ldrh r1, [r1]
#         cmp  r1, #0
#         bne  .Lboot                 @ normal/debugger mode -> boot as before
#         ldr  r3, =<ret0|1>          @ alt mode -> IplCheckCardBootSkipUI ret-0 (thumb)
#         bx   r3
#     .Lboot:
#         push {lr}                   @ lr = 0x2327926 (cont. at IplStartBootNitroCard)
#         ldr  r3, =<IplSetBootFlag|1> @ (thumb); r0 still = 0x20
#         blx  r3
#         pop  {pc}
#         .ltorg
# ---------------------------------------------------------------------------
STUB_CODE = bytes.fromhex("04490988002901d1034b184700b5034b984700bd")   # 20 B
assert len(STUB_CODE) == 20


# ---------------------------------------------------------------------------
# Optional "slow card" patch (--slow-card): alt mode only. IplInit's alt branch
# ends with `str r1,[r2]` (r1 = header[0x60] | 0x406000, r2 = &header[0x60]) and
# the hang we NOP; both words are the cart header's ROMCTRL settings (0x60 normal
# commands, 0x64 KEY1 commands) that every later card transfer is built from.
# Replace those 4 bytes with a `bl` to a 20-byte stub in the dead run (right
# after the CRC correction word) that ORs ROMCTRL bit 27 (4.2 MHz card clock
# instead of 6.7) into BOTH words before storing. Gives the box's slot-1 bridge
# twice the setup time per bit; retail carts just boot a little slower. Meant for
# flashcarts (tight FPGA timings) that fail through the bridge. Normal mode is
# untouched (the branch is isOnDebugger == 0 only).
#     ldr r3,=0x08000000 ; orrs r1,r3 ; str r1,[r2] ; ldr r0,[r2,#4]
#     orrs r0,r3 ; str r0,[r2,#4] ; bx lr ; nop ; .word 0x08000000
CARD_SLOW_STUB = bytes.fromhex("034b194311605068184350607047c04600000008")
assert len(CARD_SLOW_STUB) == 20


def make_stub(rev):
    """The 32-byte stub: position-independent code + its 3-word literal pool
    (isOnDebugger, IplCheckCardBootSkipUI ret-0 epilogue, IplSetBootFlag)."""
    import struct
    return STUB_CODE + struct.pack("<III", ISONDEBUGGER,
                                   (BASE + rev["ret0"]) | 1, (BASE + rev["setbootflag"]) | 1)


# ---- GF(2) XOR-basis affine solve: choose padding bits so eval_crc() == target ----
def solve_correction(eval_crc, nbytes, target, label):
    """eval_crc(region_bytes) -> the CRC16 of the assembled image with the
    correction region set to region_bytes. Returns the nbytes to write."""
    c0 = eval_crc(b"\x00" * nbytes)
    want = target ^ c0                              # 16-bit delta to produce
    cols = []
    for k in range(nbytes):
        for bit in range(8):
            rb = bytearray(nbytes); rb[k] ^= (1 << bit)
            cols.append((eval_crc(bytes(rb)) ^ c0, (k, bit)))
    pivots = {}                                     # high-bit -> (colval, var_mask)
    for idx, (v, _) in enumerate(cols):
        cur_v, cur_m = v, (1 << idx)
        while cur_v:
            hb = cur_v.bit_length() - 1
            if hb in pivots:
                pv, pm = pivots[hb]; cur_v ^= pv; cur_m ^= pm
            else:
                pivots[hb] = (cur_v, cur_m); break
    t, sel = want, 0
    while t:
        hb = t.bit_length() - 1
        if hb not in pivots:
            raise RuntimeError("%s: CRC delta 0x%04X unreachable in %d padding bytes"
                               % (label, want, nbytes))
        pv, pm = pivots[hb]; t ^= pv; sel ^= pm
    out = bytearray(nbytes)
    i = 0
    while sel:
        if sel & 1:
            k, bit = cols[i][1]; out[k] ^= (1 << bit)
        sel >>= 1; i += 1
    return bytes(out)


def thumb_bl(src_ram, dst_ram):
    off = dst_ram - (src_ram + 4)
    lo = 0xF000 | ((off >> 12) & 0x7FF)
    hi = 0xF800 | ((off >> 1) & 0x7FF)
    return bytes((lo & 0xFF, lo >> 8, hi & 0xFF, hi >> 8))


def patch(buf, off, old, new, what, log=print):
    cur = bytes(buf[off:off + len(old)])
    if cur != old:
        raise ValueError("%s: @0x%x expected %s got %s"
                         % (what, off, old.hex(), cur.hex()))
    buf[off:off + len(new)] = new
    log("  ok %s: @0x%x %s -> %s" % (what, off, old.hex(), new.hex()))


def supported_revisions():
    """Human-readable list of the IPL revisions in REVISIONS."""
    return ", ".join("%s (%s)" % (format_build_timestamp(ts), r["name"])
                     for ts, r in REVISIONS.items())


def build(base_fw, log=print, slow_card=False):
    """Build the dual-mode DS-IPL image from `base_fw` (raw stock firmware bytes)
    and return the rebuilt image bytes. `slow_card` adds the alt-mode-only
    4.2 MHz card-clock patch (see CARD_SLOW_STUB).

    Raises ValueError/RuntimeError on any validation failure: an unsupported
    build timestamp (no REVISIONS row), unexpected bytes at a patch site, or a
    failed CRC/end-to-end check."""
    base_fw = bytes(base_fw)

    if not any(base_fw[:0x200]):
        raise ValueError("firmware header is all zeros: this is a blank dump, not "
                         "firmware (flash JEDEC read 000000 when it was dumped). "
                         "Re-dump with the current driver and the DS running.")
    ts = read_build_timestamp(base_fw)
    rev = REVISIONS.get(ts)
    if rev is None:
        raise ValueError(
            "firmware build timestamp %s (%s) is not a supported IPL revision.\n"
            "Supported: %s.\nThe dual-mode patch offsets are only valid for "
            "those exact IPL builds; refusing to build."
            % (ts.hex(), format_build_timestamp(ts), supported_revisions()))
    log("build timestamp %s (%s): %s%s"
        % (ts.hex(), format_build_timestamp(ts), rev["name"],
           "" if rev["hw_validated"] else "  [patch set NOT yet hardware-validated]"))
    STUB = make_stub(rev)
    STUB_OFF, BOOT_OFF, RUN9_END = rev["stub_off"], rev["boot_off"], rev["run_end"]
    a7_off, a7_old, a7_new = rev["a7_gate"]
    g9_off, g9_old = rev["a9_gate"]

    info = iplrepack.unpack(base_fw)
    a9_orig, a7_orig = info["arm9boot"], info["arm7boot"]
    tgt_joint = iplrepack.crc16_modbus(a9_orig + a7_orig)   # stock part1/2 CRC (header 0x06)
    log("stock part1/2 CRC16 (joint) = 0x%04X" % tgt_joint)

    a9 = bytearray(a9_orig)
    a7 = bytearray(a7_orig)

    # ---- v6 patch set (identical) ----
    log("assembled stub: %d bytes" % len(STUB))
    if bytes(a9[STUB_OFF:STUB_OFF + len(STUB)]) != b"\x00" * len(STUB):
        raise ValueError("stub destination @0x%x is not zero-filled" % STUB_OFF)
    log("v2 base patches:")
    patch(a9, rev["a9_hang"], b"\xfe\xe7", b"\xc0\x46", "arm9 IplInit hang->nop", log)
    patch(a7, a7_off, bytes([a7_old]), bytes([a7_new]), "arm7 resource gate", log)
    log("v4 gate patch:")
    patch(a9, g9_off, g9_old, b"\xc0\x46", "arm9 !isOnDebugger beq->nop", log)
    log("v6 boot-cut patch:")
    a9[STUB_OFF:STUB_OFF + len(STUB)] = STUB
    log("  ok stub: %d bytes @0x%x (ram 0x%x)" % (len(STUB), STUB_OFF, BASE + STUB_OFF))
    patch(a9, BOOT_OFF, thumb_bl(BASE + BOOT_OFF, BASE + rev["setbootflag"]),
          thumb_bl(BASE + BOOT_OFF, BASE + STUB_OFF), "arm9 bl IplSetBootFlag->stub", log)

    # ---- v7: restore the joint part1/2 CRC via arm9 dead-padding (verified safe) ----
    corr_off = (STUB_OFF + len(STUB) + 3) & ~3      # 4-align past the stub
    if corr_off + CORR_LEN > RUN9_END:
        raise RuntimeError("correction word runs past the dead run")
    if bytes(a9[corr_off:corr_off + CORR_LEN]) != b"\x00" * CORR_LEN:
        raise RuntimeError("arm9 correction slot not dead-zero")

    if slow_card:
        site = rev["a9_hang"] - 2                      # `str r1,[r2]` + the NOPed hang
        s2 = corr_off + CORR_LEN                       # 4-aligned, past the correction word
        if s2 + len(CARD_SLOW_STUB) > RUN9_END:
            raise RuntimeError("slow-card stub runs past the dead run")
        if bytes(a9[s2:s2 + len(CARD_SLOW_STUB)]) != b"\x00" * len(CARD_SLOW_STUB):
            raise RuntimeError("slow-card stub slot not dead-zero")
        a9[s2:s2 + len(CARD_SLOW_STUB)] = CARD_SLOW_STUB
        patch(a9, site, b"\x11\x60\xc0\x46", thumb_bl(BASE + site, BASE + s2),
              "arm9 IplInit alt branch -> slow-card stub", log)
        log("  ok slow-card stub: %d bytes @0x%x (ram 0x%x)" % (len(CARD_SLOW_STUB), s2, BASE + s2))

    def eval_joint(region):
        buf = bytearray(a9); buf[corr_off:corr_off + CORR_LEN] = region
        return iplrepack.crc16_modbus(bytes(buf) + bytes(a7))
    fix = solve_correction(eval_joint, CORR_LEN, tgt_joint, "arm9/joint")
    a9[corr_off:corr_off + CORR_LEN] = fix
    log("  joint CRC fix @0x%x (%d B): %s" % (corr_off, CORR_LEN, fix.hex()))
    if iplrepack.crc16_modbus(bytes(a9) + bytes(a7)) != tgt_joint:
        raise RuntimeError("joint CRC not restored")

    # ---- repack (pure Python; recompress+encrypt parts 1/2, copy 3/4/5) ----
    img = iplrepack.repack(base_fw, arm9=bytes(a9), arm7=bytes(a7))

    # ---- end-to-end verification: re-unpack the rebuilt image ----
    v = iplrepack.unpack(img)
    va9, va7 = v["arm9boot"], v["arm7boot"]
    cj = iplrepack.crc16_modbus(va9 + va7)
    h = rev["a9_hang"]
    hang_ok = (va9[h - 2:h + 2] == bytes(a9[h - 2:h + 2]) if slow_card else va9[h:h + 2] == b"\xc0\x46")
    code_ok = (hang_ok and va7[a7_off] == a7_new and
               va9[g9_off:g9_off + 2] == b"\xc0\x46" and va9[STUB_OFF:STUB_OFF + 2] != b"\x00\x00")
    # confirm arm7boot is byte-identical to v6's (only the functional gate patch)
    a7v6 = bytearray(a7_orig); a7v6[a7_off] = a7_new
    arm7_clean = (va7 == bytes(a7v6))
    log("\nrebuilt part1/2 CRC16 (joint) = 0x%04X  (stock 0x%04X)" % (cj, tgt_joint))
    log("  joint CRC == stock: %s" % (cj == tgt_joint))
    log("  dual-mode patches present: %s" % code_ok)
    log("  arm7boot untouched except 0x%x patch (no padding edit): %s" % (a7_off, arm7_clean))
    if not (cj == tgt_joint and code_ok and arm7_clean):
        raise RuntimeError("VERIFICATION FAILED")
    return img


def main():
    slow_card = "--slow-card" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--slow-card"]
    stock = args[0] if len(args) > 0 else "firmware_dump.bin"
    out = args[1] if len(args) > 1 else "dualmode_ipl_v7.bin"
    if not os.path.exists(stock):
        sys.exit("stock firmware not found: %s\n"
                 "  pass it as the first argument: python -m pynitro.ipl.build_dualmode_v7 <stock.bin> [out.bin]"
                 % stock)

    base_fw = open(stock, "rb").read()
    try:
        img = build(base_fw, slow_card=slow_card)
    except (ValueError, RuntimeError) as e:
        sys.exit(str(e))
    open(out, "wb").write(img)
    print("\nWROTE %s (%d bytes)" % (out, len(img)))


if __name__ == "__main__":
    main()
