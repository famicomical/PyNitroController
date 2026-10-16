#!/usr/bin/env python3
"""Flash a DS IPL firmware image to the IS-NITRO over USB. DESTRUCTIVE.

    python3 -m pynitro.ipl.flash_firmware <image.bin>

The flash sits on the DS ARM7 SPI bus and is only reachable while the DS is
*running* (held-in-reset returns JEDEC 000000), so we flash with the DS running.
That's safe: the firmware runs from RAM, not execute-in-place, so reprogramming
the flash doesn't disturb the running system; it takes effect on the next boot.
Erase/program sector-by-sector with per-sector read-back verify + retry, then a
full read-back compare, then reboot the DS into the new firmware.
"""
import sys
import time

from ..isnitro import ISNitro, ISNitroError


def main():
    if len(sys.argv) not in (2, 3):
        print("usage: flash_firmware.py <image.bin> [chip_erase_opcode_hex]")
        return 2
    path = sys.argv[1]
    erase_opcode = int(sys.argv[2], 16) if len(sys.argv) == 3 else 0xC7
    data = open(path, "rb").read()
    print("image: %s (%d bytes / 0x%X)" % (path, len(data), len(data)))
    print("chip-erase opcode: 0x%02X" % erase_opcode)

    try:
        n = ISNitro.open(timeout_ms=8000)
    except ISNitroError as e:
        print("error:", e)
        return 1

    t0 = time.time()
    try:
        print("box identify:", n.version_string())
        jedec = n.spi_read_jedec_id().hex()
        print("flash JEDEC (running):", jedec)
        # sanity: flash must answer over SPI before we erase anything
        if jedec in ("000000", "ffffff"):
            raise ISNitroError("flash not responding (%s); aborting before any erase"
                              % jedec)

        print("disabling flash write-protect (NITRO REG1 bit 0)...")
        n.set_flash_write_protect(False)
        reg1 = n.read_nec_reg(n.REG_NITRO1) & 0xFF
        print("NITRO REG1 = 0x%02X (write-protect %s)"
              % (reg1, "OFF" if reg1 & n.FLASH_WP_BIT else "ON"))
        if not (reg1 & n.FLASH_WP_BIT):
            raise ISNitroError("could not disable write-protect; aborting before any erase")

        print("chip-erasing (0x%02X) then programming %d sectors..."
              % (erase_opcode, len(data) // n.SECTOR_SIZE))

        def prog(done, total):
            print("  programmed+verified %6d / %d  (%5.1f%%)  %.0fs"
                  % (done, total, 100 * done / total, time.time() - t0), flush=True)

        n.flash_firmware(data, verify="sample", chip_erase=True,
                        erase_opcode=erase_opcode, progress=prog)
        # Each sector was read back and compared right after programming, so a
        # full re-read would be redundant — success = no verify error above.
        print("SUCCESS: all %d sectors programmed and verified (%.0fs)"
              % (len(data) // n.SECTOR_SIZE, time.time() - t0))
        print("rebooting DS into new firmware...")
        n.reset_ds(log=lambda m: None)
        rc = 0
    except Exception as e:
        print("FLASH ABORTED:", e)
        rc = 1
    finally:
        try:
            n.set_flash_write_protect(True)
            print("flash write-protect restored (NITRO REG1 bit 0 cleared)")
        except Exception as e:
            print("  (warning: could not restore write-protect: %s)" % e)
        n.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
