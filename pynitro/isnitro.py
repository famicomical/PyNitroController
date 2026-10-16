"""Platform-agnostic driver for the IS-NITRO-EMULATOR over USB.

This is a Python re-implementation, based on Gericom's C# source, of the USB transport in
``LibISNitroEmulator`` (``ISDebugger.cs`` / ``ISNitro.cs``), built on pyusb +
libusb so it runs on macOS / Linux / Windows without the official Windows
driver.  See ``docs/EMULATOR.md`` for the wire protocol this mirrors.

Transport (docs/EMULATOR.md):
  - device located by VID 0x0F6E / PID 0x0404
  - bulk OUT endpoint 0x01  : command headers + write payloads
  - bulk IN  endpoint 0x82  : read responses
  - every command starts with a fixed 16-byte little-endian header:
        u16 command, u8 direction(0x10 write / 0x11 read), u8 unknown,
        u32 address, u32 length, u32 padding(0)

Only the subset needed for a basic reset is wired up here; extend it the same
way ``ISNitro.cs`` does for memory / JTAG / register access.
"""

import errno
import struct
import time

import usb.core
import usb.util

VID = 0x0F6E          # I.S. Co., Ltd. / Intelligent Systems
PID = 0x0404
EP_OUT = 0x01         # bulk OUT  (Pipe00)
EP_IN = 0x82          # bulk IN   (Pipe01)

DIR_WRITE = 0x10
DIR_READ = 0x11

DEFAULT_TIMEOUT_MS = 5000


def _find_device(pid=PID):
    """Locate an IS-NITRO device (default: the EMULATOR) by PID.

    If the optional ``libusb-package`` wheel is installed, use the libusb-1.0
    binary it bundles -- this lets ``pip install`` alone work on macOS / Linux /
    Windows with no system libusb (brew/apt) or driver setup.  Otherwise fall
    back to pyusb's default discovery of a system-installed libusb.
    """
    try:
        import libusb_package
    except ImportError:
        libusb_package = None

    if libusb_package is not None:
        try:
            dev = libusb_package.find(idVendor=VID, idProduct=pid)
            if dev is not None:
                return dev
        except Exception:
            pass  # bundled backend unusable -- fall back to system libusb

    return usb.core.find(idVendor=VID, idProduct=pid)


class ISNitroError(Exception):
    """Base error for IS-NITRO operations."""


class DeviceNotFound(ISNitroError):
    """No matching IS-NITRO device was found on the USB bus."""


def _open_device(pid=PID, name="IS-NITRO-EMULATOR"):
    """Find the device by VID/PID, configure it, and claim interface 0."""
    dev = _find_device(pid)
    if dev is None:
        raise DeviceNotFound(
            "%s (VID 0x%04X / PID 0x%04X) not found. "
            "Is it plugged in and powered on?" % (name, VID, pid)
        )

    # On Linux a generic driver may have grabbed the interface; detach it.
    # (No-op / unsupported on macOS, where libusb claims vendor devices.)
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except (NotImplementedError, usb.core.USBError):
        pass

    try:
        dev.set_configuration()
    except usb.core.USBError as e:
        raise ISNitroError(
            "Could not set USB configuration: %s. On macOS make sure no "
            "other process owns the device; on Windows a WinUSB/libusb "
            "driver must be bound (e.g. via Zadig)." % e
        )
    usb.util.claim_interface(dev, 0)
    return dev


def device_present(dev):
    """False once `dev` has been unplugged. Sends a standard GET_DESCRIPTOR on the
    control endpoint, which leaves the IS-NITRO command protocol alone."""
    try:
        dev.ctrl_transfer(0x80, 0x06, 0x0100, 0, 18, 500)
    except usb.core.USBError as e:
        return e.errno not in (errno.ENODEV, errno.EIO)
    return True


class DSProcessor:
    ARM9 = 0
    ARM7 = 1


class ISNitro:
    """High-level handle to an IS-NITRO-EMULATOR.

    Use :meth:`open` to find and claim the device, or construct directly with
    an already-opened ``usb.core.Device``.
    """

    def __init__(self, device, timeout_ms=DEFAULT_TIMEOUT_MS):
        self.dev = device
        self.timeout = timeout_ms

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def open(cls, timeout_ms=DEFAULT_TIMEOUT_MS):
        """Find the device by VID/PID, configure it, and claim interface 0."""
        return cls(_open_device(), timeout_ms)

    def close(self):
        if self.dev is not None:
            usb.util.dispose_resources(self.dev)
            self.dev = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- low-level command protocol (mirrors ISDebugger.cs) ----------------

    @staticmethod
    def _header(command, direction, unknown, address, length):
        # u16 cmd | u8 dir | u8 unk | u32 addr | u32 len | u32 pad
        return struct.pack("<HBBIII", command, direction, unknown,
                           address, length, 0)

    def send_read_command(self, command, unknown, address, length):
        """Write a read header to OUT, then read ``length`` bytes from IN."""
        header = self._header(command, DIR_READ, unknown, address, length)
        self.dev.write(EP_OUT, header, self.timeout)
        data = self.dev.read(EP_IN, length, self.timeout)
        return bytes(data)

    def send_write_command(self, command, unknown, address, payload):
        """Write a command header (and payload) to the OUT endpoint.

        Payloads over 8192 bytes are sent as a separate transfer after the
        header, matching ``ISDebugger.SendWriteCommand``.
        """
        payload = bytes(payload)
        header = self._header(command, DIR_WRITE, unknown, address, len(payload))
        if len(payload) > 8192:
            self.dev.write(EP_OUT, header, self.timeout)
            self.dev.write(EP_OUT, payload, self.timeout)
        else:
            self.dev.write(EP_OUT, header + payload, self.timeout)

    # -- identify / probe --------------------------------------------------

    def get_version(self, retries=3):
        """Read the box's build/identify string (cmd 0x13, 10 bytes).

        The official tool issues this a few times until the box
        is ready. Returns the raw bytes (ASCII build id + ``00 FF`` trailer).
        """
        last = b""
        for _ in range(max(1, retries)):
            last = self.send_read_command(0x13, 0, 0, 10)
            if any(last):
                break
        return last

    def version_string(self):
        """Best-effort decode of :meth:`get_version` to printable ASCII."""
        raw = self.get_version()
        text = "".join(chr(b) for b in raw if 0x20 <= b < 0x7F)
        return text or raw.hex()

    # -- reset (mirrors the core of ISNitro.Reset) -------------------------

    def set_resetting(self, resetting):
        """cmd 0x8A — hold the DS in reset (True) or release it (False)."""
        self.send_write_command(
            0x8A, 0, 0, bytes([0x8A, 0x00, 1 if resetting else 0, 0])
        )

    def set_current_processor(self, processor):
        """cmd 0x8B — select ARM9/ARM7 as the active processor."""
        self.send_write_command(0x8B, 0, 0, bytes([0x8B, 0x00, processor, 0]))

    # -- NEC monitor-chip registers (mirrors Read/WriteNECMemory) ----------
    #
    # The NEC chip exposes the box internals as memory-mapped registers; the
    # 0x08000000 region documents control / IPL-SPI-flash / video-out (see
    # docs/EMULATOR.md). Registers there are
    # 16-bit accesses with only the low 8 bits valid. NOTE: some addresses
    # moved between hardware revisions — verify against your unit.

    # 0x08000000 region (revision-dependent; these match the current doc)
    REG_NITRO0 = 0x08000000   # reset / cover / debug_btn
    REG_NITRO1 = 0x08000002   # power / boot_complete / write_protection
    REG_IPL_SPI_CTRL = 0x08000004
    REG_IPL_SPI_DATA = 0x08000006
    REG_COUNTER_LO = 0x08000028  # free-running counter, low byte
    REG_COUNTER_HI = 0x0800002A  # free-running counter, high byte

    def read_nec_memory(self, address, unit_size, count):
        """Read ``count`` units of ``unit_size`` bytes from NEC space.

        Mirrors ``ISNitro.ReadNECMemory``: a 0x25 setup write (unit size,
        count, address) followed by a 0x17 data read. Auto-increments address.
        """
        setup = bytes([
            0x25, unit_size,
            count & 0xFF, (count >> 8) & 0xFF,
            address & 0xFF, (address >> 8) & 0xFF,
            (address >> 16) & 0xFF, (address >> 24) & 0xFF,
        ])
        self.send_write_command(0x25, 0, 0, setup)
        return self.send_read_command(0x17, 0, 0, unit_size * count)

    def _clear_in_pipe(self):
        """Clear a halt/overflow on the bulk IN endpoint. An oversized or
        mis-sized 0x17 read can stall the pipe with stale data, after which
        every subsequent read fails with Overflow; clear_halt resets it.
        Best-effort."""
        try:
            self.dev.clear_halt(EP_IN)
        except Exception:
            pass

    def read_nec_memory_fast(self, address, length, unit_size=4, count=0x800,
                             progress=None):
        """Bulk-read ``length`` bytes from NEC space, fast.

        Each block is an independent 0x25 setup + 0x17 data read of
        ``unit_size * count`` bytes (``count`` is in UNITS). The device does NOT
        auto-increment across separate 0x17 reads (hardware-verified — a second
        0x17 without a fresh 0x25 returns garbage), so there is no setup-skipping
        "streaming".

        The dominant speed lever is ``unit_size`` (the NEC bus access width),
        NOT block size. Hardware-measured (build-06125752 unit, 4 MiB dump):
            us=1 : ~0.42 MiB/s  (same at 0x2000 or 0x8000 blocks -- bus-bound)
            us=2 : ~1.6  MiB/s
            us=4 : ~2.0  MiB/s at 0x2000 blocks ... 2.24 at 0x20000 (only +13%)
        unit_size > 4 returns WRONG data (fast but corrupt -- not a real access
        width). Block size barely matters once unit_size>=2.

        Default is unit_size=4, count=0x800 -> 0x2000 (8 KiB) per read: ~5x the
        old us=1 dump, while staying within the community's 0x2000-per-read cap
        (Gericom/ortin: larger single reads can artifact on some units/revisions
        — verified harmless on THIS unit up to 0x30000, but capped for the
        shared port). Bump ``count`` for the last ~13% on a unit you've checked.

        ``length`` must be a multiple of ``unit_size``; keep ``unit_size*count``
        a multiple of 512 to avoid an IN-overflow. Returns the bytes;
        ``progress(done, total)`` is called after each block.
        """
        if not 1 <= unit_size <= 0xFF:
            raise ValueError("unit_size must be 1..0xFF")
        if not 1 <= count <= 0xFFFF:
            raise ValueError("count must be 1..0xFFFF (16-bit field)")
        if length % unit_size:
            raise ValueError("length must be a multiple of unit_size")
        block = unit_size * count               # bytes per 0x17 read
        out = bytearray()
        done = 0
        try:
            while done < length:
                n = min(block, length - done)   # multiple of unit_size
                out += self.read_nec_memory(address + done, unit_size,
                                            n // unit_size)
                done += n
                if progress:
                    progress(done, length)
        except usb.core.USBError:
            # A too-large / mis-sized read can stall the IN pipe; clear it so the
            # device stays usable for the next op, then surface the error.
            self._clear_in_pipe()
            raise
        return bytes(out)

    def read_nec_reg(self, address):
        """Read a single 16-bit NEC register, returned as an int (LE)."""
        data = self.read_nec_memory(address, 2, 1)
        return data[0] | (data[1] << 8)

    def write_nec_memory(self, address, unit_size, count, data):
        """Write to NEC space (cmd 0x26). Mirrors ``ISNitro.WriteNECMemory``."""
        data = bytes(data)
        packet = bytes([
            0x26, unit_size,
            count & 0xFF, (count >> 8) & 0xFF,
            address & 0xFF, (address >> 8) & 0xFF,
            (address >> 16) & 0xFF, (address >> 24) & 0xFF,
        ]) + data
        self.send_write_command(0x26, 0, 0, packet)

    def write_nec_reg(self, address, value):
        """Write a single 16-bit NEC register."""
        self.write_nec_memory(address, 2, 1,
                              bytes([value & 0xFF, (value >> 8) & 0xFF]))

    def read_counter(self):
        """Read the free-running NEC counter (lo|hi<<8). Should increment."""
        lo = self.read_nec_reg(self.REG_COUNTER_LO) & 0xFF
        hi = self.read_nec_reg(self.REG_COUNTER_HI) & 0xFF
        return lo | (hi << 8)

    # -- IPL SPI flash (direct host access via the NEC chip) ---------------
    #
    # 0x08000004 (IPL SPI CTRL) + 0x08000006 (IPL SPI DATA) bit-bang SPI
    # straight to the DS IPL firmware flash chip — no DS-side agent needed.
    # Control-bit layout is inferred from the register doc (see docs/EMULATOR.md)
    # and refined empirically; addresses are revision-dependent.
    #
    # The read helpers (spi_read_jedec_id / spi_read_status / spi_read) only
    # issue read-class opcodes and cannot modify flash. The program/erase path
    # (WREN/SECTOR_ERASE/PAGE_PROGRAM, used by flash_firmware) lives in its own
    # clearly-marked section further down — it IS destructive; see the warning
    # there before calling it.

    SPI_BUSY = 0x80   # status: 1 = transmitting/receiving
    SPI_CS = 0x40     # chipselect: 1 = low (device enabled)
    SPI_XMIT = 0x08   # transmit: send a byte when DATA is written

    def _ipl_spi_wait(self, tries=2000):
        for _ in range(tries):
            if (self.read_nec_reg(self.REG_IPL_SPI_CTRL) & self.SPI_BUSY) == 0:
                return
        raise ISNitroError("IPL SPI busy timeout")

    def ipl_spi_select(self, on):
        self.write_nec_reg(self.REG_IPL_SPI_CTRL,
                          (self.SPI_CS | self.SPI_XMIT) if on else 0)

    def ipl_spi_xfer(self, byte, poll=True):
        """Full-duplex transfer one byte; return the byte clocked in (MISO).

        ``poll=False`` skips the busy wait — safe for bulk reads because a USB
        round-trip already far exceeds one SPI byte time.
        """
        self.write_nec_reg(self.REG_IPL_SPI_DATA, byte & 0xFF)
        if poll:
            self._ipl_spi_wait()
        return self.read_nec_reg(self.REG_IPL_SPI_DATA) & 0xFF

    def spi_command(self, send_bytes, read_len=0, poll=True):
        """Assert CS, clock out ``send_bytes``, read ``read_len`` more, drop CS."""
        self.ipl_spi_select(True)
        try:
            for b in send_bytes:
                self.ipl_spi_xfer(b, poll=poll)
            return bytes(self.ipl_spi_xfer(0x00, poll=poll) for _ in range(read_len))
        finally:
            self.ipl_spi_select(False)

    def spi_read_jedec_id(self):
        """Read the flash JEDEC ID (opcode 0x9F): manufacturer + device bytes."""
        return self.spi_command([0x9F], 3)

    def spi_read_status(self):
        """Read flash status register (opcode 0x05)."""
        return self.spi_command([0x05], 1)[0]

    def spi_read(self, address, length, poll=False):
        """Read ``length`` bytes from flash at ``address`` (opcode 0x03)."""
        cmd = [0x03, (address >> 16) & 0xFF, (address >> 8) & 0xFF, address & 0xFF]
        return self.spi_command(cmd, length, poll=poll)

    def dump_firmware(self, length=0x40000, chunk=0x1000, progress=None):
        """Read the whole IPL firmware flash (default 256 KiB). Read-only.

        Each 0x03 READ command auto-increments within the chip, so chunking
        only affects how often ``progress`` fires, not correctness.
        """
        out = bytearray()
        while len(out) < length:
            n = min(chunk, length - len(out))
            out += self.spi_read(len(out), n)
            if progress:
                progress(len(out), length)
        return bytes(out)

    # -- IPL SPI flash PROGRAMMING (DESTRUCTIVE) ---------------------------
    #
    # WARNING: the methods below ERASE and REWRITE the DS IPL firmware flash.
    # A bad/interrupted write can leave the unit non-booting until reflashed.
    # Opcodes match what this unit's own flash agent used (docs/EMULATOR.md):
    # WREN 0x06, SECTOR_ERASE 0x20 (4 KiB), PAGE_PROGRAM 0x02 (256 B), RDSR 0x05.

    SECTOR_SIZE = 0x1000
    PAGE_SIZE = 0x100
    SPI_WIP = 0x01   # status: write-in-progress

    FLASH_WP_BIT = 0x01   # NITRO REG1 bit 0: write-protect (SET = protection OFF)

    def set_flash_write_protect(self, protect):
        """Toggle the IS-NITRO flash write-protect (NITRO REG1 bit 0).

        protect=False sets bit 0 (protection OFF, writes allowed); protect=True
        clears it (protection ON). Read-modify-write so only bit 0 changes —
        the other REG1 bits (incl. the powercycle-capable `power` bit) are left
        untouched, so no 1->0 transition can fire.
        """
        reg = self.read_nec_reg(self.REG_NITRO1) & 0xFF
        reg = (reg & ~self.FLASH_WP_BIT) if protect else (reg | self.FLASH_WP_BIT)
        self.write_nec_reg(self.REG_NITRO1, reg)

    def _spi_send(self, payload):
        """Write-only SPI transaction: clock the bytes out, ignore MISO, no
        per-byte busy poll. ~7x fewer USB transfers than reading each byte back
        — for commands whose response we don't need (WREN, erase, program). A
        USB round-trip dwarfs one SPI byte time so bytes don't outrun the bus;
        the post-op WIP poll and per-sector verify are the backstops.
        """
        self.ipl_spi_select(True)
        try:
            for b in payload:
                self.write_nec_reg(self.REG_IPL_SPI_DATA, b & 0xFF)
        finally:
            self.ipl_spi_select(False)

    def spi_write_enable(self):
        self._spi_send([0x06])                # WREN — sets the write-enable latch

    def spi_wait_wip(self, tries=200000):
        for _ in range(tries):
            if (self.spi_read_status() & self.SPI_WIP) == 0:
                return
        raise ISNitroError("SPI write-in-progress timeout")

    def spi_sector_erase(self, address, opcode=0xD7):
        # NOTE: on the unit's LE25FW203T, neither 0x20 nor 0xD7 small-sector
        # erase actually blanks the chip over the NEC SPI path (both no-op);
        # only chip-erase (0xC7) works there. Kept for completeness / other
        # revisions. The flash_firmware path uses chip_erase, not this.
        self.spi_write_enable()
        self._spi_send([opcode, (address >> 16) & 0xFF,
                       (address >> 8) & 0xFF, address & 0xFF])
        self.spi_wait_wip()

    def spi_chip_erase(self, opcode=0xC7, wait_s=60.0):
        """Erase the whole chip to 0xFF (default opcode 0xC7). Polls WIP."""
        self.spi_write_enable()
        self._spi_send([opcode])
        t = time.time()
        while time.time() - t < wait_s:
            if (self.spi_read_status() & self.SPI_WIP) == 0:
                return
            time.sleep(0.05)
        raise ISNitroError("chip erase (0x%02X) WIP timeout" % opcode)

    def spi_page_program(self, address, data):
        if len(data) > self.PAGE_SIZE:
            raise ValueError("page program > %d bytes" % self.PAGE_SIZE)
        self.spi_write_enable()
        self._spi_send([0x02, (address >> 16) & 0xFF,
                       (address >> 8) & 0xFF, address & 0xFF] + list(data))
        self.spi_wait_wip()

    def _verify_sector(self, base, sector, mode):
        """Read back a programmed sector and compare. Returns None on match, or
        (address, expected, got) at the first mismatch.

        mode "full": every byte. mode "sample": the first 16 bytes of each
        256-byte page (covers all 16 pages — catches gross corruption and any
        dropped/wrong page, ~16x less reading than full).
        """
        if mode == "full":
            rb = self.spi_read(base, self.SECTOR_SIZE)
            if rb == sector:
                return None
            i = next(k for k in range(len(sector)) if rb[k] != sector[k])
            return base + i, sector[i], rb[i]
        for off in range(0, self.SECTOR_SIZE, self.PAGE_SIZE):
            rb = self.spi_read(base + off, 16)
            if rb != sector[off:off + 16]:
                i = next(k for k in range(16) if rb[k] != sector[off + k])
                return base + off + i, sector[off + i], rb[i]
        return None

    def flash_firmware(self, data, verify="full", retries=3,
                      chip_erase=False, erase_opcode=0xC7, progress=None):
        """Erase + program the IPL flash with ``data`` (sector-aligned).

        DESTRUCTIVE. Flash the DS while it is *running* (or crashed but out of
        reset) — the flash sits on the DS ARM7 SPI bus and is unreachable while
        the DS is held in reset.

        chip_erase=True: erase the whole chip once (opcode ``erase_opcode``) and
        verify it blanked before programming — use this when the per-sector
        erase opcode isn't known/working. Otherwise erase each sector.
        verify: "full" (every byte), "sample" (first 16 B of each page — ~3x
        faster overall), or "none". In per-sector-erase mode a mismatch is
        retried up to ``retries`` times, else it raises (stopping there).
        """
        if verify is True:
            verify = "full"
        elif verify in (False, None):
            verify = "none"
        if verify not in ("full", "sample", "none"):
            raise ValueError("verify must be full/sample/none")
        if len(data) % self.SECTOR_SIZE != 0:
            raise ISNitroError("image not a multiple of sector size (0x%X)"
                              % self.SECTOR_SIZE)
        if chip_erase:
            self.spi_chip_erase(erase_opcode)
            if any(b != 0xFF for b in self.spi_read(0, 0x200, poll=False)):
                raise ISNitroError("erase opcode 0x%02X did not blank the chip "
                                  "(aborting before any program)" % erase_opcode)
        for base in range(0, len(data), self.SECTOR_SIZE):
            sector = data[base:base + self.SECTOR_SIZE]
            for _ in range(1 if chip_erase else retries):
                if not chip_erase:
                    self.spi_sector_erase(base)
                for off in range(0, self.SECTOR_SIZE, self.PAGE_SIZE):
                    self.spi_page_program(base + off, sector[off:off + self.PAGE_SIZE])
                if verify == "none":
                    break
                mismatch = self._verify_sector(base, sector, verify)
                if mismatch is None:
                    break
            else:
                addr, exp, got = mismatch
                raise ISNitroError(
                    "verify FAILED at 0x%05X (sector 0x%05X): wrote 0x%02X read 0x%02X"
                    % (addr, base, exp, got))
            if progress:
                progress(base + self.SECTOR_SIZE, len(data))

    # -- NEC CONTROLLER-FLASH UPDATE (cmd 0x0001) — DESTRUCTIVE ------------
    #
    # WARNING: this reprograms the box's OWN NEC-controller flash (Main Program,
    # LCA FPGA bitstreams, or the device-information block) — NOT the DS IPL
    # flash above. A blob is [0x2000 RAM-resident V850 flash routine][encrypted
    # payload]; the box decrypts it to NEC RAM, runs the routine from RAM, and
    # reflashes the region the routine targets. Build blobs with
    # nec_firmware_update.py. Sent exactly as the official ISND updater does it
    # in captures/Base_Update.pcapng.
    #
    # The cmd-0x0001 write alone is NOT enough: ISND brackets the update with a
    # control-register sequence (cmd 0xAD writes a (word1,word2) pair, cmd 0x95
    # reads 0x10 back) that ARMS the flash-update path. Without that bracket the
    # box happily ACCEPTs the cmd-0x0001 write (so the USB write "succeeds") but
    # never runs the routine — no erase, no progress, flash untouched. The exact
    # bytes below are replayed from the capture (setup frames 131-147, teardown
    # 517-529). The captured update runs entirely on one handle with no reset
    # command between blobs, so this handle stays valid across the whole
    # sequence. Verify the result by re-dumping (dump_nec_flash).

    def _nec_ctrl_write(self, word1, word2):
        """cmd 0xAD control-register poke: payload = AD 00 00 00 | w1 | w2 | pad.
        (Same framing as the 0xAD pokes in Reset(); used here to arm/disarm the
        cmd-0x0001 flash path.)"""
        self.send_write_command(
            0xAD, 0, 0,
            bytes([0xAD, 0, 0, 0]) + struct.pack("<II", word1, word2) + bytes(12))

    def _nec_ctrl_readback(self, log, tag):
        """cmd 0x95 readback (0x10 bytes). Tolerant: a timeout here is logged but
        NOT fatal — it's only a readback; the 0xAD writes do the actual arming."""
        try:
            data = self.send_read_command(0x95, 0, 0, 0x10)
            log("    %s: 0x95 readback = %s" % (tag, data.hex()))
            return data
        except usb.core.USBError as e:
            log("    %s: 0x95 readback timed out (%s) — continuing" % (tag, e))
            return b""

    def _nec_update_arm(self, log):
        """ISND's pre-update control bracket (Base_Update.pcapng f131-147)."""
        log("  arming flash path (0xAD/0x95)...")
        self._nec_ctrl_write(0x00, 0x0A)
        self._nec_ctrl_readback(log, "arm-1")
        self._nec_ctrl_write(0x0A, 0x00)
        self._nec_ctrl_write(0x00, 0x02)
        self._nec_ctrl_readback(log, "arm-2")

    def _nec_update_disarm(self, log):
        """ISND's post-update control bracket (Base_Update.pcapng f517-529)."""
        log("  disarming flash path (0xAD/0x95)...")
        self._nec_ctrl_write(0x00, 0x0A)
        self._nec_ctrl_readback(log, "disarm-1")
        self._nec_ctrl_write(0x00, 0x02)
        self._nec_ctrl_readback(log, "disarm-2")

    def _drain_progress(self, log, max_words=64, word_timeout_ms=10000,
                        progress=None):
        """Drain the box's 8-byte IN-endpoint progress stream while the RAM-
        resident flash routine runs.

        THIS IS THE STEP THAT MAKES THE UPDATE ACTUALLY FLASH. After a cmd-0x0001
        blob the routine writes one 8-byte word to EP_IN after each phase
        (identify / unlock / erase / blank-check / program / verify) and BLOCKS on
        that IN write until the host reads it. If the host never drains the
        channel the routine stalls at its first word — before erase — which is
        exactly the "0x160 then dark, flash unchanged" we saw. ISND drains it with
        BARE 8-byte bulk IN reads, no command header (Base_Update.pcapng f343-356);
        word0 climbs (~3->9) and the terminator is word0 == 0x01.

        ``progress(pct, phase)`` (optional) is called with an overall percentage
        (the flash span is 45..95%) so a GUI can show a bar instead of the log.

        Returns (words, finished). The first word can take >1s (the box is busy
        erasing), so the per-read timeout is generous.
        """
        progress = progress or (lambda *a: None)
        words = []
        dots = ""                             # one dot per progress word, logged as one line
        for i in range(max_words):
            try:
                w = bytes(self.dev.read(EP_IN, 8, word_timeout_ms))
            except usb.core.USBError as e:
                log("  flashing %s STALLED (last word %s; read timed out: %s)"
                    % (dots, words[-1].hex() if words else "none", e))
                return words, False
            words.append(w)
            dots += "."
            v = w[0] if w else 0
            if v == 0x01:                     # terminator word (word0 == 1 = done)
                progress(95, "flashing")
                log("  flashing %s done" % dots)
                return words, True
            if 3 <= v <= 9:                   # climbing phase words -> 45..90%
                progress(45 + (v - 3) * 45 // 6, "flashing")
        log("  flashing %s no terminator after %d words (unexpected)" % (dots, max_words))
        return words, False

    def send_firmware_update(self, blob, poll_status=True, log=None, progress=None):
        """Upload a NEC firmware-update blob (cmd 0x0001). DESTRUCTIVE.

        Faithfully mirrors the official ISND sequence (Base_Update.pcapng):
          1. ARM the flash path (0xAD/0x95 bracket).
          2. cmd-0x0001 write: 16-byte header, then payload in 0x10000-byte chunks
             (f337/339/341), the remainder last.
          3. DRAIN the 8-byte IN progress stream until word0==0x01 — the routine
             erases+programs in lock-step with these reads (see _drain_progress).
          4. A couple of harmless 0x18/0x96 status reads (f357-369).
          5. DISARM (0xAD/0x95).
        The cmd-0x0001 sequence itself issues no reset command (the whole capture
        runs on one handle). Verify the result by re-dumping (dump_nec_flash).
        Take + verify a full backup first. Pass ``log`` to trace phases.

        ``progress(pct, phase)`` (optional) reports an overall 0..100% and a short
        phase label ("arming"/"uploading"/"flashing"/"done") so a GUI can show a
        progress bar instead of the per-phase log.

        Returns (finished, words): finished=True if the drain saw the terminator.
        """
        log = log or (lambda *a: None)
        progress = progress or (lambda *a: None)
        blob = bytes(blob)
        if len(blob) < 0x2100 or len(blob) % 4:
            raise ISNitroError("implausible NEC update blob (len 0x%X)" % len(blob))

        progress(0, "arming")
        self._nec_update_arm(log)
        finished, words = self._upload_and_drain(blob, poll_status, log, progress)
        progress(97, "disarming")
        try:
            self._nec_update_disarm(log)
        except usb.core.USBError as e:
            log("  disarm timed out (%s) — expected if the box is busy/rebooted" % e)
        progress(100, "done" if finished else "stalled")
        return finished, words

    def _upload_and_drain(self, blob, poll_status, log, progress):
        """Upload ONE cmd-0x0001 blob and drain its progress stream — everything
        BETWEEN the arm and disarm brackets. `progress(pct, phase)` is called with
        this blob's local 0..100. Returns (finished, words). Shared by
        send_firmware_update (single blob) and send_firmware_update_multi (a full
        Base Update, where many blobs run inside one arm/disarm)."""
        blob = bytes(blob)
        if poll_status:                       # faithful pre-reads (harmless polls)
            log("  pre-reads (0x96/0x18/0x96)...")
            try:
                self.send_read_command(0x96, 0, 0, 4)
                self.send_read_command(0x18, 0, 0, 0x78)
                self.send_read_command(0x96, 0, 0, 4)
            except usb.core.USBError as e:
                log("    pre-reads timed out (%s) — continuing" % e)

        # Header alone, then payload in 0x10000-byte chunks — exactly how ISND
        # streamed the Main blob on the wire (frames 337/339/341: 0x10000 +
        # 0x10000 + 0x2100), rather than one giant transfer. Upload spans 5..40%.
        total = len(blob)
        progress(5, "uploading")
        log("  sending cmd 0x0001 header (len 0x%X)..." % total)
        self.dev.write(EP_OUT, self._header(0x0001, DIR_WRITE, 0, 0, total),
                       self.timeout)
        sent = 0
        for off in range(0, total, 0x10000):
            chunk = blob[off:off + 0x10000]
            log("    payload chunk @0x%X (0x%X bytes)..." % (off, len(chunk)))
            self.dev.write(EP_OUT, chunk, self.timeout)
            sent += len(chunk)
            progress(5 + 35 * sent // total, "uploading")
        log("  blob sent.")

        # The critical step: drain the progress stream so the routine can run to
        # completion. In lock-step with these reads the box erases then programs
        # the region. (drain reports 45..95%.)
        progress(42, "flashing")
        words, finished = self._drain_progress(log, progress=progress)

        # After the terminator ISND reads 0x18/0x96 a couple of times (f357-369);
        # purely informational here — harmless if they time out.
        if finished:
            log("  post-flash status reads (0x18/0x96)...")
            for _ in range(2):
                try:
                    st = self.send_read_command(0x18, 0, 0, 0x78)
                    log("    0x18 = %s" % st[:8].hex())
                    self.send_read_command(0x96, 0, 0, 4)
                except usb.core.USBError as e:
                    log("    status read timed out (%s)" % e)
                    break
        return finished, words

    def send_firmware_update_multi(self, blobs, labels=None, poll_status=True,
                                   log=None, progress=None):
        """Stream several cmd-0x0001 blobs inside ONE arm/disarm bracket — exactly
        how ISND performs a full Base Update. DESTRUCTIVE.

        In Base_Update.pcapng the updater arms once (f131-147), streams Main +
        LCA1 + LCA2 + LCA3 back-to-back on a SINGLE handle with NO reset between
        them (f335/373/413/451), draining the 8-byte progress stream after each,
        then disarms once (f517-529). This reproduces that: arm, then for each
        blob upload + drain (via _upload_and_drain), then disarm.

        STOPS at the first blob that does not reach its terminator — continuing
        past a stalled/partial region is not safe (a partial region is still
        recoverable via the on-chip backups + DIP-switch-4). Pre-reads are issued
        only before the first blob (matching the capture; the inter-blob 0x18/0x96
        reads are the per-blob post-flash reads).

        The sequence itself issues no reset command; verify the result by
        re-dumping. `progress(pct, phase)` reports overall 0..100 across all
        blobs. Returns a list of (finished, words), one per blob attempted."""
        log = log or (lambda *a: None)
        progress = progress or (lambda *a: None)
        blobs = [bytes(b) for b in blobs]
        for b in blobs:
            if len(b) < 0x2100 or len(b) % 4:
                raise ISNitroError("implausible NEC update blob (len 0x%X)" % len(b))
        if not blobs:
            return []
        n = len(blobs)
        labels = list(labels) if labels else ["region %d" % i for i in range(n)]

        progress(0, "arming")
        self._nec_update_arm(log)
        results = []
        try:
            for i, (b, label) in enumerate(zip(blobs, labels)):
                lo, span = 100 * i // n, 100 // n
                def pg(pct, phase, lo=lo, span=span, label=label):
                    progress(lo + pct * span // 100, "%s: %s" % (label, phase))
                log("  === blob %d/%d: %s (len 0x%X) ===" % (i + 1, n, label, len(b)))
                finished, words = self._upload_and_drain(
                    b, poll_status and i == 0, log, pg)
                results.append((finished, words))
                if not finished:
                    log("  %s did NOT reach its terminator — STOPPING the sequence "
                        "(remaining regions left untouched)." % label)
                    break
        finally:
            log("  disarming after %d blob(s)..." % len(results))
            try:
                self._nec_update_disarm(log)
            except usb.core.USBError as e:
                log("  disarm timed out (%s)" % e)
        done = len(results) == n and all(f for f, _ in results)
        progress(100, "done" if done else "stopped")
        return results

    def reset_ds(self, log=print):
        """Reset the emulated DS subsystem over USB.

        This reproduces the reset primitives of ``ISNitro.Reset()`` *without*
        loading a ROM or debugger image — enough to pulse the DS through reset
        and confirm the USB command path works end to end. It does NOT touch
        the box's own flash; it is safe and reversible.
        """
        # "Won't reset from firmware otherwise" (ISNitro.Reset).
        log("  -> 0x81 reset prep")
        self.send_write_command(0x81, 0, 0, bytes([0x81, 0x00]))

        log("  -> 0x8A assert reset")
        self.set_resetting(True)
        time.sleep(1.0)

        # The undocumented control-register poke from Reset() (selector 0x09).
        log("  -> 0xAD control register")
        self.send_write_command(0xAD, 0, 0, bytes([
            0xAD, 0x00, 0x00, 0x00,
            0x09, 0x00, 0x00, 0x00,
            0xAD, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]))
        time.sleep(1.0)

        log("  -> 0x8A release reset")
        self.set_resetting(False)


def _cli(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        description="Talk to an IS-NITRO-EMULATOR over USB.")
    parser.add_argument("--version", action="store_true",
                       help="read and print the box's identify string")
    parser.add_argument("--reset", action="store_true",
                       help="reset the DS subsystem")
    args = parser.parse_args(argv)

    try:
        nitro = ISNitro.open()
    except ISNitroError as e:
        print("error:", e)
        return 1

    try:
        print("Connected: %s" % nitro.version_string())
        if args.version and not args.reset:
            pass  # already printed
        if args.reset:
            print("Resetting DS...")
            nitro.reset_ds()
            print("Reset complete.")
    except ISNitroError as e:
        print("error:", e)
        return 1
    finally:
        nitro.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
