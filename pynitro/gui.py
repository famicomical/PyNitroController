#!/usr/bin/env python3
"""Minimal cross-platform GUI for the IS-NITRO-EMULATOR.

A small Tkinter window (Tkinter ships with CPython, so this runs anywhere a
desktop Python does) exposing the operations we've reverse-engineered:
identify (a read-only device report — box build string, the Device Information
block, the live + backup Main Program versions/build dates, and the IPL-SPI
flash JEDEC ID), NEC register reads, a full DS-firmware dump, a read-only NEC
controller-flash backup, a read-only extract of just the Main Program region
(a reflashable image), a DS reset, and a family of flash WRITES: the IPL
firmware flash, the NEC Main Program (single region or a full Main + LCA1/2/3
"Base Update" from a 4 MiB dump), and the device-info video unlock. Two ops are
offline file→file builders that need no device: Build DualMode IPL (a dual-mode
DS-IPL from a dump) and Special Mode Patch (an alt-mode AGB+video Main image from
a Main dump); their output is flashed afterwards with Flash Firmware / Update
Main Prog respectively.

Connect auto-detects the box: an IS-NITRO-EMULATOR gets every operation; an
IS-NITRO-CAPTURE gets the subset its protocol supports (Identify, Reset DS, Dump
NEC Flash, Extract Main Prog, Update Main Prog) plus Video Config, an editor for
teod's video patch (offsets, gaps, aspect-ratio fix) that writes the box's
Main Program. Unsupported buttons stay greyed.

All device I/O runs on worker threads; logging is funnelled back to the text
pane through a thread-safe queue. The flash-WRITE actions (Flash Firmware,
Reflash Main Prog, Full FW Update, Write Device Info) are destructive and each
requires explicit confirmation; everything else (Identify, NEC Registers, the
two dumps, Extract Main Prog, Reset DS, and the offline file builders) is
non-destructive to the device.

Run:  python3 gui.py   (from the repository root)
"""

import hashlib
import os
import queue
import struct
import threading
import time
import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox, scrolledtext, ttk

from .ipl import build_dualmode_v7 as bdm
from .isnitro import DeviceNotFound, ISNitro, ISNitroError, device_present
from .isnitro_capture import (ASPECT_MODES, CONFIG_BASE, CONFIG_SIZE, CURSOR_CHARS,
                             STOCK_CURSOR, VIDEO_FIELDS, ISNitroCapture,
                             build_update_blob as build_capture_blob, patch_builtin_cursor,
                             patch_video_config, read_builtin_cursor, read_video_config,
                             saved_video_configs)
from .nec import altmode_video_patch as avp
from .nec.dump_nec_flash import (read_flash, parse_dump, find_devinfo, report_devinfo,
                            parse_main_header, find_build_string, FLASH_SIZE,
                            FLAG_BITS)
from .nec.nec_firmware_update import (read_options, set_options,
                                 build_devinfo_blob_wp,
                                 build_main_blob, build_region_blob, DEVINFO_DEST,
                                 DEVINFO_SIZE, MAIN_DEST, MAIN_SIZE, REGION_BASE,
                                 REGION_SPAN, REGION_TAG)

# Main Program backup region (0x200000 above the live Main region; see the NEC
# memory map in dump_nec_flash). Used by Identify to report the backup version.
MAIN_BACKUP_DEST = MAIN_DEST + 0x200000

# Buttons that work on an IS-NITRO-CAPTURE; every other button is EMULATOR-only,
# except CAPTURE_ONLY ones.
CAPTURE_OPS = {"Identify", "Reset DS", "Dump NEC Flash…", "Extract Main Prog…",
               "Update Main Prog…", "Video Config…", "Dump Video Configs…"}
CAPTURE_ONLY = {"Video Config…", "Dump Video Configs…"}


# -- operations: each takes (nitro, log) and runs on a worker thread ---------

def op_identify(n, log, progress=None):
    """Full device-information report: the box build/identify string, the
    Device Information block (maker/model/serial/options), the live + backup
    Main Program versions and build dates, and the IPL flash JEDEC ID. All
    read-only. `progress(pct, phase)` is optional (drives the GUI bar while the
    two 0x20000 Main regions are read)."""
    progress = progress or (lambda *a: None)

    # 1. box build/identify string (cmd 0x13)
    log("  box identify : %s" % n.version_string())

    # 2. Device Information block (read just the 0x100-byte header live)
    try:
        block = bytes(n.read_nec_memory(DEVINFO_DEST, 1, 0x100))
        di = find_devinfo(block)
        if di is None:
            log("  device info  : signature not found at 0x%06X" % DEVINFO_DEST)
        else:
            log("  device info @ 0x%06X:" % DEVINFO_DEST)
            report_devinfo(block, di, base_addr=DEVINFO_DEST + di,
                           log=lambda m: log("  " + m))
    except Exception as e:
        log("  device info read failed: %s" % e)

    # 3. Main Program (live + backup) version number / build date
    try:
        def rd(addr, phase):
            return read_flash(n, addr, MAIN_SIZE,
                              progress=lambda d, t: progress(100 * d // t, phase))
        for addr, label in ((MAIN_DEST, "Main Program"),
                            (MAIN_BACKUP_DEST, "backup Main ")):
            region = rd(addr, "reading " + label.strip())
            h = parse_main_header(region)
            if h is None:
                log("  %s : Main Program header not found" % label)
                continue
            build = find_build_string(region)
            log("  %s : v%s  (0x%04X, type 0x%X)%s"
                % (label, h["version_str"], h["version"], h["type"],
                   "  [%s]" % build if build else ""))
    except Exception as e:
        log("  Main Program version read failed: %s" % e)

    # 4. IPL flash JEDEC ID (merged in from the former "Flash JEDEC ID" button)
    try:
        j = n.spi_read_jedec_id()
        log("  flash JEDEC  : %s  (manufacturer 0x%02X)" % (j.hex(), j[0]))
        log("  flash status : 0x%02X" % n.spi_read_status())
    except Exception as e:
        log("  flash JEDEC read failed: %s" % e)


def op_identify_capture(n, log, progress=None):
    """IS-NITRO-CAPTURE report: serial, firmware versions, the flash the
    firmware detected, and the live Main Program header. All read-only."""
    progress = progress or (lambda *a: None)
    log("  serial       : %s" % n.serial())
    log("  firmware     : Main v0x%X type %d, LCA1 v0x%X type %d" % n.firmware_version())
    try:
        log("  flash        : size 0x%X, type 0x%X, last block 0x%X  (v2.10 RAM layout)"
            % n.flash_info())
        region = read_flash(n, MAIN_DEST, MAIN_SIZE,
                            progress=lambda d, t: progress(100 * d // t, "reading Main"))
    except ISNitroError as e:
        log("  memory read  : %s" % e)
        return
    h = parse_main_header(region)
    if h is None:
        log("  Main Program : header not found at 0x%06X" % MAIN_DEST)
        return
    build = find_build_string(region)
    log("  Main Program : v%s  (0x%04X, type 0x%X)%s"
        % (h["version_str"], h["version"], h["type"],
           "  [%s]" % build if build else ""))


def op_nec_registers(n, log):
    r0 = n.read_nec_reg(n.REG_NITRO0) & 0xFF
    r1 = n.read_nec_reg(n.REG_NITRO1) & 0xFF
    ctrl = n.read_nec_reg(n.REG_IPL_SPI_CTRL) & 0xFF
    log("  NITRO REG0  = 0x%02X  %s   reset=%d (1=normal)  cover/dbg=%d"
        % (r0, format(r0, "08b"), (r0 >> 4) & 1, (r0 >> 1) & 1))
    log("  NITRO REG1  = 0x%02X  %s   (power/boot_complete/write_protection)"
        % (r1, format(r1, "08b")))
    log("  IPL SPI CTRL= 0x%02X  %s   busy=%d cs=%d"
        % (ctrl, format(ctrl, "08b"), (ctrl >> 7) & 1, (ctrl >> 6) & 1))


def op_reset(n, log):
    n.reset_ds(log=log)
    log("  reset complete")


class App:
    def __init__(self, root):
        self.root = root
        self.nitro = None
        self.busy = False           # a device operation is running
        self.log_queue = queue.Queue()
        self.progress_queue = queue.Queue()
        self.op_buttons = []        # (label, button): connection-gated
        self.offline_buttons = []   # usable without a device (file-only operations)

        root.title("IS-NITRO Controller")
        root.minsize(560, 420)

        top = tk.Frame(root, padx=10, pady=10)
        top.pack(fill="x")
        self.status_var = tk.StringVar(value="Disconnected")
        tk.Label(top, text="Status:").pack(side="left")
        self.status_label = tk.Label(top, textvariable=self.status_var, fg="#a00",
                                     font=("TkDefaultFont", 0, "bold"))
        self.status_label.pack(side="left", padx=(4, 0))
        self.connect_btn = tk.Button(top, text="Connect", width=12,
                                     command=self.on_connect)
        self.connect_btn.pack(side="right")

        # operation buttons in a grid
        ops = tk.LabelFrame(root, text="Operations", padx=8, pady=8)
        ops.pack(fill="x", padx=10)
        # Each spec is (label, command[, enabled]). enabled defaults True
        # (connection-gated). enabled=False stays permanently greyed; "always"
        # is an offline op (file-only) that's usable without a device.
        # Order = grid position: filled left-to-right, top-to-bottom (3 cols),
        # so list index i lands at row i//3, column i%3.
        specs = [
            # row 0: quick read-only info + reset
            ("Identify", self.on_identify),                                    # [0][0]
            ("NEC Registers", lambda: self._run("NEC registers", op_nec_registers)),  # [0][1]
            ("Reset DS", lambda: self._run("Reset DS", op_reset)),             # [0][2]
            # row 1: IPL flash dump/flash flanking the offline DualMode IPL build
            ("Dump Firmware…", self.on_dump),                                  # [1][0]
            ("Build DualMode IPL…", self.on_build_dualmode, "always"),         # [1][1]
            ("Flash Firmware…", self.on_flash),                                # [1][2]
            # row 2: NEC Main-Program region extract / offline special-mode build /
            #        live write-back
            ("Extract Main Prog…", self.on_extract_main),                      # [2][0]
            ("Special Mode Patch…", self.on_config_altmode_video, "always"),   # [2][1]
            ("Update Main Prog…", self.on_reflash_main),                       # [2][2]
            # row 3: NEC-flash dump, full Base Update (Main + LCA1/2/3),
            #        device-info options editor (video / RAM / wireless flags)
            ("Dump NEC Flash…", self.on_dump_nec),                             # [3][0]
            ("Full NEC Update…", self.on_full_update),                         # [3][1]
            ("Write Device Info…", self.on_write_devinfo),                     # [3][2]
            # row 4: IS-NITRO-CAPTURE video patch editor
            ("Video Config…", self.on_video_config),                           # [4][0]
            ("Dump Video Configs…", self.on_dump_video_configs),               # [4][1]
        ]
        for i, spec in enumerate(specs):
            label, cmd = spec[0], spec[1]
            enabled = spec[2] if len(spec) > 2 else True
            initial = "normal" if enabled == "always" else "disabled"
            b = tk.Button(ops, text=label, width=16, state=initial, command=cmd)
            b.grid(row=i // 3, column=i % 3, padx=4, pady=4, sticky="ew")
            if enabled is True:
                self.op_buttons.append((label, b))  # connection-gated
            elif enabled == "always":
                self.offline_buttons.append(b)   # usable offline
            # enabled is False -> stays permanently disabled
        for c in range(3):
            ops.grid_columnconfigure(c, weight=1)

        # progress bar + label — driven by long operations (firmware update,
        # backup, dumps) instead of spamming the log with per-step debug lines.
        prog = tk.Frame(root, padx=10)
        prog.pack(fill="x")
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(prog, maximum=100,
                                            variable=self.progress_var)
        self.progress_bar.pack(side="left", fill="x", expand=True)
        self.progress_text = tk.StringVar(value="")
        tk.Label(prog, textvariable=self.progress_text, width=22, anchor="w").pack(
            side="left", padx=(8, 0))

        self.log_widget = scrolledtext.ScrolledText(root, height=16, state="disabled",
                                                    font=("TkFixedFont", 0))
        self.log_widget.pack(fill="both", expand=True, padx=10, pady=10)

        self.log("Not connected. Click Connect to find the IS-NITRO.")
        self.root.after(100, self._drain_log_queue)

    # -- logging (thread-safe via queue) -----------------------------------

    def log(self, msg):
        self.log_queue.put(str(msg))

    def _drain_log_queue(self):
        dirty = False
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log_widget.configure(state="normal")
                self.log_widget.insert("end", msg + "\n")
                self.log_widget.see("end")
                self.log_widget.configure(state="disabled")
                dirty = True
        except queue.Empty:
            pass
        # apply the most recent progress update (coalesce; drop the rest)
        latest = None
        try:
            while True:
                latest = self.progress_queue.get_nowait()
        except queue.Empty:
            pass
        if latest is not None:
            pct, text = latest
            self.progress_var.set(pct)
            self.progress_text.set(text)
            dirty = True
        if dirty:
            # macOS' bundled Tk 8.5 often won't repaint quick updates on its own.
            self.log_widget.update_idletasks()
            self.progress_bar.update_idletasks()
        self.root.after(80, self._drain_log_queue)

    # -- progress bar (thread-safe via queue) ------------------------------

    def set_progress(self, pct, text=""):
        """Update the progress bar from any thread. pct is 0..100."""
        self.progress_queue.put((max(0, min(100, pct)),
                                 "%s %d%%" % (text, pct) if text else ""))

    def clear_progress(self):
        self.progress_queue.put((0, ""))

    def _set_status(self, text, connected):
        self.status_var.set(text)
        self.status_label.configure(fg="#080" if connected else "#a00")

    def _set_ops_enabled(self, enabled):
        capture = isinstance(self.nitro, ISNitroCapture)
        for label, b in self.op_buttons:
            ok = enabled and (label in CAPTURE_OPS if capture else label not in CAPTURE_ONLY)
            b.configure(state="normal" if ok else "disabled")

    # -- connect / disconnect ----------------------------------------------

    def on_connect(self):
        if self.nitro is not None:
            self._disconnect()
            return
        self.connect_btn.configure(state="disabled")
        self.log("Connecting...")
        threading.Thread(target=self._connect_worker, daemon=True).start()

    def _connect_worker(self):
        try:
            try:
                nitro = ISNitro.open()
            except DeviceNotFound:
                nitro = ISNitroCapture.open()
            version = nitro.version_string()
        except DeviceNotFound:
            self.log("Connect failed: no IS-NITRO-EMULATOR or IS-NITRO-CAPTURE found. "
                     "Is it plugged in and powered on?")
            self.root.after(0, lambda: self.connect_btn.configure(state="normal"))
            return
        except ISNitroError as e:
            self.log("Connect failed: %s" % e)
            self.root.after(0, lambda: self.connect_btn.configure(state="normal"))
            return
        self.nitro = nitro
        self.log("Connected to %s. Box identify: %s" % (self._kind(), version))
        self.root.after(0, self._on_connected_ui)

    def _kind(self):
        return ("IS-NITRO-CAPTURE" if isinstance(self.nitro, ISNitroCapture)
                else "IS-NITRO-EMULATOR")

    def _on_connected_ui(self):
        self._set_status("Connected (%s)" % self._kind(), True)
        self.connect_btn.configure(text="Disconnect", state="normal")
        self._set_ops_enabled(True)
        self.root.after(1000, self._watch_device, self.nitro)

    def _watch_device(self, nitro):
        """Auto-disconnect when the cable is pulled (checked once a second while idle)."""
        if self.nitro is not nitro:
            return                          # disconnected or reconnected meanwhile
        if not self.busy and not device_present(nitro.dev):
            self.log("USB device unplugged.")
            self._disconnect()
            return
        self.root.after(1000, self._watch_device, nitro)

    def _disconnect(self):
        try:
            self.nitro.close()
        except Exception:
            pass
        self.nitro = None
        self._set_status("Disconnected", False)
        self.connect_btn.configure(text="Connect", state="normal")
        self._set_ops_enabled(False)
        self.log("Disconnected.")

    # -- generic operation runner ------------------------------------------

    def _run(self, label, fn):
        if self.nitro is None:
            return
        self.busy = True
        self._set_ops_enabled(False)
        self.connect_btn.configure(state="disabled")
        self.log("[%s]" % label)

        def worker():
            try:
                fn(self.nitro, self.log)
            except Exception as e:
                self.log("  %s failed: %s" % (label, e))
            finally:
                self.root.after(0, self._op_done)

        threading.Thread(target=worker, daemon=True).start()

    def _op_done(self):
        self.busy = False
        self._set_ops_enabled(True)
        self.connect_btn.configure(state="normal")
        self.clear_progress()

    # -- offline operation runner (file-only; needs no device) -------------

    def _run_offline(self, label, fn):
        """Run an offline (no-device) operation on a worker thread. fn takes the
        log callback. Device ops are left alone — this only touches local files —
        but the offline buttons are disabled to prevent re-entry."""
        self._set_offline_enabled(False)
        self.log("[%s]" % label)

        def worker():
            try:
                fn(self.log)
            except Exception as e:
                self.log("  %s failed: %s" % (label, e))
            finally:
                self.root.after(0, self._offline_done)

        threading.Thread(target=worker, daemon=True).start()

    def _offline_done(self):
        self._set_offline_enabled(True)
        self.clear_progress()

    def _set_offline_enabled(self, enabled):
        state = "normal" if enabled else "disabled"
        for b in self.offline_buttons:
            b.configure(state=state)

    # -- identify: device-info report (reads two Main regions -> progress) --

    def on_identify(self):
        op = op_identify_capture if isinstance(self.nitro, ISNitroCapture) else op_identify
        self._run("Identify", lambda n, log: op(n, log, progress=self.set_progress))

    # -- dump needs a file dialog on the main thread first -----------------

    def on_dump(self):
        if self.nitro is None:
            return
        path = filedialog.asksaveasfilename(
            title="Save firmware dump", defaultextension=".bin",
            initialfile="fw_live_dump.bin",
            filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
        if not path:
            return

        def fn(n, log):
            data = n.dump_firmware(
                progress=lambda done, total: self.set_progress(
                    100 * done // total, "dumping"))
            with open(path, "wb") as f:
                f.write(data)
            log("  wrote %d bytes -> %s" % (len(data), path))
            log("  md5: %s" % hashlib.md5(data).hexdigest())

        self._run("Dump firmware", fn)

    # -- NEC controller-flash backup (read-only) ---------------------------

    def on_dump_nec(self):
        if self.nitro is None:
            return
        path = filedialog.asksaveasfilename(
            title="Save NEC controller-flash backup", defaultextension=".bin",
            initialfile="nec_flash_backup.bin",
            filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
        if not path:
            return

        def fn(n, log):
            log("  reading 4 MiB NEC flash (read-only)...")
            data = read_flash(n, 0x0, FLASH_SIZE,
                              progress=lambda done, total: self.set_progress(
                                  100 * done // total, "reading flash"))
            with open(path, "wb") as f:
                f.write(data)
            log("  wrote %d bytes -> %s" % (len(data), path))
            log("  md5: %s" % hashlib.md5(data).hexdigest())
            if not isinstance(n, ISNitroCapture):   # region labels follow the EMULATOR's map
                parse_dump(data, log=log)

        self._run("Dump NEC flash", fn)

    # -- extract the live Main Program region (read-only; reflashable image) --

    def on_extract_main(self):
        """Read just the live Main Program region (MAIN_SIZE bytes at MAIN_DEST)
        and save it. Read-only; the result is a region image accepted as-is by
        'Reflash Main Prog'."""
        if self.nitro is None:
            return
        path = filedialog.asksaveasfilename(
            title="Save Main Program region", defaultextension=".bin",
            initialfile="main_program.bin",
            filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
        if not path:
            return

        def fn(n, log):
            log("  reading Main Program region (0x%X bytes at 0x%06X, read-only)..."
                % (MAIN_SIZE, MAIN_DEST))
            data = read_flash(n, MAIN_DEST, MAIN_SIZE,
                              progress=lambda done, total: self.set_progress(
                                  100 * done // total, "reading Main"))
            h = parse_main_header(data)
            if h is None:
                log("  WARNING: 'Main Program' header not found at 0x%06X — saving "
                    "the raw region anyway." % MAIN_DEST)
            else:
                build = find_build_string(data)
                log("  Main Program : v%s  (0x%04X, type 0x%X)%s"
                    % (h["version_str"], h["version"], h["type"],
                       "  [%s]" % build if build else ""))
            with open(path, "wb") as f:
                f.write(data)
            log("  wrote %d bytes -> %s" % (len(data), path))
            log("  md5: %s" % hashlib.md5(data).hexdigest())

        self._run("Extract Main Program", fn)

    # -- build a dual-mode DS-IPL from the user's dump (offline; no device) --

    def on_build_dualmode(self):
        """Build a dual-mode DS-IPL image (source-level debug in normal NEC mode +
        cartridge boot in DIP alt mode) from the user's dumped firmware. Offline:
        unpack -> apply the v7 dual-mode patch set -> repack. Refuses any input
        whose firmware-header build timestamp differs from the reference IPL
        revision the patch offsets were derived against — the patch targets fixed
        code offsets that are only valid for that exact revision."""
        src = filedialog.askopenfilename(
            title="Select your dumped DS-IPL firmware (input)",
            filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
        if not src:
            return
        try:
            base_fw = open(src, "rb").read()
        except OSError as e:
            messagebox.showerror("Build DualMode IPL", "Could not read file:\n%s" % e)
            return

        # Verify the firmware-header build timestamp BEFORE prompting for output,
        # so a wrong-version dump is rejected up front rather than mid-build.
        try:
            ts = bdm.read_build_timestamp(base_fw)
        except ValueError as e:
            messagebox.showerror("Build DualMode IPL", "Not a DS firmware image:\n%s" % e)
            return
        if ts != bdm.EXPECTED_BUILD_TS:
            messagebox.showerror(
                "Build DualMode IPL — unsupported firmware",
                "This firmware's build timestamp is\n\n"
                "    %s  (%s)\n\n"
                "but the dual-mode patch was built for the supported IPL revision\n\n"
                "    %s  (%s)\n\n"
                "The patch offsets are only valid for that exact IPL revision, so "
                "building from this image is refused."
                % (ts.hex(), bdm.format_build_timestamp(ts),
                   bdm.EXPECTED_BUILD_TS.hex(),
                   bdm.format_build_timestamp(bdm.EXPECTED_BUILD_TS)))
            return

        out = filedialog.asksaveasfilename(
            title="Save dual-mode DS-IPL image", defaultextension=".bin",
            initialfile="dualmode_ipl_v7.bin",
            filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
        if not out:
            return

        def fn(log):
            log("  source: %s (%d bytes)" % (os.path.basename(src), len(base_fw)))
            img = bdm.build(base_fw, log=log)
            with open(out, "wb") as f:
                f.write(img)
            log("  wrote %d bytes -> %s" % (len(img), out))
            log("  md5: %s" % hashlib.md5(img).hexdigest())
            log("  Now flash it with 'Flash Firmware…' while the unit is connected.")

        self._run_offline("Build DualMode IPL", fn)

    # -- flash: file dialog + DESTRUCTIVE-action confirmation on main thread --

    def on_flash(self):
        if self.nitro is None:
            return
        path = filedialog.askopenfilename(
            title="Select firmware image to flash",
            filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
        if not path:
            return
        try:
            data = open(path, "rb").read()
        except OSError as e:
            messagebox.showerror("Flash firmware", "Could not read file:\n%s" % e)
            return
        if len(data) == 0 or len(data) % 0x1000 != 0:
            messagebox.showerror(
                "Flash firmware",
                "Image size 0x%X is not a non-zero multiple of the 4 KB sector "
                "size; refusing to flash." % len(data))
            return

        if not messagebox.askokcancel(
                "Flash firmware — DESTRUCTIVE",
                "This will ERASE and reprogram the DS IPL firmware flash with:\n\n"
                "    %s\n    (%d bytes)\n\n"
                "A bad or interrupted write can leave the unit non-booting until "
                "reflashed. Do NOT disconnect anything during the ~1 minute "
                "operation.\n\nProceed?" % (os.path.basename(path), len(data)),
                icon="warning", default="cancel"):
            self.log("Flash cancelled.")
            return

        def fn(n, log):
            t0 = time.time()
            jedec = n.spi_read_jedec_id().hex()
            log("  flash JEDEC: %s" % jedec)
            if jedec in ("000000", "ffffff"):
                raise ISNitroError("flash not responding (%s); aborting" % jedec)
            log("  disabling write-protect...")
            n.set_flash_write_protect(False)
            try:
                n.flash_firmware(data, verify="sample", chip_erase=True,
                                erase_opcode=0xC7,
                                progress=lambda done, total: self.set_progress(
                                    100 * done // total, "programming"))
                log("  all sectors programmed + verified (%.0fs)" % (time.time() - t0))
                log("  rebooting DS into new firmware...")
                n.reset_ds(log=lambda m: None)
                log("  flash complete.")
            finally:
                n.set_flash_write_protect(True)
                log("  write-protect restored")

        self._run("Flash firmware", fn)

    # -- NEC controller-flash updates (DESTRUCTIVE; mandatory backup) -------

    def _backup_then(self, label, backup_path, build_and_send):
        """Worker: optionally take+verify a full 4 MB NEC-flash backup, then call
        build_and_send(n, log, backup_data). If backup_path is falsy the backup is
        skipped and build_and_send gets backup_data=None. Aborts (no write) on a
        bad backup."""
        def fn(n, log):
            data = None
            if backup_path:
                def prog(done, total):
                    self.set_progress(100 * done // total, "backing up")

                log("  taking full 4 MiB backup...")
                data = read_flash(n, 0x0, FLASH_SIZE, progress=prog)
                with open(backup_path, "wb") as f:
                    f.write(data)
                log("  backup -> %s  md5 %s"
                    % (backup_path, hashlib.md5(data).hexdigest()))
                if (len(data) != FLASH_SIZE or find_devinfo(data) is None
                        or data[0x10000:0x10013] != b"INTELLIGENT SYSTEMS"):
                    raise ISNitroError("backup failed sanity check (no devinfo / Main "
                                       "header) — ABORTING before any write")
                if not isinstance(n, ISNitroCapture):   # labels follow the EMULATOR's map
                    parse_dump(data, log=log)
            else:
                log("  skipping backup (not requested).")
            build_and_send(n, log, data)

        self._run(label, fn)

    def on_write_devinfo(self):
        # Device-info options editor: read the live options register (0x3FE080),
        # let the user tick the extensions to enable, show a live diff vs the box,
        # and rewrite the device-info block (0x3FE000) with the chosen value. Block 70
        # is factory locked-DOWN, so the write goes through the WP#-override builder
        # (build_devinfo_blob_wp) — the stub drives the flash WP# pin high via the
        # Sub-LCA CPLD's magic-key sequence so the lock can be cleared. The block has
        # NO on-chip backup, so a full backup is mandatory before any write.
        if self.nitro is None:
            return
        # Read just the device-info header (0x100 bytes) to get the live options byte.
        try:
            hdr = bytes(self.nitro.read_nec_memory(DEVINFO_DEST, 1, 0x100))
            cur = read_options(hdr)
        except ValueError:
            messagebox.showerror(
                "Write Device Info",
                "Device-info signature not found at 0x%06X on this unit; aborting."
                % DEVINFO_DEST)
            return
        except Exception as e:
            messagebox.showerror("Write Device Info",
                                 "Could not read device-info:\n%s" % e)
            return
        self._open_devinfo_dialog(cur)

    def _open_devinfo_dialog(self, cur):
        # `cur` is the live options byte. A SET bit = extension NOT available, so a
        # ticked box (enable) CLEARS the bit and an unticked box SETS it. Unknown bits
        # (not in FLAG_BITS) are preserved untouched.
        win = tk.Toplevel(self.root)
        win.title("Write Device Info")
        win.transient(self.root)
        win.grab_set()
        tk.Label(win, text=(
            "Tick the extensions to ENABLE on this unit, then write. These are "
            "AVAILABILITY flags only — the matching hardware (RAM module, wireless, "
            "video board) must be physically installed for a ticked feature to work.\n\n"
            "Options register @0x%06X." % (DEVINFO_DEST + 0x80)),
            wraplength=460, justify="left").grid(
            row=0, column=0, columnspan=3, padx=10, pady=(10, 8), sticky="w")
        tk.Label(win, text="Enable", fg="#666").grid(
            row=1, column=0, padx=(10, 6), sticky="w")
        tk.Label(win, text="Extension", fg="#666").grid(row=1, column=1, sticky="w")
        tk.Label(win, text="Currently", fg="#666").grid(
            row=1, column=2, padx=(12, 10), sticky="w")

        vars_by_bit = []                 # (bit, BooleanVar) for each FLAG_BITS entry
        new_lbl = tk.Label(win, font=("TkDefaultFont", 0, "bold"))
        widgets = {}                     # holds write_btn once created

        def compute_new():
            v = cur
            for bit, var in vars_by_bit:
                if var.get():
                    v &= ~(1 << bit)     # enable -> clear bit
                else:
                    v |= (1 << bit)      # disable -> set bit
            return v & 0xFF

        def recompute(*_):
            nv = compute_new()
            changed = nv != cur
            new_lbl.configure(
                text="Options: 0x%02X  →  0x%02X%s"
                     % (cur, nv, "" if changed else "    (identical — nothing to write)"))
            if "write" in widgets:
                widgets["write"].configure(state="normal" if changed else "disabled")

        row = 2
        for bit, name in FLAG_BITS:
            enabled_now = not ((cur >> bit) & 1)
            var = tk.BooleanVar(value=enabled_now)
            var.trace_add("write", recompute)
            tk.Checkbutton(win, variable=var).grid(
                row=row, column=0, padx=(10, 6), sticky="w")
            tk.Label(win, text="bit%d  %s" % (bit, name)).grid(
                row=row, column=1, sticky="w")
            tk.Label(win, text="ENABLED" if enabled_now else "not present",
                     fg="#1a7d3a" if enabled_now else "#a33").grid(
                     row=row, column=2, padx=(12, 10), sticky="w")
            vars_by_bit.append((bit, var))
            row += 1

        new_lbl.grid(row=row, column=0, columnspan=3, padx=10, pady=(8, 2), sticky="w")
        row += 1

        def on_write():
            nv = compute_new()
            if nv == cur:                # belt-and-suspenders: button is also disabled
                messagebox.showinfo(
                    "Write Device Info",
                    "Selection matches what's already on the unit (options 0x%02X). "
                    "Nothing to write." % cur, parent=win)
                return
            changes = []
            for bit, name in FLAG_BITS:
                was = not ((cur >> bit) & 1)
                now = not ((nv >> bit) & 1)
                if was != now:
                    changes.append("  • %s: %s -> %s"
                                   % (name, "enabled" if was else "off",
                                      "ENABLED" if now else "OFF"))
            if not messagebox.askokcancel(
                    "Write Device Info — DESTRUCTIVE",
                    "Rewrite the device-info block (0x%06X) so the options register "
                    "goes 0x%02X -> 0x%02X:\n\n%s\n\n"
                    "Block 70 is locked-down; the routine drives the flash WP# pin high "
                    "(via the Sub-LCA CPLD) to clear the lock, then erase/program/verify."
                    "\n\nThis block has NO on-chip backup. A full 4 MB backup is taken "
                    "first (you choose where); recovery from a bad write needs an "
                    "external chip programmer.\n\nProceed?"
                    % (DEVINFO_DEST, cur, nv, "\n".join(changes)),
                    icon="warning", default="cancel", parent=win):
                return
            backup_path = filedialog.asksaveasfilename(
                parent=win, title="Save MANDATORY full backup first",
                defaultextension=".bin", initialfile="nec_flash_backup.bin",
                filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
            if not backup_path:
                self.log("Write Device Info cancelled (backup required).")
                return
            win.grab_release()
            win.destroy()
            self._write_devinfo_options(nv, backup_path)

        def on_cancel():
            win.grab_release()
            win.destroy()
            self.log("Write Device Info cancelled.")

        btns = tk.Frame(win)
        btns.grid(row=row, column=0, columnspan=3, pady=10)
        widgets["write"] = tk.Button(btns, text="Write to device", command=on_write)
        widgets["write"].pack(side="left", padx=6)
        tk.Button(btns, text="Cancel", command=on_cancel).pack(side="left", padx=6)
        win.protocol("WM_DELETE_WINDOW", on_cancel)
        recompute()                      # initial label + disabled Write (== current)

    def _write_devinfo_options(self, new_options, backup_path):
        def build_and_send(n, log, data):
            if find_devinfo(data) != DEVINFO_DEST:
                raise ISNitroError("device-info not at 0x%06X on this box; aborting"
                                   % DEVINFO_DEST)
            block = data[DEVINFO_DEST:DEVINFO_DEST + DEVINFO_SIZE]
            new_block, info = set_options(block, new_options)
            log("  options @0x%06X: 0x%02X -> 0x%02X"
                % (DEVINFO_DEST + info["offset"], info["before"], info["after"]))
            if not info["changed"]:
                log("  options already 0x%02X — nothing to write." % info["after"])
                return
            blob = build_devinfo_blob_wp(new_block)
            log("  built WP#-override update blob (0x%X bytes); arming + sending "
                "cmd 0x0001 (see progress bar)..." % len(blob))
            finished, words = n.send_firmware_update(
                blob, log=lambda *a: None, progress=self.set_progress)
            if not finished:
                raise ISNitroError(
                    "progress drain did NOT reach the terminator — the routine "
                    "likely stalled. Power-cycle and re-dump to check.")
            log("  flash routine completed (progress terminator seen).")
            log("  Re-run 'Dump NEC Flash' to confirm options is now 0x%02X."
                % info["after"])

        self._backup_then("Write Device Info", backup_path, build_and_send)

    def on_reflash_main(self):
        if self.nitro is None:
            return
        path = filedialog.askopenfilename(
            title="Select Main Program region image (0x%X bytes)" % MAIN_SIZE,
            filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
        if not path:
            return
        try:
            img = open(path, "rb").read()
        except OSError as e:
            messagebox.showerror("Reflash Main", "Could not read file:\n%s" % e)
            return
        if (len(img) != MAIN_SIZE or img[:19] != b"INTELLIGENT SYSTEMS"
                or img[0x20:0x2C] != b"Main Program"):
            messagebox.showerror(
                "Reflash Main",
                "Not a Main Program region image (need 0x%X bytes starting with the "
                "'INTELLIGENT SYSTEMS' / 'Main Program' header)." % MAIN_SIZE)
            return
        capture = isinstance(self.nitro, ISNitroCapture)
        if capture:
            try:
                build_capture_blob(0, img)       # validates: CAPTURE Main, right size
            except ValueError as e:
                messagebox.showerror("Reflash Main", str(e))
                return
        if not messagebox.askokcancel(
                "Reflash Main Program — DESTRUCTIVE",
                "This reflashes the Main Program region (0x10000) with:\n\n"
                "    %s\n    (%d bytes)\n\n"
                "Main has a backup region + DIP-switch-4 restore, so this is the "
                "recoverable path.%s\n\nProceed?"
                % (os.path.basename(path), len(img), self._dip4_note()),
                icon="warning", default="cancel"):
            self.log("Reflash Main cancelled.")
            return
        go, backup_path = self._ask_backup()
        if not go:
            self.log("Reflash Main cancelled.")
            return

        def build_and_send(n, log, data):
            if capture:
                self._capture_write_main(n, log, img)
                return
            # The blob's 0x100-byte tail must be the real flash bytes that follow
            # Main (NEC 0x30000 = the LCA1 header), exactly as ISND streamed it —
            # NOT 0xFF padding. Read it live from the box.
            log("  reading the 0x100 bytes after Main (0x30000) for the blob tail...")
            trailing = bytes(n.read_nec_memory(0x30000, 1, 0x100))
            log("    tail = %s ('%s')" % (
                trailing[:12].hex(),
                "".join(chr(c) if 32 <= c < 127 else "." for c in trailing[:12])))
            blob = build_main_blob(img, trailing=trailing)
            log("  built vanilla Main update blob (0x%X bytes); arming + sending "
                "cmd 0x0001 (see progress bar)..." % len(blob))
            finished, words = n.send_firmware_update(
                blob, log=lambda *a: None, progress=self.set_progress)
            if not finished:
                raise ISNitroError(
                    "progress drain did NOT reach the terminator — the routine "
                    "likely stalled. Power-cycle and re-dump to check.")
            log("  flash routine completed (progress terminator seen).")
            log("  Re-run 'Dump NEC Flash' to confirm the Main region (0x10000) "
                "changed.")

        self._backup_then("Reflash Main", backup_path, build_and_send)

    def _dip4_note(self):
        if isinstance(self.nitro, ISNitroCapture):
            return ("\n\nOn an IS-NITRO-CAPTURE the DIP-4 restore brings back the "
                    "backup copy (usually stock firmware), not your current settings.")
        return ""

    def _ask_backup(self, parent=None):
        """Offer (but don't require) a full backup before a write.
        Returns (go, backup_path or None)."""
        want = messagebox.askyesnocancel(
            "Save a full backup first?",
            "Take a full 4 MB NEC-flash backup before writing?\n\n"
            "Recommended, but optional — Main has its own backup region + "
            "DIP-switch-4 restore.\n\n"
            "Yes: choose where to save the backup.\n"
            "No: write without a backup.\n"
            "Cancel: abort.", parent=parent)
        if want is None:
            return False, None
        if not want:
            return True, None
        path = filedialog.asksaveasfilename(
            parent=parent, title="Save full backup first", defaultextension=".bin",
            initialfile="nec_flash_backup.bin",
            filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
        return bool(path), path or None

    def _capture_write_main(self, n, log, image):
        """Worker: flash a CAPTURE Main Program image, then read it back to verify."""
        blob = build_capture_blob(0, image)
        log("  sending CAPTURE Main update (0x%X bytes; see progress bar)..." % len(blob))
        finished, _ = n.send_firmware_update(blob, log=log, progress=self.set_progress)
        if not finished:
            raise ISNitroError("progress drain did NOT reach the terminator — the "
                               "routine likely stalled. Power-cycle and re-dump to check.")
        log("  flash routine completed; reading Main back to verify...")
        back = read_flash(n, MAIN_DEST, MAIN_SIZE)
        # +0x50 (size) and +0xFC are filled in by the update itself.
        bad = [i for i, (a, b) in enumerate(zip(back, image))
               if a != b and not (0x50 <= i < 0x54 or 0xFC <= i < 0x100)]
        if bad:
            raise ISNitroError("verify FAILED: %d bytes differ (first at 0x%06X)"
                               % (len(bad), MAIN_DEST + bad[0]))
        log("  verified: Main Program on the box matches (version 0x%X)."
            % struct.unpack_from("<I", back, 0x40)[0])

    # -- IS-NITRO-CAPTURE video patch editor (teod's ISNP patch) -------

    def on_video_config(self):
        if not isinstance(self.nitro, ISNitroCapture):
            return
        try:
            lca1 = self.nitro.firmware_version()[3]     # the word the firmware tests (0x30044)
            main = self.nitro.read_memory(MAIN_DEST, MAIN_SIZE)
            cfg = read_video_config(main, lca1)
        except (ISNitroError, ValueError) as e:
            messagebox.showerror("Video Config", "Could not read the video settings:\n%s" % e)
            return
        self._open_video_dialog(main, cfg, lca1)

    def on_dump_video_configs(self):
        """Save every video config in the box's DIP2-on save log as an .nvi file,
        inside an nvi_configs folder at the chosen location."""
        parent = filedialog.askdirectory(title="Where to create the nvi_configs folder")
        if not parent:
            return
        folder = os.path.join(parent, "nvi_configs")

        def fn(n, log):
            os.makedirs(folder, exist_ok=True)
            block = n.read_memory(CONFIG_BASE, CONFIG_SIZE,
                                  progress=lambda d, t: self.set_progress(100 * d // t, "reading"))
            configs = saved_video_configs(block)
            if not configs:
                log("  no valid video config at 0x%06X (DIP2 on uses built-in defaults)"
                    % CONFIG_BASE)
                return
            for i, (addr, rec) in enumerate(configs):
                active = i == len(configs) - 1
                name = "video_config_%02d_%06X%s.nvi" % (i, addr, "_active" if active else "")
                with open(os.path.join(folder, name), "wb") as f:
                    f.write(rec)
                x1, x2, y1, y2 = struct.unpack_from("<4I", rec, 0x34)
                log("  %s  X %X/%X  Y %X/%X" % (name, x1, x2, y1, y2))
            log("  wrote %d .nvi files -> %s (the box uses the _active one with DIP2 on)"
                % (len(configs), folder))

        self._run("Dump video configs", fn)

    def _open_video_dialog(self, main, cur, lca1):
        win = tk.Toplevel(self.root)
        win.title("Video Config")
        win.transient(self.root)
        win.grab_set()
        tk.Label(win, text=(
            "Built-in video settings in the box's Main Program, used at power-on with "
            "DIP 2 OFF. These are the values for this box's LCA1 type (%d). With DIP 2 "
            "ON the box applies its saved config over them, and while ISNP is "
            "connected it uses ISNP's Options instead.\n\n"
            "Values are hex or decimal. Gaps 16–31 are negative (−16..−1)." % lca1),
            wraplength=440, justify="left").grid(
            row=0, column=0, columnspan=4, padx=10, pady=(10, 8), sticky="w")
        tk.Label(win, text="AV1", fg="#666").grid(row=1, column=1)
        tk.Label(win, text="AV2", fg="#666").grid(row=1, column=2)
        labels = (("x", "X single"), ("y", "Y single"), ("x_dual", "X dual"),
                  ("y_dual", "Y dual"), ("gap", "Gap"))
        tops = {entry[0]: entry[3] for entry in VIDEO_FIELDS}
        entries = {}
        for r, (key, text) in enumerate(labels, start=2):
            tk.Label(win, text=text).grid(row=r, column=0, padx=(10, 6), sticky="w")
            for c, av in enumerate(("av1", "av2"), start=1):
                name = "%s_%s" % (av, key)
                e = tk.Entry(win, width=8)
                e.insert(0, "0x%X" % cur[name])
                e.grid(row=r, column=c, padx=4, pady=2)
                entries[name] = e
            tk.Label(win, text="0–0x%X" % tops["av1_" + key], fg="#666").grid(
                row=r, column=3, padx=(6, 10), sticky="w")
        r = len(labels) + 2
        tk.Label(win, text="Aspect-ratio fix").grid(row=r, column=0, padx=(10, 6), sticky="w")
        aspect_text = {"keep": "keep (stock)", "dip2_off": "remove with DIP2 off",
                       "dip2_on": "DIP2 on only (most likely no effect)",
                       "always": "remove always (DIP2 off and on)"}
        # "DIP2 on only" is offered only if the box already has it: nothing clears
        # the aspect registers after the boot path sets them, so it does nothing.
        modes = [m for m in ASPECT_MODES if m != "dip2_on" or cur["aspect"] == "dip2_on"]
        aspect = tk.StringVar(value=aspect_text[cur["aspect"]])
        tk.OptionMenu(win, aspect, *[aspect_text[m] for m in modes]).grid(
            row=r, column=1, columnspan=2, sticky="ew")
        r += 1
        tk.Label(win, text="Version").grid(row=r, column=0, padx=(10, 6), sticky="w")
        ver = tk.Entry(win, width=8)
        ver.insert(0, "0x%X" % cur["version"])
        ver.grid(row=r, column=1, padx=4, pady=2)
        tk.Label(win, text="ISNP v2.15 refuses a box newer than 0x1DE", fg="#666").grid(
            row=r, column=2, columnspan=2, padx=(6, 10), sticky="w")
        try:
            orig_cursor = read_builtin_cursor(main)
        except ValueError:
            orig_cursor = None                  # unknown layout: no cursor editing
        cursor = {"rows": orig_cursor}

        def on_write():
            try:
                cfg = {name: int(e.get(), 0) for name, e in entries.items()}
                cfg["version"] = int(ver.get(), 0)
                cfg["aspect"] = next(m for m in ASPECT_MODES if aspect_text[m] == aspect.get())
                new = patch_video_config(main, cfg, lca1)
            except ValueError as e:
                messagebox.showerror("Video Config", str(e), parent=win)
                return
            changes = ["  • %s: %s -> %s" % (k, cur[k], cfg[k]) for k in cfg if cfg[k] != cur[k]]
            if cursor["rows"] != orig_cursor:
                new = patch_builtin_cursor(new, cursor["rows"])
                changed = sum(a != b for ra, rb in zip(orig_cursor, cursor["rows"])
                              for a, b in zip(ra, rb))
                changes.append("  • built-in cursor: %d pixel(s) changed" % changed)
            if not changes:
                messagebox.showinfo("Video Config", "Nothing changed.", parent=win)
                return
            if not messagebox.askokcancel(
                    "Video Config — DESTRUCTIVE",
                    "Rewrite the Main Program (0x10000) with:\n\n%s%s\n\nProceed?"
                    % ("\n".join(changes), self._dip4_note()),
                    icon="warning", default="cancel", parent=win):
                return
            go, backup_path = self._ask_backup(parent=win)
            if not go:
                return
            win.grab_release()
            win.destroy()
            self._backup_then("Video Config", backup_path,
                              lambda n, log, data: self._capture_write_main(n, log, new))

        def on_cancel():
            win.grab_release()
            win.destroy()
            self.log("Video Config cancelled.")

        btns = tk.Frame(win)
        btns.grid(row=r + 1, column=0, columnspan=4, pady=10)
        tk.Button(btns, text="Edit Built-in Cursor…",
                  state="normal" if orig_cursor else "disabled",
                  command=lambda: self._open_cursor_editor(win, cursor)).pack(side="left", padx=6)
        tk.Button(btns, text="Write to device", command=on_write).pack(side="left", padx=6)
        tk.Button(btns, text="Cancel", command=on_cancel).pack(side="left", padx=6)
        win.protocol("WM_DELETE_WINDOW", on_cancel)

    def _open_cursor_editor(self, parent, state):
        """16x16 text editor for the built-in (DIP3) cursor. Every edit overwrites a
        pixel, so the picture always stays 16x16; OK stores it in state["rows"]."""
        win = tk.Toplevel(parent)
        win.title("Built-in Cursor")
        win.transient(parent)
        win.grab_set()
        tk.Label(win, text=("#  white     o  black     .  transparent\n"
                            "Hotspot: row 7, column 7 (counting from 0).\n"
                            "Typing overwrites; Backspace and Delete clear a pixel."),
                 justify="left").pack(padx=10, pady=(10, 4), anchor="w")
        # A real copy of the platform's monospace font: a ("TkFixedFont", 14) tuple
        # names a font *family*, which Tk can silently swap for a proportional one.
        win.mono = tkfont.nametofont("TkFixedFont").copy()
        win.mono.configure(size=14)
        txt = tk.Text(win, width=16, height=16, wrap="none", undo=False, font=win.mono)
        txt.pack(padx=10)
        txt.focus_set()

        def fill(rows):
            txt.delete("1.0", "end")
            txt.insert("1.0", "\n".join(rows))
            txt.mark_set("insert", "1.0")

        fill(state["rows"])

        def put(line, col, ch):
            txt.delete("%d.%d" % (line, col))
            txt.insert("%d.%d" % (line, col), ch)

        def on_key(e):
            if e.keysym in ("Left", "Right", "Up", "Down", "Home", "End"):
                return None                     # let the widget move the cursor
            line, col = map(int, txt.index("insert").split("."))
            if line > 16:
                return "break"
            if e.keysym == "BackSpace":
                if col > 0:
                    put(line, col - 1, ".")
                    txt.mark_set("insert", "%d.%d" % (line, col - 1))
            elif e.keysym == "Delete":
                if col < 16:
                    put(line, col, ".")
                    txt.mark_set("insert", "%d.%d" % (line, col))
            elif e.char and e.char in CURSOR_CHARS + " ":
                if col >= 16:                   # end of a row: continue on the next one
                    if line == 16:
                        return "break"
                    line, col = line + 1, 0
                put(line, col, "." if e.char == " " else e.char)
                txt.mark_set("insert", "%d.%d" % (line, col + 1))
            return "break"                      # nothing else may change the text

        txt.bind("<Key>", on_key)
        for seq in ("<<Paste>>", "<<Cut>>", "<<Clear>>", "<<PasteSelection>>"):
            txt.bind(seq, lambda e: "break")

        def close(save):
            if save:
                state["rows"] = txt.get("1.0", "16.end").split("\n")
            win.grab_release()
            win.destroy()

        tools = tk.Frame(win)
        tools.pack(pady=(8, 0))
        tk.Button(tools, text="Clear", command=lambda: fill(["." * 16] * 16)).pack(side="left", padx=6)
        tk.Button(tools, text="Restore", command=lambda: fill(STOCK_CURSOR)).pack(side="left", padx=6)
        btns = tk.Frame(win)
        btns.pack(pady=10)
        tk.Button(btns, text="OK", command=lambda: close(True)).pack(side="left", padx=6)
        tk.Button(btns, text="Cancel", command=lambda: close(False)).pack(side="left", padx=6)
        win.protocol("WM_DELETE_WINDOW", lambda: close(False))

    # -- full Base Update: Main + LCA1/2/3 from a supplied 4 MiB flash dump -----

    def on_full_update(self):
        """Reflash Main Program + LCA1/2/3 from a user-supplied 4 MiB NEC flash
        dump, via the official ISND Base-Update sequence (one arm/disarm bracket,
        four cmd-0x0001 blobs streamed on one handle — see send_firmware_update_
        multi). LCA4 and the device-info block are NOT touched."""
        if self.nitro is None:
            return
        path = filedialog.askopenfilename(
            title="Select a 4 MiB NEC flash dump (Main + LCA1/2/3 source)",
            filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
        if not path:
            return
        try:
            dump = open(path, "rb").read()
        except OSError as e:
            messagebox.showerror("Full FW Update", "Could not read file:\n%s" % e)
            return
        if len(dump) != FLASH_SIZE:
            messagebox.showerror(
                "Full FW Update",
                "Image is 0x%X bytes; a full NEC controller-flash dump must be "
                "exactly 0x%X (4 MiB)." % (len(dump), FLASH_SIZE))
            return
        # Refuse unless every region we're about to flash has its expected header.
        bad = [REGION_TAG[s].decode()
               for s in (0, 1, 2, 3)
               if (dump[REGION_BASE[s]:REGION_BASE[s] + 19] != b"INTELLIGENT SYSTEMS"
                   or dump[REGION_BASE[s] + 0x20:REGION_BASE[s] + 0x20 + len(REGION_TAG[s])]
                   != REGION_TAG[s])]
        if bad:
            messagebox.showerror(
                "Full FW Update",
                "These region headers are missing/wrong in the image — refusing "
                "to flash:\n\n    %s" % ", ".join(bad))
            return
        src_main = parse_main_header(dump[MAIN_DEST:MAIN_DEST + MAIN_SIZE])
        src_build = find_build_string(dump[MAIN_DEST:MAIN_DEST + MAIN_SIZE])
        srcdesc = ("Main v%s%s" % (src_main["version_str"],
                                   "  [%s]" % src_build if src_build else "")
                   if src_main else "Main version unknown")

        if not messagebox.askokcancel(
                "Full FW Update — DESTRUCTIVE",
                "This reflashes FOUR NEC controller-flash regions from:\n\n"
                "    %s\n    (source: %s)\n\n"
                "    • Main Program  (0x010000)\n"
                "    • LCA1 / AGB     (0x030000)\n"
                "    • LCA2 / NTR     (0x060000)\n"
                "    • LCA3 / Monitor (0x090000)\n\n"
                "It uses the official ISND Base-Update sequence (one arm/disarm "
                "bracket, four blobs streamed on one handle, no reset). LCA4 and "
                "the device-info block are NOT touched.\n\n"
                "Main + the LCAs all have backup regions + DIP-switch-4 restore, so "
                "this is recoverable; a bad/interrupted write may need DIP-4 restore "
                "or an external programmer. Do NOT disconnect during the operation."
                "\n\nProceed?"
                % (os.path.basename(path), srcdesc),
                icon="warning", default="cancel"):
            self.log("Full FW Update cancelled.")
            return
        # Optional full backup of the CURRENT flash (the regions are recoverable
        # via on-chip backups + DIP-4, so this mirrors Reflash Main: Yes/No/Cancel).
        want_backup = messagebox.askyesnocancel(
            "Save a full backup first?",
            "Take a full 4 MB NEC-flash backup of the CURRENT firmware before "
            "reflashing?\n\nRecommended, but optional — these regions have on-chip "
            "backups + DIP-switch-4 restore.\n\n"
            "Yes: choose where to save the backup.\nNo: reflash without a backup.\n"
            "Cancel: abort.")
        if want_backup is None:
            self.log("Full FW Update cancelled.")
            return
        backup_path = None
        if want_backup:
            backup_path = filedialog.asksaveasfilename(
                title="Save full backup of current firmware first",
                defaultextension=".bin", initialfile="nec_flash_backup.bin",
                filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
            if not backup_path:
                self.log("Full FW Update cancelled.")
                return

        def build_and_send(n, log, data):
            selectors = (0, 1, 2, 3)
            blobs, labels = [], []
            for sel in selectors:
                base, span = REGION_BASE[sel], REGION_SPAN[sel]
                image = dump[base:base + span]    # FULL region span (routine programs all of it)
                blobs.append(build_region_blob(sel, image))
                labels.append(REGION_TAG[sel].decode())
            log("  built %d update blobs (%s); arming once + streaming via the "
                "Base-Update sequence (see progress bar)..."
                % (len(blobs), ", ".join(labels)))
            results = n.send_firmware_update_multi(
                blobs, labels=labels, log=lambda *a: None, progress=self.set_progress)
            for (finished, _), label in zip(results, labels):
                log("    %-13s : %s" % (label, "OK" if finished else "STALLED"))
            done = len(results) == len(blobs) and all(f for f, _ in results)
            if not done:
                raise ISNitroError(
                    "full update did NOT complete every region (a region stalled "
                    "before its terminator). The remaining regions were left "
                    "untouched. Power-cycle; if the box won't boot, use DIP-switch-4 "
                    "to restore from the backup regions.")
            log("  all four regions flashed (progress terminators seen).")
            log("  Re-run Identify / 'Dump NEC Flash' to confirm the new Main + "
                "LCA1/2/3.")

        self._backup_then("Full FW Update", backup_path, build_and_send)

    # -- special-mode patch: offline build of an alt-mode video Main image --------
    #    read a dump -> detect/preload stub params -> edit -> save a patched file

    def on_config_altmode_video(self):
        """Build a special-mode (DIP alt-mode) AGB+video Main Program image from the
        user's dumped Main region — offline, no device needed (mirrors 'Build
        DualMode IPL…'). Read the dump -> detect any existing alt-mode stub and
        preload its video params (else defaults) -> let the user edit them -> apply
        the checksum-transparent alt-mode stub -> save the patched image to a new
        file. Flash the result afterwards with 'Update Main Prog…' while connected."""
        src = filedialog.askopenfilename(
            title="Select your dumped Main Program region (input)",
            filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
        if not src:
            return
        try:
            main = open(src, "rb").read()
        except OSError as e:
            messagebox.showerror("Special Mode Patch", "Could not read file:\n%s" % e)
            return
        if (len(main) != avp.MAIN_SIZE or main[:19] != b"INTELLIGENT SYSTEMS"
                or main[0x20:0x2C] != b"Main Program"):
            messagebox.showerror(
                "Special Mode Patch",
                "Not a Main Program region image (need 0x%X bytes starting with the "
                "'INTELLIGENT SYSTEMS' / 'Main Program' header)." % avp.MAIN_SIZE)
            return

        params = avp.parse_stub(main)
        present = avp.stub_present(main)
        self._open_altmode_video_dialog(src, main, params, present)

    def _open_altmode_video_dialog(self, src, main, params, present):
        if params is not None:
            msg = ("Loaded the video settings currently programmed by the alt-mode "
                   "stub in this Main dump. Edit them, then save a patched image.")
        elif present:
            msg = ("An alt-mode stub is installed in this dump but has no readable "
                   "video config (older/other version). Defaults loaded — saving will "
                   "upgrade it to a video-capable stub.")
            params = dict(avp.DEFAULT_PARAMS)
        else:
            msg = ("No alt-mode stub detected in this dump. Defaults loaded — saving "
                   "will install one (needs a vanilla Main; refuses if 0x11952 holds an "
                   "unrelated hook).")
            params = dict(avp.DEFAULT_PARAMS)

        win = tk.Toplevel(self.root)
        win.title("Configure Alt-Mode Video")
        win.transient(self.root)
        win.grab_set()
        tk.Label(win, text=msg, wraplength=440, justify="left").grid(
            row=0, column=0, columnspan=2, padx=10, pady=(10, 8), sticky="w")
        tk.Label(win, text="(values accept decimal or 0x-hex)", fg="#666").grid(
            row=1, column=0, columnspan=2, padx=10, sticky="w")

        # monitor_state is rendered as 8 per-bit boxes (bit7..bit0); everything else
        # is a plain integer entry.
        MON_BITS = [(7, "dflk\ntype"), (6, "dflk\nstate"), (5, "av1\nhi"), (4, "av1\nlo"),
                    (3, "rot\ndir"), (2, "rot"), (1, "av2\nhi"), (0, "av2\nlo")]
        entries = {}        # key -> (var, lo, hi, label)
        mon_bits = []       # list of (bit_index, StringVar)
        row = 2
        for key, label, default, lo, hi in avp.PARAM_SPECS:
            if key == "monitor_state":
                tk.Label(win, text=label).grid(row=row, column=0, sticky="nw",
                                               padx=(10, 6), pady=2)
                bf = tk.Frame(win)
                bf.grid(row=row, column=1, sticky="w", padx=(0, 10), pady=2)
                cur = params[key]
                for col, (bit, name) in enumerate(MON_BITS):
                    tk.Label(bf, text="b%d\n%s" % (bit, name), justify="center",
                             font=("TkDefaultFont", 0)).grid(row=0, column=col, padx=1)
                    bv = tk.StringVar(value=str((cur >> bit) & 1))
                    tk.Entry(bf, width=2, justify="center", textvariable=bv).grid(
                        row=1, column=col, padx=1)
                    mon_bits.append((bit, bv))
            else:
                tk.Label(win, text=label).grid(row=row, column=0, sticky="w",
                                               padx=(10, 6), pady=2)
                var = tk.StringVar(value=str(params[key]))
                tk.Entry(win, width=12, textvariable=var).grid(
                    row=row, column=1, sticky="w", padx=(0, 10), pady=2)
                entries[key] = (var, lo, hi, label)
            row += 1

        def on_ok():
            newp = {}
            for key, (var, lo, hi, label) in entries.items():
                s = var.get().strip()
                try:
                    v = int(s, 0)
                except ValueError:
                    messagebox.showerror("Invalid value",
                                         "%s: '%s' is not an integer." % (label, s),
                                         parent=win)
                    return
                if not (lo <= v <= hi):
                    messagebox.showerror("Out of range",
                                         "%s must be %d..%d (got %d)." % (label, lo, hi, v),
                                         parent=win)
                    return
                newp[key] = v
            ms = 0
            for bit, bv in mon_bits:
                s = bv.get().strip()
                if s not in ("0", "1"):
                    messagebox.showerror("Invalid bit",
                                         "Monitor-state bit %d must be 0 or 1 (got '%s')."
                                         % (bit, s), parent=win)
                    return
                ms |= int(s) << bit
            newp["monitor_state"] = ms
            win.grab_release()
            win.destroy()
            self._save_altmode_video(src, main, newp)

        def on_cancel():
            win.grab_release()
            win.destroy()
            self.log("  Special Mode Patch cancelled.")

        btns = tk.Frame(win)
        btns.grid(row=row, column=0, columnspan=2, pady=10)
        tk.Button(btns, text="Save patched image with these settings",
                  command=on_ok).pack(side="left", padx=6)
        tk.Button(btns, text="Cancel", command=on_cancel).pack(side="left", padx=6)
        win.protocol("WM_DELETE_WINDOW", on_cancel)

    def _save_altmode_video(self, src, main, newp):
        # Validate/build the patch in-memory BEFORE prompting for an output file, so
        # an unpatchable Main (e.g. an unknown 0x11952 redirect) fails cleanly here.
        try:
            patched = avp.patch_main(main, newp)
        except ValueError as e:
            messagebox.showerror("Special Mode Patch", "Cannot patch this Main:\n%s" % e)
            return

        out = filedialog.asksaveasfilename(
            title="Save special-mode (alt-mode video) Main image",
            defaultextension=".bin", initialfile="main_special_mode.bin",
            filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
        if not out:
            return

        def fn(log):
            log("  source: %s (%d bytes)" % (os.path.basename(src), len(main)))
            log("  video stub configured:")
            for key, label, *_ in avp.PARAM_SPECS:
                log("    %-26s = %d (0x%X)" % (label, newp[key], newp[key]))
            # Checksum-neutral: the correction word drives the Main's XOR-32 to the stock
            # value ISND expects, so its cmd-0x18 integrity check passes.
            patched_x = avp.region_xor32(patched)
            base_x = avp.unpatched_xor(main)        # this Main with our stub removed
            log("  Main XOR-32 integrity checksum = 0x%08X (= stock 0x%08X; ISND's cmd-0x18 "
                "check passes)." % (patched_x, avp.STOCK_MAIN_XOR))
            if base_x != avp.STOCK_MAIN_XOR:
                log("    WARNING: the base Main (stub removed) = 0x%08X, not the stock "
                    "0x%08X — it's non-stock firmware (e.g. a bumped version word). "
                    "The XOR is forced to stock, but ISND may still reflash on the "
                    "version/content mismatch; rebuild from a stock 0x160 Main."
                    % (base_x, avp.STOCK_MAIN_XOR))
            with open(out, "wb") as f:
                f.write(patched)
            log("  wrote %d bytes -> %s" % (len(patched), out))
            log("  md5: %s" % hashlib.md5(patched).hexdigest())
            log("  This sets the VIDEO-OUT registers in DIP alt-mode; it does NOT enable "
                "video output — that's the device-info video flag in 'Write Device Info…'.")
            log("  Now flash it with 'Update Main Prog…' while the unit is connected.")

        self._run_offline("Special Mode Patch", fn)


def main():
    root = tk.Tk()
    app = App(root)
    root.protocol("WM_DELETE_WINDOW",
                  lambda: (app.nitro and app.nitro.close(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
