import gi
import os
import re
import uuid
import json
import time
import threading
import subprocess
import shutil
from queue import Queue, Empty

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib


class Scanner(Gtk.Window):

    def __init__(self):
        super().__init__(title="Forensic Scanner PRO v1.0")
        self.set_default_size(1450, 850)

        # ================= STATE =================
        self.targets = []
        self.queue = Queue()

        self.scan_token = 0
        self.cancel_flag = False
        self.pause_flag = False

        self.total = 0
        self.done = 0
        self.running = 0

        self.results_seen = set()
        self.lock = threading.Lock()

        self.match_total = 0
        self.match_done = 0

        # ================= MAIN =================
        main = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.add(main)

        # ==================================================
        # LEFT PANEL
        # ==================================================
        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        left.set_size_request(330, -1)
        main.pack_start(left, False, False, 5)

        self.btn_folder = Gtk.Button(label="Select Folder")
        self.btn_folder.connect("clicked", self.select_folder)
        left.pack_start(self.btn_folder, False, False, 0)

        self.btn_files = Gtk.Button(label="Select Files")
        self.btn_files.connect("clicked", self.select_files)
        left.pack_start(self.btn_files, False, False, 0)

        # ---------- FILE TYPES ----------
        left.pack_start(Gtk.Label(label="File Types:"), False, False, 0)

        self.chk_dll = Gtk.CheckButton(label="DLL")
        self.chk_exe = Gtk.CheckButton(label="EXE")
        self.chk_apk = Gtk.CheckButton(label="APK")
        self.chk_other = Gtk.CheckButton(label="Other")

        self.chk_dll.set_active(True)

        left.pack_start(self.chk_dll, False, False, 0)
        left.pack_start(self.chk_exe, False, False, 0)
        left.pack_start(self.chk_apk, False, False, 0)
        left.pack_start(self.chk_other, False, False, 0)

        # ---------- REGEX ----------
        left.pack_start(Gtk.Label(label="Regex Pattern:"), False, False, 0)

        self.chk_text = Gtk.CheckButton(label="Use Textbox Regex")
        self.chk_text.set_active(True)
        left.pack_start(self.chk_text, False, False, 0)

        self.chk_json = Gtk.CheckButton(label="Use regex.json")
        left.pack_start(self.chk_json, False, False, 0)

        self.entry = Gtk.Entry()
        self.entry.set_placeholder_text("api|token|key")
        left.pack_start(self.entry, False, False, 0)

        # ---------- THREADS ----------
        left.pack_start(Gtk.Label(label="Thread Count:"), False, False, 0)

        self.thread_spin = Gtk.SpinButton()
        self.thread_spin.set_range(1, 32)
        self.thread_spin.set_increments(1, 1)
        self.thread_spin.set_numeric(True)
        self.thread_spin.set_value(4)
        left.pack_start(self.thread_spin, False, False, 0)

        # ---------- CONTEXT ----------
        left.pack_start(Gtk.Label(label="Context Lines Before/After:"), False, False, 0)

        self.context_spin = Gtk.SpinButton()
        self.context_spin.set_range(1, 50)
        self.context_spin.set_increments(1, 1)
        self.context_spin.set_numeric(True)
        self.context_spin.set_value(5)
        left.pack_start(self.context_spin, False, False, 0)

        # ---------- BUTTONS ----------
        self.btn_start = Gtk.Button(label="Start Scan")
        self.btn_start.connect("clicked", self.start_scan)
        left.pack_start(self.btn_start, False, False, 0)

        self.btn_pause = Gtk.Button(label="Pause / Resume")
        self.btn_pause.connect("clicked", self.toggle_pause)
        left.pack_start(self.btn_pause, False, False, 0)

        self.btn_cancel = Gtk.Button(label="Cancel")
        self.btn_cancel.connect("clicked", self.cancel_scan)
        left.pack_start(self.btn_cancel, False, False, 0)

        self.btn_clear = Gtk.Button(label="Clear Results")
        self.btn_clear.connect("clicked", lambda x: self.store.clear())
        left.pack_start(self.btn_clear, False, False, 0)

        # ---------- STATUS ----------
        self.status = Gtk.Label(label="Idle")
        left.pack_start(self.status, False, False, 5)

        left.pack_start(Gtk.Label(label="File Scan Progress"), False, False, 0)

        self.progress = Gtk.ProgressBar()
        self.progress.set_show_text(True)
        left.pack_start(self.progress, False, False, 0)

        left.pack_start(Gtk.Label(label="Results Progress"), False, False, 0)

        self.progress2 = Gtk.ProgressBar()
        self.progress2.set_show_text(True)
        left.pack_start(self.progress2, False, False, 0)

        # ==================================================
        # RIGHT PANEL
        # ==================================================
        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        main.pack_start(right, True, True, 5)

        self.search = Gtk.Entry()
        self.search.set_placeholder_text("Filter results...")
        self.search.connect("changed", self.apply_filter)
        right.pack_start(self.search, False, False, 0)

        # hidden context column kept internally
        self.store = Gtk.ListStore(str, str, str, str, str, str)

        self.filter_model = self.store.filter_new()
        self.filter_model.set_visible_func(self.filter_func)

        self.tree = Gtk.TreeView(model=self.filter_model)

        columns = [
            ("File", 0),
            ("Class", 1),
            ("Method", 2),
            ("Match", 3),
            ("Severity", 5),
        ]

        for title, idx in columns:
            cell = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, cell, text=idx)

            if title == "Severity":
                col.set_cell_data_func(cell, self.color_cell)

            col.set_resizable(True)
            self.tree.append_column(col)

        self.tree.connect("row-activated", self.on_click)

        scroll = Gtk.ScrolledWindow()
        scroll.add(self.tree)
        right.pack_start(scroll, True, True, 0)

    # ==================================================
    # COLORS
    # ==================================================
    def color_cell(self, col, cell, model, itr, data):
        sev = model.get_value(itr, 5)

        colors = {
            "Critical": "red",
            "High": "orange",
            "Medium": "gold",
            "Low": "blue",
            "Informational": "gray",
            "Manual": "purple"
        }

        cell.set_property("foreground", colors.get(sev, "black"))

    # ==================================================
    # FILTER
    # ==================================================
    def filter_func(self, model, itr, data=None):
        txt = self.search.get_text().lower()

        if not txt:
            return True

        for i in range(6):
            val = model.get_value(itr, i)
            if val and txt in str(val).lower():
                return True

        return False

    def apply_filter(self, w):
        self.filter_model.refilter()

    # ==================================================
    # PATTERNS
    # ==================================================
    def load_patterns(self):
        out = []

        if self.chk_text.get_active():
            t = self.entry.get_text().strip()
            if t:
                out.append({
                    "regex": re.compile(t, re.I),
                    "info": "Manual"
                })

        if self.chk_json.get_active():
            try:
                data = json.load(open("regex.json"))
                for x in data:
                    out.append({
                        "regex": re.compile(x["pattern"], re.I),
                        "info": x.get("matchInfo", "Informational")
                    })
            except:
                pass

        return out

    # ==================================================
    # FILE TYPES
    # ==================================================
    def get_exts(self):
        exts = []

        if self.chk_dll.get_active():
            exts.append(".dll")

        if self.chk_exe.get_active():
            exts.append(".exe")

        if self.chk_apk.get_active():
            exts.append(".apk")

        if self.chk_other.get_active():
            exts += [".txt", ".json", ".xml", ".log"]

        return exts

    def collect(self, folder):
        exts = self.get_exts()

        return [
            os.path.join(r, f)
            for r, _, files in os.walk(folder)
            for f in files
            if any(f.lower().endswith(e) for e in exts)
        ]

    # ==================================================
    # FILE SELECT
    # ==================================================
    def select_folder(self, w):
        dlg = Gtk.FileChooserDialog(
            title="Select Folder",
            parent=self,
            action=Gtk.FileChooserAction.SELECT_FOLDER
        )
        dlg.add_buttons(Gtk.STOCK_CANCEL, 0, Gtk.STOCK_OPEN, 1)

        if dlg.run() == 1:
            self.targets = self.collect(dlg.get_filename())

        dlg.destroy()

    def select_files(self, w):
        dlg = Gtk.FileChooserDialog(
            title="Select Files",
            parent=self,
            action=Gtk.FileChooserAction.OPEN
        )
        dlg.set_select_multiple(True)
        dlg.add_buttons(Gtk.STOCK_CANCEL, 0, Gtk.STOCK_OPEN, 1)

        if dlg.run() == 1:
            self.targets = dlg.get_filenames()

        dlg.destroy()

    # ==================================================
    # CONTROL
    # ==================================================
    def start_scan(self, w):
        patterns = self.load_patterns()

        if not patterns or not self.targets:
            return

        self.scan_token += 1
        token = self.scan_token

        self.cancel_flag = False
        self.pause_flag = False

        self.total = len(self.targets)
        self.done = 0
        self.running = int(self.thread_spin.get_value())

        self.match_total = 0
        self.match_done = 0

        self.results_seen.clear()
        self.store.clear()

        self.progress.set_fraction(0)
        self.progress.set_text("0%")

        self.progress2.set_fraction(0)
        self.progress2.set_text("Waiting...")

        self.status.set_text("Scanning files...")

        self.btn_start.set_sensitive(False)

        self.queue = Queue()

        for t in self.targets:
            self.queue.put(t)

        for _ in range(self.running):
            threading.Thread(
                target=self.worker,
                args=(patterns, token),
                daemon=True
            ).start()

    def toggle_pause(self, w):
        self.pause_flag = not self.pause_flag

    def cancel_scan(self, w):
        self.cancel_flag = True

    # ==================================================
    # SAFE APPEND
    # ==================================================
    def safe_append(self, row):
        self.store.append(row)

    # ==================================================
    # WORKER
    # ==================================================
    def worker(self, patterns, token):

        cmd = os.path.expanduser("~/.dotnet/tools/ilspycmd")

        while not self.cancel_flag and token == self.scan_token:

            while self.pause_flag and not self.cancel_flag:
                time.sleep(0.2)

            try:
                file = self.queue.get_nowait()
            except Empty:
                break

            self.done += 1
            GLib.idle_add(self.update_progress)

            outdir = f"/tmp/scan_{uuid.uuid4().hex}"
            os.makedirs(outdir, exist_ok=True)

            proc = None

            try:
                if file.lower().endswith((".dll", ".exe")):
                    proc = subprocess.Popen(
                        [cmd, file, "-o", outdir],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )

                elif file.lower().endswith(".apk"):
                    proc = subprocess.Popen(
                        ["apktool", "d", file, "-o", outdir, "-f"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )

                else:
                    outdir = os.path.dirname(file)

                if proc:
                    while proc.poll() is None:
                        if self.cancel_flag:
                            proc.terminate()
                            break
                        time.sleep(0.2)

            except:
                pass

            for r, _, files in os.walk(outdir):
                for f in files:

                    path = os.path.join(r, f)

                    try:
                        lines = open(path, errors="ignore").read().splitlines()
                    except:
                        continue

                    for i, line in enumerate(lines):

                        for p in patterns:

                            if p["regex"].search(line):

                                ctx = int(self.context_spin.get_value())

                                start = max(0, i - ctx)
                                end = min(len(lines), i + ctx + 1)

                                snippet = "\n".join(lines[start:end])

                                match_text = line.strip()

                                key = (
                                    os.path.basename(file).lower(),
                                    match_text.lower(),
                                    p["info"].lower()
                                )

                                with self.lock:
                                    if key in self.results_seen:
                                        continue

                                    self.results_seen.add(key)
                                    self.match_total += 1

                                GLib.idle_add(
                                    self.safe_append,
                                    [
                                        os.path.basename(file),
                                        "",
                                        "",
                                        match_text,
                                        snippet,
                                        p["info"]
                                    ]
                                )

                                GLib.idle_add(self.update_result_progress)
                                break

            if os.path.exists(outdir) and outdir.startswith("/tmp/scan_"):
                shutil.rmtree(outdir, ignore_errors=True)

        with self.lock:
            self.running -= 1
            if self.running == 0:
                GLib.idle_add(self.finish_scan)

    # ==================================================
    # PROGRESS
    # ==================================================
    def update_progress(self):
        if self.total == 0:
            return

        pct = self.done / self.total

        self.progress.set_fraction(pct)
        self.progress.set_text(f"{self.done}/{self.total} files")
        self.status.set_text("Scanning files...")

    def update_result_progress(self):

        self.match_done += 1

        if self.match_total == 0:
            return

        pct = self.match_done / self.match_total

        self.progress2.set_fraction(pct)
        self.progress2.set_text(
            f"{self.match_done}/{self.match_total} results"
        )

        self.status.set_text("Rendering results...")

    def finish_scan(self):
        self.btn_start.set_sensitive(True)

        self.progress.set_fraction(1.0)
        self.progress.set_text(f"{self.total}/{self.total} files")

        self.progress2.set_fraction(1.0)

        total_results = max(self.match_done, self.match_total)
        self.progress2.set_text(
            f"{total_results}/{total_results} results"
        )

        self.status.set_text("Finished")

    # ==================================================
    # CONTEXT VIEW
    # ==================================================
    def on_click(self, tree, path, col):

        itr = self.filter_model.get_iter(path)
        context = self.filter_model.get_value(itr, 4)

        win = Gtk.Window(title="Context Viewer")
        win.set_default_size(900, 600)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        win.add(box)

        tv = Gtk.TextView()
        tv.set_editable(False)
        tv.set_wrap_mode(Gtk.WrapMode.NONE)
        tv.get_buffer().set_text(context)

        scr = Gtk.ScrolledWindow()
        scr.add(tv)

        box.pack_start(scr, True, True, 0)

        win.show_all()


win = Scanner()
win.connect("destroy", Gtk.main_quit)
win.show_all()
Gtk.main()
