"""
YouTube Downloader GUI

- Solid backgrounds, no fake acrylic
- Large pill buttons (corner_radius=20)
- Apple Blue (#0071e3) only accent
- DPI-aware sizing for 4K screens
- Real download progress bar with %, speed, ETA
- Log in separate window
"""

import os
import sys
import threading
import traceback
import tkinter as tk

import customtkinter as ctk

from yt_downloader.browser_cookies import extract_cookies, is_admin
from yt_downloader.downloader import (
    find_yt_dlp, fetch_formats, get_resolution_list, download_video,
)

# ── Colors ────────────────────────────────────────────────────────
APPLE_BLUE = "#0071e3"
GREEN = "#34C759"

LIGHT = {
    "bg":        "#FFFFFF",
    "surface":   "#F5F5F7",
    "primary":   "#1D1D1F",
    "secondary": "#6E6E73",
    "divider":   "#E5E5EA",
    "entry_bg":  "#F5F5F7",
    "progress_bg": "#E5E5EA",
}

DARK = {
    "bg":        "#1A1A1A",
    "surface":   "#2C2C2E",
    "primary":   "#F5F5F7",
    "secondary": "#98989D",
    "divider":   "#38383A",
    "entry_bg":  "#2C2C2E",
    "progress_bg": "#38383A",
}

PADDING = 28
PILL_RADIUS = 20
ENTRY_RADIUS = 12

FONT_TITLE = ("Segoe UI", 18)
FONT_BODY = ("Segoe UI", 13)
FONT_SMALL = ("Segoe UI", 11)
FONT_CODE = ("Consolas", 9)
FONT_PROGRESS = ("Segoe UI", 11)


# ── Log Window ────────────────────────────────────────────────────

class LogWindow(ctk.CTkToplevel):
    def __init__(self, master, colors):
        super().__init__(master)
        self.title("Log")
        self.geometry("500x340")
        self.minsize(380, 220)
        self._c = colors
        self._build()

    def _build(self):
        C = self._c
        frame = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        frame.pack(fill="both", expand=True)

        hdr = ctk.CTkFrame(frame, fg_color="transparent", height=44)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text="Log", font=FONT_BODY, text_color=C["primary"],
        ).pack(side="left", padx=16, pady=12)
        ctk.CTkButton(
            hdr, text="✕", width=24, height=24, corner_radius=12,
            fg_color="transparent", hover_color=C["surface"],
            text_color=C["secondary"], command=self.destroy,
            font=("Segoe UI", 10),
        ).pack(side="right", padx=12, pady=10)

        ctk.CTkFrame(frame, fg_color=C["divider"], height=1).pack(fill="x")

        self.text = tk.Text(
            frame, wrap="word", state="disabled", font=FONT_CODE,
            bg=C["entry_bg"], fg=C["primary"],
            borderwidth=0, highlightthickness=0, relief="flat",
            selectbackground=APPLE_BLUE,
        )
        self.text.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        sb = tk.Scrollbar(self.text, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")

    def log(self, msg):
        self.text.configure(state="normal")
        self.text.insert("end", msg + "\n")
        self.text.see("end")
        self.text.configure(state="disabled")
        self.update_idletasks()


# ── Resolution Modal ──────────────────────────────────────────────

class ResolutionDialog(ctk.CTkToplevel):
    def __init__(self, master, title, resolutions, colors):
        super().__init__(master)
        self.title("Choose Quality")
        self.resolutions = resolutions
        self._c = colors
        self._result = None
        self.res_var = tk.StringVar(value="best")

        px = master.winfo_rootx()
        py = master.winfo_rooty()
        pw = master.winfo_width()
        ph = master.winfo_height()
        self.geometry(f"+{px + pw // 2 - 180}+{py + ph // 2 - 210}")

        self._build(title)
        self.grab_set()
        self.transient(master)
        self.wait_window()

    def _build(self, title):
        C = self._c
        self.geometry("360x440")
        self.resizable(False, False)

        bg = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        bg.pack(fill="both", expand=True)

        # Header
        hdr = ctk.CTkFrame(bg, fg_color="transparent", height=48)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text="Quality", font=("Segoe UI", 15),
            text_color=C["primary"],
        ).pack(side="left", padx=20, pady=14)
        ctk.CTkButton(
            hdr, text="✕", width=24, height=24, corner_radius=12,
            fg_color="transparent", hover_color=C["surface"],
            text_color=C["secondary"], command=self._close,
            font=("Segoe UI", 10),
        ).pack(side="right", padx=16, pady=12)

        ctk.CTkFrame(bg, fg_color=C["divider"], height=1).pack(fill="x")

        # Video title
        ctk.CTkLabel(
            bg, text=title, wraplength=300,
            font=FONT_SMALL, text_color=C["secondary"],
            justify="left",
        ).pack(fill="x", padx=20, pady=(12, 4))

        # Radio list
        scroll = ctk.CTkScrollableFrame(bg, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=20, pady=(8, 12))

        self._radio(scroll, "Best quality available", "best")
        for height, label in self.resolutions:
            self._radio(scroll, label, str(height))

        ctk.CTkFrame(bg, fg_color=C["divider"], height=1).pack(fill="x")

        ctk.CTkButton(
            bg, text="Download",
            font=("Segoe UI", 14), height=42, corner_radius=PILL_RADIUS,
            fg_color=APPLE_BLUE, hover_color="#006DD8",
            text_color="#FFFFFF", command=self._ok,
        ).pack(fill="x", padx=20, pady=(12, 16))

    def _radio(self, parent, text, value):
        ctk.CTkRadioButton(
            parent, text=text, variable=self.res_var, value=value,
            font=FONT_BODY, text_color=self._c["primary"],
        ).pack(anchor="w", pady=(6, 2))

    def _ok(self):
        self._result = self.res_var.get()
        self.destroy()

    def _close(self):
        self._result = None
        self.destroy()

    @property
    def result(self):
        return self._result


# ── Main App ──────────────────────────────────────────────────────

class YouTubeDownloaderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("YouTube Downloader")

        # DPI-aware sizing
        self._scale = self._detect_scale()
        w = int(600 * self._scale)
        h = int(400 * self._scale)
        self.root.geometry(f"{w}x{h}")
        self.root.minsize(int(440 * self._scale), int(340 * self._scale))

        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

        self._dark = ctk.get_appearance_mode() == "Dark"
        self.c = DARK if self._dark else LIGHT

        self.cookie_file = os.path.join(os.environ["TEMP"], "yt_cookies_gui.txt")
        self.browser_native = None
        self.log_win = None
        self.busy = False

        # Progress state
        self.dl_progress = 0.0
        self.dl_speed = ""
        self.dl_eta = ""

        self._build()

    def _detect_scale(self):
        """Detect Windows display scale. Returns 1.75 for 4K at 175%."""
        try:
            import ctypes as _ct
            root = tk.Tk()
            root.withdraw()
            # Set DPI awareness so GetSystemMetrics returns physical pixels
            try:
                _ct.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass
            phys_w = _ct.windll.user32.GetSystemMetrics(0)  # SM_CXSCREEN
            logical_w = root.winfo_screenwidth()
            root.destroy()
            scale = phys_w / logical_w if logical_w > 0 else 1.0
            return max(1.0, min(scale, 2.5))
        except Exception:
            return 1.0

    # ── Build ─────────────────────────────────────────────────────

    def _build(self):
        C = self.c

        bg = ctk.CTkFrame(self.root, fg_color=C["bg"], corner_radius=0)
        bg.pack(fill="both", expand=True)

        # ── Header ──
        hdr = ctk.CTkFrame(bg, fg_color="transparent")
        hdr.pack(fill="x", padx=PADDING, pady=(24, 0))

        ctk.CTkLabel(
            hdr, text="YouTube Downloader",
            font=FONT_TITLE, text_color=C["primary"],
        ).pack(anchor="w")

        st = "Administrator" if is_admin() else "Standard"
        sc = GREEN if is_admin() else "#FF9500"
        ctk.CTkLabel(
            hdr, text=f"● {st}", text_color=sc,
            font=FONT_SMALL,
        ).pack(anchor="w", pady=(2, 0))

        # ── Content ──
        main = ctk.CTkFrame(bg, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=PADDING, pady=24)

        # Browser label + pills
        ctk.CTkLabel(
            main, text="Browser",
            font=FONT_SMALL, text_color=C["secondary"],
        ).pack(anchor="w", pady=(0, 4))

        pills = ctk.CTkFrame(main, fg_color="transparent")
        pills.pack(fill="x", pady=(0, 16))

        self.browser_var = tk.StringVar(value="Chrome")
        for browser in ["Chrome", "Edge", "Firefox"]:
            ctk.CTkRadioButton(
                pills, text=browser,
                variable=self.browser_var, value=browser,
                font=FONT_BODY, text_color=C["primary"],
            ).pack(side="left", padx=(0, 20))

        # URL label + entry
        ctk.CTkLabel(
            main, text="URL",
            font=FONT_SMALL, text_color=C["secondary"],
        ).pack(anchor="w", pady=(0, 4))

        self.url_var = tk.StringVar()
        self.url_entry = ctk.CTkEntry(
            main, textvariable=self.url_var,
            placeholder_text="https://www.youtube.com/watch?v=...",
            font=FONT_CODE, height=int(42 * self._scale), corner_radius=ENTRY_RADIUS,
            border_width=0, fg_color=C["entry_bg"],
            text_color=C["primary"],
        )
        self.url_entry.pack(fill="x", pady=(0, 14))
        self.url_entry.bind("<Return>", lambda e: self._go())

        # ── Progress area (hidden until download) ──
        self.progress_frame = ctk.CTkFrame(main, fg_color="transparent")

        self.progress_bar = ctk.CTkProgressBar(
            self.progress_frame, height=8, corner_radius=4,
            progress_color=APPLE_BLUE, fg_color=C["progress_bg"],
        )
        self.progress_bar.pack(fill="x")
        self.progress_bar.set(0)

        info_row = ctk.CTkFrame(self.progress_frame, fg_color="transparent")
        info_row.pack(fill="x", pady=(4, 0))

        self.progress_pct_label = ctk.CTkLabel(
            info_row, text="0%",
            font=FONT_PROGRESS, text_color=C["primary"],
        )
        self.progress_pct_label.pack(side="left")

        self.progress_detail = ctk.CTkLabel(
            info_row, text="",
            font=("Segoe UI", 10), text_color=C["secondary"],
        )
        self.progress_detail.pack(side="right")

        # ── Status row ──
        srow = ctk.CTkFrame(main, fg_color="transparent")
        srow.pack(fill="x", pady=(14, 0))

        self.status_label = ctk.CTkLabel(
            srow, text="Paste a URL and press Download",
            font=FONT_SMALL, text_color=C["secondary"],
        )
        self.status_label.pack(side="left", pady=4)

        ctk.CTkButton(
            srow, text="Log",
            font=("Segoe UI", 10), width=50, height=22, corner_radius=11,
            fg_color="transparent", hover_color=C["surface"],
            text_color=C["secondary"], command=self._open_log,
        ).pack(side="right")

        # ── Download button ──
        self.action_btn = ctk.CTkButton(
            main, text="Download",
            font=("Segoe UI", 14), height=int(42 * self._scale),
            corner_radius=PILL_RADIUS,
            fg_color=APPLE_BLUE, hover_color="#006DD8",
            text_color="#FFFFFF", command=self._go,
        )
        self.action_btn.pack(fill="x", pady=(14, 0))

    # ── Progress update ───────────────────────────────────────────

    def _update_progress(self, pct, speed, eta):
        self.dl_progress = pct
        self.dl_speed = speed
        self.dl_eta = eta
        self.progress_bar.set(pct)
        pct_str = f"{pct * 100:.1f}%"
        self.progress_pct_label.configure(text=pct_str)
        detail = f"{speed} · {eta}" if speed else ""
        self.progress_detail.configure(text=detail)

    def _reset_progress(self):
        self.progress_bar.set(0)
        self.progress_pct_label.configure(text="0%")
        self.progress_detail.configure(text="")
        self.dl_progress = 0.0
        self.dl_speed = ""
        self.dl_eta = ""

    # ── Helpers ───────────────────────────────────────────────────

    def _open_log(self):
        if self.log_win is None or not self.log_win.winfo_exists():
            self.log_win = LogWindow(self.root, self.c)
            self.log_win.deiconify()
        else:
            self.log_win.focus()

    def _log(self, msg):
        if self.log_win and self.log_win.winfo_exists():
            self.log_win.log(msg)
        self.root.update_idletasks()

    def _status(self, msg):
        self.status_label.configure(text=msg)

    def _reset(self):
        self.busy = False
        self.action_btn.configure(state="normal", text="Download")
        self._reset_progress()
        self.progress_frame.pack_forget()
        # Restore status text
        self._status("Paste a URL and press Download")

    def _go(self):
        url = self.url_var.get().strip()
        if not url:
            self.root.bell()
            self.url_entry.focus()
            return

        browser = self.browser_var.get()
        if browser == "Edge" and not is_admin():
            self._log("Edge requires Administrator privileges.")
            self._status("Edge requires admin — restart as Administrator")
            return

        if self.busy:
            return
        self.busy = True

        self.action_btn.configure(state="disabled", text="Loading…")
        self._status("Extracting cookies…")
        self._reset_progress()

        def worker():
            try:
                use_cookie_file, browser_native = extract_cookies(
                    browser, self.cookie_file,
                    log_callback=lambda m: self.root.after(0, self._log, m),
                )
                self.browser_native = browser_native
                cookie_file = self.cookie_file if use_cookie_file else None
                bn = browser_native if not use_cookie_file else None

                self.root.after(0, self._status, "Fetching video info…")
                info = fetch_formats(
                    url, cookie_file, browser_native=bn,
                    log_callback=lambda m: self.root.after(0, self._log, m),
                )

                title = info.get("title", "Unknown")
                resolutions = get_resolution_list(info)

                def show_modal():
                    dlg = ResolutionDialog(self.root, title, resolutions, self.c)
                    resolution = dlg.result
                    if resolution:
                        self.root.after(0, lambda: self._download(
                            url, cookie_file, bn, resolution, title,
                        ))
                    else:
                        self.root.after(0, self._reset)

                self.root.after(0, show_modal)

            except Exception as e:
                self.root.after(0, self._log, f"ERROR: {e}")
                self.root.after(0, self._log, traceback.format_exc())
                self.root.after(0, self._status, "Failed")
                self.root.after(0, self._reset)

        threading.Thread(target=worker, daemon=True).start()

    def _download(self, url, cookie_file, bn, resolution, title):
        # Show progress bar
        self.progress_frame.pack(fill="x", pady=(0, 12), before=self.status_label.master)
        self._status(f"Downloading: {title[:50]}…")
        self._reset_progress()

        def worker():
            try:
                process = download_video(
                    url=url, cookie_file=cookie_file,
                    resolution=resolution, browser_native=bn,
                    log_callback=lambda m: self.root.after(0, self._log, m),
                    progress_callback=lambda pct, spd, eta: self.root.after(
                        0, self._update_progress, pct, spd, eta
                    ),
                )

                if process.returncode == 0:
                    self.root.after(0, self._update_progress, 1.0, "", "")
                    self.root.after(0, self._log, "Download complete!")
                    self.root.after(0, self._status, "Download complete!")
                else:
                    self.root.after(0, self._log, f"Failed (code {process.returncode})")
                    self.root.after(0, self._status, f"Failed (exit {process.returncode})")

            except Exception as e:
                self.root.after(0, self._log, f"ERROR: {e}")
                self.root.after(0, self._status, "Error")
            finally:
                self.root.after(0, self._reset)

        threading.Thread(target=worker, daemon=True).start()


def main():
    ctk.set_appearance_mode("system")
    root = ctk.CTk()
    YouTubeDownloaderGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
