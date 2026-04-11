"""
YouTube Downloader GUI - CustomTkinter + pywinstyles (Apple/Fluent Design)
"""

import os
import sys
import threading
import traceback
import ctypes
import tkinter as tk

import customtkinter as ctk
import pywinstyles

from yt_downloader.browser_cookies import extract_cookies, is_admin
from yt_downloader.downloader import find_yt_dlp, fetch_formats, get_resolution_list, download_video


class YouTubeDownloaderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("YouTube Downloader")
        self.root.geometry("580x720")
        self.root.minsize(480, 600)
        self.root.resizable(True, True)

        # DPI awareness
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

        # CustomTkinter setup
        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("blue")

        # State
        self.cookie_file = os.path.join(os.environ["TEMP"], "yt_cookies_gui.txt")
        self.selected_format_id = None
        self.video_info = None
        self.browser_native = None

        self._setup_mica()
        self._build_ui()

    def _setup_mica(self):
        """Apply Win11 Mica material (Fluent Design frosted glass)."""
        self.root.update()
        try:
            pywinstyles.apply_style(self.root, "mica")
            pywinstyles.change_header_color(self.root, "transparent")
        except Exception:
            pass

    def _build_ui(self):
        """Apple-style single-column card layout."""
        # Detect theme
        self._is_dark = ctk.get_appearance_mode() == "Dark"

        # Card background colors
        self._card_bg = "#2B2B2B" if self._is_dark else "#F2F2F7"
        self._log_bg = "#222222" if self._is_dark else "#F2F2F7"
        self._log_fg = "#E5E5E5" if self._is_dark else "#1D1D1F"
        self._text_secondary = "#8E8E93" if self._is_dark else "#86868B"
        self._text_primary = "#FFFFFF" if self._is_dark else "#1D1D1F"

        # Main scrollable frame
        self.main_frame = ctk.CTkScrollableFrame(
            self.root, corner_radius=0, fg_color="transparent"
        )
        self.main_frame.pack(fill="both", expand=True, padx=24, pady=20)

        # ---- Title Area ----
        title_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        title_frame.pack(fill="x", pady=(0, 16))

        ctk.CTkLabel(
            title_frame,
            text="YouTube Downloader",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=22, weight="bold"),
        ).pack(anchor="w")

        status_text = "Administrator" if is_admin() else "Standard User"
        status_color = "#34C759" if is_admin() else "#FF9500"
        ctk.CTkLabel(
            title_frame,
            text=f"\u25cf {status_text}",
            text_color=status_color,
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=11),
        ).pack(anchor="w", pady=(2, 0))

        # ---- Browser Selection ----
        self._section_label("Browser")
        self.browser_var = tk.StringVar(value="Chrome")

        browser_row = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        browser_row.pack(fill="x", pady=(0, 2))

        for i, browser in enumerate(["Chrome", "Edge", "Firefox"]):
            rb = ctk.CTkRadioButton(
                browser_row,
                text=browser,
                variable=self.browser_var,
                value=browser,
                font=ctk.CTkFont(family="Microsoft YaHei UI", size=13),
                command=self._on_browser_change,
            )
            rb.pack(side="left", padx=(0, 20))

        # ---- URL Input ----
        self._section_label("Video URL")

        url_card = ctk.CTkFrame(self.main_frame, fg_color=self._card_bg, corner_radius=12)
        url_card.pack(fill="x", pady=(0, 16))

        self.url_var = tk.StringVar()
        self.url_entry = ctk.CTkEntry(
            url_card,
            textvariable=self.url_var,
            placeholder_text="https://www.youtube.com/watch?v=...",
            font=ctk.CTkFont(family="Consolas", size=13),
            corner_radius=10,
            height=44,
            border_width=0,
        )
        self.url_entry.pack(fill="x", padx=12, pady=10)
        self.url_entry.bind("<Return>", lambda e: self.fetch_video_info())

        # ---- Fetch Button ----
        self.fetch_btn = ctk.CTkButton(
            self.main_frame,
            text="Fetch",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=14, weight="bold"),
            height=44,
            corner_radius=22,
            command=self.fetch_video_info,
        )
        self.fetch_btn.pack(fill="x", pady=(0, 8))

        # ---- Status ----
        self.status_label = ctk.CTkLabel(
            self.main_frame,
            text="Ready",
            text_color=self._text_secondary,
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=11),
        )
        self.status_label.pack(anchor="w", pady=(0, 12))

        # ---- Progress ----
        self.progress = ctk.CTkProgressBar(self.main_frame, height=4, corner_radius=2)
        self.progress.pack(fill="x", pady=(0, 12))
        self.progress.set(0)

        # ---- Log ----
        self._section_label("Log")
        log_card = ctk.CTkFrame(
            self.main_frame, fg_color=self._card_bg, corner_radius=12
        )
        log_card.pack(fill="both", expand=False, pady=(0, 16))

        self.log_text = tk.Text(
            log_card,
            height=6,
            wrap="word",
            state="disabled",
            font=("Consolas", 9),
            bg=self._log_bg,
            fg=self._log_fg,
            borderwidth=0,
            highlightthickness=0,
            relief="flat",
            selectbackground="#007AFF",
        )
        self.log_text.pack(fill="both", expand=True, padx=12, pady=10)
        self._configure_scrollbar()

        # ---- Resolution Selection ----
        self._section_label("Resolution")
        res_card = ctk.CTkFrame(
            self.main_frame, fg_color=self._card_bg, corner_radius=12
        )
        res_card.pack(fill="x", pady=(0, 16))

        self.res_scroll = ctk.CTkScrollableFrame(
            res_card, fg_color="transparent", corner_radius=0
        )
        self.res_scroll.pack(fill="x", padx=12, pady=10)

        self.resolution_var = tk.StringVar(value="best")
        self.res_placeholder = ctk.CTkLabel(
            self.res_scroll,
            text='Click "Fetch" to load resolutions...',
            text_color=self._text_secondary,
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=12),
        )
        self.res_placeholder.pack(anchor="w", pady=8)

        # ---- Download Button ----
        self.download_btn = ctk.CTkButton(
            self.main_frame,
            text="Download",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=14, weight="bold"),
            height=44,
            corner_radius=22,
            command=self.start_download,
            state="disabled",
            fg_color="#007AFF",
            hover_color="#0055CC",
        )
        self.download_btn.pack(fill="x", pady=(0, 8))

        self.folder_btn = ctk.CTkButton(
            self.main_frame,
            text="Open Download Folder",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=13),
            height=40,
            corner_radius=20,
            command=self.open_download_folder,
            fg_color="transparent",
            hover_color=self._text_secondary,
            text_color=self._text_primary,
        )
        self.folder_btn.pack(fill="x")

        # ---- Spacer ----
        ctk.CTkFrame(self.main_frame, fg_color="transparent", height=20).pack(fill="x")

    def _configure_scrollbar(self):
        """Add scrollbar to log text."""
        scrollbar = tk.Scrollbar(
            self.log_text,
            orient="vertical",
            command=self.log_text.yview,
        )
        self.log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

    def _section_label(self, text):
        """Apple-style section heading."""
        ctk.CTkLabel(
            self.main_frame,
            text=text,
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=15, weight="bold"),
            text_color=self._text_primary,
        ).pack(anchor="w", pady=(12, 4))

    def _on_browser_change(self):
        """Update UI when browser selection changes."""
        pass

    def log(self, msg):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
        self.root.update_idletasks()

    def set_status(self, msg):
        self.status_label.configure(text=msg)

    def set_progress(self, running=False):
        if running:
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.set(0)

    def fetch_video_info(self):
        url = self.url_var.get().strip()
        if not url:
            self.root.bell()
            self.url_entry.focus()
            return

        browser = self.browser_var.get()
        if browser == "Edge" and not is_admin():
            self.root.bell()
            return
        if browser == "Chrome" and not is_admin():
            # Show warning in log instead of popup
            self.log("Note: Chrome works without admin via chromelevator (may be slower)")

        self.fetch_btn.configure(state="disabled")
        self.download_btn.configure(state="disabled")
        self.set_status("Extracting cookies...")
        self.set_progress(True)
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

        def worker():
            try:
                use_cookie_file, browser_native = extract_cookies(
                    browser, self.cookie_file,
                    log_callback=lambda m: self.root.after(0, self.log, m),
                )
                self.browser_native = browser_native
                cookie_file = self.cookie_file if use_cookie_file else None
                bn = browser_native if not use_cookie_file else None

                self.root.after(0, self.set_status, "Fetching video info...")
                info = fetch_formats(
                    url, cookie_file,
                    browser_native=bn,
                    log_callback=lambda m: self.root.after(0, self.log, m),
                )
                self.video_info = info
                title = info.get("title", "Unknown")
                self.root.after(0, self.log, f"Title: {title}")

                resolutions = get_resolution_list(info)
                self.root.after(0, self.set_status, f"Found {len(resolutions)} resolutions")
                self.root.after(0, lambda: self.populate_resolutions(resolutions))
                self.root.after(0, self.download_btn.configure, {"state": "normal"})

            except Exception as e:
                self.root.after(0, self.log, f"ERROR: {e}")
                self.root.after(0, self.log, traceback.format_exc())
                self.root.after(0, self.set_status, "Failed")
            finally:
                self.root.after(0, self.fetch_btn.configure, {"state": "normal"})
                self.root.after(0, self.set_progress, False)

        threading.Thread(target=worker, daemon=True).start()

    def _restart_as_admin(self):
        """Restart the GUI with admin privileges."""
        script = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{a}"' for a in sys.argv[1:]])
        python_exe = sys.executable
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", python_exe, f'"{script}" {params}', None, 1
        )
        if int(ret) <= 32:
            self.log("Failed to restart as Administrator.")
        else:
            self.root.destroy()

    def populate_resolutions(self, resolutions):
        for widget in self.res_scroll.winfo_children():
            widget.destroy()

        # "Best" option
        rb = ctk.CTkRadioButton(
            self.res_scroll,
            text="Best quality available",
            variable=self.resolution_var,
            value="best",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=12),
        )
        rb.pack(anchor="w", pady=2)
        self.resolution_var.set("best")

        for height, res_label in resolutions:
            rb = ctk.CTkRadioButton(
                self.res_scroll,
                text=res_label,
                variable=self.resolution_var,
                value=str(height),
                font=ctk.CTkFont(family="Microsoft YaHei UI", size=12),
            )
            rb.pack(anchor="w", pady=2)

    def start_download(self):
        url = self.url_var.get().strip()
        if not url:
            self.root.bell()
            self.url_entry.focus()
            return

        resolution = self.resolution_var.get()
        self.download_btn.configure(state="disabled")
        self.set_status("Starting download...")
        self.set_progress(True)

        def worker():
            try:
                cookie_file = self.cookie_file if os.path.exists(self.cookie_file) else None
                bn = self.browser_native if not cookie_file else None

                process = download_video(
                    url=url,
                    cookie_file=cookie_file,
                    resolution=resolution,
                    browser_native=bn,
                    log_callback=lambda m: self.root.after(0, self.log, m),
                )

                if process.returncode == 0:
                    self.root.after(0, self.log, "\u2500" * 50)
                    self.root.after(0, self.log, "Download complete!")
                    self.root.after(0, self.set_status, "Download complete!")
                else:
                    self.root.after(0, self.log, "\u2500" * 50)
                    self.root.after(0, self.log, f"Download failed (code {process.returncode})")
                    self.root.after(0, self.set_status, "Download failed")

            except Exception as e:
                self.root.after(0, self.log, f"ERROR: {e}")
                self.root.after(0, self.set_status, "Error")
            finally:
                self.root.after(0, self.download_btn.configure, {"state": "normal"})
                self.root.after(0, self.set_progress, False)

        threading.Thread(target=worker, daemon=True).start()

    def open_download_folder(self):
        save_dir = os.path.join(os.environ["USERPROFILE"], "Videos")
        os.makedirs(save_dir, exist_ok=True)
        os.startfile(save_dir)


def main():
    root = ctk.CTk()
    YouTubeDownloaderGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
