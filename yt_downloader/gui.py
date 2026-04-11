"""
YouTube Downloader GUI - Tkinter-based interface.
"""

import os
import sys
import threading
import traceback
import webbrowser
import ctypes
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from yt_downloader.browser_cookies import (
    extract_cookies,
    is_admin,
)
from yt_downloader.downloader import (
    find_yt_dlp,
    fetch_formats,
    get_resolution_list,
    download_video,
)


class YouTubeDownloaderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("YouTube Downloader")
        self.root.geometry("700x620")
        self.root.resizable(True, True)
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

        self.cookie_file = os.path.join(os.environ["TEMP"], "yt_cookies_gui.txt")
        self.selected_format_id = None
        self.video_info = None
        self.browser_native = None

        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 12, "pady": 5}

        # ----- Browser Selection -----
        frm_browser = ttk.LabelFrame(self.root, text="1. Select Browser")
        frm_browser.pack(fill="x", **pad)

        self.browser_var = tk.StringVar(value="Chrome")
        for i, browser in enumerate(["Chrome", "Edge", "Firefox"]):
            ttk.Radiobutton(
                frm_browser,
                text=browser,
                variable=self.browser_var,
                value=browser,
            ).grid(row=0, column=i, padx=15, pady=8, sticky="w")

        admin_label = "Admin" if is_admin() else "No Admin"
        admin_color = "green" if is_admin() else "red"
        ttk.Label(frm_browser, text=admin_label, foreground=admin_color,
                  font=("Consolas", 9)).grid(row=0, column=3, padx=15, pady=8)

        # ----- URL Input -----
        frm_url = ttk.LabelFrame(self.root, text="2. Video URL")
        frm_url.pack(fill="x", **pad)

        self.url_var = tk.StringVar()
        ttk.Entry(frm_url, textvariable=self.url_var, width=70).pack(
            side="left", fill="x", expand=True, padx=8, pady=8
        )

        # ----- Fetch Button -----
        frm_fetch = ttk.Frame(self.root)
        frm_fetch.pack(fill="x", **pad)

        self.fetch_btn = ttk.Button(
            frm_fetch, text="Fetch Video Info", command=self.fetch_video_info
        )
        self.fetch_btn.pack(side="left", padx=5)

        self.status_label = ttk.Label(frm_fetch, text="Ready", foreground="gray")
        self.status_label.pack(side="left", padx=10)

        # ----- Progress Bar -----
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", **pad)

        # ----- Log Area -----
        frm_log = ttk.LabelFrame(self.root, text="Log")
        frm_log.pack(fill="both", expand=True, **pad)

        self.log_text = scrolledtext.ScrolledText(
            frm_log, height=6, wrap="word", state="disabled", font=("Consolas", 9)
        )
        self.log_text.pack(fill="both", expand=True, padx=8, pady=8)

        # ----- Resolution Selection -----
        frm_res = ttk.LabelFrame(self.root, text="3. Select Resolution")
        frm_res.pack(fill="x", **pad)

        self.resolution_var = tk.StringVar(value="best")
        self.res_frame = ttk.Frame(frm_res)
        self.res_frame.pack(fill="x", padx=8, pady=8)

        self.res_placeholder = ttk.Label(
            self.res_frame,
            text='Click "Fetch Video Info" to load resolutions...',
            foreground="gray",
        )
        self.res_placeholder.pack(anchor="w")

        # ----- Download Button -----
        frm_dl = ttk.Frame(self.root)
        frm_dl.pack(fill="x", **pad)

        self.download_btn = ttk.Button(
            frm_dl, text="Download", command=self.start_download, state="disabled"
        )
        self.download_btn.pack(side="left", padx=5)

        ttk.Button(
            frm_dl, text="Open Download Folder", command=self.open_download_folder
        ).pack(side="left", padx=5)

    def log(self, msg):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
        self.root.update_idletasks()

    def set_status(self, msg):
        self.status_label.config(text=msg)

    def set_progress(self, running=False):
        if running:
            self.progress.start(10)
        else:
            self.progress.stop()

    def fetch_video_info(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a YouTube URL.")
            return

        browser = self.browser_var.get()
        # Edge v20: requires admin for DPAPI decryption; chromelevator is unreliable for Edge
        # Chrome: works via chromelevator fallback even without admin
        if browser == "Edge" and not is_admin():
            result = messagebox.askyesno(
                "Administrator Required for Edge",
                "Edge v20 cookie decryption requires Administrator privileges.\n\n"
                f"Click Yes to restart as Administrator, or No to cancel.",
            )
            if result:
                self._restart_as_admin()
                return
            else:
                return
        # Chrome: admin enables faster DPAPI mode; falls back to chromelevator
        if browser == "Chrome" and not is_admin():
            result = messagebox.askyesno(
                "Administrator Recommended",
                "Chrome works without admin (via chromelevator), but admin mode\n"
                f"is faster and more reliable.\n\n"
                f"Click Yes to restart as Administrator, or No to continue without admin.",
            )
            if result:
                self._restart_as_admin()
                return

        self.fetch_btn.config(state="disabled")
        self.download_btn.config(state="disabled")
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
                self.root.after(0, self.download_btn.config, {"state": "normal"})

            except Exception as e:
                self.root.after(0, self.log, f"ERROR: {e}")
                self.root.after(0, self.log, traceback.format_exc())
                self.root.after(0, self.set_status, "Failed")
            finally:
                self.root.after(0, self.fetch_btn.config, {"state": "normal"})
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
            messagebox.showerror(
                "Elevation Failed",
                "Failed to restart as Administrator. Please right-click and select 'Run as Administrator'.",
            )
        else:
            self.root.destroy()

    def populate_resolutions(self, resolutions):
        for widget in self.res_frame.winfo_children():
            widget.destroy()

        best_rb = ttk.Radiobutton(
            self.res_frame,
            text="best (highest quality available)",
            variable=self.resolution_var,
            value="best",
        )
        best_rb.pack(anchor="w")
        self.resolution_var.set("best")

        for height, res_label in resolutions:
            rb = ttk.Radiobutton(
                self.res_frame,
                text=res_label,
                variable=self.resolution_var,
                value=str(height),
            )
            rb.pack(anchor="w")

    def start_download(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a YouTube URL.")
            return

        resolution = self.resolution_var.get()
        self.download_btn.config(state="disabled")
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
                    self.root.after(0, self.log, "-" * 50)
                    self.root.after(0, self.log, "[SUCCESS] Download complete!")
                    self.root.after(0, self.set_status, "Download complete!")
                else:
                    self.root.after(0, self.log, "-" * 50)
                    self.root.after(0, self.log, f"[ERROR] Download failed (code {process.returncode})")
                    self.root.after(0, self.set_status, "Download failed")

            except Exception as e:
                self.root.after(0, self.log, f"ERROR: {e}")
                self.root.after(0, self.set_status, "Error")
            finally:
                self.root.after(0, self.download_btn.config, {"state": "normal"})
                self.root.after(0, self.set_progress, False)

        threading.Thread(target=worker, daemon=True).start()

    def open_download_folder(self):
        save_dir = os.path.join(os.environ["USERPROFILE"], "Videos")
        os.makedirs(save_dir, exist_ok=True)
        os.startfile(save_dir)
