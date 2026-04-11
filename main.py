"""
YouTube Downloader - Entry point.
Run: python main.py
"""

import sys
import customtkinter as ctk
from tkinter import messagebox

from yt_downloader.browser_cookies import is_admin, elevate
from yt_downloader.downloader import find_yt_dlp
from yt_downloader.gui import YouTubeDownloaderGUI


def main():
    ctk.set_appearance_mode("system")

    if find_yt_dlp() is None:
        root = ctk.CTk()
        root.withdraw()
        messagebox.showerror(
            "Missing Dependency",
            "yt-dlp is not installed.\n\n"
            "Please install it via one of:\n"
            "  pip install yt-dlp\n"
            "  OR\n"
            "  winget install yt-dlp",
        )
        root.destroy()
        sys.exit(1)

    if not is_admin():
        root = ctk.CTk()
        root.withdraw()
        result = messagebox.askyesno(
            "Administrator Recommended",
            "YouTube cookie decryption works best with Administrator privileges.\n\n"
            "Without admin, Chrome/Edge extraction falls back to a slower method.\n\n"
            "Run as Administrator now?",
        )
        root.destroy()
        if result:
            print("Requesting Administrator privileges (UAC)...")
            elevate()
            return

    root = ctk.CTk()
    app = YouTubeDownloaderGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
