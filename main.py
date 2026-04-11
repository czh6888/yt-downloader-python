"""
YouTube Downloader - Entry point.
Run the GUI application: python main.py
"""

import sys
import tkinter as tk
from tkinter import messagebox

from yt_downloader.browser_cookies import is_admin, elevate
from yt_downloader.downloader import find_yt_dlp
from yt_downloader.gui import YouTubeDownloaderGUI


def main():
    # Check yt-dlp first (no admin needed)
    if find_yt_dlp() is None:
        root = tk.Tk()
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

    # Check admin for Chrome/Edge cookie decryption
    if not is_admin():
        print("Requesting Administrator privileges (UAC)...")
        elevate()
        return

    root = tk.Tk()
    app = YouTubeDownloaderGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
