"""
yt-dlp download wrapper.
"""

import json
import os
import shutil
import subprocess
import sys


def find_yt_dlp():
    """Find yt-dlp executable. Prefers system yt-dlp command."""
    if shutil.which("yt-dlp"):
        return ["yt-dlp"]
    if shutil.which("yt-dlp.exe"):
        return ["yt-dlp.exe"]
    if subprocess.run([sys.executable, "-m", "yt_dlp", "--version"],
                      capture_output=True).returncode == 0:
        return [sys.executable, "-m", "yt_dlp"]
    return None


def fetch_formats(url, cookie_file, browser_native=None, log_callback=None):
    """Get available video formats from YouTube.

    Args:
        url: YouTube video URL
        cookie_file: Path to Netscape cookie file
        browser_native: Browser name for --cookies-from-browser, or None
        log_callback: Optional logging callback

    Returns:
        dict: yt-dlp JSON info
    """
    yt_dlp = find_yt_dlp()
    if not yt_dlp:
        raise RuntimeError(
            "yt-dlp not found. Install with:\npip install yt-dlp\nor\nwinget install yt-dlp"
        )

    cmd = yt_dlp + [
        "--no-warnings",
        "--dump-json",
        "--no-download",
    ]

    if browser_native:
        cmd += ["--cookies-from-browser", browser_native]
    elif cookie_file and os.path.exists(cookie_file):
        cmd += ["--cookies", cookie_file]

    cmd += [url]

    if log_callback:
        log_callback("Fetching video info from YouTube...")

    result = subprocess.run(cmd, capture_output=True, timeout=60)
    if result.returncode != 0:
        err = result.stderr.decode("utf-8", errors="replace") if result.stderr else "Unknown error"
        raise RuntimeError(f"yt-dlp failed:\n{err}")

    lines = result.stdout.decode("utf-8", errors="replace").strip().split("\n")
    info = json.loads(lines[0])
    return info


def get_resolution_list(info):
    """Return list of (height, resolution_label) sorted by quality descending."""
    formats = info.get("formats", [])
    seen = set()
    items = []

    for fmt in formats:
        vcodec = fmt.get("vcodec", "none")
        if vcodec == "none":
            continue

        height = fmt.get("height")
        if height is None:
            continue

        res_label = f"{height}p"
        fps = fmt.get("fps")
        if fps and fps > 30:
            res_label += f" {fps}fps"

        note = fmt.get("format_note", "")
        if "hdr" in note.lower() or "HDR" in note:
            res_label += " HDR"

        if height in seen:
            continue
        seen.add(height)

        items.append((height, res_label))

    items.sort(key=lambda x: x[0], reverse=True)
    return items


def download_video(url, cookie_file, resolution, browser_native=None, save_dir=None, log_callback=None):
    """Download a YouTube video.

    Args:
        url: YouTube video URL
        cookie_file: Path to Netscape cookie file
        resolution: "best" or height value (e.g. "720")
        browser_native: Browser name for --cookies-from-browser, or None
        save_dir: Download directory (default: ~/Videos)
        log_callback: Optional logging callback

    Returns:
        subprocess.CompletedProcess
    """
    if save_dir is None:
        save_dir = os.path.join(os.environ["USERPROFILE"], "Videos")
    os.makedirs(save_dir, exist_ok=True)

    yt_dlp = find_yt_dlp()
    if not yt_dlp:
        raise RuntimeError("yt-dlp not found. Install with: pip install yt-dlp")

    output_template = os.path.join(save_dir, "%(title)s [%(id)s].%(ext)s")

    cmd = yt_dlp + [
        "-o", output_template,
        "--merge-output-format", "mp4",
    ]

    if browser_native:
        cmd += ["--cookies-from-browser", browser_native]
    elif cookie_file and os.path.exists(cookie_file):
        cmd += ["--cookies", cookie_file]

    if resolution == "best":
        cmd += ["-f", "bestvideo+bestaudio/best"]
    else:
        # resolution is a height value like "720"
        cmd += ["-f", f"bestvideo[height<={resolution}]+bestaudio/best[height<={resolution}]"]

    cmd += [url]

    if log_callback:
        log_callback(f"Command: {' '.join(cmd)}")
        log_callback("-" * 50)

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    for line in process.stdout:
        if log_callback:
            log_callback(line.rstrip())
        else:
            print(line.rstrip())

    process.wait()
    return process
