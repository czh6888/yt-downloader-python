"""
yt-dlp download wrapper.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile


def find_yt_dlp():
    """Find yt-dlp. Prefer bundled exe, then system executable."""
    mod_dir = os.path.dirname(os.path.abspath(__file__))
    bundled = os.path.join(mod_dir, "yt-dlp.exe")
    if os.path.isfile(bundled):
        return [bundled]

    path = shutil.which("yt-dlp") or shutil.which("yt-dlp.exe")
    if path:
        return [path]

    return None


def fetch_formats(url, cookie_file, browser_native=None, log_callback=None):
    """Get available video formats from YouTube.

    Uses ytdlp_helper.py (run via python.exe) to ensure yt-dlp
    has a proper console for JS challenge solving.
    """
    mod_dir = os.path.dirname(os.path.abspath(__file__))
    helper = os.path.join(mod_dir, "ytdlp_helper.py")

    python_exe = _find_python_exe()

    cookie_arg = cookie_file if (cookie_file and os.path.exists(cookie_file)) else "NONE"
    browser_arg = browser_native if browser_native else "NONE"
    out_file = os.path.join(tempfile.gettempdir(), f"ytdlp_out_{os.getpid()}.json")

    cmd = [python_exe, helper, cookie_arg, browser_arg, url, out_file]

    if log_callback:
        log_callback("Fetching video info from YouTube...")
        log_callback(f"Helper command: {' '.join(cmd)}")
        if cookie_file and os.path.exists(cookie_file):
            size = os.path.getsize(cookie_file)
            first = open(cookie_file, encoding='utf-8').readline().strip()[:80]
            log_callback(f"Cookie file: {size} bytes, header: {first}")

    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"

    # Use CREATE_NEW_CONSOLE if parent has no console (pythonw.exe)
    creationflags = 0
    if sys.executable and "pythonw" in sys.executable.lower():
        creationflags = subprocess.CREATE_NEW_CONSOLE

    result = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        timeout=120,
        env=env,
        creationflags=creationflags,
    )

    if log_callback and result.stdout.strip():
        log_callback(result.stdout.strip()[:300])
    if log_callback and result.stderr.strip():
        log_callback(f"Helper stderr: {result.stderr.strip()[:300]}")

    # Read result from output file
    info = None
    if os.path.exists(out_file):
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                info = json.load(f)
        except Exception:
            pass
        try:
            os.remove(out_file)
        except Exception:
            pass

    if info and "error" in info:
        raise RuntimeError(f"yt-dlp error: {info['error']}")

    if not info:
        raise RuntimeError(
            f"yt-dlp returned no data.\n"
            f"Helper stdout: {result.stdout[:500]}\n"
            f"Helper stderr: {result.stderr[:500]}"
        )

    return info


def _find_python_exe():
    """Find python.exe (console version), not pythonw.exe."""
    # If current interpreter is pythonw.exe, find corresponding python.exe
    exe = sys.executable or ""
    if "pythonw" in exe.lower():
        pythonw_dir = os.path.dirname(exe)
        python_exe = os.path.join(pythonw_dir, "python.exe")
        if os.path.isfile(python_exe):
            return python_exe
    # Otherwise use sys.executable or fallback to python.exe in PATH
    if exe and os.path.isfile(exe):
        return exe
    path = shutil.which("python.exe") or shutil.which("python")
    return path or "python"


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


def download_video(url, cookie_file, resolution, browser_native=None, save_dir=None,
                   log_callback=None, progress_callback=None):
    """Download a YouTube video.

    Args:
        url: YouTube video URL
        cookie_file: Path to Netscape cookie file
        resolution: "best" or height value (e.g. "720")
        browser_native: Browser name for --cookies-from-browser, or None
        save_dir: Download directory (default: ~/Videos)
        log_callback: Optional logging callback
        progress_callback: Optional callback(pct, speed, eta)
            pct: 0.0-1.0, speed: str, eta: str

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

    import re

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    progress_re = re.compile(
        r'\[download\]\s+([\d.]+)%\s+of\s+~?\s*([\d.]+\w+)\s+at\s+([\d.]+\w+/s)\s+ETA\s+(.+)'
    )
    progress_re2 = re.compile(r'\[download\]\s+([\d.]+)%')

    for line in process.stdout:
        line = line.rstrip()
        if log_callback:
            log_callback(line)

        if progress_callback:
            m = progress_re.search(line) or progress_re2.search(line)
            if m:
                pct = float(m.group(1)) / 100.0
                if m.lastindex >= 3:
                    speed = m.group(3)
                    eta = m.group(4)
                else:
                    speed = ""
                    eta = ""
                progress_callback(pct, speed, eta)

    process.wait()
    return process
