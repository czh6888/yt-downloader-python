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
    # 1. Bundled yt-dlp.exe shipped with the project
    mod_dir = os.path.dirname(os.path.abspath(__file__))
    bundled = os.path.join(mod_dir, "yt-dlp.exe")
    if os.path.isfile(bundled):
        return [bundled]

    # 2. System yt-dlp executable as fallback
    path = shutil.which("yt-dlp") or shutil.which("yt-dlp.exe")
    if path:
        return [path]

    return None


def fetch_formats(url, cookie_file, browser_native=None, log_callback=None):
    """Get available video formats from YouTube.

    Strategy: write JSON output to a temp file, then read it back.
    This avoids pipe buffering / handle issues in GUI subprocess.
    """
    yt_dlp = find_yt_dlp()
    if not yt_dlp:
        raise RuntimeError(
            "yt-dlp not found. Install with:\npip install yt-dlp\nor\nwinget install yt-dlp"
        )

    # Create temp files for stdout and stderr
    tmpdir = tempfile.mkdtemp(prefix="ytdlp_")
    stdout_file = os.path.join(tmpdir, "stdout.txt")
    stderr_file = os.path.join(tmpdir, "stderr.txt")

    cmd = yt_dlp + [
        "--no-warnings",
        "--dump-json",
        "--no-download",
        "-o", "NUL",
    ]

    if browser_native:
        cmd += ["--cookies-from-browser", browser_native]
    elif cookie_file and os.path.exists(cookie_file):
        cmd += ["--cookies", cookie_file]

    cmd += [url]

    if log_callback:
        log_callback("Fetching video info from YouTube...")
        log_callback(f"yt-dlp path: {' '.join(yt_dlp)}")
        log_callback(f"Command: {' '.join(cmd)}")
        if cookie_file and os.path.exists(cookie_file):
            size = os.path.getsize(cookie_file)
            first = open(cookie_file, encoding='utf-8').readline().strip()[:80]
            log_callback(f"Cookie file: {size} bytes, header: {first}")

    # Use shell=True to exactly replicate CMD execution
    cmd_str = " ".join(f'"{c}"' if " " in c else c for c in cmd)
    cmd_str += f" > \"{stdout_file}\" 2> \"{stderr_file}\""

    if log_callback:
        log_callback(f"Shell command: {cmd_str}")

    result = subprocess.run(
        cmd_str,
        text=True,
        shell=True,
        timeout=120,
    )

    # Read outputs from files
    stdout_text = ""
    stderr_text = ""
    try:
        with open(stdout_file, "r", encoding="utf-8") as f:
            stdout_text = f.read()
    except Exception:
        pass
    try:
        with open(stderr_file, "r", encoding="utf-8") as f:
            stderr_text = f.read()
    except Exception:
        pass

    # Clean up temp files
    try:
        os.remove(stdout_file)
        os.remove(stderr_file)
        os.rmdir(tmpdir)
    except Exception:
        pass

    if result.returncode != 0:
        raise RuntimeError(
            f"yt-dlp failed (exit {result.returncode}):\n"
            f"STDERR: {stderr_text.strip()[:1000]}\n"
            f"STDOUT: {stdout_text.strip()[:500]}"
        )

    # Find JSON line
    for line in stdout_text.strip().split("\n"):
        if line.startswith("{"):
            return json.loads(line)

    raise RuntimeError(f"yt-dlp returned no JSON data:\nSTDOUT: {stdout_text[:500]}\nSTDERR: {stderr_text[:500]}")


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
