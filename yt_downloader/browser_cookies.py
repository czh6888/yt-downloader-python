"""
Browser cookie extraction for Chrome, Edge (Chromium), and Firefox.
Delegates to decrypt_chromium.py for Chromium v20/v10/DPAPI decryption
and chromelevator as fallback.
"""

import ctypes
import ctypes.wintypes
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Browser configuration
# ---------------------------------------------------------------------------

BROWSERS = {
    "Chrome": {
        "cookie_db": r"AppData\Local\Google\Chrome\User Data\Default\Network\Cookies",
        "local_state": r"AppData\Local\Google\Chrome\User Data\Local State",
        "process": "chrome.exe",
    },
    "Edge": {
        "cookie_db": r"AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies",
        "local_state": r"AppData\Local\Microsoft\Edge\User Data\Local State",
        "process": "msedge.exe",
    },
}

FIREFOX_COOKIE_DB = r"AppData\Roaming\Mozilla\Firefox\Profiles"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def elevate():
    """Re-launch current script as Administrator via UAC prompt."""
    script = sys.argv[0]
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    python_exe = sys.executable
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", python_exe, f'"{script}" {params}', None, 1
    )
    sys.exit(0)


def rstrtmgr_copy(src, dst):
    """Copy a file using Restart Manager to release file locks."""
    rstrtmgr = ctypes.windll.LoadLibrary("Rstrtmgr")

    @ctypes.WINFUNCTYPE(None, ctypes.c_uint)
    def _cb(pct):
        pass

    sh = ctypes.wintypes.DWORD(0)
    sf = ctypes.wintypes.DWORD(0)
    sk = (ctypes.wintypes.WCHAR * 256)()
    rstrtmgr.RmStartSession(ctypes.byref(sh), sf, sk)
    try:
        rstrtmgr.RmRegisterResources(
            sh, 1, ctypes.byref(ctypes.pointer(ctypes.create_unicode_buffer(src))),
            0, None, 0, None,
        )
        rstrtmgr.RmShutdown(sh, 1, _cb)
    finally:
        rstrtmgr.RmEndSession(sh)
    shutil.copy2(src, dst)


def copy_unlocked(src, dst, log_callback=None):
    """Copy a file, trying normal copy first then Rstrtmgr fallback."""
    try:
        shutil.copy2(src, dst)
    except PermissionError:
        if log_callback:
            log_callback("File is locked, unlocking via Rstrtmgr...")
        rstrtmgr_copy(src, dst)


def to_netscape(cookies):
    """Convert cookies to Netscape cookie file format."""
    lines = ["# Netscape HTTP Cookie File", ""]
    for host, name, value, secure, httponly, expiry in cookies:
        domain = host if host.startswith(".") else "." + host
        lines.append(
            f"{domain}\tTRUE\t/\t{'TRUE' if secure else 'FALSE'}\t{expiry}\t{name}\t{value}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Chromium cookie extraction (via decrypt_chromium.py subprocess)
# ---------------------------------------------------------------------------

def extract_chromium_cookies(browser_name, cookie_file, log_callback=None):
    """Extract cookies using the unified decrypt_chromium.py subprocess.

    Supports v20, v10, DPAPI, and plaintext cookie formats across 20+ Chromium browsers.

    Returns (use_cookie_file, browser_for_native) tuple.
    """
    mod_dir = os.path.dirname(os.path.abspath(__file__))
    helper = os.path.join(mod_dir, "decrypt_chromium.py")

    if not os.path.exists(helper):
        if log_callback:
            log_callback(f"Unified Chromium decrypt script not found at {helper}")
        return (False, browser_name)

    if log_callback:
        log_callback(f"Using {os.path.basename(helper)} for {browser_name} cookie extraction...")

    browser_map = {"Chrome": "chrome", "Edge": "edge"}
    bkey = browser_map.get(browser_name, browser_name.lower())

    result = subprocess.run(
        [sys.executable, helper, bkey, cookie_file],
        capture_output=True, text=True, timeout=120,
        encoding="utf-8", errors="replace",
    )

    if log_callback:
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                log_callback(f"  {line.strip()}")

    if result.returncode != 0:
        err = result.stderr.strip() if result.stderr else "Unknown error"
        if log_callback:
            log_callback(f"Decryption failed (exit {result.returncode})")
            for line in err.split("\n")[-5:]:
                if line.strip():
                    log_callback(f"  {line.strip()}")
        return (False, browser_name)

    if not os.path.exists(cookie_file):
        if log_callback:
            log_callback("Cookie file not created after extraction")
        return (False, browser_name)

    if log_callback:
        log_callback(f"{browser_name} cookies saved to {cookie_file}")
    return (True, None)


# ---------------------------------------------------------------------------
# Firefox cookie extraction (direct SQLite read, no encryption)
# ---------------------------------------------------------------------------

def extract_firefox_cookies(cookie_file, log_callback=None):
    """Extract cookies from Firefox. Firefox cookies are NOT encrypted."""
    up = os.environ["USERPROFILE"]
    profiles_dir = os.path.join(up, FIREFOX_COOKIE_DB)

    if not os.path.exists(profiles_dir):
        raise FileNotFoundError(
            f"Firefox profiles not found:\n{profiles_dir}\n\n"
            "Please make sure Firefox is installed."
        )

    # Search all subdirectories for cookies.sqlite
    profile_path = None
    for entry in sorted(os.listdir(profiles_dir)):
        full = os.path.join(profiles_dir, entry)
        if os.path.isdir(full) and os.path.exists(os.path.join(full, "cookies.sqlite")):
            profile_path = full
            break

    if not profile_path:
        raise FileNotFoundError(
            "No Firefox profile with cookies.sqlite found. Please open Firefox and log in first."
        )

    db_path = os.path.join(profile_path, "cookies.sqlite")
    if log_callback:
        log_callback(f"Reading Firefox cookie database: {db_path}")

    with tempfile.TemporaryDirectory() as td:
        tmp_db = os.path.join(td, "cookies.sqlite")
        copy_unlocked(db_path, tmp_db, log_callback)

        con = sqlite3.connect(Path(tmp_db).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute(
            "SELECT host, name, value, isSecure, isHttpOnly, expiry FROM moz_cookies"
        )
        all_cookies = cur.fetchall()
        con.close()

    result = []
    for c in all_cookies:
        host, name, value, secure, httponly, expiry = c
        result.append(
            (host, name, value, int(secure), int(httponly), str(int(expiry) if expiry else 0))
        )

    content = to_netscape(result)
    with open(cookie_file, "w", encoding="utf-8") as f:
        f.write(content)

    msg = f"Extracted {len(result)} cookies from Firefox"
    if log_callback:
        log_callback(msg)
    return (True, None)


# ---------------------------------------------------------------------------
# chromelevator (process injection + COM DecryptData)
# ---------------------------------------------------------------------------

def _find_chromelevator():
    """Find chromelevator_x64.exe in known locations."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base, "tools", "chromelevator_x64.exe"),
        os.path.join(base, "chromelevator_x64.exe"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "chromelevator_x64.exe"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def _json_cookies_to_netscape(json_cookies):
    """Convert chromelevator JSON cookies to Netscape format."""
    lines = ["# Netscape HTTP Cookie File", ""]
    for c in json_cookies:
        host = c.get("host", "")
        value = c.get("value", "")
        if not value:
            continue
        secure = c.get("is_secure", False)
        httponly = c.get("is_httponly", False)
        expiry = c.get("expires", 0)
        domain = host if host.startswith(".") else "." + host
        lines.append(
            f"{domain}\tTRUE\t{c.get('path', '/')}\t{'TRUE' if secure else 'FALSE'}\t{expiry}\t{c.get('name', '')}\t{value}"
        )
    return "\n".join(lines)


def extract_chromium_with_chromelevator(browser_name, cookie_file, log_callback=None):
    """Extract cookies using chromelevator (process injection + COM hijack)."""
    exe_path = _find_chromelevator()
    if not exe_path:
        if log_callback:
            log_callback("chromelevator_x64.exe not found")
        return (False, browser_name)

    browser_map = {"Chrome": "chrome", "Edge": "edge"}
    chromelevator_name = browser_map.get(browser_name, browser_name.lower())

    if log_callback:
        log_callback(f"Using chromelevator for {browser_name}...")
        log_callback("Launching browser process injection (this may take a moment)...")

    output_dir = tempfile.mkdtemp(prefix=f"{browser_name.lower()}_cookies_")

    try:
        cmd = [exe_path, "-o", output_dir, chromelevator_name]
        proc = subprocess.run(cmd, capture_output=True, timeout=120, text=True,
                            encoding="utf-8", errors="replace")

        if proc.returncode != 0:
            if log_callback:
                log_callback(f"chromelevator failed (exit {proc.returncode})")
                stderr = proc.stderr.strip()
                if stderr:
                    for line in stderr.split("\n")[-10:]:
                        if line.strip():
                            log_callback(f"  {line.strip()}")
            return (False, browser_name)

        profile_dir = chromelevator_name.capitalize()
        if chromelevator_name == "chrome":
            profile_dir = "Chrome"

        cookie_json_path = os.path.join(output_dir, profile_dir, "Default", "cookies.json")
        if not os.path.exists(cookie_json_path):
            alt_path = os.path.join(output_dir, "Default", "cookies.json")
            if os.path.exists(alt_path):
                cookie_json_path = alt_path
            else:
                if log_callback:
                    log_callback("Extracted cookies JSON not found in output directory")
                return (False, browser_name)

        with open(cookie_json_path, "rb") as f:
            raw = f.read()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
        cookies = json.loads(text)

        if log_callback:
            yt_count = sum(1 for c in cookies if "youtube.com" in c.get("host", ""))
            log_callback(f"Loaded {len(cookies)} cookies ({yt_count} YouTube domain)")

        content = _json_cookies_to_netscape(cookies)
        with open(cookie_file, "w", encoding="utf-8") as f:
            f.write(content)

        non_comment = [l for l in content.split("\n") if l and not l.startswith("#")]
        msg = f"Extracted {len(non_comment)} cookies from {browser_name} via chromelevator"
        if log_callback:
            log_callback(msg)
        return (True, None)

    except subprocess.TimeoutExpired:
        if log_callback:
            log_callback("chromelevator timed out")
        return (False, browser_name)
    except Exception as e:
        if log_callback:
            log_callback(f"chromelevator error: {e}")
        return (False, browser_name)
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def extract_cookies(browser_name, cookie_file, log_callback=None):
    """Unified cookie extraction entry point.

    Priority per browser:
    - Firefox: direct SQLite read (no encryption)
    - Chrome/Edge: decrypt_chromium.py > chromelevator

    Returns (use_cookie_file, browser_for_native) where:
    - (True, None): pass --cookies <file> to yt-dlp
    - (False, "Edge"): pass --cookies-from-browser edge
    """
    if browser_name == "Firefox":
        try:
            return extract_firefox_cookies(cookie_file, log_callback)
        except (FileNotFoundError, Exception) as e:
            if log_callback:
                log_callback(f"Firefox direct extraction failed: {e}")
                log_callback("Falling back to --cookies-from-browser firefox...")
            return (False, "firefox")
    elif browser_name in BROWSERS:
        result = extract_chromium_cookies(browser_name, cookie_file, log_callback)
        if result[0]:
            return result
        if log_callback:
            log_callback(f"Unified decrypt failed for {browser_name}, trying chromelevator...")
        return extract_chromium_with_chromelevator(browser_name, cookie_file, log_callback)
    else:
        return (False, browser_name)
