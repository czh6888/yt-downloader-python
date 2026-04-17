"""
Browser cookie extraction with v20 decryption support.
Supports: Chrome, Edge (Chromium), Firefox
"""

import json
import os
import sqlite3
import struct
import binascii
import ctypes
import shutil
import subprocess
import sys
import tempfile
from io import BytesIO
from pathlib import Path
from contextlib import contextmanager

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

import windows
import windows.crypto
import windows.generated_def as gdef

# ---------------------------------------------------------------------------
# Browser configuration
# ---------------------------------------------------------------------------

BROWSERS = {
    "Chrome": {
        "cookie_db": r"AppData\Local\Google\Chrome\User Data\Default\Network\Cookies",
        "local_state": r"AppData\Local\Google\Chrome\User Data\Local State",
        "key_name": "Google Chromekey1",
        "process": "chrome.exe",
    },
    "Edge": {
        "cookie_db": r"AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies",
        "local_state": r"AppData\Local\Microsoft\Edge\User Data\Local State",
        "key_name": "Microsoft EdgeKey1",
        "process": "msedge.exe",
    },
}

FIREFOX_COOKIE_DB = r"AppData\Roaming\Mozilla\Firefox\Profiles"

# Known hardcoded keys for Chromium v20 decryption
CHROME_FIXED_AES_KEY = bytes.fromhex(
    "B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787"
)
CHROME_FIXED_CHACHA_KEY = bytes.fromhex(
    "E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660"
)
ABE_XOR_KEY = bytes.fromhex(
    "CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390"
)

# ---------------------------------------------------------------------------
# Privilege / token helpers
# ---------------------------------------------------------------------------


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def elevate():
    import sys

    script = sys.argv[0]
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    python_exe = sys.executable
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", python_exe, f'"{script}" {params}', None, 1
    )
    sys.exit(0)


@contextmanager
def impersonate_lsass():
    """Impersonate lsass.exe token with SeDebugPrivilege for ABE key access."""
    orig = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
        imp = proc.token.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation,
        )
        windows.current_thread.token = imp
        yield
    finally:
        windows.current_thread.token = orig


# ---------------------------------------------------------------------------
# Windows Restart Manager - unlock locked browser databases
# ---------------------------------------------------------------------------


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
            sh,
            1,
            ctypes.byref(ctypes.pointer(ctypes.create_unicode_buffer(src))),
            0,
            None,
            0,
            None,
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


# ---------------------------------------------------------------------------
# v20 key blob parsing & decryption
# ---------------------------------------------------------------------------


def parse_key_blob(blob_data):
    """Parse Chrome-style app-bound key blob.

    Structure: header_len(4) + header + content_len(4) + flag(1) + data
    """
    buf = BytesIO(blob_data)
    d = {}
    hl = struct.unpack("<I", buf.read(4))[0]
    d["header"] = buf.read(hl)
    cl = struct.unpack("<I", buf.read(4))[0]
    d["flag"] = buf.read(1)[0]
    if d["flag"] in (1, 2):
        d["iv"] = buf.read(12)
        d["ciphertext"] = buf.read(32)
        d["tag"] = buf.read(16)
    elif d["flag"] == 3:
        d["encrypted_aes_key"] = buf.read(32)
        d["iv"] = buf.read(12)
        d["ciphertext"] = buf.read(32)
        d["tag"] = buf.read(16)
    else:
        raise ValueError(f"Unsupported flag: {d['flag']}")
    return d


def parse_key_blob_edge(blob_data):
    """Parse Edge-style app-bound key blob.

    Structure: header_len(4) + header + content_len(4) + "ImportPvt1"(10) + flag(1) + data
    """
    buf = BytesIO(blob_data)
    d = {}
    hl = struct.unpack("<I", buf.read(4))[0]
    d["header"] = buf.read(hl)
    cl = struct.unpack("<I", buf.read(4))[0]
    # Edge has "ImportPvt1" prefix before flag
    prefix = buf.read(10)
    if prefix != b"ImportPvt1":
        raise ValueError(f"Expected 'ImportPvt1', got {prefix!r}")
    d["flag"] = buf.read(1)[0]
    if d["flag"] == 3:
        d["encrypted_aes_key"] = buf.read(32)
        d["iv"] = buf.read(12)
        d["ciphertext"] = buf.read(32)
        d["tag"] = buf.read(16)
    else:
        raise ValueError(f"Unsupported Edge flag: {d['flag']}")
    return d


def byte_xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _decrypt_with_cng(input_data, key_name):
    """Decrypt data using NCrypt (CNG API)."""
    ncrypt = ctypes.windll.NCrypt
    hP = gdef.NCRYPT_PROV_HANDLE()
    status = ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(hP), "Microsoft Software Key Storage Provider", 0
    )
    if status != 0:
        raise OSError(f"NCryptOpenStorageProvider failed: 0x{status & 0xFFFFFFFF:08X}")
    hK = gdef.NCRYPT_KEY_HANDLE()
    status = ncrypt.NCryptOpenKey(hP, ctypes.byref(hK), key_name, 0, 0)
    if status != 0:
        ncrypt.NCryptFreeObject(hP)
        raise OSError(f"NCryptOpenKey('{key_name}') failed: 0x{status & 0xFFFFFFFF:08X}")
    pcb = ctypes.c_ulong(0)
    ibuf = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)
    status = ncrypt.NCryptDecrypt(
        hK, ibuf, len(ibuf), None, None, 0, ctypes.byref(pcb), 0x40
    )
    if status != 0:
        ncrypt.NCryptFreeObject(hK)
        ncrypt.NCryptFreeObject(hP)
        raise OSError(f"NCryptDecrypt (size) failed: 0x{status & 0xFFFFFFFF:08X}")
    obuf = (ctypes.c_ubyte * pcb.value)()
    status = ncrypt.NCryptDecrypt(
        hK, ibuf, len(ibuf), None, obuf, pcb.value, ctypes.byref(pcb), 0x40
    )
    result = bytes(obuf[: pcb.value])
    ncrypt.NCryptFreeObject(hK)
    ncrypt.NCryptFreeObject(hP)
    return result


def derive_master_key(parsed, key_name=None):
    """Derive AES-GCM master key from parsed key blob.

    For flag=3, uses CNG (NCryptDecrypt) to decrypt the AES key,
    then XORs with the hardcoded ABE key.
    """
    flag = parsed["flag"]
    if flag == 1:
        cipher = AESGCM(CHROME_FIXED_AES_KEY)
    elif flag == 2:
        cipher = ChaCha20Poly1305(CHROME_FIXED_CHACHA_KEY)
    elif flag == 3:
        if key_name is None:
            raise ValueError("key_name required for flag=3 CNG decryption")
        # Use CNG to decrypt the encrypted_aes_key
        dec_key = _decrypt_with_cng(parsed["encrypted_aes_key"], key_name)
        cipher = AESGCM(byte_xor(dec_key, ABE_XOR_KEY))
    else:
        raise ValueError(f"Unsupported flag: {flag}")
    return cipher.decrypt(parsed["iv"], parsed["ciphertext"] + parsed["tag"], None)


def decrypt_cookie_val(cipher, ev):
    """Decrypt a v20 cookie value. ev is the raw encrypted_value bytes."""
    iv, ct, tag = ev[3:15], ev[15:-16], ev[-16:]
    pt = cipher.decrypt(iv, ct + tag, None)
    return pt[32:].decode("utf-8")


def test_master_key(key, test_cookies):
    """Test a master key against sample cookies. Returns success count."""
    if isinstance(key, bytes):
        cipher = AESGCM(key)
    else:
        cipher = key
    success = 0
    for row in test_cookies:
        ev = row[2]
        try:
            pt = cipher.decrypt(ev[3:15], ev[15:-16] + ev[-16:], None)
            val = pt[32:].decode("utf-8")
            if len(val) > 0:
                success += 1
        except Exception:
            pass
    return success


# ---------------------------------------------------------------------------
# Edge fallback decryption
# ---------------------------------------------------------------------------


def try_edge_fallback(user_dec, parsed, db_path, log_callback=None):
    """Try Edge-specific decryption methods when CNG is unavailable.

    Returns the master key (bytes or AESGCM cipher) or None.
    """

    def log(msg):
        if log_callback:
            log_callback(f"  {msg}")

    # Load sample cookies
    td_test = tempfile.mkdtemp()
    tmp_db_test = os.path.join(td_test, "Cookies")
    v20_cookies = []
    try:
        copy_unlocked(db_path, tmp_db_test)
        con_test = sqlite3.connect(Path(tmp_db_test).as_uri() + "?mode=ro", uri=True)
        cur_test = con_test.cursor()
        cur_test.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) FROM cookies")
        all_rows = cur_test.fetchall()
        con_test.close()
        v20_cookies = [c for c in all_rows if len(c[2]) > 3 and c[2][:3] == b"v20"]
        log(f"Loaded {len(v20_cookies)} v20 cookies for testing")
    except Exception as e:
        log(f"Failed to load sample cookies: {e}")
    finally:
        shutil.rmtree(td_test, ignore_errors=True)

    if not v20_cookies:
        return None

    sample = v20_cookies[:10]

    # Method 1: Try encrypted_aes_key directly as master key
    if parsed and parsed.get("flag") == 3:
        log("Trying encrypted_aes_key directly as master key...")
        try:
            direct_key = parsed["encrypted_aes_key"]
            ok = test_master_key(direct_key, sample)
            if ok > 0:
                log(f"SUCCESS: direct key works ({ok}/{len(sample)})")
                return AESGCM(direct_key)
            log(f"Failed (0/{len(sample)})")
        except Exception as e:
            log(f"Failed: {e}")

    # Method 2: Brute-force scan 32-byte positions in user_dec
    log("Scanning 32-byte positions in user_dec...")
    search_range = min(len(user_dec) - 31, 256)
    for pos in range(0, search_range):
        key_candidate = user_dec[pos:pos + 32]
        success = test_master_key(key_candidate, v20_cookies[:5])
        if success >= 2:
            log(f"SUCCESS: user_dec[{pos}:{pos+32}] works ({success}/5)")
            log(f"Master key: {key_candidate.hex()}")
            return AESGCM(key_candidate)

    log("All Edge fallback methods failed")
    return None


def _scan_user_dec_for_key(user_dec, db_path, log_callback=None):
    """Brute-force scan user_dec for a 32-byte AES key that can decrypt cookies.

    This is a last-resort fallback when NCryptOpenKey fails for Chrome v20.
    Scans overlapping 32-byte windows in user_dec, testing each as an AES-GCM
    key against actual v20 cookies from the database.
    """

    def log(msg):
        if log_callback:
            log_callback(f"  {msg}")

    # Load sample cookies for testing
    td_test = tempfile.mkdtemp()
    tmp_db_test = os.path.join(td_test, "Cookies")
    v20_cookies = []
    try:
        copy_unlocked(db_path, tmp_db_test)
        con_test = sqlite3.connect(Path(tmp_db_test).as_uri() + "?mode=ro", uri=True)
        cur_test = con_test.cursor()
        cur_test.execute(
            "SELECT host_key, name, CAST(encrypted_value AS BLOB) FROM cookies"
        )
        all_rows = cur_test.fetchall()
        con_test.close()
        v20_cookies = [c for c in all_rows if len(c[2]) > 3 and c[2][:3] == b"v20"]
        log(f"Loaded {len(v20_cookies)} v20 cookies for key scanning")
    except Exception as e:
        log(f"Failed to load sample cookies: {e}")
    finally:
        shutil.rmtree(td_test, ignore_errors=True)

    if not v20_cookies:
        return None

    sample = v20_cookies[:5]
    # Scan overlapping 32-byte windows in user_dec
    search_range = min(len(user_dec) - 31, 256)
    log(f"Scanning {search_range} byte positions in user_dec...")
    for pos in range(search_range):
        key_candidate = user_dec[pos:pos + 32]
        success = 0
        for c in sample:
            ev = c[2]
            try:
                cipher = AESGCM(key_candidate)
                pt = cipher.decrypt(ev[3:15], ev[15:-16] + ev[-16:], None)
                val = pt[32:].decode("utf-8")
                if len(val) > 0:
                    success += 1
            except Exception:
                pass
        if success >= 2:
            log(f"SUCCESS: key found at user_dec[{pos}:{pos+32}] ({success}/{len(sample)} cookies decrypted)")
            log(f"Master key: {key_candidate.hex()}")
            return AESGCM(key_candidate)

    log(f"Key scan complete - no valid key found in {search_range} positions")
    return None


# ---------------------------------------------------------------------------
# Cookie extraction
# ---------------------------------------------------------------------------


def to_netscape(cookies):
    """Convert cookies to Netscape cookie file format."""
    lines = ["# Netscape HTTP Cookie File", ""]
    for host, name, value, secure, httponly, expiry in cookies:
        domain = host if host.startswith(".") else "." + host
        lines.append(
            f"{domain}\tTRUE\t/\t{'TRUE' if secure else 'FALSE'}\t{expiry}\t{name}\t{value}"
        )
    return "\n".join(lines)


def extract_chromium_cookies(browser_name, cookie_file, log_callback=None):
    """Extract cookies for any Chromium browser using the unified decrypt_chromium.py.

    Uses decrypt_chromium.py subprocess which supports v20, v10, DPAPI,
    and plaintext cookie formats across 20+ Chromium browsers.

    Returns:
        (use_cookie_file, browser_for_native) tuple:
        - (True, None): use --cookies <file>
        - (False, "Edge"): use --cookies-from-browser edge
    """
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    mod_dir = os.path.join(base, "yt_downloader")
    if not os.path.isdir(mod_dir):
        mod_dir = os.path.dirname(os.path.abspath(__file__))

    helper = os.path.join(mod_dir, "decrypt_chromium.py")
    if not os.path.exists(helper):
        if log_callback:
            log_callback(f"Unified Chromium decrypt script not found at {helper}")
        # Fallback to old per-browser scripts
        if browser_name == "Edge":
            helper_old = os.path.join(mod_dir, "decrypt_edge_v20.py")
        else:
            helper_old = os.path.join(mod_dir, "decrypt_chrome_v20.py")
        if os.path.exists(helper_old):
            helper = helper_old
        else:
            return (False, browser_name)

    if log_callback:
        log_callback(f"Using {os.path.basename(helper)} for {browser_name} cookie extraction...")

    # Map GUI browser name to decrypt_chromium.py browser key
    browser_map = {
        "Chrome": "chrome",
        "Edge": "edge",
    }
    bkey = browser_map.get(browser_name, browser_name.lower())

    result = subprocess.run(
        [sys.executable, helper, bkey, cookie_file],
        capture_output=True, text=True, timeout=120,
        encoding="utf-8", errors="replace"
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


def extract_firefox_cookies(cookie_file, log_callback=None):
    """Extract cookies from Firefox. Firefox cookies are NOT v20 encrypted."""
    up = os.environ["USERPROFILE"]
    profiles_dir = os.path.join(up, FIREFOX_COOKIE_DB)

    if not os.path.exists(profiles_dir):
        raise FileNotFoundError(
            f"Firefox profiles not found:\n{profiles_dir}\n\n"
            "Please make sure Firefox is installed."
        )

    profile_path = None
    for entry in sorted(os.listdir(profiles_dir)):
        full = os.path.join(profiles_dir, entry)
        if os.path.isdir(full) and (
            entry.endswith(".default-release") or entry.endswith(".default")
        ):
            profile_path = full
            break

    # Fallback: try any directory with cookies.sqlite
    if not profile_path:
        for entry in sorted(os.listdir(profiles_dir)):
            full = os.path.join(profiles_dir, entry)
            if os.path.isdir(full) and os.path.exists(os.path.join(full, "cookies.sqlite")):
                profile_path = full
                break

    if not profile_path:
        raise FileNotFoundError(
            "No Firefox default profile found. Please open Firefox and log in first."
        )

    db_path = os.path.join(profile_path, "cookies.sqlite")
    if not os.path.exists(db_path):
        raise FileNotFoundError(
            f"Firefox cookie database not found:\n{db_path}"
        )

    if log_callback:
        log_callback("Reading Firefox cookie database...")

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
# Edge extraction via chromelevator (process injection + COM DecryptData)
# Based on: https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption
# ---------------------------------------------------------------------------

def _find_chromelevator():
    """Find chromelevator_x64.exe in known locations."""
    candidates = []
    # Relative to this module
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.append(os.path.join(base, "tools", "chromelevator_x64.exe"))
    candidates.append(os.path.join(base, "chromelevator_x64.exe"))
    # In same directory as this module
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "chromelevator_x64.exe"))
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def _json_cookies_to_netscape(json_cookies):
    """Convert list of cookie dicts from chromelevator JSON to Netscape format.

    Each dict has: host, name, value, path, is_secure, is_httponly, expires, domain
    """
    lines = ["# Netscape HTTP Cookie File", ""]
    for c in json_cookies:
        host = c.get("host", "")
        name = c.get("name", "")
        value = c.get("value", "")
        if not value:
            continue
        secure = c.get("is_secure", False)
        httponly = c.get("is_httponly", False)
        expiry = c.get("expires", 0)
        domain = host if host.startswith(".") else "." + host
        lines.append(
            f"{domain}\tTRUE\t{c.get('path', '/')}\t{'TRUE' if secure else 'FALSE'}\t{expiry}\t{name}\t{value}"
        )
    return "\n".join(lines)


def extract_edge_with_chromelevator(cookie_file, log_callback=None):
    """Extract Edge cookies using chromelevator (process injection + COM hijack).

    This is the only reliable method for Edge v20 cookie decryption because
    the ABE COM service validates the calling process and rejects external callers.

    Returns (use_cookie_file, browser_for_native) tuple.
    """
    exe_path = _find_chromelevator()
    if not exe_path:
        if log_callback:
            log_callback("chromelevator_x64.exe not found, falling back to native extraction.")
        return (False, "Edge")

    if log_callback:
        log_callback(f"Using chromelevator: {exe_path}")
        log_callback("Launching Edge process injection (this may take a moment)...")

    # Determine output directory (use temp dir)
    output_dir = tempfile.mkdtemp(prefix="edge_cookies_")

    try:
        cmd = [exe_path, "-o", output_dir, "edge"]
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
            return (False, "Edge")

        # Parse output for key info (skip garbled ASCII art)
        output = proc.stdout + proc.stderr
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("─") or line.startswith("│") or line.startswith("┌") or line.startswith("├") or line.startswith("└"):
                continue
            if "App-Bound Encryption Key" in line or "Copilot" in line or "Cookies" in line or "FAILED" in line or "error" in line.lower():
                if log_callback:
                    log_callback(f"  {line}")

        # Read the extracted cookies JSON
        cookie_json_path = os.path.join(output_dir, "Edge", "Default", "cookies.json")
        if not os.path.exists(cookie_json_path):
            if log_callback:
                log_callback("Extracted cookies JSON not found in output directory")
            return (False, "Edge")

        # Read with error-tolerant encoding
        with open(cookie_json_path, "rb") as f:
            raw = f.read()
        # Try UTF-8 first, fall back to latin-1
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
        cookies = json.loads(text)

        if log_callback:
            yt_count = sum(1 for c in cookies if "youtube.com" in c.get("host", ""))
            log_callback(f"Loaded {len(cookies)} cookies ({yt_count} YouTube domain)")

        # Convert to Netscape format
        content = _json_cookies_to_netscape(cookies)
        with open(cookie_file, "w", encoding="utf-8") as f:
            f.write(content)

        non_comment = [l for l in content.split("\n") if l and not l.startswith("#")]
        msg = f"Extracted {len(non_comment)} cookies from Edge via chromelevator"
        if log_callback:
            log_callback(msg)
        return (True, None)

    except subprocess.TimeoutExpired:
        if log_callback:
            log_callback("chromelevator timed out")
        return (False, "Edge")
    except Exception as e:
        if log_callback:
            log_callback(f"chromelevator error: {e}")
        return (False, "Edge")
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)


def extract_chromium_with_chromelevator(browser_name, cookie_file, log_callback=None):
    """Extract cookies using chromelevator for Chrome or Edge.

    chromelevator supports: chrome, chrome-beta, edge, brave, avast.
    """
    exe_path = _find_chromelevator()
    if not exe_path:
        if log_callback:
            log_callback("chromelevator_x64.exe not found")
        return (False, browser_name)

    # Map GUI browser name to chromelevator argument
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

        # Read the extracted cookies JSON
        profile_dir = chromelevator_name.capitalize()
        if chromelevator_name == "chrome":
            profile_dir = "Chrome"
        elif chromelevator_name == "edge":
            profile_dir = "Edge"
        elif chromelevator_name == "brave":
            profile_dir = "Brave"

        cookie_json_path = os.path.join(output_dir, profile_dir, "Default", "cookies.json")
        if not os.path.exists(cookie_json_path):
            # Try alternate path
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
# Cookie extraction entry point
# ---------------------------------------------------------------------------

def extract_cookies(browser_name, cookie_file, log_callback=None):
    """Unified cookie extraction entry point.

    Priority per browser:
    - Firefox: direct sqlite read (no encryption)
    - Chrome/Edge: decrypt_chromium.py (unified v20+v10+DPAPI) > chromelevator
    - Other Chromium: decrypt_chromium.py > chromelevator

    Returns (use_cookie_file, browser_for_native) where:
    - (True, None): pass --cookies <file> to yt-dlp
    - (False, "Edge"): pass --cookies-from-browser edge
    """
    if browser_name == "Firefox":
        return extract_firefox_cookies(cookie_file, log_callback)
    elif browser_name in BROWSERS:
        # Chrome, Edge, and other Chromium browsers
        # Try unified decrypt_chromium.py first (v20+v10+DPAPI+plaintext)
        result = extract_chromium_cookies(browser_name, cookie_file, log_callback)
        if result[0]:
            return result
        # Fall back to chromelevator (process injection + COM hijack)
        if log_callback:
            log_callback(f"Unified decrypt failed for {browser_name}, trying chromelevator...")
        return extract_chromium_with_chromelevator(browser_name, cookie_file, log_callback)
    else:
        return (False, browser_name)
