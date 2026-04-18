"""
Standalone yt-dlp helper — runs yt-dlp with full console access.
Usage: python ytdlp_helper.py <cookie_file_or_NONE> <browser_native_or_NONE> <url> <output_json_file>
"""
import sys, os, json, subprocess

mod_dir = os.path.dirname(os.path.abspath(__file__))
yt_dlp = os.path.join(mod_dir, "yt-dlp.exe")
if not os.path.isfile(yt_dlp):
    yt_dlp = "yt-dlp"

cookie_file = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != "NONE" else None
browser_native = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] != "NONE" else None
url = sys.argv[3]
out_file = sys.argv[4]

cmd = [yt_dlp, "--no-warnings", "--dump-json", "--no-download"]

if browser_native:
    cmd += ["--cookies-from-browser", browser_native]
elif cookie_file and os.path.exists(cookie_file):
    cmd += ["--cookies", cookie_file]

cmd += [url]

result = subprocess.run(cmd, text=True, capture_output=True, timeout=120)

if result.returncode != 0:
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({"error": result.stderr.strip()[:500]}, f)
    sys.exit(1)

for line in result.stdout.strip().split("\n"):
    if line.startswith("{"):
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(line)
        sys.exit(0)

with open(out_file, "w", encoding="utf-8") as f:
    json.dump({"error": "No JSON found", "stdout": result.stdout[:500]}, f)
sys.exit(1)
