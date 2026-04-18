---
name: yt-dlp GUI vs CMD discrepancy root cause
description: Detailed history of the yt-dlp CMD vs GUI failure debugging, and the fix using helper script + CREATE_NEW_CONSOLE.
type: project
---

**Fact:** yt-dlp CLI works perfectly in CMD but fails via subprocess from GUI app (pythonw.exe), returning "Requested format is not available" despite identical command, same cookie file, same bundled exe.

**Why:** pythonw.exe has no console → subprocess inherits no console → yt-dlp's deno JS solver fails → no formats available. This was NOT a cookie issue, NOT a yt-dlp version issue, NOT an environment variable issue — it was the console handle.

**How to apply:** When debugging similar issues in future:
1. Don't waste time on subprocess parameter tweaks (stdin, shell, env) — they don't fix the no-console problem
2. Check if parent process is pythonw.exe (no console) vs python.exe (has console)
3. Use CREATE_NEW_CONSOLE flag or spawn a helper script with python.exe
4. Use temp files for output, not pipes (no-console pipe buffering is unreliable)

**Failed approaches (do NOT retry):**
- Removing stdin=subprocess.DEVNULL — necessary but not sufficient
- Using cmd /c wrapper — same console issue
- Adding --list-formats flag — broke JSON parsing
- Writing output to temp files via shell redirect — deno still needs console
- Popen streaming with stderr=STDOUT — same console issue

**Timeline:** ~6 iterations wasted before switching to CREATE_NEW_CONSOLE approach.
