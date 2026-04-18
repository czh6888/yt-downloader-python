---
name: pythonw subprocess console issue
description: When calling external tools (especially yt-dlp) from a pythonw.exe GUI app, the lack of console breaks tools that need console for JS solving or interactive operations. Always use CREATE_NEW_CONSOLE or a helper script.
type: feedback
---

**Rule:** yt-dlp (and similar tools with JS challenge solving) FAILS when called via subprocess from pythonw.exe because there is no console. The tool returns empty/error results even with identical commands that work perfectly in CMD.

**Why:** yt-dlp's deno JS solver checks for console/terminal availability. In pythonw.exe (no console), subprocess inherits no console, JS solving fails, YouTube format list is empty.

**Solution pattern:**
1. Create a standalone helper script that runs the external tool
2. Spawn it via python.exe with subprocess.CREATE_NEW_CONSOLE flag
3. Pass results through temp files, not pipes

**How to apply:** Any time a GUI app needs to call external CLI tools that:
- Solve browser JS challenges
- Need terminal/tty detection
- Behave differently with/without console
Use CREATE_NEW_CONSOLE or DETACHED_PROCESS, never plain subprocess.run/PIPE from a no-console parent.
