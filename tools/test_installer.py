"""Install, start, and uninstall in an isolated CI directory; preserve user data."""
import os
import subprocess
import tempfile
import time
from pathlib import Path
with tempfile.TemporaryDirectory() as tmp:
    folder = Path(tmp)
    app = folder / "application"
    data = folder / "user-data"
    data.mkdir()
    sentinel = data / "preserve.test"
    sentinel.write_text("user-data-must-survive", encoding="utf-8")
    setup = Path("installer_out/MoiParoli-Setup.exe").resolve()
    subprocess.run([str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                    "/SP-", f"/DIR={app}"], check=True, timeout=120)
    for name in ("MoiParoli.exe", "browser_host.exe", "browser_extension/manifest.json",
                 "register_browser_host.ps1", "unins000.exe"):
        assert (app / name).is_file(), f"Missing installed file: {name}"
    env = dict(os.environ, MOIPAROLI_DIR=str(data))
    process = subprocess.Popen([str(app / "MoiParoli.exe")], env=env)
    try:
        time.sleep(5)
        assert process.poll() is None, "Installed application exited during startup"
    finally:
        if process.poll() is None:
            # PyInstaller onefile uses a launcher and a child application process.
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           check=True, capture_output=True, timeout=30)
        process.wait(timeout=30)
    subprocess.run([str(app / "unins000.exe"), "/VERYSILENT", "/SUPPRESSMSGBOXES",
                    "/NORESTART"], check=True, timeout=120)
    deadline = time.monotonic() + 30
    while (app / "MoiParoli.exe").exists() and time.monotonic() < deadline:
        time.sleep(0.25)
    assert not (app / "MoiParoli.exe").exists(), "Uninstall left the application EXE"
    assert sentinel.read_text(encoding="utf-8") == "user-data-must-survive"
print("Installer smoke checks passed: install, application startup, uninstall, user data preserved")
