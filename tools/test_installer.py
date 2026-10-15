"""Install, start, and uninstall in an isolated CI directory; preserve user data."""
import os
import subprocess
import tempfile
import time
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
with tempfile.TemporaryDirectory() as tmp:
    folder = Path(tmp)
    app = folder / "application"
    data = folder / "user-data"
    data.mkdir()
    sentinel = data / "preserve.test"
    sentinel.write_text("user-data-must-survive", encoding="utf-8")
    setup = Path("installer_out/MoiParoli-Setup.exe").resolve()
    # Seed realistic user data before installing/upgrading.
    from moi_paroli import Vault, Settings
    vault = Vault(str(data / "vault.dat"))
    vault.create("UpgradeTestOnly!789")
    record = vault.add({"title": "Upgrade account", "login": "test@example.com",
                        "password": "SavedPassword!789", "category": "Работа"})
    vault.add_attachment(record["id"], "example.txt", b"attachment-must-survive")
    settings = Settings(str(data / "settings.json"))
    settings.set("theme", "light")
    # Opaque fixture: upgrading or renaming must never rewrite Hello credentials.
    hello=data/'hello_credential.json'
    hello.write_text('{"version":1,"vault":"synthetic-fixture","encrypted":"opaque-upgrade-sentinel"}',encoding='utf-8')
    tracked = [data / "vault.dat", data / "settings.json",hello]
    tracked += list((data / "backups").glob("*"))
    before = {str(p.relative_to(data)): p.read_bytes() for p in tracked if p.is_file()}
    previous = Path("previous_release/MoiParoli-Setup.exe")
    if previous.is_file():
        subprocess.run([str(previous.resolve()), "/VERYSILENT", "/SUPPRESSMSGBOXES",
                        "/NORESTART", "/SP-", f"/DIR={app}"], check=True, timeout=120)
    subprocess.run([str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                    "/SP-", f"/DIR={app}"], check=True, timeout=120)
    for name in ("MoiParoli.exe", "browser_host.exe", "browser_extension/manifest.json",
                 "register_browser_host.ps1", "unins000.exe"):
        assert (app / name).is_file(), f"Missing installed file: {name}"
    from browser_registration import diagnose
    assert all(item["ok"] for item in diagnose()), "Installer did not register all native host views"
    subprocess.run(["node", "tools/test_native_connection.cjs", str(app / "browser_extension")],
                   check=True, timeout=120)
    # A second installation exercises the same-directory replacement too.
    subprocess.run([str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                    "/SP-", f"/DIR={app}"], check=True, timeout=120)
    for name, original in before.items():
        assert (data / name).read_bytes() == original, f"Upgrade changed user data: {name}"
    probe = Vault(str(data / "vault.dat"))
    probe.unlock("UpgradeTestOnly!789")
    assert probe.get(record["id"])["password"] == "SavedPassword!789"
    assert len(probe.get(record["id"])["attachments"]) == 1
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
    probe = Vault(str(data / "vault.dat"))
    probe.unlock("UpgradeTestOnly!789")
    assert probe.get(record["id"])["login"] == "test@example.com"
    assert Settings(str(data / "settings.json")).get("theme") == "dark"
    assert hello.read_bytes()==before['hello_credential.json'], 'Upgrade changed Windows Hello credential data'
    print("Upgrade baseline:", "4.1 installer" if previous.is_file() else "same-version reinstall")
print("Installer smoke checks passed: install, application startup, uninstall, user data preserved")
