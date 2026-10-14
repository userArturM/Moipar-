"""Validate packaged Windows executables and write SHA256 metadata."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [ROOT / "dist/MoiParoli.exe", ROOT / "dist/browser_host.exe", ROOT / "installer_out/MoiParoli-Setup.exe"]

def verify():
    result = {}
    for path in FILES:
        if not path.is_file() or path.stat().st_size < 4096:
            raise RuntimeError(f"Missing or suspiciously small executable: {path}")
        with path.open("rb") as stream:
            if stream.read(2) != b"MZ":
                raise RuntimeError(f"Not a Windows executable: {path}")
        result[path.name] = {
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    (ROOT / "dist/BUILD_MANIFEST.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result

if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
