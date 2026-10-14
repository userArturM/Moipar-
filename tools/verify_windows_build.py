"""Validate Windows PE headers and publish SHA256 hashes of built artifacts."""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [ROOT / "dist/MoiParoli.exe", ROOT / "dist/browser_host.exe",
         ROOT / "dist/hello_verify.exe", ROOT / "installer_out/MoiParoli-Setup.exe"]

def is_pe(path):
    with Path(path).open("rb") as stream:
        if stream.read(2) != b"MZ":
            return False
        stream.seek(0x3c)
        data = stream.read(4)
        if len(data) != 4:
            return False
        offset = struct.unpack("<I", data)[0]
        if not (64 <= offset <= 1048576):
            return False
        stream.seek(offset)
        return stream.read(4) == b"PE\0\0"

def verify():
    result = {}
    for path in FILES:
        if not path.is_file() or path.stat().st_size < 4096:
            raise RuntimeError(f"Missing or too small: {path}")
        if not is_pe(path):
            raise RuntimeError(f"Invalid PE header: {path}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1048576), b""):
                digest.update(chunk)
        result[path.name] = {"bytes": path.stat().st_size, "sha256": digest.hexdigest()}
    target = ROOT / "dist/BUILD_MANIFEST.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result

if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))

