"""Exercise the packaged binary over the actual Native Messaging pipes."""
import json
import struct
import subprocess
from pathlib import Path
exe = Path("dist/browser_host.exe").resolve()
payload = json.dumps({"action": "unsupported"}).encode()
result = subprocess.run([str(exe)], input=struct.pack("<I", len(payload)) + payload,
                        capture_output=True, timeout=60, check=True)
assert len(result.stdout) >= 4, "Host produced no framed response"
size = struct.unpack("<I", result.stdout[:4])[0]
assert size == len(result.stdout) - 4, "Invalid response framing"
reply = json.loads(result.stdout[4:])
assert reply["ok"] is False and reply["error"] == "Unsupported action"
print("Packaged Native Messaging host protocol passed")
