"""Availability can be checked without requesting a PIN in unattended CI."""
import subprocess
result=subprocess.run(['dist/hello_verify.exe','--availability'],capture_output=True,timeout=30)
assert result.returncode in (0,2), 'Hello availability helper failed: '+result.stderr.decode(errors='replace')
result=subprocess.run(['dist/hello_verify.exe','0'],capture_output=True,timeout=30)
assert result.returncode==2,'Invalid owner HWND must be rejected'
print('Windows Hello helper: availability and invalid-owner behavior verified')
