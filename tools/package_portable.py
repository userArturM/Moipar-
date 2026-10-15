"""Create a complete, flat portable package including browser integration."""
from pathlib import Path
import shutil
folder=Path("portable")
folder.mkdir(exist_ok=True)
for name in ("MoiParoli.exe","browser_host.exe"):
    shutil.copyfile(Path("dist")/name,folder/name)
shutil.copytree("browser_extension",folder/"browser_extension",dirs_exist_ok=True)
shutil.copyfile("register_browser_host.ps1",folder/"register_browser_host.ps1")
shutil.copyfile('icon.ico',folder/'Bitora.ico')
print("Portable package includes application, browser host, extension and registration helper")
