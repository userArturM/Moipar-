$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'Visual C++ build tools not found' }
$developer = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
New-Item -ItemType Directory -Path dist -Force | Out-Null
& cmd.exe /d /c "`"$developer`" -arch=x64 && cl /nologo /std:c++17 /EHsc /utf-8 native\hello_verify.cpp /Fe:dist\hello_verify.exe /link windowsapp.lib user32.lib"
if ($LASTEXITCODE -ne 0) { throw 'Windows Hello helper compilation failed' }
