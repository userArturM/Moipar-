param([ValidateSet('app','installer')][string]$Phase='app')
$ErrorActionPreference='Stop'
if (-not $env:MOIPAROLI_SIGNING_PFX_BASE64) {
    Write-Output 'Signing skipped: no publisher certificate configured. This build is unsigned.'
    exit 0
}
$tool=Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $tool) { throw 'Windows SDK SignTool not found' }
$certificate=Join-Path $env:RUNNER_TEMP ('moiparoli-signing-'+[guid]::NewGuid().ToString()+'.pfx')
try {
    [IO.File]::WriteAllBytes($certificate,[Convert]::FromBase64String($env:MOIPAROLI_SIGNING_PFX_BASE64))
    $files=if($Phase -eq 'app'){Get-ChildItem dist\*.exe}else{Get-Item installer_out\MoiParoli-Setup.exe}
    foreach($file in $files){
        & $tool.FullName sign /f $certificate /p $env:MOIPAROLI_SIGNING_PASSWORD /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $file.FullName
        if($LASTEXITCODE -ne 0){throw 'Publisher signing failed'}
        & $tool.FullName verify /pa $file.FullName
        if($LASTEXITCODE -ne 0){throw 'Publisher signature verification failed'}
    }
} finally {
    if(Test-Path -LiteralPath $certificate){Remove-Item -LiteralPath $certificate -Force}
}
