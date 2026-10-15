param([string]$ExtensionId,[string]$HostExe=(Join-Path $PSScriptRoot 'browser_host.exe'))
$ErrorActionPreference='Stop'
if (-not $ExtensionId) { $ExtensionId=(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'browser_extension\extension_id.txt') -Raw).Trim() }
if ($ExtensionId -cnotmatch '^[a-p]{32}$') { throw 'Invalid extension ID' }
if (-not (Test-Path -LiteralPath $HostExe -PathType Leaf)) { $HostExe=Join-Path $PSScriptRoot 'dist\browser_host.exe' }
$HostExe=[System.IO.Path]::GetFullPath($HostExe)
if (-not (Test-Path -LiteralPath $HostExe -PathType Leaf)) { throw 'browser_host.exe was not found. Install the full application.' }
$folder=Join-Path $env:APPDATA 'MoiParoli\native'
New-Item -ItemType Directory -Path $folder -Force | Out-Null
$path=Join-Path $folder 'browser_host_manifest.json'
$origins=@("chrome-extension://$ExtensionId/")
if (Test-Path -LiteralPath $path -PathType Leaf) {
    try {
        $old=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ($old.name -eq 'ru.moiparoli.host') { $origins+=@($old.allowed_origins | Where-Object { $_ -cmatch '^chrome-extension://[a-p]{32}/$' }) }
    } catch {}
}
$manifest=@{name='ru.moiparoli.host';description='Bitora password browser integration';path=$HostExe;type='stdio';allowed_origins=@($origins | Sort-Object -Unique)} | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText($path,$manifest,[System.Text.UTF8Encoding]::new($false))
foreach ($view in @([Microsoft.Win32.RegistryView]::Registry32,[Microsoft.Win32.RegistryView]::Registry64)) {
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,$view)
    foreach ($browser in @('Google\Chrome','Yandex\YandexBrowser','Microsoft\Edge','Chromium')) {
        $key=$base.CreateSubKey("Software\$browser\NativeMessagingHosts\ru.moiparoli.host")
        $key.SetValue('',$path,[Microsoft.Win32.RegistryValueKind]::String)
        $key.Dispose()
    }
    $base.Dispose()
}
Write-Output "Browser connection registered: $path"
