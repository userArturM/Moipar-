param(
    [Parameter(Mandatory=$true)][string]$ExtensionId,
    [string]$HostExe = (Join-Path $PSScriptRoot 'browser_host.exe')
)
$ErrorActionPreference = 'Stop'
if ($ExtensionId -cnotmatch '^[a-p]{32}$') { throw 'Неверный идентификатор расширения Chrome/Яндекс.' }
$HostExe = [System.IO.Path]::GetFullPath($HostExe)
if (-not (Test-Path -LiteralPath $HostExe -PathType Leaf)) { throw 'browser_host.exe не найден; сначала выполните сборку.' }
$manifestPath = Join-Path (Split-Path $HostExe -Parent) 'browser_host_manifest.json'
$manifest = @{
    name='ru.moiparoli.host'
    description='Moi Paroli approved autofill'
    path=$HostExe
    type='stdio'
    allowed_origins=@("chrome-extension://$ExtensionId/")
} | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText($manifestPath, $manifest, [System.Text.UTF8Encoding]::new($false))
foreach ($browser in @('Google\Chrome', 'Yandex\YandexBrowser')) {
    $key = "HKCU:\Software\$browser\NativeMessagingHosts\ru.moiparoli.host"
    New-Item -Path $key -Force | Out-Null
    Set-Item -Path $key -Value $manifestPath
}
Write-Host "Native Messaging host зарегистрирован: $manifestPath"
