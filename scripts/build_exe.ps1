param(
    [string]$SpecPath = "floss.spec"
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $ProjectRoot

Write-Host "Building FLOSS executable using $SpecPath"
pyinstaller --noconfirm --clean $SpecPath

$distPath = Join-Path $ProjectRoot "dist"
$exePath = Join-Path $distPath "floss\\floss.exe"

Write-Host "Build finished. Executable should be available at: $exePath"
