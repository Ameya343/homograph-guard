# Build the Windows installer: dist\HomographGuard-Setup-<version>.exe
#
#   powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 [-Python C:\path\to\python.exe]
#
# Needs Python 3.11-3.13 with Tk (python.org installers have it). Everything else - PyInstaller and
# NSIS - is fetched into build\ and checked against pinned SHA-256 hashes; nothing is installed system-wide.
param([string]$Python = "python")

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Build = Join-Path $Root "build\windows"
$Dist = Join-Path $Root "dist"
$NsisVersion = "3.12"
$NsisSha256 = "56581f90db321581c5381193d796fffcf2d24b2f8fed2160a6c6a3baa67f2c4f"
$PyInstallerVersion = "6.22.3"
New-Item -ItemType Directory -Force $Build, $Dist | Out-Null

Write-Host "== Python build environment"
$venv = Join-Path $Build "venv"
if (-not (Test-Path "$venv\Scripts\python.exe")) { & $Python -m venv $venv }
$py = "$venv\Scripts\python.exe"
$env:PIP_USER = "0"
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet "pyinstaller==$PyInstallerVersion"
& $py -m pip install --quiet --require-hashes --only-binary=:all: --no-deps -r (Join-Path $Root "requirements.lock")
& $py -m pip install --quiet --no-deps $Root
$version = & $py -c "import homograph_guard; print(homograph_guard.__version__)"
& $py -c "import tkinter" ; if ($LASTEXITCODE) { throw "this Python has no Tk; use a python.org build" }

Write-Host "== PyInstaller ($version)"
$appDir = Join-Path $Build "app"
& $py -m PyInstaller --noconfirm --clean --distpath $appDir --workpath (Join-Path $Build "work") (Join-Path $PSScriptRoot "homograph_guard.spec")
if ($LASTEXITCODE) { throw "PyInstaller failed" }
$app = Join-Path $appDir "HomographGuard"
# The browser extension (without its tests), the setup guide and the licence go next to the programs.
$ext = Join-Path $app "extension"
if (Test-Path $ext) { Remove-Item -Recurse -Force $ext }
Copy-Item -Recurse (Join-Path $Root "extension") $ext
Remove-Item -Recurse -Force (Join-Path $ext "tests")
Copy-Item (Join-Path $PSScriptRoot "extension-setup.html") $app
Copy-Item (Join-Path $Root "LICENSE") (Join-Path $app "LICENSE.txt")

Write-Host "== NSIS $NsisVersion"
$nsisZip = Join-Path $Build "nsis-$NsisVersion.zip"
if (-not (Test-Path $nsisZip)) {
  # SourceForge serves browsers an HTML mirror page; a command-line user agent gets the file itself.
  Invoke-WebRequest -UseBasicParsing -UserAgent "Wget/1.21" -MaximumRedirection 10 `
    -Uri "https://downloads.sourceforge.net/project/nsis/NSIS%203/$NsisVersion/nsis-$NsisVersion.zip" -OutFile $nsisZip
}
$hash = (Get-FileHash $nsisZip -Algorithm SHA256).Hash.ToLower()
if ($hash -ne $NsisSha256) { Remove-Item $nsisZip; throw "NSIS download hash mismatch: $hash" }
$nsisDir = Join-Path $Build "nsis-$NsisVersion"
if (-not (Test-Path $nsisDir)) { Expand-Archive $nsisZip -DestinationPath $Build }
$out = Join-Path $Dist "HomographGuard-Setup-$version.exe"
& (Join-Path $nsisDir "makensis.exe") /V2 "/DVERSION=$version" "/DSRCDIR=$app" "/DOUTFILE=$out" (Join-Path $PSScriptRoot "installer.nsi")
if ($LASTEXITCODE) { throw "makensis failed" }
$sha = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
"$sha  $(Split-Path $out -Leaf)" | Set-Content -Encoding ascii "$out.sha256"
Write-Host "== Built $out"
Write-Host "   SHA-256 $sha"
