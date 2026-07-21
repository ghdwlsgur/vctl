param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$Checksum64,
  [string]$OutputDirectory = 'dist/chocolatey'
)

$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$') {
  throw "invalid package version: $Version"
}
if ($Checksum64 -notmatch '^[0-9a-fA-F]{64}$') {
  throw 'Checksum64 must be a SHA-256 hex digest'
}

$sourceDir = $PSScriptRoot
$stageDir = Join-Path ([System.IO.Path]::GetTempPath()) "vctl-chocolatey-$Version"
if (Test-Path $stageDir) { Remove-Item -Recurse -Force $stageDir }
New-Item -ItemType Directory -Force $stageDir | Out-Null
Copy-Item (Join-Path $sourceDir 'vctl.nuspec') $stageDir
Copy-Item (Join-Path $sourceDir 'tools') $stageDir -Recurse

$nuspec = Join-Path $stageDir 'vctl.nuspec'
$installScript = Join-Path $stageDir 'tools/chocolateyinstall.ps1'
(Get-Content $nuspec -Raw).Replace('__VERSION__', $Version) | Set-Content $nuspec -Encoding utf8NoBOM
(Get-Content $installScript -Raw).Replace('__CHECKSUM64__', $Checksum64.ToLowerInvariant()) | Set-Content $installScript -Encoding utf8NoBOM

$output = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force $output | Out-Null
choco pack $nuspec --outputdirectory $output
if ($LASTEXITCODE -ne 0) { throw "choco pack failed with exit code $LASTEXITCODE" }
