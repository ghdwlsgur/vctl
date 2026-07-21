$ErrorActionPreference = 'Stop'

$packageName = 'vctl'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$version = $env:ChocolateyPackageVersion
$url64 = "https://github.com/ghdwlsgur/vctl/releases/download/v$version/vctl_${version}_windows_amd64.zip"

Install-ChocolateyZipPackage `
  -PackageName $packageName `
  -Url64bit $url64 `
  -UnzipLocation $toolsDir `
  -Checksum64 '__CHECKSUM64__' `
  -ChecksumType64 'sha256'
