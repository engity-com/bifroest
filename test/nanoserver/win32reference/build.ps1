param([Parameter(Mandatory = $true)][string]$OutputDirectory)

$ErrorActionPreference = 'Stop'
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$installation = & $vswhere -latest -version '[17.0,18.0)' -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or !$installation) { throw 'MSVC 2022 x64 is required for the final CI-only reference comparison' }
$setup = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
$variables = & $env:ComSpec /d /s /c "`"$setup`" -no_logo -arch=amd64 -host_arch=amd64 >nul && set"
if ($LASTEXITCODE -ne 0) { throw 'MSVC environment preparation failed' }
foreach ($line in $variables) {
    if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
}
$directory = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($directory) | Out-Null
$source = Join-Path $PSScriptRoot 'main.c'
$executable = Join-Path $directory 'conpty-reference.exe'
$object = Join-Path $directory 'conpty-reference.obj'
# Static CRT: no redistributable DLL or additional runtime in the Nano image.
& cl.exe /nologo /W4 /WX /O2 /MT /guard:cf /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 $source "/Fe:$executable" "/Fo:$object" /link /DYNAMICBASE /NXCOMPAT /guard:cf advapi32.lib
if ($LASTEXITCODE -ne 0) { throw 'Native ConPTY reference compilation failed' }
& dumpbin.exe /dependents $executable
if ($LASTEXITCODE -ne 0) { throw 'Native ConPTY reference import inspection failed' }
Get-FileHash -Algorithm SHA256 -LiteralPath $executable
