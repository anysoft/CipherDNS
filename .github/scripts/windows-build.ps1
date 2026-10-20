param([string] $Version)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Native failures are checked after Tee-Object so their complete logs are retained.
$PSNativeCommandUseErrorActionPreference = $false

function Invoke-LoggedNative {
    param(
        [Parameter(Mandatory)] [string] $Executable,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [Parameter(Mandatory)] [string] $LogPath
    )
    & $Executable @Arguments 2>&1 | Tee-Object -FilePath $LogPath
    $nativeExitCode = $LASTEXITCODE
    if ($nativeExitCode -ne 0) {
        throw "$Executable failed with exit code $nativeExitCode; see $LogPath"
    }
}

function Assert-CacheValue {
    param([hashtable] $Cache, [string] $Name, [string] $Expected)
    if (-not $Cache.ContainsKey($Name) -or $Cache[$Name] -cne $Expected) {
        throw "Unexpected CMake cache value for ${Name}: '$($Cache[$Name])'; expected '$Expected'"
    }
}

if (-not $IsWindows) {
    throw 'The native MSVC build requires Windows.'
}

# Discover VS 2022 rather than depending on its edition or installation path.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vsInstall = & $vswhere -latest -products '*' -version '[17.1,18.0)' `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsInstall)) {
    throw 'Visual Studio 2022 with the x64 C/C++ toolchain was not found.'
}
$vsLauncher = Join-Path $vsInstall 'Common7/Tools/Launch-VsDevShell.ps1'
# Microsoft's supported PowerShell entry point preserves this shell's environment.
& $vsLauncher -Arch amd64 -HostArch amd64 -SkipAutomaticLocation 2>&1 | Tee-Object -FilePath toolchain-init.log
if ($env:VSCMD_ARG_TGT_ARCH -ne 'x64' -or $env:VSCMD_ARG_HOST_ARCH -ne 'x64') {
    throw 'The Visual Studio developer environment is not configured for x64.'
}
$compiler = (Get-Command cl.exe -CommandType Application -ErrorAction Stop).Source
foreach ($tool in @('cmake', 'ninja', 'ctest', 'dumpbin.exe')) {
    Get-Command $tool -CommandType Application -ErrorAction Stop | Out-Null
}

if ([string]::IsNullOrEmpty($Version)) {
    if ($env:GITHUB_REF -like 'refs/tags/v*') {
        $Version = $env:GITHUB_REF_NAME.Substring(1)
    } else {
        $Version = '0.2.0-dev+' + $env:GITHUB_SHA.Substring(0, 12)
    }
}

foreach ($mode in @('BOTH', 'SERVER', 'CLIENT')) {
    $buildDir = "build-$mode"
    # Each array element is one argument, including paths containing spaces.
    $configureArguments = @(
        '-S', '.', '-B', $buildDir, '-G', 'Ninja',
        '-DCMAKE_BUILD_TYPE:STRING=MinSizeRel',
        "-DCMAKE_C_COMPILER:FILEPATH=$compiler",
        "-DCIPHERDNS_MODE:STRING=$mode",
        "-DCIPHERDNS_VERSION:STRING=$Version",
        '-DCIPHERDNS_LINK:STRING=static',
        '-DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON',
        '-DCIPHERDNS_BUILD_TESTS:BOOL=ON',
        '-DCIPHERDNS_INTEGRATION_TESTS:BOOL=ON'
    )
    Invoke-LoggedNative cmake $configureArguments "configure-$mode.log"

    $cache = @{}
    foreach ($line in Get-Content -LiteralPath "$buildDir/CMakeCache.txt") {
        if ($line -match '^([A-Za-z_][A-Za-z0-9_]*):[^=]+=(.*)$') {
            $cache[$Matches[1]] = $Matches[2]
        }
    }
    Assert-CacheValue $cache 'CIPHERDNS_MODE' $mode
    Assert-CacheValue $cache 'CIPHERDNS_LINK' 'static'
    Assert-CacheValue $cache 'CIPHERDNS_VERSION' $Version
    Assert-CacheValue $cache 'CMAKE_BUILD_TYPE' 'MinSizeRel'
    Assert-CacheValue $cache 'CMAKE_GENERATOR' 'Ninja'
    if (-not $cache.ContainsKey('CMAKE_C_COMPILER') -or
        [IO.Path]::GetFullPath($cache['CMAKE_C_COMPILER']) -ine [IO.Path]::GetFullPath($compiler)) {
        throw "CMake did not select the initialized MSVC compiler for $mode."
    }
    $compilerFiles = @(Get-ChildItem -LiteralPath "$buildDir/CMakeFiles" -Filter CMakeCCompiler.cmake -Recurse)
    if ($compilerFiles.Count -ne 1) {
        throw "Expected one generated CMake compiler description for $mode."
    }
    $compilerDescription = Get-Content -LiteralPath $compilerFiles[0].FullName -Raw
    if ($compilerDescription -notmatch 'set\(CMAKE_C_COMPILER_ID "MSVC"\)' -or
        $compilerDescription -notmatch 'set\((?:MSVC_C_ARCHITECTURE_ID|CMAKE_C_COMPILER_ARCHITECTURE_ID) "?x64"?\)') {
        throw "CMake did not identify MSVC x64 for $mode."
    }

    # static means /MT on MSVC; Windows system DLL imports are still expected.
    $commands = @(Get-Content -LiteralPath "$buildDir/compile_commands.json" -Raw | ConvertFrom-Json)
    if ($commands.Count -eq 0) {
        throw "CMake did not export compile commands for $mode."
    }
    foreach ($entry in $commands) {
        if ($entry.command -notmatch '(?:^|\s)[/-]MT(?:\s|$)' -or
            $entry.command -match '(?:^|\s)[/-]MDd?(?:\s|$)') {
            throw "Expected the static MSVC /MT runtime for $($entry.file)."
        }
    }
    Invoke-LoggedNative cmake @('--build', $buildDir, '--parallel') "build-$mode.log"
    Invoke-LoggedNative ctest @('--test-dir', $buildDir, '--output-on-failure') "test-$mode.log"
    Invoke-LoggedNative "./$buildDir/cipherdns.exe" @('--version') "version-$mode.log"
}
