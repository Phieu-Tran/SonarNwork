$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repository = "Phieu-Tran/SonarNwork"
$releaseApi = "https://api.github.com/repos/$repository/releases/latest"
$installRoot = $null
$temporaryRoot = $null

function Get-ReleaseAsset {
    param(
        [Parameter(Mandatory)] $Release,
        [Parameter(Mandatory)] [string] $NamePattern
    )

    $matches = @($Release.assets | Where-Object { $_.name -match $NamePattern })
    if ($matches.Count -ne 1) {
        throw "Expected exactly one release asset matching '$NamePattern'; found $($matches.Count)."
    }

    $matches[0]
}

function Add-InstallRootToUserPath {
    param([Parameter(Mandatory)] [string] $Path)

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $pathEntries = @($userPath -split ";" | Where-Object { $_ })
    $normalizedPath = $Path.TrimEnd([IO.Path]::DirectorySeparatorChar)
    $alreadyPresent = $pathEntries | Where-Object {
        [string]::Equals(
            $_.TrimEnd([IO.Path]::DirectorySeparatorChar),
            $normalizedPath,
            [StringComparison]::OrdinalIgnoreCase
        )
    }

    if (-not $alreadyPresent) {
        $updatedPath = (@($pathEntries) + $Path) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $updatedPath, "User")
    }

    if (-not ($env:Path -split ";" | Where-Object {
        [string]::Equals(
            $_.TrimEnd([IO.Path]::DirectorySeparatorChar),
            $normalizedPath,
            [StringComparison]::OrdinalIgnoreCase
        )
    })) {
        $env:Path = "$Path;$env:Path"
    }
}

try {
    if (-not $env:LOCALAPPDATA) {
        throw "LOCALAPPDATA is unavailable; run this installer from a standard Windows user session."
    }
    $installRoot = Join-Path $env:LOCALAPPDATA "Programs\SonarNwork"

    $headers = @{ "User-Agent" = "SonarNwork-Installer" }
    $release = Invoke-RestMethod -Uri $releaseApi -Headers $headers
    $bundle = Get-ReleaseAsset -Release $release -NamePattern "^SonarNwork-.+-windows-x64-portable\.zip$"
    $checksums = Get-ReleaseAsset -Release $release -NamePattern "^SHA256SUMS\.txt$"

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "SonarNwork-$($release.tag_name)-install"
    New-Item -ItemType Directory -Force -Path $temporaryRoot | Out-Null
    $archivePath = Join-Path $temporaryRoot $bundle.name
    $checksumsPath = Join-Path $temporaryRoot "SHA256SUMS.txt"
    $expandedPath = Join-Path $temporaryRoot "expanded"

    Invoke-WebRequest -Uri $bundle.browser_download_url -Headers $headers -OutFile $archivePath
    Invoke-WebRequest -Uri $checksums.browser_download_url -Headers $headers -OutFile $checksumsPath

    $checksumLine = Get-Content -LiteralPath $checksumsPath | Where-Object {
        $_ -match ("^([0-9a-fA-F]{64})\\s{2}" + [regex]::Escape($bundle.name) + "$")
    } | Select-Object -First 1
    if (-not $checksumLine) {
        throw "No SHA-256 checksum was published for $($bundle.name)."
    }

    $expectedHash = ($checksumLine -split "\\s+")[0].ToLowerInvariant()
    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "SHA-256 verification failed for $($bundle.name)."
    }

    Expand-Archive -LiteralPath $archivePath -DestinationPath $expandedPath -Force
    foreach ($fileName in "sonar.exe", "sonarnwork.exe", "sonarnwork-app.exe") {
        if (-not (Test-Path -LiteralPath (Join-Path $expandedPath $fileName) -PathType Leaf)) {
            throw "The portable bundle is missing $fileName."
        }
    }

    New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
    Copy-Item -Path (Join-Path $expandedPath "*") -Destination $installRoot -Recurse -Force
    Add-InstallRootToUserPath -Path $installRoot

    & (Join-Path $installRoot "sonar.exe") --version
    Write-Host "SonarNwork $($release.tag_name) installed to $installRoot" -ForegroundColor Green
    Write-Host "Open a new terminal, then run: sonar" -ForegroundColor Green
}
finally {
    if ($temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
