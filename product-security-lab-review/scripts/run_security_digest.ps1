[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,

    [string]$PythonPath = "python",

    [string]$LogRoot,

    [ValidateSet("json", "markdown")]
    [string]$Format = "json"
)

$ErrorActionPreference = "Stop"

function Resolve-AbsolutePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue
    )

    if (Test-Path -LiteralPath $PathValue) {
        return (Resolve-Path -LiteralPath $PathValue).Path
    }

    $executionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PathValue)
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildScript = Join-Path $scriptDir "build_security_digest.py"
if (-not (Test-Path -LiteralPath $buildScript)) {
    throw "build_security_digest.py not found at $buildScript"
}

$resolvedConfigPath = Resolve-AbsolutePath -PathValue $ConfigPath
$resolvedOutputRoot = Resolve-AbsolutePath -PathValue $OutputRoot

New-Item -ItemType Directory -Force -Path $resolvedOutputRoot | Out-Null

if ([string]::IsNullOrWhiteSpace($LogRoot)) {
    $logFolderName = ([string][char]0x8FD0) + ([string][char]0x884C) + ([string][char]0x65E5) + ([string][char]0x5FD7)
    $resolvedLogRoot = Join-Path $resolvedOutputRoot $logFolderName
} else {
    $resolvedLogRoot = Resolve-AbsolutePath -PathValue $LogRoot
}
New-Item -ItemType Directory -Force -Path $resolvedLogRoot | Out-Null

$logDateFolder = Get-Date -Format "yyyy-MM-dd"
$dailyLogRoot = Join-Path $resolvedLogRoot $logDateFolder
New-Item -ItemType Directory -Force -Path $dailyLogRoot | Out-Null

$logFilePrefix = ([string][char]0x8FD0) + ([string][char]0x884C) + ([string][char]0x65E5) + ([string][char]0x5FD7)
$logFile = Join-Path $dailyLogRoot ("{0}-{1}.log" -f $logFilePrefix, (Get-Date -Format "yyyy-MM-dd-HH-mm-ss"))

$arguments = @(
    $buildScript,
    "--config", $resolvedConfigPath,
    "--output-root", $resolvedOutputRoot,
    "--format", $Format
)

& $PythonPath @arguments 2>&1 | Tee-Object -FilePath $logFile
$exitCode = $LASTEXITCODE
if ($null -eq $exitCode) {
    $exitCode = 0
}

if ($exitCode -ne 0) {
    throw "Digest run failed with exit code $exitCode. See $logFile"
}

Write-Output ("Log file: {0}" -f $logFile)
