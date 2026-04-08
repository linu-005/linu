[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,

    [ValidatePattern("^\d{2}:\d{2}$")]
    [string]$ScheduleTime = "22:00",

    [string]$TaskName = "Codex Product Security Digest",

    [string]$TaskPath = "\Codex\",

    [string]$Description = "Generate the product-security-lab-review digest every day.",

    [string]$PythonPath = "python",

    [string]$PowerShellPath = "powershell.exe",

    [string]$LogRoot,

    [switch]$Force
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

function Quote-Arg {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    '"' + $Value.Replace('"', '\"') + '"'
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$runScript = Join-Path $scriptDir "run_security_digest.ps1"
if (-not (Test-Path -LiteralPath $runScript)) {
    throw "run_security_digest.ps1 not found at $runScript"
}

$resolvedConfigPath = Resolve-AbsolutePath -PathValue $ConfigPath
$resolvedOutputRoot = Resolve-AbsolutePath -PathValue $OutputRoot
$resolvedLogRoot = $null
if (-not [string]::IsNullOrWhiteSpace($LogRoot)) {
    $resolvedLogRoot = Resolve-AbsolutePath -PathValue $LogRoot
}

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$triggerAt = [datetime]::ParseExact($ScheduleTime, "HH:mm", [System.Globalization.CultureInfo]::InvariantCulture)

if (-not $TaskPath.StartsWith("\")) {
    $TaskPath = "\" + $TaskPath
}
if (-not $TaskPath.EndsWith("\")) {
    $TaskPath = $TaskPath + "\"
}

$argumentParts = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", (Quote-Arg $runScript),
    "-ConfigPath", (Quote-Arg $resolvedConfigPath),
    "-OutputRoot", (Quote-Arg $resolvedOutputRoot),
    "-PythonPath", (Quote-Arg $PythonPath)
)
if ($resolvedLogRoot) {
    $argumentParts += @("-LogRoot", (Quote-Arg $resolvedLogRoot))
}
$actionArguments = $argumentParts -join " "

$action = New-ScheduledTaskAction -Execute $PowerShellPath -Argument $actionArguments
$trigger = New-ScheduledTaskTrigger -Daily -At $triggerAt
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew

$targetLabel = "$TaskPath$TaskName"
if ($PSCmdlet.ShouldProcess($targetLabel, "Register daily digest task")) {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -TaskPath $TaskPath `
        -Description $Description `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Force:$Force | Out-Null
    Write-Output ("Registered scheduled task {0} at {1} for user {2}" -f $targetLabel, $ScheduleTime, $currentUser)
    Write-Output ("Task action: {0} {1}" -f $PowerShellPath, $actionArguments)
}
