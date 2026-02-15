param(
    [string]$DataDir = (Join-Path $PSScriptRoot "..\data"),
    [switch]$NoBackup,
    [string]$BackupDir = "",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Write-Action {
    param([string]$Message)
    Write-Host $Message
}

function Assert-DirectoryWritable {
    param([Parameter(Mandatory = $true)][string]$Path)
    $probe = Join-Path $Path ".clear_all_data_write_test.tmp"
    try {
        Set-Content -Path $probe -Value "ok" -Encoding ascii -ErrorAction Stop
        Remove-Item -Path $probe -Force -ErrorAction Stop
    } catch {
        throw "Write access is required for '$Path'. Run cmd/PowerShell as a user with modify rights."
    }
}

if (-not (Test-Path -Path $DataDir -PathType Container)) {
    throw "Data directory not found: $DataDir"
}

$resolvedDataDir = (Resolve-Path -Path $DataDir).Path
$commandsDir = Join-Path $resolvedDataDir "commands"

$targets = Get-ChildItem -Path $resolvedDataDir -File -Force | Where-Object {
    $_.Extension -in @(".db", ".json", ".lastrun", ".log") -or
    $_.Name -in @("guardianbridge.db-wal", "guardianbridge.db-shm")
}

$commandsTargets = @()
if (Test-Path -Path $commandsDir -PathType Container) {
    $commandsTargets = Get-ChildItem -Path $commandsDir -Force
}

$resolvedBackupDir = ""
if (-not $NoBackup) {
    if ([string]::IsNullOrWhiteSpace($BackupDir)) {
        $backupRoot = Join-Path (Split-Path -Path $resolvedDataDir -Parent) "AutoBackUp"
        if (-not (Test-Path -Path $backupRoot -PathType Container)) {
            if (-not $DryRun) {
                New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
            }
        }
        $resolvedBackupDir = Join-Path $backupRoot ("data_reset_" + (Get-Date -Format "yyyyMMdd-HHmmss"))
    } else {
        $resolvedBackupDir = $BackupDir
    }
}

Write-Action ""
Write-Action "Data directory: $resolvedDataDir"
Write-Action "Files to remove: $($targets.Count)"
Write-Action "commands/ entries to remove: $($commandsTargets.Count)"
if (-not $NoBackup) {
    Write-Action "Backup directory: $resolvedBackupDir"
}
if ($DryRun) {
    Write-Action "Mode: DRY RUN (no files will be changed)"
}
Write-Action ""

if (-not $DryRun) {
    Assert-DirectoryWritable -Path $resolvedDataDir

    if (-not $NoBackup) {
        New-Item -ItemType Directory -Path $resolvedBackupDir -Force | Out-Null
        foreach ($file in $targets) {
            Copy-Item -Path $file.FullName -Destination (Join-Path $resolvedBackupDir $file.Name) -Force
        }
        if (Test-Path -Path $commandsDir -PathType Container) {
            $backupCommandsDir = Join-Path $resolvedBackupDir "commands"
            New-Item -ItemType Directory -Path $backupCommandsDir -Force | Out-Null
            foreach ($item in $commandsTargets) {
                Copy-Item -Path $item.FullName -Destination (Join-Path $backupCommandsDir $item.Name) -Recurse -Force
            }
        }
    }

    foreach ($file in $targets) {
        Remove-Item -Path $file.FullName -Force -ErrorAction Stop
    }

    if (Test-Path -Path $commandsDir -PathType Container) {
        foreach ($item in (Get-ChildItem -Path $commandsDir -Force)) {
            Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
        }
    } else {
        New-Item -ItemType Directory -Path $commandsDir -Force | Out-Null
    }

    Write-Action "Data clear complete."
    if (-not $NoBackup) {
        Write-Action "Backup saved to: $resolvedBackupDir"
    }
} else {
    foreach ($file in $targets) {
        Write-Action "Would remove file: $($file.FullName)"
    }
    foreach ($item in $commandsTargets) {
        Write-Action "Would remove commands entry: $($item.FullName)"
    }
}
