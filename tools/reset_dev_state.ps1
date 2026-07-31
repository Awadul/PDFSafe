#Requires -Version 5.1
<#
.SYNOPSIS
    Reset PDFSafe's local state so the same test files can be scanned again.

.DESCRIPTION
    Scanning a file twice is not a repeatable test. The first scan writes a
    history row, copies the bytes into the content-addressed store, and - when
    the verdict is malicious - renames the original to '<name>.quarantine' so
    Windows will not open it. The second scan therefore starts from a different
    world than the first, and the results are not comparable.

    This script puts things back:

      * stops any running PDFSafe, which holds the SQLite file open
      * deletes the scan database and its -wal / -shm sidecars
      * empties the content-addressed file store and the quarantine vault
      * renames '<name>.quarantine' files in -TestFolder back to '<name>'

    It never touches the source tree, and it leaves settings alone unless you
    ask for -ResetSettings, so your AI configuration survives a reset.

    Restoring quarantined names makes those files openable again. That is the
    point during testing, but it means -TestFolder must be a folder of test
    documents you control - never a real Downloads folder.

.PARAMETER TestFolder
    Folder holding your test PDFs. Files renamed by quarantine are restored
    here. Omit it and nothing outside PDFSafe's own data directory is touched.

.PARAMETER DataDir
    Override PDFSafe's data directory. Defaults to %LOCALAPPDATA%\PDFSafe,
    matching pdfsafe.paths.local_dir().

.PARAMETER ClearLogs
    Also delete the rotating application logs. Off by default: the log is
    usually the thing you want to read after a failed test.

.PARAMETER ResetSettings
    Also delete config.json, returning every setting to its default. Does NOT
    remove API keys - those live in Windows Credential Manager, not on disk.

.PARAMETER Force
    Skip the confirmation prompt.

.EXAMPLE
    .\tools\reset_dev_state.ps1 -TestFolder C:\temp\pdftest

.EXAMPLE
    .\tools\reset_dev_state.ps1 -TestFolder C:\temp\pdftest -ClearLogs -Force

.EXAMPLE
    .\tools\reset_dev_state.ps1 -TestFolder C:\temp\pdftest -WhatIf
    Shows everything that would be removed without removing any of it.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $TestFolder,
    [string] $DataDir = (Join-Path $env:LOCALAPPDATA "PDFSafe"),
    [switch] $ClearLogs,
    [switch] $ResetSettings,
    [switch] $Force
)

$ErrorActionPreference = "Stop"

function Write-Step { param([string] $Text) Write-Host "`n=== $Text ===" -ForegroundColor Cyan }
function Write-Note { param([string] $Text) Write-Host "    $Text" -ForegroundColor DarkGray }
function Write-Warn { param([string] $Text) Write-Host "    ! $Text" -ForegroundColor Yellow }

$ConfigDir = Join-Path $env:APPDATA "PDFSafe"

$targets = [ordered]@{
    "scan database"  = Join-Path $DataDir "data"
    "file store"     = Join-Path $DataDir "files"
    "quarantine"     = Join-Path $DataDir "quarantine"
    "update cache"   = Join-Path $DataDir "cache"
}
if ($ClearLogs)     { $targets["logs"]     = Join-Path $DataDir "logs" }
if ($ResetSettings) { $targets["settings"] = Join-Path $ConfigDir "config.json" }

# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------
Write-Step "About to reset PDFSafe state"
foreach ($name in $targets.Keys) {
    $path = $targets[$name]
    $state = if (Test-Path $path) { "" } else { "  (already absent)" }
    Write-Note ("{0,-14} {1}{2}" -f $name, $path, $state)
}

if ($TestFolder) {
    if (-not (Test-Path $TestFolder)) { throw "TestFolder does not exist: $TestFolder" }
    $TestFolder = (Resolve-Path $TestFolder).Path
    Write-Note ("{0,-14} {1}" -f "restore names", $TestFolder)
} else {
    Write-Warn "No -TestFolder given: quarantined files keep their .quarantine names."
}

if (-not $Force -and -not $WhatIfPreference) {
    $answer = Read-Host "`nProceed? This cannot be undone [y/N]"
    if ($answer -notmatch '^(y|yes)$') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# ---------------------------------------------------------------------------
# 1. Stop the app - it keeps the database and its DLLs open
# ---------------------------------------------------------------------------
Write-Step "Stopping PDFSafe"
$running = @(Get-Process -Name "PDFSafe" -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    if ($PSCmdlet.ShouldProcess("PDFSafe ($($running.Count) process(es))", "Stop")) {
        $running | Stop-Process -Force
        Start-Sleep -Milliseconds 750
        Write-Note "Stopped $($running.Count) process(es)"
    }
} else {
    Write-Note "Not running"
}

# ---------------------------------------------------------------------------
# 2. Remove state
# ---------------------------------------------------------------------------
Write-Step "Removing state"
foreach ($name in $targets.Keys) {
    $path = $targets[$name]
    if (-not (Test-Path $path)) { Write-Note "$name - nothing to remove"; continue }

    if ($PSCmdlet.ShouldProcess($path, "Remove")) {
        try {
            # Quarantined copies are stored read-only so they cannot be opened
            # or overwritten by accident; clear that before deleting.
            Get-ChildItem $path -Recurse -File -Force -ErrorAction SilentlyContinue |
                ForEach-Object { $_.IsReadOnly = $false }

            Remove-Item $path -Recurse -Force
            Write-Note "$name - removed"
        } catch {
            Write-Warn "$name - could not remove: $($_.Exception.Message)"
            Write-Warn "Close anything using $path and run again."
        }
    }
}

# ---------------------------------------------------------------------------
# 3. Restore quarantined filenames
# ---------------------------------------------------------------------------
if ($TestFolder) {
    Write-Step "Restoring quarantined filenames"

    # Matches both '<name>.quarantine' and the collision form
    # '<name>.quarantine.3' produced when the same file is quarantined twice.
    $pattern = '^(?<base>.+?)\.quarantine(\.\d+)?$'
    $restored = 0
    $skipped = 0

    Get-ChildItem $TestFolder -Recurse -File -Force |
        Where-Object { $_.Name -match $pattern } |
        ForEach-Object {
            $original = [regex]::Match($_.Name, $pattern).Groups['base'].Value
            $target = Join-Path $_.DirectoryName $original

            if (Test-Path $target) {
                # An earlier '.quarantine' already claimed this name. Renaming
                # over it would silently destroy one of the two files.
                Write-Warn "$($_.Name) - '$original' already exists, left alone"
                $skipped++
                return
            }

            if ($PSCmdlet.ShouldProcess($_.FullName, "Rename to $original")) {
                try {
                    $_.IsReadOnly = $false
                    Rename-Item -LiteralPath $_.FullName -NewName $original
                    Write-Note "$($_.Name) -> $original"
                    $restored++
                } catch {
                    Write-Warn "$($_.Name) - $($_.Exception.Message)"
                    $skipped++
                }
            }
        }

    Write-Note "Restored $restored file(s), skipped $skipped"
}

Write-Step "Done"
Write-Host "PDFSafe will recreate its database on next launch." -ForegroundColor Green
if (-not $ResetSettings) {
    Write-Note "Settings kept. Pass -ResetSettings to clear config.json too."
}
