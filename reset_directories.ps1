# PowerShell script to reset directories based on config.ini
# Moves files from benign/quarantine/error back to input preserving structure
# Empties reports directory completely. No logging, prints operations and summary.

param(
    [string]$ConfigFile = "config.ini"
)

function Read-Ini {
    param([string]$Path)
    if (-not (Test-Path $Path)) { throw "Config file not found: $Path" }
    $hash = @{}
    foreach ($line in Get-Content $Path) {
        $line = $line.Trim()
        if ($line -eq '' -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }
        if ($line -match '^\[.*\]$') { continue }
        if ($line -match '^([^=]+)=(.*)$') {
            $k = $Matches[1].Trim(); $v = $Matches[2].Trim(); $hash[$k] = $v
        }
    }
    return $hash
}

function Expand-PathString {
    param([string]$s)
    if (-not $s) { return $s }
    $expanded = [System.Environment]::ExpandEnvironmentVariables($s)
    $expanded = $expanded -replace '^~',$env:USERPROFILE
    return $expanded
}

function Move-WithStructure {
    param(
        [string]$src,
        [string]$dst
    )
    if (-not (Test-Path $src)) { return 0 }
    $count = 0
    Get-ChildItem -Path $src -File -Recurse | ForEach-Object {
        $rel = $_.FullName.Substring($src.Length).TrimStart('\\')
        $dest = Join-Path -Path $dst -ChildPath $rel
        $dird = Split-Path -Path $dest -Parent
        if (-not (Test-Path $dird)) { New-Item -ItemType Directory -Path $dird -Force | Out-Null }
        Move-Item -Path $_.FullName -Destination $dest -Force
        Write-Host "Moved $rel"
        $count++
    }
    return $count
}

function Clear-Directory {
    param([string]$dir)
    if (-not (Test-Path $dir)) { return 0 }
    $cnt = 0
    Get-ChildItem -Path $dir -Recurse -Force | ForEach-Object {
        Remove-Item -Path $_.FullName -Force -Recurse
        $cnt++
    }
    return $cnt
}

# main
$config = Read-Ini -Path $ConfigFile
$input = Expand-PathString $config['input_directory']
$benign = Expand-PathString $config['benign_directory']
$quarantine = Expand-PathString $config['quarantine_directory']
$error = Expand-PathString $config['error_directory']
$reports = Expand-PathString $config['reports_directory']

Write-Host "Configuration:"
Write-Host "  input:       $input"
Write-Host "  benign:      $benign"
Write-Host "  quarantine:  $quarantine"
Write-Host "  error:       $error"
Write-Host "  reports:     $reports"
Write-Host ""
Write-Host "Actions to be performed:"
Write-Host "  * Move all files from benign/quarantine/error into input (keeping folder structure)."
Write-Host "  * Completely empty the reports directory."
Write-Host ""
$resp = Read-Host "Proceed with these actions? (yes/no)"
if ($resp -ne 'yes') { Write-Host "Cancelled."; exit 0 }

$tot = 0
$tot += Move-WithStructure -src $benign -dst $input
$tot += Move-WithStructure -src $quarantine -dst $input
$tot += Move-WithStructure -src $error -dst $input
Write-Host "Moved a total of $tot files into $input"

$del = Clear-Directory -dir $reports
Write-Host "Removed $del items from reports directory"

Write-Host "Done."