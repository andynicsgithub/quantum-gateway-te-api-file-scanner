# PowerShell script to reset directories by moving files back to input_directory
# Reads config.ini, moves files from output directories back to input_directory,
# preserves subdirectory structure, and permanently deletes reports files

param(
    [string]$ConfigFile = "config.ini"
)

# =======================
# Helper Functions
# =======================

function Read-IniFile {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        throw "Config file not found: $FilePath"
    }
    
    $config = @{}
    $content = Get-Content $FilePath -Raw
    
    foreach ($line in $content -split [System.Environment]::NewLine) {
        $line = $line.Trim()
        
        # Skip empty lines and comments
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith(';') -or $line.StartsWith('#')) {
            continue
        }
        
        # Skip section headers like [DEFAULT]
        if ($line -match '^\[.*\]$') {
            continue
        }
        
        # Parse key=value pairs
        if ($line -match '^([^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            $value = $Matches[2].Trim()
            $config[$key] = $value
        }
    }
    
    return $config
}

function Expand-Path {
    param([string]$PathString)
    
    # Expand environment variables and home directory
    $expanded = [System.Environment]::ExpandEnvironmentVariables($PathString)
    $expanded = $expanded -replace '~', $env:USERPROFILE
    
    return $expanded
}

function Move-FilesWithStructure {
    param(
        [string]$SourceDir,
        [string]$DestinationDir,
        [string]$DirectoryName
    )
    
    if (-not (Test-Path $SourceDir)) {
        Write-Warning "Source directory does not exist: $SourceDir"
        return 0
    }
    
    $fileCount = 0
    
    try {
        $files = Get-ChildItem -Path $SourceDir -File -Recurse
        
        if ($files.Count -eq 0) {
            Write-Host "  No files found in $DirectoryName"
            return 0
        }
        
        foreach ($file in $files) {
            # Calculate relative path from source directory
            $relativePath = $file.FullName.Substring($SourceDir.Length).TrimStart('\')
            $destinationPath = Join-Path -Path $DestinationDir -ChildPath $relativePath
            $destinationFileDir = Split-Path -Path $destinationPath -Parent
            
            # Create destination directory if it doesn't exist
            if (-not (Test-Path $destinationFileDir)) {
                New-Item -ItemType Directory -Path $destinationFileDir -Force | Out-Null
                Write-Host "    Created directory: $destinationFileDir"
            }
            
            # Move file
            Move-Item -Path $file.FullName -Destination $destinationPath -Force
            Write-Host "    Moved: $relativePath"
            $fileCount++
        }
    }
    catch {
        Write-Error "Error moving files from $DirectoryName : $_"
        return -1
    }
    
    return $fileCount
}

function Remove-FilesSecurely {
    param(
        [string]$SourceDir,
        [string]$DirectoryName
    )
    
    if (-not (Test-Path $SourceDir)) {
        Write-Warning "Directory does not exist: $SourceDir"
        return 0
    }
    
    $fileCount = 0
    
    try {
        $files = Get-ChildItem -Path $SourceDir -File -Recurse
        
        if ($files.Count -eq 0) {
            Write-Host "  No files to delete in $DirectoryName"
            return 0
        }
        
        foreach ($file in $files) {
            $relativePath = $file.FullName.Substring($SourceDir.Length).TrimStart('\')
            
            # Use Remove-Item with -Force to delete permanently
            # Note: This does NOT use recycle bin if -Force is used with Remove-Item
            Remove-Item -Path $file.FullName -Force
            Write-Host "    Deleted: $relativePath"
            $fileCount++
        }
    }
    catch {
        Write-Error "Error deleting files from $DirectoryName : $_"
        return -1
    }
    
    return $fileCount
}

# =======================
# Main Script
# =======================

Write-Host "========================================"
Write-Host "Directory Reset Tool"
Write-Host "========================================"
Write-Host ""

# Read configuration file
Write-Host "Reading configuration from: $ConfigFile"
try {
    $config = Read-IniFile -FilePath $ConfigFile
}
catch {
    Write-Error "Failed to read config file: $_"
    exit 1
}

# Expand paths
$inputDir = Expand-Path $config['input_directory']
$reportsDir = Expand-Path $config['reports_directory']
$benignDir = Expand-Path $config['benign_directory']
$quarantineDir = Expand-Path $config['quarantine_directory']
$errorDir = Expand-Path $config['error_directory']

# Verify input directory exists
if (-not (Test-Path $inputDir)) {
    Write-Error "Input directory does not exist: $inputDir"
    exit 1
}

Write-Host "Configuration loaded:"
Write-Host "  Input directory:       $inputDir"
Write-Host "  Reports directory:     $reportsDir"
Write-Host "  Benign directory:      $benignDir"
Write-Host "  Quarantine directory:  $quarantineDir"
Write-Host "  Error directory:       $errorDir"
Write-Host ""

# Confirm with user
Write-Host "This script will:"
Write-Host "  1. Move files from benign_directory to input_directory"
Write-Host "  2. Move files from quarantine_directory to input_directory"
Write-Host "  3. Move files from error_directory to input_directory"
Write-Host "  4. Move files from reports_directory to input_directory"
Write-Host "  5. Permanently delete all files from reports_directory"
Write-Host "  6. Preserve all subdirectory structures"
Write-Host ""

$confirmation = Read-Host "Do you want to proceed? (yes/no)"
if ($confirmation -ne 'yes') {
    Write-Host "Operation cancelled."
    exit 0
}

Write-Host ""
Write-Host "Starting reset process..."
Write-Host ""

$totalMoved = 0
$totalDeleted = 0

# Move files from benign directory
Write-Host "Processing benign_directory..."
$moved = Move-FilesWithStructure -SourceDir $benignDir -DestinationDir $inputDir -DirectoryName "benign_directory"
if ($moved -ge 0) {
    Write-Host "  Total moved: $moved files"
    $totalMoved += $moved
}
Write-Host ""

# Move files from quarantine directory
Write-Host "Processing quarantine_directory..."
$moved = Move-FilesWithStructure -SourceDir $quarantineDir -DestinationDir $inputDir -DirectoryName "quarantine_directory"
if ($moved -ge 0) {
    Write-Host "  Total moved: $moved files"
    $totalMoved += $moved
}
Write-Host ""

# Move files from error directory
Write-Host "Processing error_directory..."
$moved = Move-FilesWithStructure -SourceDir $errorDir -DestinationDir $inputDir -DirectoryName "error_directory"
if ($moved -ge 0) {
    Write-Host "  Total moved: $moved files"
    $totalMoved += $moved
}
Write-Host ""

# Move files from reports directory
Write-Host "Processing reports_directory..."
$moved = Move-FilesWithStructure -SourceDir $reportsDir -DestinationDir $inputDir -DirectoryName "reports_directory"
if ($moved -ge 0) {
    Write-Host "  Total moved: $moved files"
    $totalMoved += $moved
}
Write-Host ""

# Permanently delete remaining files from reports directory
Write-Host "Permanently deleting files from reports_directory..."
$deleted = Remove-FilesSecurely -SourceDir $reportsDir -DirectoryName "reports_directory"
if ($deleted -ge 0) {
    Write-Host "  Total deleted: $deleted files"
    $totalDeleted += $deleted
}
Write-Host ""

# Summary
Write-Host "========================================"
Write-Host "Reset Complete"
Write-Host "========================================"
Write-Host "Total files moved to input_directory: $totalMoved"
Write-Host "Total files permanently deleted:      $totalDeleted"
Write-Host ""
Write-Host "All subdirectory structures have been preserved."
Write-Host ""
