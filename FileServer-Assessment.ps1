###########################################################################
# File Server Assessment Script
# Purpose:
#   Azure File Server Migration Assessment
#   Suitable for Azure Files / Azure Migrate Discovery
#
# Usage:
#   .\FileServer-Assessment.ps1 -OutputFolder "C:\Assessment"
#   .\FileServer-Assessment.ps1 -TargetFolders "F:\Finance","F:\HR"
#   .\FileServer-Assessment.ps1 -SftpRootDirectories "F:\SFTPDrop"
#
# Notes:
#   - When -TargetFolders is omitted, scan targets are auto-discovered from
#     local SMB shares (built-in shares such as ADMIN$, IPC$, print$ and
#     single drive-letter shares like C$/D$/K$ are excluded automatically).
#   - When -SftpRootDirectories is omitted, SFTP root directories are
#     auto-detected per Windows OpenSSH's actual behavior: an active,
#     uncommented "ChrootDirectory" inside a "Match User" block wins;
#     otherwise the root is the user's local profile path (Get-CimInstance
#     Win32_UserProfile, falling back to C:\Users\<user>). If the real data
#     lives behind a junction/symlink inside that profile (a common pattern
#     when ChrootDirectory isn't used, e.g. C:\Users\<user>\Data pointing at
#     F:\SFTPDrop\<user>), the resolved junction target is auto-scanned too.
#     If you already know the real data path, pass it directly with
#     -SftpRootDirectories to skip auto-detection entirely.
#   - Each folder is scanned with a single recursive file enumeration that
#     feeds every downstream report, which keeps runtime reasonable on
#     multi-drive, multi-terabyte file servers with many shares.
###########################################################################

[CmdletBinding()]
param(
    # Folder where all reports will be written
    [string]$OutputFolder = "C:\Assessment",

    # Folders to assess; leave empty (default) to auto-discover from local SMB shares
    [string[]]$TargetFolders = @(),

    # Local usernames to check for SFTP root directory; defaults to users found in sshd_config "Match User" blocks
    [string[]]$SftpUsers = @(),

    # SFTP root directories to scan; leave empty (default) to auto-discover from sshd_config "Match User" blocks
    [string[]]$SftpRootDirectories = @(),

    # Files older than this many days (by LastWriteTime) are reported as cold data
    [int]$ColdDataThresholdDays = 365,

    # Full paths longer than this are reported as long-path risks
    [int]$LongPathThreshold = 240,

    # Number of largest files to keep in the final report
    [int]$TopLargestFilesCount = 100
)

$ErrorLog = New-Object System.Collections.Generic.List[object]

function Write-AssessmentError
{
    param($Stage, $Target, $Message)

    $script:ErrorLog.Add([PSCustomObject]@{
        Stage   = $Stage
        Target  = $Target
        Message = $Message
        Time    = Get-Date
    })
    Write-Warning "[$Stage] $Target : $Message"
}

try
{
    New-Item `
        -Path $OutputFolder `
        -ItemType Directory `
        -Force `
        -ErrorAction Stop | Out-Null
}
catch
{
    Write-Error "Unable to create output folder '$OutputFolder': $_"
    return
}

###########################################################################
# 1. Share Inventory & Target Folder Discovery
###########################################################################

Write-Host ""
Write-Host "Collecting Share Inventory..."

# Built-in/administrative shares to always exclude; single drive-letter shares
# (C$, D$, K$, ...) are excluded via regex so this works across any drive layout
$AdminShareNames = @('ADMIN$', 'IPC$', 'print$', 'prtproc$')

$AllShares = @()
try
{
    $AllShares = Get-SmbShare -ErrorAction Stop
}
catch
{
    Write-AssessmentError "ShareInventory" "Get-SmbShare" $_.Exception.Message
}

$FilteredShares = $AllShares | Where-Object {
    ($_.Name -notin $AdminShareNames) -and
    ($_.Name -notmatch '^[A-Za-z]\$$') -and
    (-not [string]::IsNullOrWhiteSpace($_.Path))
}

$FilteredShares |
Select-Object `
    Name,
    Path,
    Description |
Export-Csv `
    "$OutputFolder\ShareInventory.csv" `
    -NoTypeInformation `
    -Encoding UTF8

if ($TargetFolders -and $TargetFolders.Count -gt 0)
{
    $SmbFolders = $TargetFolders
}
else
{
    Write-Host "No -TargetFolders specified; auto-discovering from local SMB shares..."
    $SmbFolders = $FilteredShares.Path
}

$SmbFolders = $SmbFolders |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Sort-Object -Unique

$ValidSmbFolders = @()
foreach ($Folder in $SmbFolders)
{
    if (Test-Path $Folder)
    {
        $ValidSmbFolders += $Folder
    }
    else
    {
        Write-AssessmentError "Discovery" $Folder "Path not found or inaccessible; skipped"
    }
}
$SmbFolders = $ValidSmbFolders

Write-Host "SMB target folders to assess: $($SmbFolders.Count)"


###########################################################################
# 2. SFTP Root Directory Detection (Windows OpenSSH)
###########################################################################
# Same auto-discovery pattern as SMB shares: if -SftpRootDirectories is not
# specified, root directories are auto-detected from sshd_config "Match User"
# blocks (falling back to each user's profile path when chroot isn't set) and
# then merged into the scan target list below.

Write-Host ""
Write-Host "Detecting SFTP Root Directories..."

$SftpRootResults = @()
$SftpFolders = @()

if ($SftpRootDirectories -and $SftpRootDirectories.Count -gt 0)
{
    $SftpFolders = $SftpRootDirectories
}
else
{
    $SshdConfigPath = "$env:ProgramData\ssh\sshd_config"

    if (-not (Test-Path $SshdConfigPath))
    {
        Write-Warning "OpenSSH sshd_config not found at '$SshdConfigPath'. Skipping SFTP root directory auto-detection."
    }
    else
    {
        $ConfigLines = Get-Content $SshdConfigPath

        # Only "Match User" blocks and top-level directives are honored; other Match types (Group/Address) are ignored
        $GlobalChroot = $null
        $CurrentMatchUsers = @()
        $MatchChrootMap = @{}

        foreach ($Line in $ConfigLines)
        {
            $Trimmed = $Line.Trim()

            if ($Trimmed -eq "" -or $Trimmed.StartsWith("#"))
            {
                continue
            }

            $IsIndented = $Line -match '^\s+\S'

            if (-not $IsIndented -and $Trimmed -match '^Match\s+User\s+(.+)$')
            {
                $CurrentMatchUsers = $Matches[1] -split '[,\s]+' | Where-Object { $_ -ne "" }
                foreach ($MatchUser in $CurrentMatchUsers)
                {
                    if (-not $MatchChrootMap.ContainsKey($MatchUser))
                    {
                        $MatchChrootMap[$MatchUser] = $null
                    }
                }
                continue
            }

            if (-not $IsIndented -and $Trimmed -match '^Match\b')
            {
                # Non "Match User" block (e.g. Match Group/Address) - stop tracking user-specific directives
                $CurrentMatchUsers = @()
                continue
            }

            if ($Trimmed -match '^ChrootDirectory\s+(.+)$')
            {
                $ChrootValue = $Matches[1].Trim()

                if ($IsIndented -and $CurrentMatchUsers.Count -gt 0)
                {
                    foreach ($MatchUser in $CurrentMatchUsers)
                    {
                        $MatchChrootMap[$MatchUser] = $ChrootValue
                    }
                }
                elseif (-not $IsIndented)
                {
                    $GlobalChroot = $ChrootValue
                    $CurrentMatchUsers = @()
                }
            }
            elseif (-not $IsIndented)
            {
                # A new top-level (unindented) directive ends any active Match block
                $CurrentMatchUsers = @()
            }
        }

        $UsersToCheck = if ($SftpUsers -and $SftpUsers.Count -gt 0)
        {
            $SftpUsers
        }
        else
        {
            $MatchChrootMap.Keys
        }

        foreach ($UserName in $UsersToCheck)
        {
            $ConfiguredChroot = if ($MatchChrootMap.ContainsKey($UserName) -and $MatchChrootMap[$UserName])
            {
                $MatchChrootMap[$UserName]
            }
            else
            {
                $GlobalChroot
            }

            $ChrootEnabled = (-not [string]::IsNullOrWhiteSpace($ConfiguredChroot)) -and ($ConfiguredChroot -ne "none")

            $ProfilePath = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
                Where-Object { (Split-Path $_.LocalPath -Leaf) -eq $UserName } |
                Select-Object -First 1 -ExpandProperty LocalPath

            if (-not $ProfilePath)
            {
                $ProfilePath = "C:\Users\$UserName"
            }

            $EffectiveRoot = if ($ChrootEnabled)
            {
                $ConfiguredChroot -replace '%u', $UserName
            }
            else
            {
                $ProfilePath
            }

            # When Chroot isn't enabled, the real data often lives behind a junction/symlink
            # inside the profile root (e.g. C:\Users\<user>\Data -> F:\SFTPDrop\<user>) rather
            # than in the profile shell itself, so surface and scan those resolved targets too.
            $JunctionTargets = @()
            if (-not $ChrootEnabled -and (Test-Path $EffectiveRoot))
            {
                $ReparseChildren = Get-ChildItem -Path $EffectiveRoot -Directory -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.LinkType -in @('Junction', 'SymbolicLink', 'HardLink') -and $_.Target }

                foreach ($Child in $ReparseChildren)
                {
                    foreach ($Target in $Child.Target)
                    {
                        if (-not [string]::IsNullOrWhiteSpace($Target))
                        {
                            $JunctionTargets += $Target
                        }
                    }
                }
            }
            $JunctionTargets = $JunctionTargets | Sort-Object -Unique

            $SftpRootResults += [PSCustomObject]@{
                UserName                  = $UserName
                ConfiguredChrootDirectory = $ConfiguredChroot
                ChrootEnabled             = $ChrootEnabled
                ProfilePath               = $ProfilePath
                EffectiveSftpRoot         = $EffectiveRoot
                JunctionTargets           = $JunctionTargets -join '; '
            }
        }

        if ($SftpRootResults.Count -eq 0)
        {
            Write-Warning "No 'Match User' blocks found in sshd_config and no -SftpUsers specified. Nothing to auto-detect."
        }

        # Scan both the effective root and any junction/symlink targets found inside it
        $SftpFolders = @(
            $SftpRootResults | Select-Object -ExpandProperty EffectiveSftpRoot
            $SftpRootResults | Select-Object -ExpandProperty JunctionTargets |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { $_ -split ';\s*' }
        )
    }
}

$SftpFolders = $SftpFolders |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Sort-Object -Unique

$ValidSftpFolders = @()
foreach ($Folder in $SftpFolders)
{
    if (Test-Path $Folder)
    {
        $ValidSftpFolders += $Folder
    }
    else
    {
        Write-AssessmentError "SftpDiscovery" $Folder "SFTP root directory not found or inaccessible; skipped"
    }
}
$SftpFolders = $ValidSftpFolders

Write-Host "SFTP root folders to assess: $($SftpFolders.Count)"

$SftpRootResults |
Export-Csv `
    "$OutputFolder\SftpRootDirectory.csv" `
    -NoTypeInformation `
    -Encoding UTF8


###########################################################################
# 3. Combined Target Folder List
###########################################################################

$Folders = @($SmbFolders + $SftpFolders) | Sort-Object -Unique

if ($Folders.Count -eq 0)
{
    Write-Warning "No valid target folders to assess. Exiting."
    return
}

Write-Host "Total folders to assess (SMB + SFTP): $($Folders.Count)"

# Build a unique, filesystem-safe report-name per folder (handles duplicate leaf
# names, drive letters, and special characters such as & or spaces in share paths)
$InvalidFileNameChars = [regex]::Escape(([System.IO.Path]::GetInvalidFileNameChars() -join ''))
$UsedNames = @{}
$FolderNameMap = @{}

foreach ($Folder in $Folders)
{
    $Base = ($Folder -replace '^[A-Za-z]:\\?', '') -replace '\\', '_'
    if ([string]::IsNullOrWhiteSpace($Base))
    {
        $Base = Split-Path $Folder -Leaf
    }

    $Safe = [regex]::Replace($Base, "[$InvalidFileNameChars]", '_').Trim('_')
    if ([string]::IsNullOrWhiteSpace($Safe))
    {
        $Safe = "Folder"
    }

    $Candidate = $Safe
    $Suffix = 1
    while ($UsedNames.ContainsKey($Candidate))
    {
        $Suffix++
        $Candidate = "$Safe`_$Suffix"
    }
    $UsedNames[$Candidate] = $true
    $FolderNameMap[$Folder] = $Candidate
}


###########################################################################
# 4. ACL Export + Single-Pass File Scan
###########################################################################
# Each folder is enumerated recursively exactly once; the resulting file list
# feeds file counts, extension stats, last-access, cold data, long-path,
# invalid-name, and largest-file reports without re-walking the filesystem.

Write-Host ""
Write-Host "Scanning target folders (ACLs, counts, ages, sizes)..."

$DateThreshold = (Get-Date).AddDays(-$ColdDataThresholdDays)
$InvalidNamePattern = '[<>:"/\\|?*]'

$FileCountResults = @()
$ColdFiles = @()
$LongPathFiles = @()
$InvalidFiles = @()
$LargestFilesCandidates = @()
$TotalFilesScanned = 0
# $TotalSizeBytes = 0

foreach ($Folder in $Folders)
{
    $FolderName = $FolderNameMap[$Folder]
    Write-Host "  -> $Folder"

    try
    {
        icacls $Folder /save "$OutputFolder\$FolderName-ACL.txt" /t /c 2>$null | Out-Null
    }
    catch
    {
        Write-AssessmentError "ACL" $Folder $_.Exception.Message
    }

    try
    {
        Get-Acl $Folder -ErrorAction Stop |
        Export-Clixml "$OutputFolder\$FolderName-ACL.xml"
    }
    catch
    {
        Write-AssessmentError "ACL" $Folder $_.Exception.Message
    }

    $Files = Get-ChildItem `
        -Path $Folder `
        -File `
        -Recurse `
        -Force `
        -ErrorAction SilentlyContinue

    $FolderFileCount = 0
    $ExtensionCounts = @{}
    $FolderColdFiles = @()
    $FolderLongPathFiles = @()
    $FolderInvalidFiles = @()
    $FolderLastAccess = @()

    foreach ($File in $Files)
    {
        $FolderFileCount++
        $TotalFilesScanned++
        # $TotalSizeBytes += $File.Length

        $Ext = if ([string]::IsNullOrEmpty($File.Extension)) { "(none)" } else { $File.Extension }
        if (-not $ExtensionCounts.ContainsKey($Ext)) { $ExtensionCounts[$Ext] = 0 }
        $ExtensionCounts[$Ext]++

        $FolderLastAccess += [PSCustomObject]@{
            FullName       = $File.FullName
            Length         = $File.Length
            LastAccessTime = $File.LastAccessTime
            LastWriteTime  = $File.LastWriteTime
        }

        if ($File.LastWriteTime -lt $DateThreshold)
        {
            $FolderColdFiles += [PSCustomObject]@{
                FullName      = $File.FullName
                Length        = $File.Length
                LastWriteTime = $File.LastWriteTime
            }
        }

        if ($File.FullName.Length -gt $LongPathThreshold)
        {
            $FolderLongPathFiles += [PSCustomObject]@{
                FullName      = $File.FullName
                PathLength    = $File.FullName.Length
                Length        = $File.Length
                LastWriteTime = $File.LastWriteTime
            }
        }

        if ($File.Name -match $InvalidNamePattern)
        {
            $FolderInvalidFiles += [PSCustomObject]@{
                FullName = $File.FullName
                Name     = $File.Name
            }
        }
    }

    $FileCountResults += [PSCustomObject]@{
        Folder    = $Folder
        FileCount = $FolderFileCount
    }

    if ($ExtensionCounts.Count -gt 0)
    {
        $ExtensionCounts.GetEnumerator() |
        Sort-Object Value -Descending |
        Select-Object @{Name="Name";Expression={$_.Key}}, @{Name="Count";Expression={$_.Value}} |
        Export-Csv "$OutputFolder\$FolderName-FileTypes.csv" -NoTypeInformation -Encoding UTF8
    }

    $FolderLastAccess |
    Export-Csv "$OutputFolder\$FolderName-LastAccess.csv" -NoTypeInformation -Encoding UTF8

    $ColdFiles += $FolderColdFiles
    $LongPathFiles += $FolderLongPathFiles
    $InvalidFiles += $FolderInvalidFiles

    # Bound memory by keeping only each folder's own top-N candidates before the final merge
    $LargestFilesCandidates += ($Files |
        Sort-Object Length -Descending |
        Select-Object -First $TopLargestFilesCount FullName, Length, LastWriteTime)
}

$FileCountResults |
Export-Csv "$OutputFolder\FileCount.csv" -NoTypeInformation -Encoding UTF8

$ColdFiles |
Export-Csv "$OutputFolder\ColdDataReport.csv" -NoTypeInformation -Encoding UTF8

$LongPathFiles |
Export-Csv "$OutputFolder\LongPathReport.csv" -NoTypeInformation -Encoding UTF8

$InvalidFiles |
Export-Csv "$OutputFolder\InvalidFileNames.csv" -NoTypeInformation -Encoding UTF8

$LargestFilesCandidates |
Sort-Object Length -Descending |
Select-Object -First $TopLargestFilesCount |
Export-Csv "$OutputFolder\LargestFiles.csv" -NoTypeInformation -Encoding UTF8


###########################################################################
# 5. Assessment Summary
###########################################################################

Write-Host ""
Write-Host "Creating Summary Report..."

$ColdFilesCount = if ($null -eq $ColdFiles) { 0 } else { @($ColdFiles).Count }
$LongPathCount = if ($null -eq $LongPathFiles) { 0 } else { @($LongPathFiles).Count }
$InvalidFileCount = if ($null -eq $InvalidFiles) { 0 } else { @($InvalidFiles).Count }
$SftpUserCount = if ($null -eq $SftpRootResults) { 0 } else { @($SftpRootResults).Count }

$Summary = [PSCustomObject]@{
    AssessmentDate    = Get-Date
    TotalFolders      = $Folders.Count
    SmbFolders        = $SmbFolders.Count
    SftpFolders       = $SftpFolders.Count
    TotalFiles        = $TotalFilesScanned
    # TotalSizeGB     = [Math]::Round(($TotalSizeBytes / 1GB), 2)
    ColdFiles         = $ColdFilesCount
    LongPathFiles     = $LongPathCount
    InvalidNames      = $InvalidFileCount
    SftpUsersFound    = $SftpUserCount
    ScanErrors        = $ErrorLog.Count
}

$Summary | Export-Csv `
    "$OutputFolder\Summary.csv" `
    -NoTypeInformation `
    -Encoding UTF8

if ($ErrorLog.Count -gt 0)
{
    $ErrorLog | Export-Csv "$OutputFolder\ScanErrors.csv" -NoTypeInformation -Encoding UTF8
}


###########################################################################
# 6. Folder Access Matrix (SMB vs SFTP)
###########################################################################

Write-Host ""
Write-Host "Creating Folder Access Matrix..."

$AccessMatrix = foreach ($Folder in $Folders)
{
    [PSCustomObject]@{
        Folder = $Folder
        SMB    = if ($SmbFolders -contains $Folder) { "Yes" } else { "No" }
        SFTP   = if ($SftpFolders -contains $Folder) { "Yes" } else { "No" }
    }
}

$AccessMatrix |
Export-Csv "$OutputFolder\FolderAccessMatrix.csv" -NoTypeInformation -Encoding UTF8

Write-Host ""
$AccessMatrix | Format-Table Folder, SMB, SFTP -AutoSize | Out-Host


###########################################################################
# Completion
###########################################################################

Write-Host ""
Write-Host "===================================="
Write-Host "Assessment Completed Successfully"
Write-Host ""
Write-Host "Output Location:"
Write-Host $OutputFolder
Write-Host "===================================="