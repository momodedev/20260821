###########################################################################
# File Server Assessment Script
# Purpose:
#   Azure File Server Migration Assessment
#   Suitable for Azure Files / Azure Migrate Discovery
#
# Usage:
#   .\FileServer-Assessment.ps1 -OutputFolder "C:\Assessment" -TargetFolders "F:\Finance","F:\HR"
#
###########################################################################

[CmdletBinding()]
param(
    # Folder where all reports will be written
    [string]$OutputFolder = "C:\Assessment",

    # Folders to assess; defaults to the original lab targets
    [string[]]$TargetFolders = @(
        "F:\Finance",
        "F:\HR",
        "F:\Archive",
        "F:\SFTPDrop"
    )
)

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
# 1. Share Inventory
###########################################################################

Write-Host ""
Write-Host "Collecting Share Inventory..."

Get-SmbShare |
Where-Object {
    $_.Name -notmatch "ADMIN\$|IPC\$|C\$|D\$|E\$|F\$"
} |
Select-Object `
    Name,
    Path,
    Description |
Export-Csv `
    "$OutputFolder\ShareInventory.csv" `
    -NoTypeInformation `
    -Encoding UTF8


###########################################################################
# 2. ACL Export
###########################################################################

Write-Host ""
Write-Host "Exporting ACLs..."

$Folders = $TargetFolders

foreach ($Folder in $Folders)
{
    if(-not (Test-Path $Folder))
    {
        Write-Warning "Target folder not found, skipping: $Folder"
        continue
    }

    $FolderName = Split-Path $Folder -Leaf

    icacls $Folder /save `
        "$OutputFolder\$FolderName-ACL.txt" `
        /t `
        /c | Out-Null

    Get-Acl $Folder |
    Export-Clixml `
        "$OutputFolder\$FolderName-ACL.xml"
}


###########################################################################
# 3. File Count Report
###########################################################################

Write-Host ""
Write-Host "Collecting File Count..."

$FileCountResults = foreach($Folder in $Folders)
{
    if(Test-Path $Folder)
    {
        $Files = Get-ChildItem `
                    $Folder `
                    -File `
                    -Recurse `
                    -Force `
                    -ErrorAction SilentlyContinue

        [PSCustomObject]@{
            Folder = $Folder
            FileCount = $Files.Count
        }
    }
}

$FileCountResults |
Export-Csv `
"$OutputFolder\FileCount.csv" `
-NoTypeInformation


###########################################################################
# 4. File Size Distribution
###########################################################################

Write-Host ""
Write-Host "Collecting File Type Statistics..."

foreach($Folder in $Folders)
{
    if(Test-Path $Folder)
    {
        $FolderName = Split-Path $Folder -Leaf

        Get-ChildItem `
            $Folder `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
        Group-Object Extension |
        Sort-Object Count -Descending |
        Select-Object `
            Name,
            Count |
        Export-Csv `
            "$OutputFolder\$FolderName-FileTypes.csv" `
            -NoTypeInformation
    }
}


###########################################################################
# 5. Last Access / Last Modified
###########################################################################

Write-Host ""
Write-Host "Collecting File Age Information..."

foreach($Folder in $Folders)
{
    if(Test-Path $Folder)
    {
        $FolderName = Split-Path $Folder -Leaf

        Get-ChildItem `
            $Folder `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
        Select-Object `
            FullName,
            Length,
            LastAccessTime,
            LastWriteTime |
        Export-Csv `
            "$OutputFolder\$FolderName-LastAccess.csv" `
            -NoTypeInformation
    }
}


###########################################################################
# 6. Cold Data Analysis
###########################################################################

Write-Host ""
Write-Host "Analyzing Cold Data..."

$DateThreshold = (Get-Date).AddYears(-1)

$ColdFiles = foreach($Folder in $Folders)
{
    if(Test-Path $Folder)
    {
        Get-ChildItem `
            $Folder `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LastWriteTime -lt $DateThreshold
        }
    }
}

$ColdFiles |
Select-Object `
    FullName,
    Length,
    LastWriteTime |
Export-Csv `
"$OutputFolder\ColdDataReport.csv" `
-NoTypeInformation


###########################################################################
# 7. Long Path Assessment
###########################################################################

Write-Host ""
Write-Host "Scanning for Long Paths..."

$LongPathFiles = foreach($Folder in $Folders)
{
    if(Test-Path $Folder)
    {
        Get-ChildItem `
            $Folder `
            -File `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName.Length -gt 240
        }
    }
}

$LongPathFiles |
Select-Object `
    FullName,
    @{Name="PathLength";Expression={$_.FullName.Length}},
    Length,
    LastWriteTime |
Export-Csv `
"$OutputFolder\LongPathReport.csv" `
-NoTypeInformation `
-Encoding UTF8


###########################################################################
# 8. Invalid Filename Assessment
###########################################################################

Write-Host ""
Write-Host "Scanning Invalid File Names..."

$InvalidFiles = foreach($Folder in $Folders)
{
    if(Test-Path $Folder)
    {
        Get-ChildItem `
            $Folder `
            -File `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '[<>:"/\\|?*]'
        }
    }
}

$InvalidFiles |
Select-Object `
    FullName,
    Name |
Export-Csv `
"$OutputFolder\InvalidFileNames.csv" `
-NoTypeInformation


###########################################################################
# 9. Largest Files Report
###########################################################################

Write-Host ""
Write-Host "Collecting Largest Files..."

$LargestFiles = foreach($Folder in $Folders)
{
    if(Test-Path $Folder)
    {
        Get-ChildItem `
            $Folder `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue
    }
}

$LargestFiles |
Sort-Object Length -Descending |
Select-Object -First 100 `
    FullName,
    Length,
    LastWriteTime |
Export-Csv `
"$OutputFolder\LargestFiles.csv" `
-NoTypeInformation


###########################################################################
# 10. Assessment Summary
###########################################################################

Write-Host ""
Write-Host "Creating Summary Report..."

$AllFiles = $LargestFiles

$TotalSizeBytes = ($AllFiles | Measure-Object Length -Sum).Sum

if ($null -eq $TotalSizeBytes)
{
    $TotalSizeBytes = 0
}

$AllFilesCount = if ($null -eq $AllFiles) { 0 } else { @($AllFiles).Count }
$ColdFilesCount = if ($null -eq $ColdFiles) { 0 } else { @($ColdFiles).Count }
$LongPathCount = if ($null -eq $LongPathFiles) { 0 } else { @($LongPathFiles).Count }
$InvalidFileCount = if ($null -eq $InvalidFiles) { 0 } else { @($InvalidFiles).Count }

$Summary = [PSCustomObject]@{
    AssessmentDate = Get-Date
    TotalFolders   = $Folders.Count
    TotalFiles     = $AllFilesCount
    TotalSizeGB    = [Math]::Round(($TotalSizeBytes / 1GB), 2)
    ColdFiles      = $ColdFilesCount
    LongPathFiles  = $LongPathCount
    InvalidNames   = $InvalidFileCount
}

$Summary | Export-Csv `
    "$OutputFolder\Summary.csv" `
    -NoTypeInformation `
    -Encoding UTF8


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