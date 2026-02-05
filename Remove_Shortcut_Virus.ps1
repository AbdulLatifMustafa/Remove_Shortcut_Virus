
# Shortcut Virus Removal Tool for USB Drives


# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "This script requires administrator privileges." -ForegroundColor Red
    Write-Host "Please run this script as administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit
}


$host.UI.RawUI.BackgroundColor = "Black"
Clear-Host


Write-Host "=============================================" -ForegroundColor Green


Write-Host "     Shortcut Virus Removal Tool for USB     " -ForegroundColor Yellow


Write-Host "         By abdullatifmustafa                " -ForegroundColor Cyan

Write-Host "Website: https://abdullatifmustafa.netlify.app/" -ForegroundColor Blue



Write-Host "=============================================" -ForegroundColor Green


# Get all connected removable drives
Write-Host "Scanning for USB drives..." -ForegroundColor Yellow

# Simple approach using Get-Volume with debugging
try {
    Write-Host "Step 1: Getting all volumes..." -ForegroundColor Cyan
    $allVolumes = Get-Volume
    Write-Host "Found $($allVolumes.Count) total volumes" -ForegroundColor Cyan

    Write-Host "Step 2: Filtering for removable volumes..." -ForegroundColor Cyan
    $volumes = $allVolumes | Where-Object {$_.DriveType -eq 'Removable'}
    Write-Host "Found $($volumes.Count) removable volumes" -ForegroundColor Cyan

    if ($volumes -ne $null -and $volumes.Count -gt 0) {
        $drives = @()
        foreach ($volume in $volumes) {
            Write-Host "Processing volume: $($volume.DriveLetter) - $($volume.FileSystemLabel)" -ForegroundColor Cyan
            if ($volume.DriveLetter -ne $null) {
                $driveLetter = $volume.DriveLetter + ":"
                try {
                    $diskInfo = Get-PSDrive -Name $volume.DriveLetter
                    if ($diskInfo -ne $null) {
                        # Create a custom object to match the expected format
                        $driveObj = New-Object PSObject -Property @{
                            DeviceID = $driveLetter
                            VolumeName = $volume.FileSystemLabel
                            DriveType = 2
                            Size = $volume.Size
                            FreeSpace = $volume.SizeRemaining
                        }
                        $drives += $driveObj
                        Write-Host "Added drive: $driveLetter" -ForegroundColor Green
                    }
                    else {
                        Write-Host "Could not get PSDrive info for $($volume.DriveLetter)" -ForegroundColor Yellow
                    }
                }
                catch {
                    Write-Host "Error getting PSDrive for $($volume.DriveLetter): $_" -ForegroundColor Red
                }
            }
            else {
                Write-Host "Volume has no drive letter" -ForegroundColor Yellow
            }
        }
        Write-Host "Final drive count: $($drives.Count)" -ForegroundColor Green
    }
    else {
        Write-Host "No removable volumes found" -ForegroundColor Yellow
        $drives = $null
    }
}
catch {
    Write-Host "Error detecting USB drives: $_" -ForegroundColor Red
    $drives = $null
}

# Try alternative method if no drives found
if ($drives -eq $null -or $drives.Count -eq 0) {
    Write-Host "Trying alternative detection method..." -ForegroundColor Yellow
    try {
        # Try using WMI with different approach
        $disks = Get-WmiObject Win32_DiskDrive | Where-Object {$_.InterfaceType -eq "USB"}

        if ($disks -ne $null -and $disks.Count -gt 0) {
            $drives = @()
            foreach ($disk in $disks) {
                # Get partitions for this disk
                $partitions = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} WHERE AssocClass = Win32_DiskDriveToDiskPartition"

                foreach ($partition in $partitions) {
                    # Get logical disks for this partition
                    $logicalDisks = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} WHERE AssocClass = Win32_LogicalDiskToPartition"

                    foreach ($logicalDisk in $logicalDisks) {
                        $driveObj = New-Object PSObject -Property @{
                            DeviceID = $logicalDisk.DeviceID
                            VolumeName = $logicalDisk.VolumeName
                            DriveType = 2
                            Size = $logicalDisk.Size
                            FreeSpace = $logicalDisk.FreeSpace
                        }
                        $drives += $driveObj
                        Write-Host "Found USB drive: $($logicalDisk.DeviceID)" -ForegroundColor Green
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Alternative method failed: $_" -ForegroundColor Red
    }
}

# Third method if still no drives found
if ($drives -eq $null -or $drives.Count -eq 0) {
    Write-Host "Trying third detection method..." -ForegroundColor Yellow
    try {
        # Use CIM approach which is more modern
        $usbDisks = Get-CimInstance -ClassName Win32_DiskDrive | Where-Object {$_.InterfaceType -eq "USB"}

        if ($usbDisks -ne $null -and $usbDisks.Count -gt 0) {
            $drives = @()
            foreach ($disk in $usbDisks) {
                Write-Host "Found USB disk: $($disk.Model)" -ForegroundColor Cyan
                $partitions = Get-CimAssociatedInstance -InputObject $disk -ResultClassName Win32_DiskPartition

                foreach ($partition in $partitions) {
                    $logicalDisks = Get-CimAssociatedInstance -InputObject $partition -ResultClassName Win32_LogicalDisk

                    foreach ($logicalDisk in $logicalDisks) {
                        $driveObj = New-Object PSObject -Property @{
                            DeviceID = $logicalDisk.DeviceID
                            VolumeName = $logicalDisk.VolumeName
                            DriveType = 2
                            Size = $logicalDisk.Size
                            FreeSpace = $logicalDisk.FreeSpace
                        }
                        $drives += $driveObj
                        Write-Host "Found USB drive: $($logicalDisk.DeviceID)" -ForegroundColor Green
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Third method failed: $_" -ForegroundColor Red
    }
}

# Fourth method using CMD if still no drives found
if ($drives -eq $null -or $drives.Count -eq 0) {
    Write-Host "Trying fourth detection method using CMD..." -ForegroundColor Yellow
    try {
        # Use WMIC command to find USB drives
        $output = cmd /c "wmic logicaldisk where drivetype=2 get deviceid,volumename,size,freespace /format:csv" 2>&1
        $lines = $output -split "`r`n"

        # Skip header line and empty lines
        $dataLines = $lines | Where-Object { $_ -notmatch "Node,DeviceID,FreeSpace,Size,VolumeName" -and $_.Trim() -ne "" }

        if ($dataLines.Count -gt 0) {
            $drives = @()
            foreach ($line in $dataLines) {
                if ($line.Trim() -ne "") {
                    $parts = $line -split ","
                    if ($parts.Count -ge 5) {
                        $deviceID = $parts[1].Trim()
                        $freeSpace = $parts[2].Trim()
                        $size = $parts[3].Trim()
                        $volumeName = $parts[4].Trim()

                        $driveObj = New-Object PSObject -Property @{
                            DeviceID = $deviceID
                            VolumeName = $volumeName
                            DriveType = 2
                            Size = $size
                            FreeSpace = $freeSpace
                        }
                        $drives += $driveObj
                        Write-Host "Found USB drive: $deviceID" -ForegroundColor Green
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Fourth method failed: $_" -ForegroundColor Red
    }
}

# Fifth method using Get-Disk if still no drives found
if ($drives -eq $null -or $drives.Count -eq 0) {
    Write-Host "Trying fifth detection method using Get-Disk..." -ForegroundColor Yellow
    try {
        # Find all USB disks
        $usbDisks = Get-Disk | Where-Object { $_.BusType -eq "USB" }

        if ($usbDisks -ne $null -and $usbDisks.Count -gt 0) {
            $drives = @()
            foreach ($disk in $usbDisks) {
                Write-Host "Found USB disk: $($disk.FriendlyName)" -ForegroundColor Cyan
                $partitions = Get-Partition -Disk $disk.Number

                foreach ($partition in $partitions) {
                    if ($partition.DriveLetter) {
                        $driveLetter = $partition.DriveLetter + ":"
                        $volume = Get-Volume -Partition $partition

                        $driveObj = New-Object PSObject -Property @{
                            DeviceID = $driveLetter
                            VolumeName = $volume.FileSystemLabel
                            DriveType = 2
                            Size = $volume.Size
                            FreeSpace = $volume.SizeRemaining
                        }
                        $drives += $driveObj
                        Write-Host "Found USB drive: $driveLetter" -ForegroundColor Green
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Fifth method failed: $_" -ForegroundColor Red
    }
}

# Sixth method using comprehensive scan if still no drives found
if ($drives -eq $null -or $drives.Count -eq 0) {
    Write-Host "Trying sixth detection method - comprehensive scan..." -ForegroundColor Yellow
    try {
        # Get all logical disks
        $allDisks = Get-PSDrive -PSProvider FileSystem

        # Try to identify USB drives by checking their physical disk
        $drives = @()

        foreach ($disk in $allDisks) {
            if ($disk.Name -match "^[A-Z]$" -and $disk.Root) {
                Write-Host "Checking drive: $($disk.Name) ($($disk.Root))" -ForegroundColor Cyan

                # Check if it's a removable drive by checking if it's not a fixed drive
                $isRemovable = $false

                try {
                    # Try to get the volume information
                    $volume = Get-Volume -DriveLetter $disk.Name -ErrorAction SilentlyContinue

                    if ($volume) {
                        # Check if it's a removable or external drive
                        if ($volume.DriveType -eq "Removable") {
                            $isRemovable = $true
                            Write-Host "Drive $($disk.Name) identified as Removable" -ForegroundColor Green
                        }

                        # Try to get the physical disk information
                        $partition = Get-Partition -DriveLetter $disk.Name -ErrorAction SilentlyContinue
                        if ($partition) {
                            $physicalDisk = Get-Disk -Number $partition.DiskNumber -ErrorAction SilentlyContinue
                            if ($physicalDisk) {
                                if ($physicalDisk.BusType -eq "USB" -or $physicalDisk.IsRemovable -or $physicalDisk.IsSystem -eq $false) {
                                    $isRemovable = $true
                                    Write-Host "Drive $($disk.Name) identified as USB/External" -ForegroundColor Green
                                }
                            }
                        }
                    }

                    # If we think it's removable, add it to our list
                    if ($isRemovable) {
                        $driveObj = New-Object PSObject -Property @{
                            DeviceID = $disk.Name + ":"
                            VolumeName = if ($volume) { $volume.FileSystemLabel } else { "Unknown" }
                            DriveType = 2
                            Size = if ($volume) { $volume.Size } else { 0 }
                            FreeSpace = if ($volume) { $volume.SizeRemaining } else { 0 }
                        }
                        $drives += $driveObj
                        Write-Host "Added USB drive: $($disk.Name):" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Host "Error checking drive $($disk.Name): $_" -ForegroundColor Red
                }
            }
        }

        # If still no drives found, try to find any drive that might be USB
        if ($drives.Count -eq 0) {
            Write-Host "No clearly identified USB drives found. Checking all drives..." -ForegroundColor Yellow

            # Get all drives except system drives (C: typically)
            $allVolumes = Get-Volume | Where-Object { $_.DriveLetter -ne $null -and $_.DriveLetter -ne "C" }

            foreach ($volume in $allVolumes) {
                $driveLetter = $volume.DriveLetter + ":"
                Write-Host "Considering drive: $driveLetter" -ForegroundColor Cyan

                # Ask the user if this might be their USB drive
                $choice = Read-Host "Is $driveLetter your USB drive? (y/n)"
                if ($choice -eq "y" -or $choice -eq "Y") {
                    $driveObj = New-Object PSObject -Property @{
                        DeviceID = $driveLetter
                        VolumeName = $volume.FileSystemLabel
                        DriveType = 2
                        Size = $volume.Size
                        FreeSpace = $volume.SizeRemaining
                    }
                    $drives += $driveObj
                    Write-Host "Added drive: $driveLetter" -ForegroundColor Green
                }
            }
        }
    }
    catch {
        Write-Host "Sixth method failed: $_" -ForegroundColor Red
    }
}

# Final check and user guidance
if ($drives -eq $null -or $drives.Count -eq 0) {
    Write-Host "No USB drives found connected to the system!" -ForegroundColor Red
    Write-Host "Please make sure your USB drive is properly connected." -ForegroundColor Yellow
    Write-Host "Try reconnecting the USB drive or running this script as administrator." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit
}

Write-Host "Found the following USB drives:" -ForegroundColor Yellow
if ($drives -ne $null -and $drives.Count -gt 0) {
    for ($i=0; $i -lt $drives.Count; $i++) {
        $driveLabel = if ([string]::IsNullOrEmpty($drives[$i].VolumeName)) { "No Label" } else { $drives[$i].VolumeName }
        Write-Host ($i+1).ToString() + ". " + $drives[$i].DeviceID + " (" + $driveLabel + ")" -ForegroundColor White
    }
} else {
    Write-Host "No USB drives found." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit
}

$validSelection = $false
do {
    $selection = Read-Host "Select the number of the USB drive you want to scan"

    # Try to convert input to integer
    try {
        $selection = [int]$selection
        if ($selection -ge 1 -and $selection -le $drives.Count) {
            $validSelection = $true
        } else {
            Write-Host "Invalid selection! Please enter a number between 1 and" $drives.Count -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Invalid input! Please enter a valid number." -ForegroundColor Red
    }
} until ($validSelection)

$selectedDrive = $drives[$selection-1].DeviceID
Write-Host "Selected USB drive: " $selectedDrive -ForegroundColor Green

# Change to the selected USB drive
Set-Location $selectedDrive

# Main menu
do {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Shortcut Virus Removal Tool - Main Menu" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Current Drive: " $selectedDrive -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Show hidden files and folders" -ForegroundColor White
    Write-Host "2. Scan and remove virus files" -ForegroundColor White
    Write-Host "3. Scan and remove virus folders" -ForegroundColor White
    Write-Host "4. Check registry for virus entries" -ForegroundColor White
    Write-Host "5. Repair USB drive (Full scan and repair)" -ForegroundColor White
    Write-Host "6. Exit" -ForegroundColor White
    Write-Host ""

    $choice = Read-Host "Enter your choice (1-6)"

    switch ($choice) {
        1 {
            # Show hidden files and folders
            Write-Host "Showing hidden files and folders..." -ForegroundColor Yellow
            cmd /c "attrib -s -h -r /s /d"
            Write-Host "All files and folders have been unhidden." -ForegroundColor Green
            Read-Host "Press Enter to continue"
        }

        2 {
            # Scan and remove virus files
            $virusFiles = @(
                "*.lnk",
                "*.vbs",
                "*.bat",
                "autorun.inf",
                "desktop.ini",
                "recycler.exe",
                "system.exe",
                "heap41a"
            )

            Write-Host "Scanning for virus files..." -ForegroundColor Yellow

            foreach ($file in $virusFiles) {
                $foundFiles = Get-ChildItem -Path $selectedDrive -Name -Recurse -Include $file -ErrorAction SilentlyContinue
                if ($foundFiles) {
                    Write-Host "Found virus files: " $file -ForegroundColor Red
                    foreach ($foundFile in $foundFiles) {
                        try {
                            Remove-Item -Path "$selectedDrive\$foundFile" -Force -Recurse -ErrorAction Stop
                            Write-Host "Deleted: $foundFile" -ForegroundColor Green
                        }
                        catch {
                            Write-Host "Failed to delete: $foundFile" -ForegroundColor Red
                            Write-Host "Reason: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                }
            }

            Write-Host "Virus file scan completed." -ForegroundColor Green
            Read-Host "Press Enter to continue"
        }

        3 {
            # Scan and remove virus folders
            $virusFolders = @(
                "RECYCLER",
                "System Volume Information",
                "heap41a"
            )

            Write-Host "Scanning for virus folders..." -ForegroundColor Yellow

            foreach ($folder in $virusFolders) {
                $foundFolders = Get-ChildItem -Path $selectedDrive -Directory -Recurse -Include $folder -ErrorAction SilentlyContinue
                if ($foundFolders) {
                    Write-Host "Found virus folders: " $folder -ForegroundColor Red
                    foreach ($foundFolder in $foundFolders) {
                        try {
                            Remove-Item -Path $foundFolder.FullName -Force -Recurse -ErrorAction Stop
                            Write-Host "Deleted folder: $($foundFolder.FullName)" -ForegroundColor Green
                        }
                        catch {
                            Write-Host "Failed to delete folder: $($foundFolder.FullName)" -ForegroundColor Red
                            Write-Host "Reason: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                }
            }

            Write-Host "Virus folder scan completed." -ForegroundColor Green
            Read-Host "Press Enter to continue"
        }

        4 {
            # Check registry for virus entries
            Write-Host "Scanning registry for virus entries..." -ForegroundColor Yellow

            $registryPaths = @(
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
            )

            foreach ($path in $registryPaths) {
                try {
                    $entries = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                    if ($entries) {
                        foreach ($entry in $entries.PSObject.Properties) {
                            if ($entry.Name -ne "PSPath" -and $entry.Name -ne "PSParentPath" -and $entry.Name -ne "PSChildName" -and $entry.Name -ne "PSDrive") {
                                if ($entry.Value -like "*.vbs" -or $entry.Value -like "*.bat" -or $entry.Value -like "*wscript.exe*") {
                                    Write-Host "Found suspicious registry entry: $($entry.Name) = $($entry.Value)" -ForegroundColor Red
                                    $choice = Read-Host "Do you want to delete this entry? (y/n)"
                                    if ($choice -eq "y" -or $choice -eq "Y") {
                                        Remove-ItemProperty -Path $path -Name $entry.Name -Force
                                        Write-Host "Entry deleted successfully" -ForegroundColor Green
                                    }
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Host "Error scanning registry: $($_.Exception.Message)" -ForegroundColor Red
                }
            }

            Write-Host "Registry scan completed." -ForegroundColor Green
            Read-Host "Press Enter to continue"
        }

        5 {
            # Repair USB drive (Full scan and repair)
            Write-Host "Starting full USB drive repair process..." -ForegroundColor Yellow

            # Step 1: Show all hidden files
            Write-Host "Step 1: Showing all hidden files..." -ForegroundColor Yellow
            cmd /c "attrib -s -h -r /s /d"

            # Step 2: Remove virus files
            Write-Host "Step 2: Removing virus files..." -ForegroundColor Yellow
            $virusFiles = @(
                "*.lnk",
                "*.vbs",
                "*.bat",
                "autorun.inf",
                "desktop.ini",
                "recycler.exe",
                "system.exe",
                "heap41a"
            )

            foreach ($file in $virusFiles) {
                $foundFiles = Get-ChildItem -Path $selectedDrive -Name -Recurse -Include $file -ErrorAction SilentlyContinue
                if ($foundFiles) {
                    foreach ($foundFile in $foundFiles) {
                        try {
                            Remove-Item -Path "$selectedDrive\$foundFile" -Force -Recurse -ErrorAction Stop
                            Write-Host "Deleted: $foundFile" -ForegroundColor Green
                        }
                        catch {
                            Write-Host "Failed to delete: $foundFile" -ForegroundColor Red
                        }
                    }
                }
            }

            # Step 3: Remove virus folders
            Write-Host "Step 3: Removing virus folders..." -ForegroundColor Yellow
            $virusFolders = @(
                "RECYCLER",
                "System Volume Information",
                "heap41a"
            )

            foreach ($folder in $virusFolders) {
                $foundFolders = Get-ChildItem -Path $selectedDrive -Directory -Recurse -Include $folder -ErrorAction SilentlyContinue
                if ($foundFolders) {
                    foreach ($foundFolder in $foundFolders) {
                        try {
                            Remove-Item -Path $foundFolder.FullName -Force -Recurse -ErrorAction Stop
                            Write-Host "Deleted folder: $($foundFolder.FullName)" -ForegroundColor Green
                        }
                        catch {
                            Write-Host "Failed to delete folder: $($foundFolder.FullName)" -ForegroundColor Red
                        }
                    }
                }
            }

            # Step 4: Check for remaining shortcuts
            Write-Host "Step 4: Checking for remaining shortcuts..." -ForegroundColor Yellow
            $shortcutFiles = Get-ChildItem -Path $selectedDrive -Recurse -Include "*.lnk" -ErrorAction SilentlyContinue
            if ($shortcutFiles.Count -gt 0) {
                Write-Host "Found " $shortcutFiles.Count " shortcut files on the USB drive." -ForegroundColor Yellow
                Write-Host "These might be legitimate shortcuts or remnants of the virus." -ForegroundColor Yellow
                $choice = Read-Host "Do you want to delete all remaining shortcut files? (y/n)"
                if ($choice -eq "y" -or $choice -eq "Y") {
                    foreach ($shortcut in $shortcutFiles) {
                        try {
                            Remove-Item -Path $shortcut.FullName -Force -ErrorAction Stop
                            Write-Host "Deleted: $($shortcut.FullName)" -ForegroundColor Green
                        }
                        catch {
                            Write-Host "Failed to delete: $($shortcut.FullName)" -ForegroundColor Red
                        }
                    }
                }
            }

            # Step 5: Final check for hidden files
            Write-Host "Step 5: Final check for hidden files..." -ForegroundColor Yellow
            cmd /c "attrib -s -h -r /s /d"

            $hiddenFiles = Get-ChildItem -Path $selectedDrive -Recurse -Hidden -ErrorAction SilentlyContinue
            if ($hiddenFiles.Count -gt 0) {
                Write-Host "Found " $hiddenFiles.Count " hidden files after attempting to unhide them." -ForegroundColor Yellow
                foreach ($file in $hiddenFiles) {
                    Write-Host "Hidden file: $($file.FullName)" -ForegroundColor White
                }
            }

            Write-Host "USB drive repair process completed." -ForegroundColor Green
            Read-Host "Press Enter to continue"
        }

        6 {
            Write-Host "Exiting the program..." -ForegroundColor Yellow
            break
        }

        default {
            Write-Host "Invalid choice! Please enter a number between 1 and 6." -ForegroundColor Red
            Read-Host "Press Enter to continue"
        }
    }
} while ($choice -ne 6)

Write-Host "========================================" -ForegroundColor Green
Write-Host "      Thank you for using this tool!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

