# USB Shortcut Virus Removal Tool

A comprehensive PowerShell script designed to detect and remove shortcut viruses from USB drives and external storage devices.

## Features

- **Multi-method USB Detection**: Uses 6 different approaches to identify connected USB drives
- **Hidden File Recovery**: Reveals and restores hidden files and folders
- **Virus File Removal**: Scans and deletes malicious files (.lnk, .vbs, .bat, etc.)
- **Virus Folder Cleanup**: Removes infected directories and system remnants
- **Registry Scan**: Checks and cleans suspicious registry entries
- **Full Repair Mode**: Complete scanning and restoration process

## How It Works

The tool systematically:
1. Detects all connected USB/removable drives using multiple detection methods
2. Allows user selection of target drive
3. Provides menu-driven options for different cleanup operations
4. Safely removes virus components while preserving legitimate data

## Usage

1. Run the script as Administrator
2. Select your infected USB drive from the detected list
3. Choose from the main menu options:
   - Show hidden files
   - Scan and remove virus files
   - Scan and remove virus folders
   - Check registry entries
   - Full repair scan
   - Exit

## Requirements

- Windows OS
- PowerShell execution permissions
- Administrator privileges

## Safety Notes

- Always backup important data before running
- The script only affects the selected USB drive
- Legitimate shortcut files may be removed during full repair
- Registry modifications require confirmation

## Author

Developed by abdullatifmustafa  
Website: https://abdullatifmustafa.netlify.app/