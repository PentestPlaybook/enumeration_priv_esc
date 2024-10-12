# FIND MATCHES BETWEEN 2 .TXT FILES WITH COLOR:
# Define the file paths
$vulnerableFile = "C:\Users\steve\Documents\vulnerable_executables.txt"
$scheduledFile = "C:\Users\steve\output\scheduled_executables.txt"

# Read the contents of both files, trim any extra whitespace, and remove empty lines
$vulnerableExecutables = Get-Content $vulnerableFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
$scheduledExecutables = Get-Content $scheduledFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

# Find matching lines using case-insensitive comparison
$matchingExecutables = $vulnerableExecutables | Where-Object { $_ -in $scheduledExecutables -or $_.ToLower() -in $scheduledExecutables.ToLower() }

# Print the matching lines with color
if ($matchingExecutables) {
    # Print the message in Yellow
    Write-Host "Matching executables found:" -ForegroundColor Yellow

    # Print each matching executable in Green
    $matchingExecutables | ForEach-Object { Write-Host $_ -ForegroundColor Green }
} else {
    Write-Host "No matching executables found." -ForegroundColor Red
}


# PRINT A LIST OF SCHEDULED TASKS:
# Function to extract the .exe file names from the Task to Run lines and save to a file
function Extract-ExecutableNamesFromTasks {
    # Define the output file path
    $outputDirectory = "C:\Users\steve\output"  # Use a valid existing directory
    $outputFilePath = "$outputDirectory\scheduled_executables.txt"

    # Create the directory if it doesn't exist
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Run schtasks command and retrieve output
    $tasks = schtasks /query /fo LIST /v | Select-String -Pattern "Task To Run:"

    # Iterate through the matching lines
    foreach ($line in $tasks) {
        # Extract the path after "Task To Run:"
        $taskPath = $line -replace "Task To Run:\s*", ""

        # Validate the task path by checking for illegal characters
        try {
            $isValidPath = [System.IO.Path]::GetFullPath($taskPath) -ne $null
        } catch {
            Write-Host "Skipping invalid path: $taskPath" -ForegroundColor Red
            continue
        }

        # If the line contains a .exe file, extract the filename
        if ($taskPath -like "*.exe*") {
            # Extract the .exe file name by splitting on the last backslash
            $exeFileName = [System.IO.Path]::GetFileName($taskPath)

            # Save the .exe file name to the output file
            Add-Content -Path $outputFilePath -Value $exeFileName
        }
    }

    Write-Output "Executable file names have been saved to $outputFilePath"
}

# Run the function
Extract-ExecutableNamesFromTasks


# Print a List of Modifiable Executables

function Check-FilePermissions {
    param (
        [string]$filePath
    )

    try {
        $acl = Get-Acl $filePath -ErrorAction Stop
    } catch {
        return @{ IsExecutable = $false; CanBeOverwritten = $false }
    }

    $isExecutable = $false
    $canBeOverwritten = $false

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $adminGroups = @("SYSTEM", "Administrators")

    $acl.Access | ForEach-Object {
        # Check if file is executable by SYSTEM or Administrators
        if ($_.IdentityReference -match "SYSTEM|Administrators" -and $_.FileSystemRights -match "FullControl|Modify|ExecuteFile") {
            $isExecutable = $true
        }

        # Check if the current user has write/modify permissions
        if ($_.IdentityReference -eq $currentUser -and $_.FileSystemRights -match "Write|Modify|FullControl") {
            $canBeOverwritten = $true
        }

        # Check if the Users group has write/modify permissions
        if ($_.IdentityReference -match "BUILTIN\\Users" -and $_.FileSystemRights -match "Write|Modify|FullControl") {
            $canBeOverwritten = $true
        }

        # Check if the Authenticated Users group has write/modify permissions
        if ($_.IdentityReference -match "NT AUTHORITY\\Authenticated Users" -and $_.FileSystemRights -match "Write|Modify|FullControl") {
            $canBeOverwritten = $true
        }

    }

    return @{ IsExecutable = $isExecutable; CanBeOverwritten = $canBeOverwritten } 
}

function Check-Executables {
    param (
        [string]$directory,
        [string]$outputFile
    )

    try {
        Get-ChildItem -Path $directory -Recurse -Filter *.exe -ErrorAction SilentlyContinue | ForEach-Object {
            $permissions = Check-FilePermissions $_.FullName

            # Only print output if the file is executable and can be overwritten
            if ($permissions.IsExecutable -and $permissions.CanBeOverwritten) {
                Write-Host "Vulnerable executable found: $($_.FullName)" -ForegroundColor Yellow
                
                # Extract the executable file name after the last '\'
                $fileName = $_.FullName.Split('\')[-1]
                
                # Write the file name to the output .txt file
                Add-Content -Path $outputFile -Value $fileName
            }
        }
    } catch {
        Write-Host "Error while searching in directory: $directory - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Define the output .txt file path in a user folder
$outputFile = "$env:USERPROFILE\Documents\vulnerable_executables.txt"

# Ensure the output file is cleared or created before appending
Clear-Content -Path $outputFile -ErrorAction SilentlyContinue

Write-Host "Checking all executables in C:\ for vulnerabilities..." -ForegroundColor Yellow
Check-Executables -directory "C:\" -outputFile $outputFile

Write-Host "Vulnerable executables saved to $outputFile." -ForegroundColor Green
