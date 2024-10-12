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
        [string]$directory
    )

    try {
        Get-ChildItem -Path $directory -Recurse -Filter *.exe -ErrorAction SilentlyContinue | ForEach-Object {
            $permissions = Check-FilePermissions $_.FullName

            # Only print output if the file is executable and can be overwritten
            if ($permissions.IsExecutable -and $permissions.CanBeOverwritten) {
                Write-Output "Vulnerable executable found: $($_.FullName)"
            }
        }
    } catch {
        Write-Output "Error while searching in directory: $directory - $($_.Exception.Message)"
    }
}

Write-Output "Checking all executables in C:\ for vulnerabilities..."
Check-Executables -directory "C:\"

##########################################################################################################################################
########## EXECUTE THIS SCRIPT TO FIND EXECUTABLES THAT CAN BE OVERWRITTEN ###############################################################
# PS C:\Users\yoshi\Documents> .\overwrite.ps1
# Checking all executables in C:\ for vulnerabilities...
# Vulnerable executable found: C:\TEMP\backup.exe
# Vulnerable executable found: C:\TEMP\met.exe

# To remove permissions:
# PS C:\Users\yoshi\Documents> icacls C:\TEMP\met.exe /inheritance:d
# processed file: C:\TEMP\met.exe
# Successfully processed 1 files; Failed processing 0 files

# PS C:\Users\yoshi\Documents> icacls C:\TEMP\met.exe /remove "MEDTECH\yoshi"
# processed file: C:\TEMP\met.exe
# Successfully processed 1 files; Failed processing 0 files

# PS C:\Users\yoshi\Documents> icacls C:\TEMP\met.exe
# C:\TEMP\met.exe MEDTECH\yoshi:(R)
                # NT AUTHORITY\SYSTEM:(I)(F)
                # BUILTIN\Administrators:(I)(F)
                # BUILTIN\Users:(I)(RX)
                # MEDTECH\yoshi:(I)(F)

# ONCE YOU REMOVE THE PERMISSIONS FOR THE CURRENT USER, RUN THE SCRIPT AGAIN TO CONFIRM THE EXECUTABLE DOESN'T GET FLAGGED #
# TO GRANT FULL PERMISSIONS TO YOURSELF AGAIN, RUN THE FOLLOWING COMMAND #
# PS C:\Users\yoshi\Documents> icacls C:\TEMP\met.exe /grant "MEDTECH\yoshi:(R)"
# processed file: C:\TEMP\met.exe
# Successfully processed 1 files; Failed processing 0 files
# PS C:\Users\yoshi\Documents> icacls C:\TEMP\met.exe
# C:\TEMP\met.exe MEDTECH\yoshi:(R)
                # NT AUTHORITY\SYSTEM:(F)
                # BUILTIN\Administrators:(F)
                # BUILTIN\Users:(RX)
##########################################################################################################################################
