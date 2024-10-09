function Check-IfExecutableRunsAutomatically {
    param (
        [string]$filePath
    )

    $runsAutomatically = $false

    Write-Output "Checking if $filePath is in scheduled tasks..." | Out-Host
    try {
        $scheduledTasks = Get-ScheduledTask | Where-Object { $_.Actions.Execute -match [regex]::Escape($filePath) }
        if ($scheduledTasks) {
            Write-Output "Found in scheduled tasks: $filePath" | Out-Host
            $runsAutomatically = $true
        }
    } catch {
        Write-Output "Error while checking scheduled tasks: $_.Exception.Message" | Out-Host
    }

    Write-Output "Checking if $filePath is in services..." | Out-Host
    try {
        $services = Get-CimInstance Win32_Service | Where-Object { $_.PathName -match [regex]::Escape($filePath) }
        if ($services) {
            Write-Output "Found in services: $filePath" | Out-Host
            if ($services.StartMode -eq "Auto") {
                Write-Output "Service is set to start automatically: $filePath" | Out-Host
                $runsAutomatically = $true
            }
        }
    } catch {
        Write-Output "Error while checking services: $_.Exception.Message" | Out-Host
    }

    Write-Output "Checking if $filePath is in startup programs..." | Out-Host
    try {
        $startupPrograms = Get-CimInstance Win32_StartupCommand | Where-Object { $_.Command -match [regex]::Escape($filePath) }
        if ($startupPrograms) {
            Write-Output "Found in startup programs: $filePath" | Out-Host
            $runsAutomatically = $true
        }
    } catch {
        Write-Output "Error while checking startup programs: $_.Exception.Message" | Out-Host
    }

    Write-Output "Runs automatically: $runsAutomatically" | Out-Host
    return $runsAutomatically
}

# Example usage
$filePath = "C:\TEMP\backup.exe"
Check-IfExecutableRunsAutomatically -filePath $filePaths


########## EXECUTE THIS SCRIPT TO FIND FILES THAT RUN AUTOMATICALLY ########################
# PS C:\Users\yoshi\Documents> .\m.ps1
# Checking if  is in scheduled tasks...
# Found in scheduled tasks:
# Checking if  is in services...
# Found in services:
# Service is set to start automatically:
# Checking if  is in startup programs...
# Found in startup programs:
# Runs automatically: True
# True
