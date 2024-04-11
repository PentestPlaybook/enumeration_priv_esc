# Define the path to the file containing the PowerUp output
$filePath = ".\PowerUpOutput.txt"

# Read the content of the file
$fileContent = Get-Content $filePath

# Initialize an empty array to hold services info
$services = @()

# Temporary hashtable to store individual service info
$tempService = @{}

# Process each line in the file
foreach ($line in $fileContent) {
    if ($line -match "ServiceName\s+:\s+(.+)") {
        # If we encounter a new service, and tempService is not empty, add it to services and reset tempService
        if ($tempService.Count -gt 0) {
            $services += $tempService
            $tempService = @{}
        }
        $tempService["ServiceName"] = $matches[1].Trim()
    }
    elseif ($line -match "Path\s+:\s+(.+)") {
        $tempService["Path"] = $matches[1].Trim()
    }
    elseif ($line -match "ModifiableFile\s+:\s+(.+)") {
        $tempService["ModifiableFile"] = $matches[1].Trim()
    }
    elseif ($line -match "CanRestart\s+:\s+(.+)") {
        $tempService["CanRestart"] = $matches[1].Trim()
    }
}

# Add the last service to the array
if ($tempService.Count -gt 0) {
    $services += $tempService
}

# Filter services based on criteria: ModifiableFile is not C:\, and CanRestart is True
$vulnerableServices = $services | Where-Object {
    $_.ModifiableFile -ne 'C:\' -and
    $_.CanRestart -eq 'True'
}

# Output vulnerable services
foreach ($service in $vulnerableServices) {
    Write-Output "Vulnerable Service Found: $($service.ServiceName) with Modifiable Path: $($service.ModifiableFile)"
}
