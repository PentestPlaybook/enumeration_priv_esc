# Clean up previous output files
Remove-Item "services_output.txt" -ErrorAction SilentlyContinue
Remove-Item "permissions_output.txt" -ErrorAction SilentlyContinue
Remove-Item "icacls_output.txt" -ErrorAction SilentlyContinue
Remove-Item "running_services_output.txt" -ErrorAction SilentlyContinue

# Initialize permissions_output.txt to ensure it exists even if empty
"" | Out-File "permissions_output.txt"

# Get all running services and their executable paths
$services = Get-CimInstance -ClassName win32_service | Where-Object {$_.State -eq 'Running'} | Select-Object Name, PathName

# Output the running services to a file
$services | Out-File -FilePath "running_services_output.txt"

foreach ($service in $services) {
    try {
        # Extract the executable path, accurately handling paths with or without quotes and parameters
        $executablePath = if ($service.PathName -match '^"([^"]+)"') { $matches[1] } else { $service.PathName -split ' ' | Select-Object -First 1 }

        # Skip if the path is empty or null
        if ([string]::IsNullOrWhiteSpace($executablePath)) {
            continue
        }

        # Attempt to resolve path and catch permission errors gracefully
        $resolvedPath = Resolve-Path $executablePath -ErrorAction SilentlyContinue
        if (-not $resolvedPath) {
            "Unable to access path or path does not exist for service: $($service.Name), Path: $executablePath" | Out-File -Append -FilePath "services_output.txt"
            continue
        }

        $icaclsOutput = icacls $resolvedPath.Path
        # Write the icacls output for each resolved path to icacls_output.txt
        $icaclsOutput | Out-File -Append -FilePath "icacls_output.txt"

        # Extract and display the specific permissions of interest (Full or Modify) for the Users group
        if ($icaclsOutput -match 'Users.*?\((F|M)\)') {
            $permissionsMatch = $matches[0]
            $permissionsDetail = if ($matches[1] -eq 'F') {'Full'} else {'Modify'}
            "Service: $($service.Name), Path: $executablePath, Permissions for Users group: $permissionsDetail" | Out-File -Append -FilePath "permissions_output.txt"
        }
    } catch {
        # Generic catch for any other unforeseen errors
        "An error occurred with service: $($service.Name), Error: $_" | Out-File -Append -FilePath "services_output.txt"
    }
}

# Optionally, display the contents of the permissions_output.txt in the terminal
Get-Content "permissions_output.txt" | ForEach-Object { Write-Host $_ }
