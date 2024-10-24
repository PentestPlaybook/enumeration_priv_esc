# Define the base directory to start the search (excluding System32)
$baseDir = "C:\"

# Get all directories except System32
$directories = Get-ChildItem -Path $baseDir -Directory -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike "*system32*" }

# Loop through directories to find ones with both .exe and .log files
foreach ($dir in $directories) {
    $exeFiles = Get-ChildItem -Path $dir.FullName -Filter *.exe -ErrorAction SilentlyContinue
    $logFiles = Get-ChildItem -Path $dir.FullName -Filter *.log -ErrorAction SilentlyContinue
    
    if ($exeFiles -and $logFiles) {
        # Flag directories containing both .exe and .log files
        Write-Host "Found .exe and .log files in directory: $($dir.FullName)"
    }
}
