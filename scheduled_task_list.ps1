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
