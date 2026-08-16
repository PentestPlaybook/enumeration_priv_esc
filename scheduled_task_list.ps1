# Extract executable names from scheduled tasks' "Task To Run:" lines.
function Extract-ExecutableNamesFromTasks {
    $outputDirectory = Join-Path $env:USERPROFILE "output"
    $outputFilePath  = Join-Path $outputDirectory "scheduled_executables.txt"

    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }
    # Start clean each run.
    Set-Content -Path $outputFilePath -Value $null

    $tasks = schtasks /query /fo LIST /v | Select-String -Pattern "Task To Run:"

    foreach ($line in $tasks) {
        $taskPath = ($line -replace "Task To Run:\s*", "").Trim()
        if ($taskPath -eq "") { continue }

        $exeName = $null

        # Case 1: quoted path -> take the executable inside the quotes.
        if ($taskPath -match '^"([^"]+)"') {
            $exeName = Split-Path $matches[1] -Leaf
        }
        # Case 2: an .exe anywhere, possibly followed by args -> grab up to and including .exe.
        elseif ($taskPath -match '([^\\/:*?"<>|\r\n]+\.exe)') {
            $exeName = $matches[1]
        }
        # Case 3: rundll32/COM style "something.dll,Entry" -> record the dll+entry as-is.
        elseif ($taskPath -match '([^\\/]+\.dll,[^\s]+)') {
            $exeName = $matches[1]
        }
        # Otherwise: not a resolvable executable (e.g. "source LogonIdleTask") -> skip.
        else {
            continue
        }

        if ($exeName) {
            Add-Content -Path $outputFilePath -Value $exeName
        }
    }

    Write-Output "Executable file names have been saved to $outputFilePath"
}

Extract-ExecutableNamesFromTasks
