<#
    Find scheduled-task executables writable by the current user.
    Writable SYSTEM/admin task binaries are a privesc path: replace the binary,
    wait for (or trigger) the task, and your code runs in the task's context.
#>

# Work in a temp dir so we don't litter the current directory, and so cleanup is trivial.
$workDir = Join-Path $env:TEMP ("wtask_" + [guid]::NewGuid().ToString("N").Substring(0,8))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

$inputFile   = Join-Path $workDir "input.txt"
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "[*] Current user : $currentUser"
Write-Host "[*] Working dir  : $workDir`n"

# 1. Dump all scheduled tasks.
schtasks /query /fo LIST /v > $inputFile 2>$null

# 2. Extract executable paths from each "Task To Run:" line.
$executablePaths = New-Object System.Collections.Generic.HashSet[string]

foreach ($line in Get-Content -Path $inputFile) {
    if ($line -match "Task To Run:\s*(.+)") {
        $raw = $matches[1].Trim()

        # Expand env vars (%windir%, etc.).
        $raw = [System.Environment]::ExpandEnvironmentVariables($raw)

        # Skip COM-handler tasks — they have no file path.
        if ($raw -match "^COM handler" -or $raw -eq "") { continue }

        # Pull the executable out, handling quoted paths and trailing arguments.
        if ($raw -match '^"([^"]+)"') {
            # Quoted path: take what's inside the quotes.
            $exePath = $matches[1]
        }
        else {
            # Unquoted: cut at the first arg that starts with / or - (best effort),
            # otherwise take the first whitespace-delimited token.
            $exePath = $raw
            if ($exePath -match '^(.+?\.exe)\b') { $exePath = $matches[1] }
            else { $exePath = ($raw -split '\s+')[0] }
        }

        $exePath = $exePath.Trim()
        if ($exePath -ne "" -and (Test-Path -LiteralPath $exePath -PathType Leaf)) {
            [void]$executablePaths.Add($exePath)
        }
    }
}

if ($executablePaths.Count -eq 0) {
    Write-Host "[-] No resolvable task executables found."
    Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
    return
}

Write-Host "[*] Resolved $($executablePaths.Count) unique task executable(s). Checking permissions...`n"

# 3. Check each binary's ACL for a write-capable entry for the current user or its groups.
#    We match (M)odify, (F)ull, (W)rite, and generic-all/write on the identities in the user's token.
$identity   = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$identityRefs = @($identity.Name)
$identityRefs += $identity.Groups | ForEach-Object {
    try { $_.Translate([System.Security.Principal.NTAccount]).Value } catch { $null }
} | Where-Object { $_ }

$writableHits = @()

foreach ($path in $executablePaths) {
    $acl = icacls $path 2>$null
    foreach ($aclLine in $acl) {
        foreach ($ref in $identityRefs) {
            if ($aclLine -like "*$ref*" -and $aclLine -match "\((?:[^)]*[MFW][^)]*)\)") {
                # Extract the permission token(s) shown for readability.
                $perm = ([regex]::Matches($aclLine, "\(([^)]+)\)") | ForEach-Object { $_.Groups[1].Value }) -join ""
                $writableHits += [pscustomobject]@{
                    Path       = $path
                    Identity   = $ref
                    Permission = $perm
                }
            }
        }
    }
}

# 4. Report, deduped.
if ($writableHits.Count -eq 0) {
    Write-Host "[-] No task executables are writable by the current user or its groups."
}
else {
    Write-Host "[+] Writable task executables found:`n"
    $writableHits |
        Sort-Object Path, Identity -Unique |
        Format-Table -AutoSize Path, Identity, Permission
    Write-Host "`n[!] To exploit: back up the original, replace it with your payload, then wait for or trigger the task."
}

# 5. Clean up — always, and without erroring.
Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
