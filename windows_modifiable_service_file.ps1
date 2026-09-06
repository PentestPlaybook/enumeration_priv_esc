# windows_modifiable_service_file.ps1
# Parses PowerUp's Get-ModifiableServiceFile output, then enriches each service
# with LIVE data (StartMode/State + real file ACL) and reports honest
# exploitability instead of just "binary is writable".

$filePath = ".\PowerUpOutput.txt"

if (-not (Test-Path $filePath)) {
    Write-Output "[!] $filePath not found. Run: Get-ModifiableServiceFile > PowerUpOutput.txt"
    return
}

$fileContent = Get-Content $filePath

# --- Parse PowerUp output into service objects ---
$services   = @()
$tempService = @{}

foreach ($line in $fileContent) {
    if ($line -match "ServiceName\s+:\s+(.+)") {
        if ($tempService.Count -gt 0) { $services += $tempService; $tempService = @{} }
        $tempService["ServiceName"] = $matches[1].Trim()
    }
    elseif ($line -match "^Path\s+:\s+(.+)")           { $tempService["Path"]           = $matches[1].Trim() }
    elseif ($line -match "ModifiableFile\s+:\s+(.+)")  { $tempService["ModifiableFile"] = $matches[1].Trim() }
    elseif ($line -match "CanRestart\s+:\s+(.+)")      { $tempService["CanRestart"]     = $matches[1].Trim() }
}
if ($tempService.Count -gt 0) { $services += $tempService }

# Keep only services whose flagged file is an actual binary (drop the 'C:\' drive-root noise),
# and de-duplicate by service name (PowerUp lists some services twice).
$services = $services |
    Where-Object { $_.ModifiableFile -and $_.ModifiableFile -ne 'C:\' } |
    Group-Object ServiceName | ForEach-Object { $_.Group[0] }

if (-not $services) {
    Write-Output "No services with a modifiable binary found."
    return
}

# --- Work out which identities the current user effectively is ---
$me         = (whoami)
$myGroups   = @('BUILTIN\Users','NT AUTHORITY\Authenticated Users','Everyone', $me)

# Helper: given a file path, return what the current user can do to it.
# Returns one of: 'Replace' (can rename+drop), 'Overwrite' (can only overwrite contents), 'None'
function Get-MyFileCapability($path) {
    if (-not (Test-Path $path)) { return 'None' }
    try { $acl = Get-Acl $path } catch { return 'None' }

    [int]$rights = 0
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if ($myGroups -contains $ace.IdentityReference.Value) {
            $rights = $rights -bor [int]$ace.FileSystemRights
        }
    }

    $DELETE   = 0x00010000
    $FULL     = 0x001F01FF
    $MODIFY   = 0x000301BF
    $WRITEDATA= 0x00000002
    $APPEND   = 0x00000004

    if ( ($rights -band $FULL)  -eq $FULL  -or
         ($rights -band $MODIFY) -eq $MODIFY -or
         ($rights -band $DELETE) ) { return 'Replace' }        # has Delete -> can move/rename+replace
    if ( $rights -band ($WRITEDATA -bor $APPEND) ) { return 'Overwrite' }  # can only overwrite in place
    return 'None'
}

# --- Enrich each service with live state and report a verdict ---
"{0,-16} {1,-9} {2,-8} {3,-14} {4}" -f 'SERVICE','STATE','START','FILE-ACCESS','VERDICT'
"{0,-16} {1,-9} {2,-8} {3,-14} {4}" -f '-------','-----','-----','-----------','-------'

foreach ($svc in $services) {
    $name = $svc.ServiceName
    $cim  = Get-CimInstance win32_service -Filter "Name='$name'" -ErrorAction SilentlyContinue

    $state = if ($cim) { $cim.State }     else { 'Unknown' }
    $start = if ($cim) { $cim.StartMode } else { 'Unknown' }
    $cap   = Get-MyFileCapability $svc.ModifiableFile

    # Verdict logic:
    #  - Must be able to place a payload (Replace or Overwrite)
    #  - Must have a trigger: Auto start -> a reboot relaunches it as its StartName account
    if ($cap -eq 'None') {
        $verdict = "NOT usable - you can't write the binary"
    }
    elseif ($start -eq 'Auto') {
        $verdict = "EXPLOITABLE - $cap binary, Auto-start => replace + reboot"
    }
    else {
        $verdict = "PARTIAL - $cap binary, but $start start (need a way to start it; reboot won't)"
    }

    "{0,-16} {1,-9} {2,-8} {3,-14} {4}" -f $name, $state, $start, $cap, $verdict
}
