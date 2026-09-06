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

# --- Parse PowerUp output into service objects (PSCustomObjects, not hashtables) ---
$services = [System.Collections.Generic.List[object]]::new()
$cur = $null

function Flush-Current {
    param($obj)
    if ($obj -and $obj.ServiceName) { $script:services.Add([pscustomobject]$obj) }
}

foreach ($line in $fileContent) {
    if ($line -match "ServiceName\s+:\s+(.+)") {
        Flush-Current $cur
        $cur = @{ ServiceName = $matches[1].Trim(); Path = ''; ModifiableFile = ''; CanRestart = '' }
    }
    elseif ($cur -and $line -match "^Path\s+:\s+(.+)")          { $cur.Path           = $matches[1].Trim() }
    elseif ($cur -and $line -match "ModifiableFile\s+:\s+(.+)") { $cur.ModifiableFile = $matches[1].Trim() }
    elseif ($cur -and $line -match "CanRestart\s+:\s+(.+)")     { $cur.CanRestart     = $matches[1].Trim() }
}
Flush-Current $cur

# Keep only services whose flagged file is an actual binary (drop the 'C:\' drive-root noise),
# and de-duplicate by service name (PowerUp lists some services twice).
$services = $services |
    Where-Object { $_.ModifiableFile -and $_.ModifiableFile -ne 'C:\' } |
    Group-Object ServiceName | ForEach-Object { $_.Group[0] }

if (-not $services) {
    Write-Output "No services with a modifiable binary found."
    return
}

# --- Identities the current user effectively is (for a rough effective-rights check) ---
$me       = (whoami)
$myGroups = @('BUILTIN\Users','NT AUTHORITY\Authenticated Users','Everyone', $me)

# Given a file path, return what the current user can do to it:
#   'Replace'   -> holds Delete/Modify/Full: can rename+drop a new binary
#   'Overwrite' -> only Write: can overwrite contents in place
#   'None'
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

    $DELETE    = 0x00010000
    $FULL      = 0x001F01FF
    $MODIFY    = 0x000301BF
    $WRITEDATA = 0x00000002
    $APPEND    = 0x00000004

    if ( (($rights -band $FULL)   -eq $FULL)   -or
         (($rights -band $MODIFY) -eq $MODIFY) -or
         ($rights -band $DELETE) ) { return 'Replace' }
    if ( $rights -band ($WRITEDATA -bor $APPEND) ) { return 'Overwrite' }
    return 'None'
}

# --- Enrich each service with live state and report a verdict ---
$fmt = "{0,-16} {1,-9} {2,-8} {3,-11} {4}"
$fmt -f 'SERVICE','STATE','START','FILE-ACC','VERDICT'
$fmt -f '-------','-----','-----','--------','-------'

foreach ($svc in $services) {
    $name = $svc.ServiceName
    $cim  = Get-CimInstance win32_service -Filter "Name='$name'" -ErrorAction SilentlyContinue

    $state = if ($cim) { $cim.State }     else { 'Unknown' }
    $start = if ($cim) { $cim.StartMode } else { 'Unknown' }
    $cap   = Get-MyFileCapability $svc.ModifiableFile

    if ($cap -eq 'None') {
        $verdict = "NOT usable - can't write the binary"
    }
    elseif ($svc.CanRestart -eq 'True') {
        $verdict = "EXPLOITABLE - $cap binary + you can restart it => replace + net stop/start (no reboot)"
    }
    elseif ($start -eq 'Auto') {
        $verdict = "EXPLOITABLE - $cap binary + Auto-start (can't restart) => replace + reboot"
    }
    else {
        $verdict = "PARTIAL - $cap binary, $start start, can't restart (need a trigger; reboot won't launch it)"
    }

    $fmt -f $name, $state, $start, $cap, $verdict
}
