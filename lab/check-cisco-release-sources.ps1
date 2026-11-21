#Requires -Version 5.1
<#
.SYNOPSIS
Settles the unverified points of "Where the Latest Release and the NX-OS Upgrade Target
come from" (#89) with the operator's own Cisco API key.

.DESCRIPTION
Asks for the client ID and the client secret (hidden), gets one token from id.cisco.com,
then asks apix.cisco.com:
  - openVuln OSType/nxos, with and without platformAlias: the shape of `platforms` and its
    `firstFixes`, and whether a fix lies in the queried release's Train;
  - openVuln OSType/iosxe: how many `firstFixed` entries an Advisory has, and in which Trains;
  - openVuln OS_version/OS_data for iosxe and nxos: size, fields, and the highest releases;
  - Software Suggestion: software/productIds, releases/mdfIds, compatible/productId and
    compatible/mdfId (no currentRelease), counting Cisco Suggested (Y) and other (N) releases.

It prints only HTTP status, Cisco error codes, counts, field names, yes/no answers and public
release strings from Cisco's catalogue. It never prints or writes the secret or the token,
and it writes no files. "Highest" uses this script's own simple version order (numbers
compared as numbers, letters as text); it is a test aid, not the tool's rule.

Use only the CML lab's releases and public catalogue base PIDs, never a real network's.
Planning asset for the Network Analysis map; not part of the tool.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\check-cisco-release-sources.ps1 -IosXeRelease 17.12.4 -NxosRelease '10.4(3)' -ProductId C9300-24T
#>
[CmdletBinding()]
param(
    [string[]] $IosXeRelease = @(),
    [string[]] $NxosRelease = @(),
    [string] $NxosPlatformAlias = 'NEXUS9000',
    [string[]] $ProductId = @()
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$TokenUri = 'https://id.cisco.com/oauth2/default/v1/token'
$Vuln = 'https://apix.cisco.com/security/advisories/v2'
$Sugg = 'https://apix.cisco.com/software/suggestion/v2/suggestions'

function Read-List([string] $Prompt) {
    return @((Read-Host $Prompt) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
}

function Get-Field($Object, [string] $Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Get-FieldNames($Object) {
    if ($null -eq $Object) { return '(none)' }
    return (@($Object.PSObject.Properties | ForEach-Object { $_.Name }) | Sort-Object) -join ', '
}

function Join-Sorted($Items) { return ((@($Items | Where-Object { $_ } | Sort-Object -Unique)) -join ', ') }

# One HTTPS call, no redirects. Returns status, Cisco's error header, size and parsed JSON; never throws.
function Invoke-Cisco {
    param([string] $Uri, [hashtable] $Headers = @{}, [string] $Method = 'Get', $Body = $null)
    Start-Sleep -Milliseconds 400   # stay well under openVuln's 5 calls a second
    $params = @{ Uri = $Uri; Method = $Method; Headers = $Headers; UseBasicParsing = $true; MaximumRedirection = 0 }
    if ($null -ne $Body) { $params.Body = $Body; $params.ContentType = 'application/x-www-form-urlencoded' }
    try {
        $r = Invoke-WebRequest @params
        $json = $null
        try { $json = $r.Content | ConvertFrom-Json } catch { $json = $null }
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Mashery = $null; Size = $r.Content.Length; Json = $json }
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { return [pscustomobject]@{ Status = 0; Mashery = "no reply ($($_.Exception.Status))"; Size = 0; Json = $null } }
        $json = $null
        try { $json = (New-Object System.IO.StreamReader($resp.GetResponseStream())).ReadToEnd() | ConvertFrom-Json } catch { $json = $null }
        return [pscustomobject]@{ Status = [int]$resp.StatusCode; Mashery = $resp.Headers['X-Mashery-Error-Code']; Size = 0; Json = $json }
    } catch {
        return [pscustomobject]@{ Status = -1; Mashery = "failed: $($_.Exception.GetType().Name)"; Size = 0; Json = $null }
    }
}

function Write-Result([string] $Label, $Result) {
    $line = "  {0}: HTTP {1}" -f $Label, $Result.Status
    if ($Result.Mashery) { $line += ", X-Mashery-Error-Code $($Result.Mashery)" }
    if ($Result.Status -eq 200 -and $null -eq $Result.Json) { $line += ", reply not parsed ($($Result.Size) chars)" }
    Write-Host $line
    $err = Get-Field $Result.Json 'errorCode'
    if (-not $err) { $err = Get-Field (Get-Field $Result.Json 'errorDetailsResponse') 'errorCode' }
    if ($err) { Write-Host "    errorCode $err" }
}

function ConvertTo-Unpadded([string] $Release) {
    return (@($Release -split '\.' | ForEach-Object { if ($_ -match '^0+(\d.*)$') { $Matches[1] } else { $_ } })) -join '.'
}

# Train: IOS-XE 17.12.4 -> 17.12; NX-OS 10.4(3)F -> 10.4, 7.0(3)I7(9) -> 7.0(3)I7.
function Get-Train([string] $Release) {
    $u = ConvertTo-Unpadded $Release
    if ($u -match '^(\d+\.\d+)\.') { return $Matches[1] }
    if ($u -match '^(.*)\(\d+[a-z]?\)[A-Z]?$') { return $Matches[1] }
    return $u
}

function Compare-Release([string] $A, [string] $B) {
    $ta = @([regex]::Matches((ConvertTo-Unpadded $A), '\d+|[A-Za-z]+') | ForEach-Object { $_.Value })
    $tb = @([regex]::Matches((ConvertTo-Unpadded $B), '\d+|[A-Za-z]+') | ForEach-Object { $_.Value })
    for ($i = 0; $i -lt [Math]::Max($ta.Count, $tb.Count); $i++) {
        if ($i -ge $ta.Count) { return -1 }
        if ($i -ge $tb.Count) { return 1 }
        $x = $ta[$i]; $y = $tb[$i]
        if ($x -match '^\d+$' -and $y -match '^\d+$') { $c = ([long]$x).CompareTo([long]$y) }
        elseif ($x -match '^\d+$') { $c = 1 } elseif ($y -match '^\d+$') { $c = -1 }
        else { $c = [string]::CompareOrdinal($x.ToLowerInvariant(), $y.ToLowerInvariant()) }
        if ($c -ne 0) { return [Math]::Sign($c) }
    }
    return 0
}

function Get-Highest($Releases, [int] $Count = 1) {
    $left = New-Object System.Collections.ArrayList
    foreach ($r in @($Releases | Where-Object { $_ } | Sort-Object -Unique)) { [void]$left.Add([string]$r) }
    $out = @()
    while ($out.Count -lt $Count -and $left.Count -gt 0) {
        $best = $left[0]
        foreach ($r in $left) { if ((Compare-Release $r $best) -gt 0) { $best = $r } }
        $out += $best
        [void]$left.Remove($best)
    }
    return $out
}

function Get-ReleaseDate($Suggestion) {
    $d = Get-Field $Suggestion 'releaseDate'
    if (-not $d) { return $null }
    try { return [datetime]::ParseExact($d.Trim(), 'dd MMM yyyy', [Globalization.CultureInfo]::InvariantCulture) } catch { return $null }
}

# ---- Inputs (CML lab releases, public catalogue PIDs) ----
Write-Host 'Use only the CML lab''s releases and public catalogue base PIDs, never a real network''s.'
if ($IosXeRelease.Count -eq 0) { $IosXeRelease = Read-List 'IOS-XE release(s), e.g. 17.12.4, comma separated (blank to skip)' }
if ($NxosRelease.Count -eq 0) { $NxosRelease = Read-List 'NX-OS release(s), e.g. 10.4(3), comma separated (blank to skip)' }
if ($ProductId.Count -eq 0) { $ProductId = Read-List 'Catalogue base PID(s) for Software Suggestion, comma separated (blank to skip)' }

$clientId = Read-Host 'Client ID'
$secret = Read-Host 'Client secret (hidden)' -AsSecureString

# ---- Token ----
Write-Host "`nToken (id.cisco.com)"
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try {
    $body = @{ grant_type = 'client_credentials'; client_id = $clientId; client_secret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    $tok = Invoke-Cisco -Uri $TokenUri -Method Post -Body $body
    $body = $null
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $secret.Dispose()
    $secret = $null
}
Write-Result 'token' $tok
$accessToken = Get-Field $tok.Json 'access_token'
$tok = $null
if (-not $accessToken) { Write-Host '  no token; stopping.'; exit 1 }
$auth = @{ Authorization = "Bearer $accessToken"; Accept = 'application/json' }

# ---- openVuln: NX-OS platforms / firstFixes ----
Write-Host "`nopenVuln NX-OS (OSType/nxos)"
foreach ($rel in $NxosRelease) {
    $train = Get-Train $rel
    foreach ($alias in @($NxosPlatformAlias, '')) {
        $uri = "$Vuln/OSType/nxos?version=$([Uri]::EscapeDataString($rel))"
        $label = "nxos $rel, no platformAlias"
        if ($alias) { $uri += "&platformAlias=$alias"; $label = "nxos $rel, platformAlias $alias" }
        $r = Invoke-Cisco -Uri $uri -Headers $auth
        Write-Result $label $r
        $adv = @(Get-Field $r.Json 'advisories' | Where-Object { $null -ne $_ })
        if ($adv.Count -eq 0) { continue }
        Write-Host "    reply top-level fields: $(Get-FieldNames $r.Json)"
        Write-Host "    advisories $($adv.Count); advisory-level firstFixed present on: $(@($adv | Where-Object { Get-Field $_ 'firstFixed' }).Count)"
        $plats = @($adv | ForEach-Object { @(Get-Field $_ 'platforms') } | Where-Object { $null -ne $_ -and $_ -isnot [string] })
        $withFix = @($adv | Where-Object { @(@(Get-Field $_ 'platforms') | Where-Object { $null -ne $_ -and $_ -isnot [string] -and @(Get-Field $_ 'firstFixes' | Where-Object { $_ }).Count -gt 0 }).Count -gt 0 })
        $fixes = @($plats | ForEach-Object { @(Get-Field $_ 'firstFixes') } | Where-Object { $null -ne $_ })
        $fixNames = @($fixes | ForEach-Object { if ($_ -is [string]) { $_ } else { Get-Field $_ 'name' } })
        $maxPer = 0; foreach ($p in $plats) { $n = @(Get-Field $p 'firstFixes' | Where-Object { $_ }).Count; if ($n -gt $maxPer) { $maxPer = $n } }
        $inTrain = @($adv | Where-Object {
            @(@(Get-Field $_ 'platforms') | Where-Object { $null -ne $_ -and $_ -isnot [string] } | ForEach-Object { @(Get-Field $_ 'firstFixes') } |
              Where-Object { $null -ne $_ } | ForEach-Object { if ($_ -is [string]) { $_ } else { Get-Field $_ 'name' } } | Where-Object { $_ -and (Get-Train $_) -eq $train }).Count -gt 0 })
        Write-Host "    platforms entries $($plats.Count); platform fields: $(if ($plats.Count) { Get-FieldNames $plats[0] } else { '(none)' })"
        Write-Host "    platform names: $(Join-Sorted ($plats | ForEach-Object { Get-Field $_ 'name' }))"
        Write-Host "    vulnerabilityState values: $(Join-Sorted ($plats | ForEach-Object { Get-Field $_ 'vulnerabilityState' }))"
        Write-Host "    firstFixes item type: $(if ($fixes.Count) { if ($fixes[0] -is [string]) { 'string' } else { 'object: ' + (Get-FieldNames $fixes[0]) } } else { '(none)' })"
        Write-Host "    advisories with a non-empty firstFixes: $($withFix.Count) of $($adv.Count); most firstFixes on one platform: $maxPer"
        Write-Host "    advisories with a fix in Train ${train}: $($inTrain.Count) of $($adv.Count); Trains named in firstFixes: $(Join-Sorted ($fixNames | ForEach-Object { Get-Train $_ }))"
        Write-Host "    highest first fix in Train ${train}: $(Get-Highest ($fixNames | Where-Object { (Get-Train $_) -eq $train }))"
    }
}

# ---- openVuln: IOS-XE firstFixed ----
Write-Host "`nopenVuln IOS-XE (OSType/iosxe)"
foreach ($rel in $IosXeRelease) {
    $u = ConvertTo-Unpadded $rel
    $train = Get-Train $u
    $r = Invoke-Cisco -Uri "$Vuln/OSType/iosxe?version=$([Uri]::EscapeDataString($u))" -Headers $auth
    Write-Result "iosxe $u" $r
    $adv = @(Get-Field $r.Json 'advisories' | Where-Object { $null -ne $_ })
    if ($adv.Count -eq 0) { continue }
    Write-Host "    reply top-level fields: $(Get-FieldNames $r.Json)"
    $ff = @($adv | ForEach-Object { @(Get-Field $_ 'firstFixed') } | Where-Object { $_ -and $_ -ne 'NA' })
    $maxPer = 0; foreach ($a in $adv) { $n = @(Get-Field $a 'firstFixed' | Where-Object { $_ -and $_ -ne 'NA' }).Count; if ($n -gt $maxPer) { $maxPer = $n } }
    $multiInTrain = @($adv | Where-Object { @(@(Get-Field $_ 'firstFixed') | Where-Object { $_ -and (Get-Train $_) -eq $train }).Count -gt 1 }).Count
    $noneInTrain = @($adv | Where-Object { @(@(Get-Field $_ 'firstFixed') | Where-Object { $_ -and (Get-Train $_) -eq $train }).Count -eq 0 }).Count
    Write-Host "    advisories $($adv.Count); most firstFixed entries on one: $maxPer; with 2+ entries in Train ${train}: $multiInTrain; with none in Train ${train}: $noneInTrain"
    Write-Host "    Trains named in firstFixed: $(Join-Sorted ($ff | ForEach-Object { Get-Train $_ }))"
    Write-Host "    highest first fix in Train ${train}: $(Get-Highest ($ff | Where-Object { (Get-Train $_) -eq $train }))"
}

# ---- openVuln: OS_version/OS_data ----
Write-Host "`nopenVuln OS_version/OS_data"
foreach ($os in @(@('iosxe', $IosXeRelease), @('nxos', $NxosRelease))) {
    $r = Invoke-Cisco -Uri "$Vuln/OS_version/OS_data?OSType=$($os[0])" -Headers $auth
    Write-Result "OS_data $($os[0])" $r
    $rows = @($r.Json | ForEach-Object { $_ } | Where-Object { $null -ne $_ -and $_ -isnot [string] })
    if ($rows.Count -eq 0) { Write-Host "    top-level fields: $(Get-FieldNames $r.Json)"; continue }
    $vers = @($rows | ForEach-Object { Get-Field $_ 'nos_version' } | Where-Object { $_ })
    Write-Host "    rows $($rows.Count); distinct versions $(@($vers | Sort-Object -Unique).Count); row fields: $(Get-FieldNames $rows[0])"
    Write-Host "    distinct platform_name values: $(@($rows | ForEach-Object { Get-Field $_ 'platform_name' } | Where-Object { $_ } | Sort-Object -Unique).Count)"
    # Counted outside the string: Windows PowerShell 5.1 misparses a regex with ')' or '$' inside "$( )".
    $padded = @($vers | Where-Object { $_ -match '\.0\d' }).Count
    $suffixed = @($vers | Where-Object { $_ -cmatch '\)[FM]$' }).Count
    Write-Host "    versions zero-padded (e.g. 17.09.x): $padded; ending in F or M: $suffixed"
    Write-Host "    highest 5 overall: $((Get-Highest $vers 5) -join ', ')"
    foreach ($rel in $os[1]) {
        $t = Get-Train $rel
        Write-Host "    $rel listed: $(if (@($vers | Where-Object { (ConvertTo-Unpadded $_) -eq (ConvertTo-Unpadded $rel) }).Count) { 'yes' } else { 'no' }); highest 3 in Train ${t}: $((Get-Highest ($vers | Where-Object { (Get-Train $_) -eq $t }) 3) -join ', ')"
    }
}

# ---- Software Suggestion ----
function Write-Suggestions([string] $Label, $Sugs) {
    $Sugs = @($Sugs | Where-Object { $null -ne $_ })
    $yes = @($Sugs | Where-Object { (Get-Field $_ 'isSuggested') -eq 'Y' })
    $no = @($Sugs | Where-Object { (Get-Field $_ 'isSuggested') -eq 'N' })
    $rels = @($Sugs | ForEach-Object { Get-Field $_ 'releaseFormat1' })
    $top = Get-Highest $rels
    $newest = @($Sugs | Where-Object { Get-ReleaseDate $_ } | Sort-Object { Get-ReleaseDate $_ } -Descending | Select-Object -First 1)
    $newestYes = @($yes | ForEach-Object { Get-ReleaseDate $_ } | Where-Object { $_ } | Sort-Object -Descending) | Select-Object -First 1
    $topYes = Get-Highest ($yes | ForEach-Object { Get-Field $_ 'releaseFormat1' })
    $noNewerDate = 0; if ($newestYes) { $noNewerDate = @($no | Where-Object { $d = Get-ReleaseDate $_; $d -and $d -gt $newestYes }).Count }
    $noHigher = 0; if ($topYes) { $noHigher = @($no | Where-Object { (Compare-Release (Get-Field $_ 'releaseFormat1') $topYes) -gt 0 }).Count }
    Write-Host ("    {0}: releases {1} (Y {2}, N {3}); Trains {4}; releaseLifeCycle: {5}" -f $Label, $Sugs.Count, $yes.Count, $no.Count, @($Sugs | ForEach-Object { Get-Field $_ 'releaseTrain' } | Sort-Object -Unique).Count, (Join-Sorted ($Sugs | ForEach-Object { Get-Field $_ 'releaseLifeCycle' })))
    if ($Sugs.Count -gt 0) {
        $nd = if ($newest.Count) { "$(Get-Field $newest[0] 'releaseFormat1') ($(Get-Field $newest[0] 'isSuggested'))" } else { '(no dates)' }
        Write-Host ("      highest by version: {0}; newest by releaseDate: {1}; N releases newer than newest Y by date: {2}, higher than highest Y by version: {3}" -f (Join-Sorted $top), $nd, $noNewerDate, $noHigher)
        Write-Host "      fields: $(Get-FieldNames $Sugs[0])"
    }
}

function Invoke-Paged([string] $Uri) {
    $all = @(); $page = 1; $last = 1; $first = $null
    do {
        $sep = if ($Uri.Contains('?')) { '&' } else { '?' }
        $r = Invoke-Cisco -Uri "$Uri${sep}pageIndex=$page" -Headers $auth
        if ($null -eq $first) { $first = $r }
        $pr = Get-Field $r.Json 'paginationResponseRecord'
        if ($pr) { $last = [int](Get-Field $pr 'lastIndex') }
        $all += , $r
        $page++
    } while ($r.Status -eq 200 -and $page -le $last -and $page -le 10)
    Write-Result "pages fetched $($all.Count) of $last" $first
    return $all
}

Write-Host "`nSoftware Suggestion v2"
if ($ProductId.Count -gt 0) {
    $pids = (@($ProductId | ForEach-Object { [Uri]::EscapeDataString($_) })) -join ','
    Write-Host ' software/productIds (releases and images)'
    $mdfIds = @()
    foreach ($r in (Invoke-Paged "$Sugg/software/productIds/$pids")) {
        foreach ($p in @(Get-Field $r.Json 'productList' | Where-Object { $null -ne $_ })) {
            $mdfIds += Get-Field (Get-Field $p 'product') 'mdfId'
            Write-Suggestions "product $(Get-Field (Get-Field $p 'product') 'basePID')" (Get-Field $p 'suggestions')
        }
    }
    $mdfIds = @($mdfIds | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 10)
    if ($mdfIds.Count -gt 0) {
        Write-Host ' releases/mdfIds (mdfIds taken from the reply above)'
        $n = 0
        foreach ($r in (Invoke-Paged "$Sugg/releases/mdfIds/$($mdfIds -join ',')")) {
            foreach ($p in @(Get-Field $r.Json 'productList' | Where-Object { $null -ne $_ })) {
                $n++
                Write-Suggestions "mdfId product $n" (Get-Field $p 'suggestions')
            }
        }
    }
    foreach ($id in $ProductId) {
        Write-Host " compatible/productId/$id (no currentRelease)"
        $s = @(); foreach ($r in (Invoke-Paged "$Sugg/compatible/productId/$([Uri]::EscapeDataString($id))")) { $s += @(Get-Field $r.Json 'suggestions') }
        Write-Suggestions $id $s
    }
    foreach ($m in $mdfIds) {
        Write-Host " compatible/mdfId (no currentRelease), mdfId from the reply above"
        $s = @(); foreach ($r in (Invoke-Paged "$Sugg/compatible/mdfId/$m")) { $s += @(Get-Field $r.Json 'suggestions') }
        Write-Suggestions 'mdfId' $s
    }
}

$accessToken = $null
$auth = $null
Write-Host "`nDone. Record only yes/no, codes, counts, field names and Cisco's public release strings on the ticket."
