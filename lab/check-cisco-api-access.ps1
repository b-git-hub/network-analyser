#Requires -Version 5.1
<#
.SYNOPSIS
Checks that a Cisco API Console key reaches openVuln, EoX and Software Suggestion
(ticket "Get Cisco API access for openVuln, EoX and Software Suggestion", #87).

.DESCRIPTION
Asks for the client ID and the client secret (hidden), gets one token from id.cisco.com,
then asks apix.cisco.com about the DevNet CML lab's releases and PIDs:
  - PSIRT openVuln: Advisories for each IOS-XE and NX-OS release (IOS-XE as typed and unpadded);
  - EoX v5: records by software release and by PID;
  - Software Suggestion v2: releases by PID, and whether non-suggested releases newer than
    the newest suggested one are listed.
Finally it sends one deliberately wrong secret, to show what a bad or revoked secret returns.

It prints only HTTP status, Cisco error codes, counts and field names. It never prints or
writes the secret, the token, or any value from a reply, and it writes no files.

Use only the CML lab's releases and PIDs, never a real network's.
Planning asset for the Network Analysis map; not part of the tool.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\check-cisco-api-access.ps1
#>
[CmdletBinding()]
param(
    [string[]] $IosXeRelease = @(),
    [string[]] $NxosRelease = @(),
    [string[]] $ProductId = @(),
    [switch] $SkipWrongSecretCheck
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$TokenUri = 'https://id.cisco.com/oauth2/default/v1/token'
$Apix = 'https://apix.cisco.com'

function Read-List([string] $Prompt) {
    $line = Read-Host $Prompt
    return @($line -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
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

# One HTTPS call. Returns status, Cisco's error header and the parsed JSON; never throws.
function Invoke-Cisco {
    param([string] $Uri, [hashtable] $Headers = @{}, [string] $Method = 'Get', $Body = $null)
    $params = @{ Uri = $Uri; Method = $Method; Headers = $Headers; UseBasicParsing = $true; MaximumRedirection = 0 }
    if ($null -ne $Body) {
        $params.Body = $Body
        $params.ContentType = 'application/x-www-form-urlencoded'
    }
    try {
        $r = Invoke-WebRequest @params
        $json = $null
        try { $json = $r.Content | ConvertFrom-Json } catch { $json = $null }
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Mashery = $null; Json = $json }
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -eq $resp) {
            return [pscustomobject]@{ Status = 0; Mashery = "no reply ($($_.Exception.Status))"; Json = $null }
        }
        $json = $null
        try {
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $json = $reader.ReadToEnd() | ConvertFrom-Json
        } catch { $json = $null }
        return [pscustomobject]@{ Status = [int]$resp.StatusCode; Mashery = $resp.Headers['X-Mashery-Error-Code']; Json = $json }
    } catch {
        return [pscustomobject]@{ Status = -1; Mashery = "failed: $($_.Exception.GetType().Name)"; Json = $null }
    }
}

function Write-Result([string] $Label, $Result) {
    $line = "  {0}: HTTP {1}" -f $Label, $Result.Status
    if ($Result.Mashery) { $line += ", X-Mashery-Error-Code $($Result.Mashery)" }
    Write-Host $line
}

function Get-Token([string] $ClientId, [securestring] $Secret) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    try {
        $body = @{
            grant_type    = 'client_credentials'
            client_id     = $ClientId
            client_secret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        $result = Invoke-Cisco -Uri $TokenUri -Method Post -Body $body
        $body = $null
        return $result
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-JwtClaims([string] $Jwt) {
    try {
        $p = $Jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
        switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
        return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
    } catch { return $null }
}

function ConvertTo-Unpadded([string] $Release) {
    # 17.09.04a -> 17.9.4a, as decided on "When a device counts as vulnerable".
    return (@($Release -split '\.' | ForEach-Object { if ($_ -match '^0+(\d.*)$') { $Matches[1] } else { $_ } })) -join '.'
}

function Get-ReleaseDate($Suggestion) {
    $d = Get-Field $Suggestion 'releaseDate'
    if (-not $d) { return $null }
    try { return [datetime]::ParseExact($d, 'dd MMM yyyy', [Globalization.CultureInfo]::InvariantCulture) } catch { return $null }
}

# ---- Inputs (CML lab only) ----
Write-Host 'Use only the DevNet CML lab''s releases and PIDs, never a real network''s.'
if ($IosXeRelease.Count -eq 0) { $IosXeRelease = Read-List 'IOS-XE release(s) from the lab''s show version, comma separated (blank to skip)' }
if ($NxosRelease.Count -eq 0) { $NxosRelease = Read-List 'NX-OS release(s) from the lab''s show version, e.g. 10.4(3), comma separated (blank to skip)' }
if ($ProductId.Count -eq 0) { $ProductId = Read-List 'Chassis PID(s) from the lab''s show inventory, comma separated (blank to skip)' }

$clientId = Read-Host 'Client ID'
$secret = Read-Host 'Client secret (hidden)' -AsSecureString

# ---- Token ----
Write-Host "`nToken (id.cisco.com)"
$tok = Get-Token -ClientId $clientId -Secret $secret
$secret.Dispose()
$secret = $null
Write-Result 'token' $tok
$accessToken = Get-Field $tok.Json 'access_token'
if (-not $accessToken) {
    Write-Host ("  no token; error: {0} {1}" -f (Get-Field $tok.Json 'error'), (Get-Field $tok.Json 'errorCode'))
    exit 1
}
Write-Host ("  token_type {0}, expires_in {1}, scope '{2}'" -f (Get-Field $tok.Json 'token_type'), (Get-Field $tok.Json 'expires_in'), (Get-Field $tok.Json 'scope'))
$claims = Get-JwtClaims $accessToken
if ($claims) {
    Write-Host "  token claim names: $(Get-FieldNames $claims)"
    Write-Host "  scp claim: $((@(Get-Field $claims 'scp')) -join ', ')"
}
$auth = @{ Authorization = "Bearer $accessToken"; Accept = 'application/json' }

# ---- openVuln ----
Write-Host "`nPSIRT openVuln (apix.cisco.com/security/advisories/v2)"
$queries = @()
foreach ($rel in $IosXeRelease) {
    $queries += , @("iosxe $rel", "$Apix/security/advisories/v2/OSType/iosxe?version=$([Uri]::EscapeDataString($rel))")
    $u = ConvertTo-Unpadded $rel
    if ($u -ne $rel) { $queries += , @("iosxe $u (unpadded)", "$Apix/security/advisories/v2/OSType/iosxe?version=$([Uri]::EscapeDataString($u))") }
}
foreach ($rel in $NxosRelease) {
    $queries += , @("nxos $rel NEXUS9000", "$Apix/security/advisories/v2/OSType/nxos?version=$([Uri]::EscapeDataString($rel))&platformAlias=NEXUS9000")
}
foreach ($q in $queries) {
    $r = Invoke-Cisco -Uri $q[1] -Headers $auth
    Write-Result $q[0] $r
    $adv = @(Get-Field $r.Json 'advisories')
    $err = Get-Field $r.Json 'errorCode'
    if ($err) { Write-Host "    errorCode $err" }
    if ($adv.Count -gt 0 -and $null -ne $adv[0]) {
        Write-Host "    advisories: $($adv.Count); fields: $(Get-FieldNames $adv[0])"
    }
}

# ---- EoX ----
Write-Host "`nEoX v5 (apix.cisco.com/supporttools/eox/rest/5)"
function Write-Eox([string] $Label, $Result) {
    Write-Result $Label $Result
    $page = Get-Field $Result.Json 'PaginationResponseRecord'
    if ($page) { Write-Host ("    TotalRecords {0}, PageRecords {1}, LastIndex {2}" -f (Get-Field $page 'TotalRecords'), (Get-Field $page 'PageRecords'), (Get-Field $page 'LastIndex')) }
    $recs = @(Get-Field $Result.Json 'EOXRecord')
    if ($recs.Count -gt 0 -and $null -ne $recs[0]) {
        $errs = @($recs | ForEach-Object { Get-Field (Get-Field $_ 'EOXError') 'ErrorID' } | Where-Object { $_ })
        Write-Host ("    records {0}, with EOXError {1} ({2})" -f $recs.Count, $errs.Count, ((@($errs | Sort-Object -Unique)) -join ', '))
        Write-Host "    fields: $(Get-FieldNames $recs[0])"
    }
}
$inputs = @()
foreach ($rel in $IosXeRelease) { $inputs += "$([Uri]::EscapeDataString((ConvertTo-Unpadded $rel))),IOS-XE" }
foreach ($rel in $NxosRelease) { $inputs += "$([Uri]::EscapeDataString($rel)),NX-OS" }
if ($inputs.Count -gt 0) {
    $qs = (@(for ($i = 0; $i -lt $inputs.Count; $i++) { "input$($i + 1)=$($inputs[$i])" })) -join '&'
    Write-Eox 'by software release' (Invoke-Cisco -Uri "$Apix/supporttools/eox/rest/5/EOXBySWReleaseString/1?$qs" -Headers $auth)
}
if ($ProductId.Count -gt 0) {
    $pids = (@($ProductId | ForEach-Object { [Uri]::EscapeDataString($_) })) -join ','
    Write-Eox 'by PID' (Invoke-Cisco -Uri "$Apix/supporttools/eox/rest/5/EOXByProductID/1/$pids" -Headers $auth)
}

# ---- Software Suggestion ----
Write-Host "`nSoftware Suggestion v2 (apix.cisco.com/software/suggestion/v2)"
if ($ProductId.Count -gt 0) {
    $pids = (@($ProductId | ForEach-Object { [Uri]::EscapeDataString($_) })) -join ','
    $r = Invoke-Cisco -Uri "$Apix/software/suggestion/v2/suggestions/releases/productIds/$pids" -Headers $auth
    Write-Result 'releases by PID' $r
    $topErr = Get-Field (Get-Field $r.Json 'errorDetailsResponse') 'errorCode'
    if ($topErr) { Write-Host "    errorCode $topErr" }
    $n = 0
    foreach ($entry in @(Get-Field $r.Json 'productList')) {
        if ($null -eq $entry) { continue }
        $n++
        $sugs = @(Get-Field $entry 'suggestions' | Where-Object { $null -ne $_ })
        $yes = @($sugs | Where-Object { (Get-Field $_ 'isSuggested') -eq 'Y' })
        $no = @($sugs | Where-Object { (Get-Field $_ 'isSuggested') -eq 'N' })
        $errCodes = @($sugs | ForEach-Object { Get-Field (Get-Field $_ 'errorDetailsResponse') 'errorCode' } | Where-Object { $_ })
        $newestYes = @($yes | ForEach-Object { Get-ReleaseDate $_ } | Where-Object { $_ } | Sort-Object -Descending) | Select-Object -First 1
        $newerNo = 0
        if ($newestYes) { $newerNo = @($no | Where-Object { $d = Get-ReleaseDate $_; $d -and $d -gt $newestYes }).Count }
        Write-Host ("    product {0}: suggestions {1} (isSuggested Y {2}, N {3}); non-suggested newer than newest suggested: {4}; error codes: {5}" -f $n, $sugs.Count, $yes.Count, $no.Count, $newerNo, ((@($errCodes | Sort-Object -Unique)) -join ', '))
        Write-Host "      product fields: $(Get-FieldNames (Get-Field $entry 'product'))"
        if ($sugs.Count -gt 0) { Write-Host "      suggestion fields: $(Get-FieldNames $sugs[0])" }
    }
}

# ---- Wrong secret ----
if (-not $SkipWrongSecretCheck) {
    Write-Host "`nWrong secret (one attempt with a made-up secret, to see what a bad or revoked secret returns)"
    $fake = ConvertTo-SecureString 'not-the-real-secret' -AsPlainText -Force
    $bad = Get-Token -ClientId $clientId -Secret $fake
    Write-Result 'token' $bad
    Write-Host ("  error: {0} {1}" -f (Get-Field $bad.Json 'error'), (Get-Field $bad.Json 'errorCode'))
}

$accessToken = $null
$auth = $null
Write-Host "`nDone. Record only yes/no, codes, counts and field names on the ticket."
