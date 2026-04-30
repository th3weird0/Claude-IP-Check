<#
ClaudeCheck v2.8 - Windows PowerShell Edition
Purpose: troubleshoot routing, DNS, IPv4/IPv6, TLS fingerprint and domain reachability for Claude / Anthropic related services.
Note: this script does NOT prove account safety, risk-control status, or IP purity.

Run:
  powershell -ExecutionPolicy Bypass -File .\ClaudeCheck.v2.7.ps1
  pwsh -ExecutionPolicy Bypass -File .\ClaudeCheck.v2.7.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0"
$TimeoutSec = 8

# Gold-standard exact domain set derived from the routing document.
# keyword/geosite/IP-ASN rules are routing-engine matchers, not concrete HTTPS domains.
# NTP is tested separately because it is UDP/123, not HTTPS.
$CoreDomains = @(
  "anthropic.com",
  "api.anthropic.com",
  "claude.ai",
  "claude.com",
  "clau.de",
  "claudemcpclient.com",
  "claudemcpcontent.com",
  "claudeusercontent.com"
)
$CdnDomains = @(
  "cdn.anthropic.com",
  "anthropic.com.cdn.cloudflare.net",
  "servd-anthropic-website.b-cdn.net"
)
$AuthContentDomains = @(
  "anthropic.auth0.com",
  "anthropic-com.ghost.io",
  "console.anthropic.com",
  "mcp.anthropic.com",
  "workbench.anthropic.com"
)
$TelemetryDomains = @(
  "browser-intake-us5-datadoghq.com",
  "sentry.io",
  "statsigapi.net"
)
$ThirdPartyWidgetDomains = @(
  "intercom.io",
  "intercomcdn.com",
  "cdn.usefathom.com"
)
$DomainList = @($CoreDomains + $CdnDomains + $AuthContentDomains + $TelemetryDomains + $ThirdPartyWidgetDomains | Select-Object -Unique)
$DnsTestDomains = @($DomainList | Select-Object -Unique)
$PublicDns = @("1.1.1.1", "8.8.8.8")
$NtpServers = @("time.cloudflare.com", "time.google.com", "pool.ntp.org", "time.windows.com")
$IpFallbackRules = @("160.79.104.0/21", "2607:6bc0::/32", "AS399358")
$KeywordFallbackRules = @("keyword:datadog", "keyword:sentry", "keyword:sift", "geosite:anthropic", "geosite:category-ntp")
$FlagMap = @{ CN="CN"; US="US"; HK="HK"; SG="SG"; JP="JP"; GB="GB"; TW="TW"; DE="DE"; FR="FR"; NL="NL"; CA="CA"; AU="AU"; KR="KR" }

function Write-Color {
  param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Gray, [switch]$NoNewline)
  try { $old = $Host.UI.RawUI.ForegroundColor; $Host.UI.RawUI.ForegroundColor = $Color } catch {}
  if ($NoNewline) { Write-Host $Text -NoNewline } else { Write-Host $Text }
  try { $Host.UI.RawUI.ForegroundColor = $old } catch {}
}
function Write-Kv { param([string]$Key, [string]$Value) Write-Host ("   |-- {0,-24}: {1}" -f $Key, $Value) }

function Invoke-WebText {
  param([Parameter(Mandatory=$true)][string]$Uri, [string]$Method = "GET")
  try {
    $resp = Invoke-WebRequest -Uri $Uri -Method $Method -UserAgent $UA -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
    return [string]$resp.Content
  } catch { return $null }
}
function Invoke-WebJson {
  param([Parameter(Mandatory=$true)][string]$Uri)
  $txt = Invoke-WebText $Uri
  if ([string]::IsNullOrWhiteSpace($txt)) { return $null }
  try { return ($txt | ConvertFrom-Json -ErrorAction Stop) } catch { return $null }
}

function Get-PublicIp {
  param([ValidateSet("v4","v6")][string]$Family)
  $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
  if ($curl) {
    $arg = if ($Family -eq "v4") { "-4" } else { "-6" }
    try {
      $ip = (& curl.exe $arg -sS --max-time $TimeoutSec -H "User-Agent: $UA" https://ifconfig.co/ip 2>$null).Trim()
      if ($ip -match "^[0-9a-fA-F:.]+$") { return $ip }
    } catch {}
  }
  $url = if ($Family -eq "v4") { "https://api.ipify.org" } else { "https://api6.ipify.org" }
  $txt = Invoke-WebText $url
  if ($txt) { return $txt.Trim() }
  return ""
}

function Get-CfTraceIp {
  param([string]$HostName)
  $txt = Invoke-WebText "https://$HostName/cdn-cgi/trace"
  if ($txt -match "(?m)^ip=(.+)$") { return $Matches[1].Trim() }
  return ""
}

function Get-Geo {
  param([string]$Ip)
  if ([string]::IsNullOrWhiteSpace($Ip)) { return $null }
  return Invoke-WebJson "http://ip-api.com/json/${Ip}?fields=status,country,countryCode,city,isp,as,hosting,proxy,query"
}

function Write-GeoLine {
  param([string]$Label, [string]$Ip)
  if ([string]::IsNullOrWhiteSpace($Ip)) { Write-Host ("   |-- {0,-24}: " -f $Label) -NoNewline; Write-Color "N/A" Yellow; return }
  $geo = Get-Geo $Ip
  if (-not $geo -or $geo.status -ne "success") { Write-Host ("   |-- {0,-24}: {1,-15} | Geo lookup failed" -f $Label, $Ip); return }
  $cc = [string]$geo.countryCode
  $flag = if ($FlagMap.ContainsKey($cc)) { $FlagMap[$cc] } else { "--" }
  $property = "√ not flagged as hosting/proxy by ip-api"; $propertyColor = [ConsoleColor]::Green
  if ($geo.hosting -eq $true -and $geo.proxy -eq $true) { $property = "× flagged as hosting/datacenter + proxy by ip-api"; $propertyColor = [ConsoleColor]::Red }
  elseif ($geo.hosting -eq $true) { $property = "× flagged as hosting/datacenter by ip-api"; $propertyColor = [ConsoleColor]::Red }
  elseif ($geo.proxy -eq $true) { $property = "× flagged as proxy by ip-api"; $propertyColor = [ConsoleColor]::Red }
  Write-Host ("   |-- {0,-24}: {1} {2,-15} | {3} - {4} | ISP: {5} | " -f $Label, $flag, $Ip, $geo.country, $geo.city, $geo.isp) -NoNewline
  Write-Color $property $propertyColor
  Write-Host ("       {0,-24}  {1}" -f "ASN:", $geo.as)
}

function Get-SystemDnsServers {
  $servers = @()
  try {
    $defaultIf = @()
    $routes = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric, InterfaceMetric)
    foreach ($r in $routes) { if ($null -ne $r.InterfaceIndex) { $defaultIf += [int]$r.InterfaceIndex } }
    $dnsItems = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.ServerAddresses -and @($_.ServerAddresses).Count -gt 0 })
    if (@($defaultIf).Count -gt 0) { $dnsItems = @($dnsItems | Sort-Object @{Expression={ if ($defaultIf -contains $_.InterfaceIndex) {0} else {1} }}, InterfaceIndex) }
    foreach ($d in $dnsItems) { foreach ($s in @($d.ServerAddresses)) { if ($s -and $servers -notcontains [string]$s) { $servers += [string]$s } } }
  } catch {}
  return @($servers)
}

function Parse-NslookupIps {
  param([string[]]$Lines, [ValidateSet("A","AAAA")][string]$Type)
  # Parse nslookup output carefully. Server address lines appear before "Name:" and
  # must NOT be treated as DNS answers. This avoids false positives like NXDOMAIN
  # domains appearing as 10.0.0.3 / 1.1.1.1 / 8.8.8.8.
  $ips = @()
  $inAnswer = $false
  foreach ($line in @($Lines)) {
    $t = ($line -as [string]).Trim()
    if ($t -match "^(Name|名称)\s*[:：]") { $inAnswer = $true; continue }
    if (-not $inAnswer) { continue }
    if ($t -match "^(Aliases|别名)\s*[:：]") { continue }
    if ($Type -eq "A") {
      if ($t -match "^(Address|Addresses|地址)\s*[:：]\s*(\d+\.\d+\.\d+\.\d+)\s*$") { $ips += $Matches[2] }
      elseif ($t -match "^(\d+\.\d+\.\d+\.\d+)\s*$") { $ips += $Matches[1] }
    } else {
      if ($t -match "^(Address|Addresses|地址)\s*[:：]\s*([0-9a-fA-F:]{3,})\s*$") { $ips += $Matches[2] }
      elseif ($t -match "^([0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}\s*$") { $ips += $Matches[0] }
    }
  }
  return @($ips | Where-Object { $_ -and ($_ -notmatch "^#") } | Select-Object -Unique)
}

function Invoke-NslookupDetailed {
  param([Parameter(Mandatory=$true)][string]$Domain, [ValidateSet("A","AAAA")][string]$Type = "A", [string]$Server)
  $lines = @()
  try {
    if ([string]::IsNullOrWhiteSpace($Server)) { $lines = @(& nslookup -type=$Type $Domain 2>&1) }
    else { $lines = @(& nslookup -type=$Type $Domain $Server 2>&1) }
  } catch {
    return [pscustomobject]@{ Status="ERROR"; Ips=@(); Text=[string]$_.Exception.Message }
  }
  $text = (($lines | ForEach-Object { $_ -as [string] }) -join "`n")
  $ips = @(Parse-NslookupIps -Lines $lines -Type $Type)

  # Important: parse answers before looking for NXDOMAIN keywords.
  # Some localized / proxied nslookup outputs may contain diagnostic text such as
  # "can't find" in non-answer sections even when a valid answer is present.
  # If we mark NXDOMAIN before parsing answers, existing domains become false NXDOMAIN.
  if (@($ips).Count -gt 0) { return [pscustomobject]@{ Status="NOERROR"; Ips=@($ips); Text=$text } }

  if ($text -match "(?i)NXDOMAIN|Non-existent\s+domain|server\s+can't\s+find|can't\s+find|不存在|找不到|找不到.*域名") {
    return [pscustomobject]@{ Status="NXDOMAIN"; Ips=@(); Text=$text }
  }
  if ($text -match "(?i)No\s+answer|No\s+records|No\s+response|timed\s*out|SERVFAIL|REFUSED|server\s+failed|Default\s+servers\s+are\s+not\s+available") {
    return [pscustomobject]@{ Status="NO_ANSWER"; Ips=@(); Text=$text }
  }
  return [pscustomobject]@{ Status="NO_ANSWER"; Ips=@(); Text=$text }
}

function Resolve-DnsDetailed {
  param([Parameter(Mandatory=$true)][string]$Domain, [ValidateSet("A","AAAA")][string]$Type = "A", [string]$Server)

  # Show DNS status codes; do not turn generic failures into NXDOMAIN.
  # System resolver: structured Resolve-DnsName first.
  # Specific resolver: Windows built-in nslookup first, because it exposes server-specific NXDOMAIN/NOERROR behavior.
  $ips = @()
  $status = "UNKNOWN"
  $text = ""

  if ([string]::IsNullOrWhiteSpace($Server)) {
    try {
      $records = @(Resolve-DnsName -Name $Domain -Type $Type -DnsOnly -NoHostsFile -ErrorAction Stop)
      foreach ($r in @($records)) {
        if ($null -ne $r.IPAddress -and -not [string]::IsNullOrWhiteSpace([string]$r.IPAddress)) { $ips += [string]$r.IPAddress }
      }
      if (@($ips).Count -gt 0) { $status = "NOERROR" } else { $status = "NO_ANSWER" }
    } catch {
      $msg = [string]$_.Exception.Message
      $text = $msg
      if ($msg -match "(?i)NXDOMAIN|RCODE_NAME_ERROR|DNS.*name.*does.*not.*exist|Non-existent|不存在|找不到") { $status = "NXDOMAIN" }
      elseif ($msg -match "(?i)SERVFAIL|server failed") { $status = "SERVFAIL" }
      elseif ($msg -match "(?i)REFUSED") { $status = "REFUSED" }
      elseif ($msg -match "(?i)timed out|timeout|No response") { $status = "TIMEOUT" }
      else { $status = "ERROR" }
    }

    if (@($ips).Count -eq 0 -and $status -notin @("NXDOMAIN","SERVFAIL","REFUSED","TIMEOUT")) {
      try {
        $all = @([System.Net.Dns]::GetHostAddresses($Domain))
        foreach ($a in $all) {
          if ($Type -eq "A" -and $a.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $ips += $a.IPAddressToString }
          if ($Type -eq "AAAA" -and $a.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { $ips += $a.IPAddressToString }
        }
        if (@($ips).Count -gt 0) { $status = "NOERROR" }
      } catch {}
    }
  } else {
    $ns = Invoke-NslookupDetailed -Domain $Domain -Type $Type -Server $Server
    $text = $ns.Text
    $ips = @($ns.Ips)
    $status = $ns.Status

    if (@($ips).Count -eq 0 -and $status -notin @("NXDOMAIN","SERVFAIL","REFUSED","TIMEOUT")) {
      try {
        $records = @(Resolve-DnsName -Name $Domain -Type $Type -Server $Server -DnsOnly -NoHostsFile -ErrorAction Stop)
        foreach ($r in @($records)) {
          if ($null -ne $r.IPAddress -and -not [string]::IsNullOrWhiteSpace([string]$r.IPAddress)) { $ips += [string]$r.IPAddress }
        }
        if (@($ips).Count -gt 0) { $status = "NOERROR" }
      } catch {
        $msg = [string]$_.Exception.Message
        if ($msg -match "(?i)NXDOMAIN|RCODE_NAME_ERROR|DNS.*name.*does.*not.*exist|Non-existent|不存在|找不到") { $status = "NXDOMAIN" }
        elseif ($msg -match "(?i)SERVFAIL|server failed") { $status = "SERVFAIL" }
        elseif ($msg -match "(?i)REFUSED") { $status = "REFUSED" }
        elseif ($msg -match "(?i)timed out|timeout|No response") { $status = "TIMEOUT" }
      }
    }
  }

  $ips = @($ips | Where-Object { $_ } | Select-Object -Unique)
  if (@($ips).Count -eq 0 -and [string]::IsNullOrWhiteSpace($status)) { $status = "NO_ANSWER" }
  return [pscustomobject]@{ Status=$status; Ips=@($ips); Text=$text }
}

function Format-DnsDetailed {
  param([Parameter(Mandatory=$true)]$Result, [string]$Server)
  $ips = @($Result.Ips)
  $status = if ([string]::IsNullOrWhiteSpace([string]$Result.Status)) { "UNKNOWN" } else { [string]$Result.Status }

  if (@($ips).Count -eq 0) { return $status }

  $invalid = @()
  if (-not [string]::IsNullOrWhiteSpace($Server)) { $invalid += $Server }
  $invalid += @("1.1.1.1","8.8.8.8")
  $real = @($ips | Where-Object { $invalid -notcontains $_ })
  if (@($real).Count -eq 0 -and @($ips).Count -gt 0) { return ("INVALID({0}) / {1}" -f ($ips -join ","), $status) }
  return ("{0} / {1}" -f ($ips -join ","), $status)
}

function Get-DnsVerdict {
  param([object[]]$Results)
  $flatIps = @()
  $statuses = @()
  foreach ($r in @($Results)) {
    if ($null -eq $r) { continue }
    $statuses += [string]$r.Status
    foreach ($ip in @($r.Ips)) { if ($ip) { $flatIps += [string]$ip } }
  }
  $flatIps = @($flatIps | Select-Object -Unique)
  $statuses = @($statuses | Where-Object { $_ } | Select-Object -Unique)

  if (@($flatIps).Count -eq 0) {
    if (@($statuses).Count -gt 0 -and @($statuses | Where-Object { $_ -ne "NXDOMAIN" }).Count -eq 0) { return "NXDOMAIN" }
    return ($statuses -join "/")
  }

  $resolverIps = @($SystemDns + $PublicDns | Select-Object -Unique)
  $invalidHits = @($flatIps | Where-Object { $resolverIps -contains $_ })
  if (@($invalidHits).Count -gt 0) { return ("DNS_REWRITE_SUSPECT ({0})" -f ($invalidHits -join ",")) }
  if (@($flatIps).Count -eq 1) { return "CONSISTENT" }
  return "MULTI_ANSWER / CDN_OR_INCONSISTENT"
}

function Resolve-Records {
  param([Parameter(Mandatory=$true)][string]$Domain, [ValidateSet("A","AAAA")][string]$Type = "A", [string]$Server)
  return (Format-DnsDetailed -Result (Resolve-DnsDetailed -Domain $Domain -Type $Type -Server $Server) -Server $Server)
}

function Test-Sinkhole {
  param([string]$Ips)
  if ([string]::IsNullOrWhiteSpace($Ips) -or $Ips -eq "N/A") { return $false }
  return ($Ips -match "(^|,)(0\.0\.0\.0|127\.|::1|::|5\.6\.7\.8)(,|$)")
}

function Test-HttpProbe {
  param([Parameter(Mandatory=$true)][string]$Domain, [ValidateSet("auto","v4","v6")][string]$Family = "auto")
  $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
  if ($curl) {
    $familyArg = @(); if ($Family -eq "v4") { $familyArg = @("-4") } elseif ($Family -eq "v6") { $familyArg = @("-6") }
    try {
      $out = & curl.exe @familyArg -sS -o NUL -w "%{http_code} %{time_connect} %{time_total} %{remote_ip}" --max-time $TimeoutSec -H "User-Agent: $UA" "https://$Domain" 2>$null
      if ($out -match "^(\d{3})\s+(\S+)\s+(\S+)\s+(\S+)") { return [pscustomobject]@{ Code=$Matches[1]; Connect=$Matches[2]; Total=$Matches[3]; RemoteIp=$Matches[4] } }
    } catch {}
  }
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $resp = Invoke-WebRequest -Uri "https://$Domain" -UserAgent $UA -TimeoutSec $TimeoutSec -UseBasicParsing -Method GET -ErrorAction Stop
    $sw.Stop(); return [pscustomobject]@{ Code=[string][int]$resp.StatusCode; Connect="N/A"; Total=("{0:N3}" -f $sw.Elapsed.TotalSeconds); RemoteIp="N/A" }
  } catch {
    $sw.Stop(); $code = "000"
    try { if ($_.Exception.Response -and $_.Exception.Response.StatusCode) { $code = [string][int]$_.Exception.Response.StatusCode } } catch {}
    return [pscustomobject]@{ Code=$code; Connect="N/A"; Total=("{0:N3}" -f $sw.Elapsed.TotalSeconds); RemoteIp="N/A" }
  }
}

function Get-HttpVerdict {
  param([string]$Code)
  if ([string]::IsNullOrWhiteSpace($Code) -or $Code -eq "000" -or $Code -eq "FAIL") { return [pscustomobject]@{ Label="FAIL"; Color=[ConsoleColor]::Red } }
  $n = 0
  if (-not [int]::TryParse($Code, [ref]$n)) { return [pscustomobject]@{ Label=$Code; Color=[ConsoleColor]::Red } }
  if ($n -ge 200 -and $n -lt 400) { return [pscustomobject]@{ Label=$Code; Color=[ConsoleColor]::Green } }
  if ($n -eq 401 -or $n -eq 403 -or $n -eq 404 -or $n -eq 405 -or $n -eq 406 -or $n -eq 409 -or $n -eq 421 -or $n -eq 425 -or $n -eq 429) { return [pscustomobject]@{ Label=("{0} WARN" -f $Code); Color=[ConsoleColor]::Yellow } }
  if ($n -ge 500 -and $n -le 599) { return [pscustomobject]@{ Label=("{0} ERR" -f $Code); Color=[ConsoleColor]::Red } }
  return [pscustomobject]@{ Label=("{0} WARN" -f $Code); Color=[ConsoleColor]::Yellow }
}

function Test-NtpProbe {
  param([Parameter(Mandatory=$true)][string]$Server)
  $udp = $null
  try {
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = [Math]::Max(1000, $TimeoutSec * 1000)
    $udp.Client.SendTimeout = [Math]::Max(1000, $TimeoutSec * 1000)
    $udp.Connect($Server, 123)
    $packet = New-Object byte[] 48
    $packet[0] = 0x1B
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    [void]$udp.Send($packet, $packet.Length)
    $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $resp = $udp.Receive([ref]$remote)
    $sw.Stop()
    if ($resp -and $resp.Length -ge 48) {
      return [pscustomobject]@{ Status="OK"; Color=[ConsoleColor]::Green; Rtt=("{0:N3}" -f $sw.Elapsed.TotalSeconds); Remote=$remote.ToString() }
    }
    return [pscustomobject]@{ Status="BAD_REPLY"; Color=[ConsoleColor]::Yellow; Rtt=("{0:N3}" -f $sw.Elapsed.TotalSeconds); Remote=$remote.ToString() }
  } catch {
    return [pscustomobject]@{ Status="FAIL"; Color=[ConsoleColor]::Red; Rtt="N/A"; Remote="N/A" }
  } finally {
    try { if ($udp) { $udp.Close() } } catch {}
  }
}

function Get-TimeZoneText { try { return (Get-TimeZone).Id } catch { return [System.TimeZoneInfo]::Local.Id } }

function Get-TlsFingerprint {
  $json = Invoke-WebJson "https://tls.peet.ws/api/all"
  if (-not $json) { return $null }
  $ja3 = "N/A"; $ja3h = "N/A"; $ja4 = "N/A"; $httpv = "N/A"
  try { if ($json.tls.ja3) { $ja3 = [string]$json.tls.ja3 } } catch {}
  try { if ($json.tls.ja3_hash) { $ja3h = [string]$json.tls.ja3_hash } } catch {}
  try { if ($json.tls.ja4) { $ja4 = [string]$json.tls.ja4 } } catch {}
  try { if ($json.http_version) { $httpv = [string]$json.http_version } } catch {}
  return [pscustomobject]@{ JA3=$ja3; JA3Hash=$ja3h; JA4=$ja4; HttpVersion=$httpv }
}

function New-BrowserFingerprintHtml {
  $path = Join-Path (Get-Location) "ClaudeCheck.browser-fingerprint.html"
  $html = @'
<!doctype html><html><head><meta charset="utf-8"><title>ClaudeCheck Browser Fingerprint</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;line-height:1.45}pre{background:#f6f8fa;padding:14px;border-radius:8px;white-space:pre-wrap}button{padding:8px 12px}</style></head>
<body><h2>ClaudeCheck Browser Fingerprint</h2><p>This local page computes Canvas and WebGL fingerprints in your real browser. It does not upload data.</p><button onclick="copyReport()">Copy report</button><pre id="out">Running...</pre>
<script>
async function sha256(s){const b=new TextEncoder().encode(s);const h=await crypto.subtle.digest('SHA-256',b);return [...new Uint8Array(h)].map(x=>x.toString(16).padStart(2,'0')).join('')}
function canvasData(){const c=document.createElement('canvas');c.width=420;c.height=120;const x=c.getContext('2d');x.textBaseline='top';x.font="16px 'Arial'";x.fillStyle='#f60';x.fillRect(0,0,420,120);x.fillStyle='#069';x.fillText('ClaudeCheck Canvas 漢字 🚀 1234567890',12,18);x.fillStyle='rgba(102,204,0,.7)';x.font='18px Georgia';x.fillText('The quick brown fox jumps over the lazy dog.',12,55);x.globalCompositeOperation='multiply';x.fillStyle='rgb(255,0,255)';x.beginPath();x.arc(330,55,35,0,Math.PI*2,true);x.fill();return c.toDataURL()}
function webglData(){const c=document.createElement('canvas');const gl=c.getContext('webgl')||c.getContext('experimental-webgl');if(!gl)return {supported:false};const dbg=gl.getExtension('WEBGL_debug_renderer_info');let vendor=dbg?gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL):gl.getParameter(gl.VENDOR);let renderer=dbg?gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL):gl.getParameter(gl.RENDERER);let params={vendor,renderer,version:gl.getParameter(gl.VERSION),shading:gl.getParameter(gl.SHADING_LANGUAGE_VERSION),maxTextureSize:gl.getParameter(gl.MAX_TEXTURE_SIZE),maxViewportDims:gl.getParameter(gl.MAX_VIEWPORT_DIMS).toString()};return {supported:true,params}}
async function main(){const cd=canvasData();const wg=webglData();const report={time:new Date().toString(),timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,userAgent:navigator.userAgent,platform:navigator.platform,languages:navigator.languages,hardwareConcurrency:navigator.hardwareConcurrency,deviceMemory:navigator.deviceMemory||'N/A',canvas_sha256:await sha256(cd),webgl_sha256:await sha256(JSON.stringify(wg)),webgl:wg};document.getElementById('out').textContent=JSON.stringify(report,null,2)}
function copyReport(){navigator.clipboard.writeText(document.getElementById('out').textContent)}
main();</script></body></html>
'@
  Set-Content -Path $path -Value $html -Encoding UTF8
  return $path
}

Write-Color "============================================================" Cyan
Write-Color "   ClaudeCheck v2.8 - Network Environment Self-Test for Windows" Cyan
Write-Color ("   Report Generated: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz")) Cyan
Write-Color "============================================================" Cyan
Write-Color "Note: This tool helps troubleshoot routing/DNS/reachability. It cannot certify account safety or IP purity." DarkGray
Write-Color ("Domain gold-set loaded: {0} exact HTTPS domains; plus {1} keyword/geosite/IP fallback references and {2} NTP servers." -f @($DomainList).Count, (@($KeywordFallbackRules).Count + @($IpFallbackRules).Count), @($NtpServers).Count) DarkGray

Write-Host "`n[1/7] Public egress compare: IPv4 / IPv6 / Cloudflare Trace"
$IPv4 = Get-PublicIp -Family v4; $IPv6 = Get-PublicIp -Family v6; $CfIp = Get-CfTraceIp "1.1.1.1"; $ClaudeCfIp = Get-CfTraceIp "claude.ai"
Write-GeoLine "IPv4 egress" $IPv4; Write-GeoLine "IPv6 egress" $IPv6; Write-GeoLine "Cloudflare trace" $CfIp; Write-GeoLine "claude.ai CF trace" $ClaudeCfIp
Write-Color "      Note: claude.ai /cdn-cgi/trace only shows what that Cloudflare request sees. It is not Anthropic's internal risk-control result." DarkGray

Write-Host "`n[2/7] Local DNS configuration snapshot"
try {
  $dnsServers = @(Get-DnsClientServerAddress -ErrorAction Stop | Where-Object { $_.ServerAddresses -and @($_.ServerAddresses).Count -gt 0 })
  foreach ($d in $dnsServers) { Write-Host ("   |-- Interface: {0} | {1} | DNS: {2}" -f $d.InterfaceAlias, $d.AddressFamily, (@($d.ServerAddresses) -join ",")) }
} catch { Write-Host "   |-- Get-DnsClientServerAddress failed. Try Windows PowerShell 5+ or PowerShell 7+." }
try {
  $adapters = @(Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4DefaultGateway -or $_.IPv6DefaultGateway })
  foreach ($a in $adapters) {
    $v4gw = if ($a.IPv4DefaultGateway) { (@($a.IPv4DefaultGateway.NextHop) -join ",") } else { "N/A" }
    $v6gw = if ($a.IPv6DefaultGateway) { (@($a.IPv6DefaultGateway.NextHop) -join ",") } else { "N/A" }
    Write-Host ("   |-- Default route: {0} | IPv4 GW: {1} | IPv6 GW: {2}" -f $a.InterfaceAlias, $v4gw, $v6gw)
  }
} catch {}
$SystemDns = @(Get-SystemDnsServers)
if (@($SystemDns).Count -gt 0) { Write-Host ("   |-- Preferred IPv4 DNS for active routes: {0}" -f ($SystemDns -join ",")) }

Write-Host "`n[3/7] DNS compare: system resolver / active DNS server / public DNS"
foreach ($dm in $DnsTestDomains) {
  $sysAObj = Resolve-DnsDetailed -Domain $dm -Type A
  $sysAAAAObj = Resolve-DnsDetailed -Domain $dm -Type AAAA
  $sysA = Format-DnsDetailed -Result $sysAObj
  $sysAAAA = Format-DnsDetailed -Result $sysAAAAObj

  Write-Host ("   |-- {0,-38}" -f $dm)
  Write-Host ("       {0,-10} A:    {1}" -f "system", $sysA)
  Write-Host ("       {0,-10} AAAA: {1}" -f "system", $sysAAAA)

  $verdictInputs = @($sysAObj, $sysAAAAObj)
  if (@($SystemDns).Count -gt 0) {
    $active = $SystemDns[0]
    $activeAObj = Resolve-DnsDetailed -Domain $dm -Type A -Server $active
    $activeA = Format-DnsDetailed -Result $activeAObj -Server $active
    $verdictInputs += $activeAObj
    Write-Host ("       @{0,-9} A:    {1}  [active DNS]" -f $active, $activeA)
  }
  foreach ($dns in $PublicDns) {
    $pubAObj = Resolve-DnsDetailed -Domain $dm -Type A -Server $dns
    $pubA = Format-DnsDetailed -Result $pubAObj -Server $dns
    $verdictInputs += $pubAObj
    Write-Host ("       @{0,-9} A:    {1}" -f $dns, $pubA)
  }
  $verdict = Get-DnsVerdict -Results $verdictInputs
  Write-Host ("       {0,-10} {1}" -f "result:", $verdict)
}
Write-Color "      Note: DNS section shows returned records plus resolver status code (NOERROR / NXDOMAIN / SERVFAIL / REFUSED / TIMEOUT / ERROR)." DarkGray
Write-Color "      Note: NXDOMAIN is only shown when the resolver explicitly reports non-existent domain; generic failures are not converted to NXDOMAIN." DarkGray
Write-Color "      Note: A records equal to resolver IPs like 10.0.0.3 / 1.1.1.1 / 8.8.8.8 are marked INVALID/DNS_REWRITE_SUSPECT." DarkGray

Write-Host "`n[4/7] Telemetry/monitoring domain DNS status"
foreach ($td in $TelemetryDomains) {
  $rawA = Resolve-Records -Domain $td -Type A; $rawAAAA = Resolve-Records -Domain $td -Type AAAA
  if (($rawA -eq "N/A") -and ($rawAAAA -eq "N/A")) { Write-Host ("   |-- {0,-38}: " -f $td) -NoNewline; Write-Color "NO_ANSWER" Yellow }
  elseif (($rawA -eq "NXDOMAIN") -and ($rawAAAA -eq "NXDOMAIN")) { Write-Host ("   |-- {0,-38}: " -f $td) -NoNewline; Write-Color "NXDOMAIN" Yellow -NoNewline; Write-Host (" | A={0} AAAA={1}" -f $rawA, $rawAAAA) }
  elseif ((Test-Sinkhole "$rawA,$rawAAAA")) { Write-Host ("   |-- {0,-38}: " -f $td) -NoNewline; Write-Color "INTERCEPTED/SINKHOLED" Green -NoNewline; Write-Host (" | A={0} AAAA={1}" -f $rawA, $rawAAAA) }
  else { Write-Host ("   |-- {0,-38}: " -f $td) -NoNewline; Write-Color "RESOLVES" Yellow -NoNewline; Write-Host (" | A={0} AAAA={1}" -f $rawA, $rawAAAA) }
}
Write-Color "      Note: RESOLVES only means DNS returns records. Whether to block it depends on your privacy policy and service requirements." DarkGray

Write-Host "`n[5/7] Claude / Anthropic HTTPS reachability scan (gold-standard domain set)"
Write-Host ("   |-- {0,-35} {1,-12} {2,-6} {3,-10} {4,-10} {5,-15}" -f "Domain", "Group", "Stack", "HTTP", "Total(s)", "Remote IP")
foreach ($dm in $DomainList) {
  $group = "other"
  if ($CoreDomains -contains $dm) { $group = "core" }
  elseif ($CdnDomains -contains $dm) { $group = "cdn" }
  elseif ($AuthContentDomains -contains $dm) { $group = "auth/content" }
  elseif ($TelemetryDomains -contains $dm) { $group = "telemetry" }
  elseif ($ThirdPartyWidgetDomains -contains $dm) { $group = "widget" }
  foreach ($fam in @("v4","v6")) {
    if ($fam -eq "v6" -and [string]::IsNullOrWhiteSpace($IPv6)) { continue }
    $probe = Test-HttpProbe -Domain $dm -Family $fam
    $verdict = Get-HttpVerdict -Code $probe.Code
    Write-Host ("   |-- {0,-35} {1,-12} {2,-6} " -f $dm,$group,$fam) -NoNewline
    Write-Color ("{0,-10}" -f $verdict.Label) $verdict.Color -NoNewline
    Write-Host (" {0,-10} {1,-15}" -f $probe.Total,$probe.RemoteIp)
  }
}
Write-Color "      Legend: green=normal success/redirect (2xx/3xx), yellow=reachable but abnormal/warning (401/403/404/405/429 etc.), red=no response or 5xx/failure." DarkGray
Write-Color ("      Fallback references not probed as HTTPS domains: {0}" -f (($KeywordFallbackRules + $IpFallbackRules) -join ", ")) DarkGray

Write-Host "`n[6/7] UDP/NTP reachability probe"
Write-Host ("   |-- {0,-28} {1,-10} {2,-10} {3,-24}" -f "Server", "Status", "RTT(s)", "Remote")
foreach ($ntp in $NtpServers) {
  $r = Test-NtpProbe -Server $ntp
  Write-Host ("   |-- {0,-28} " -f $ntp) -NoNewline
  Write-Color ("{0,-10}" -f $r.Status) $r.Color -NoNewline
  Write-Host (" {0,-10} {1,-24}" -f $r.Rtt, $r.Remote)
}
Write-Color "      Note: This only tests UDP/123 reachability from Windows. It cannot prove your proxy client actually forwards NTP unless your proxy stack supports UDP and you verify its logs." DarkGray

Write-Host "`n[7/7] Local metadata / TLS / browser fingerprint helpers"
Write-Kv "User-Agent used" $UA; Write-Kv "System timezone" (Get-TimeZoneText)
$tls = Get-TlsFingerprint
if ($tls) { Write-Kv "JA3 hash" $tls.JA3Hash; Write-Kv "JA3" $tls.JA3; Write-Kv "JA4" $tls.JA4; Write-Kv "TLS probe HTTP" $tls.HttpVersion; Write-Color "      Note: JA3/JA4 above belongs to this PowerShell/curl TLS request, not necessarily Chrome/Edge/Claude Code." DarkGray }
else { Write-Kv "JA3/JA4" "N/A - tls.peet.ws probe failed" }
$fpPath = New-BrowserFingerprintHtml
Write-Kv "Canvas/WebGL" "PowerShell cannot measure browser Canvas/WebGL directly. Local browser test generated."
Write-Kv "Browser test file" $fpPath
try { Start-Process $fpPath } catch {}
Write-Kv "Geo DB caveat" "hosting=false is not equal to residential; it only means this DB did not flag hosting"
Write-Kv "PowerShell" ($PSVersionTable.PSVersion.ToString())

Write-Host "`n------------------------------------------------------------"
Write-Host "Final Notes:"
Write-Host "  1. Read IPv4/IPv6 egress, DNS records, NTP/UDP behavior, TLS fingerprint, and HTTPS reachability together."
Write-Host "  2. 403/404/429 only means this single request was rejected, not found, or rate-limited. It does not prove account risk-control status."
Write-Host "  3. Canvas/WebGL fingerprints must be checked in a real browser; this script creates a local HTML helper for that."
Write-Host "------------------------------------------------------------"
