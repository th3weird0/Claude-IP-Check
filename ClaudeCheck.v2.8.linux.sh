#!/usr/bin/env bash
# shellcheck shell=bash
# =============================================================================
# ClaudeCheck v2.8 - Linux / macOS Bash Edition
# Purpose: troubleshoot routing, DNS, IPv4/IPv6, TLS fingerprint and domain
# reachability for Claude / Anthropic related services.
# Note: this script does NOT prove account safety, risk-control status, or IP purity.
# =============================================================================

set -u

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0"
TIMEOUT_SEC="8"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
PLAIN='\033[0m'

CoreDomains=(
  "anthropic.com"
  "api.anthropic.com"
  "claude.ai"
  "claude.com"
  "clau.de"
  "claudemcpclient.com"
  "claudemcpcontent.com"
  "claudeusercontent.com"
)
CdnDomains=(
  "cdn.anthropic.com"
  "anthropic.com.cdn.cloudflare.net"
  "servd-anthropic-website.b-cdn.net"
)
AuthContentDomains=(
  "anthropic.auth0.com"
  "anthropic-com.ghost.io"
  "console.anthropic.com"
  "mcp.anthropic.com"
  "workbench.anthropic.com"
)
TelemetryDomains=(
  "browser-intake-us5-datadoghq.com"
  "sentry.io"
  "statsigapi.net"
)
ThirdPartyWidgetDomains=(
  "intercom.io"
  "intercomcdn.com"
  "cdn.usefathom.com"
)
DomainList=(
  "${CoreDomains[@]}"
  "${CdnDomains[@]}"
  "${AuthContentDomains[@]}"
  "${TelemetryDomains[@]}"
  "${ThirdPartyWidgetDomains[@]}"
)
PublicDns=("1.1.1.1" "8.8.8.8")
NtpServers=("time.cloudflare.com" "time.google.com" "pool.ntp.org" "time.windows.com")
KeywordFallbackRules=("keyword:datadog" "keyword:sentry" "keyword:sift" "geosite:anthropic" "geosite:category-ntp")
IpFallbackRules=("160.79.104.0/21" "2607:6bc0::/32" "AS399358")

cprint() { printf "%b%s%b\n" "$2" "$1" "$PLAIN"; }
kv() { printf '   |-- %-24s: %s\n' "$1" "$2"; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

need_cmds=(curl jq)
missing=()
for cmd in "${need_cmds[@]}"; do has_cmd "$cmd" || missing+=("$cmd"); done
if ! has_cmd dig && ! has_cmd nslookup; then missing+=("dig-or-nslookup"); fi
if ((${#missing[@]} > 0)); then
  cprint "Missing dependencies: ${missing[*]}" "$YELLOW"
  cprint "Linux: sudo apt update && sudo apt install -y curl jq dnsutils openssl" "$GRAY"
  cprint "macOS: brew install bash curl jq bind openssl coreutils" "$GRAY"
fi

web_text() {
  local uri="$1"
  curl -L -sS --max-time "$TIMEOUT_SEC" -A "$UA" "$uri" 2>/dev/null || true
}

get_public_ip() {
  local fam="$1" ip=""
  if [[ "$fam" == "v4" ]]; then
    ip=$(curl -4 -sS --max-time "$TIMEOUT_SEC" -A "$UA" https://ifconfig.co/ip 2>/dev/null | tr -d '[:space:]' || true)
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && printf '%s' "$ip" && return
    ip=$(web_text https://api.ipify.org | tr -d '[:space:]')
  else
    ip=$(curl -6 -sS --max-time "$TIMEOUT_SEC" -A "$UA" https://ifconfig.co/ip 2>/dev/null | tr -d '[:space:]' || true)
    [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && printf '%s' "$ip" && return
    ip=$(curl -6 -sS --max-time "$TIMEOUT_SEC" -A "$UA" https://api6.ipify.org 2>/dev/null | tr -d '[:space:]' || true)
  fi
  printf '%s' "$ip"
}

get_cf_trace_ip() {
  local host="$1"
  web_text "https://${host}/cdn-cgi/trace" | awk -F= '/^ip=/{print $2; exit}' | tr -d '\r'
}

get_geo_json() {
  local ip="$1"
  [[ -z "$ip" ]] && return 1
  web_text "http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,isp,as,hosting,proxy,query"
}

write_geo_line() {
  local label="$1" ip="$2" geo status cc country city isp asn hosting proxy property color
  if [[ -z "$ip" ]]; then
    printf '   |-- %-24s: ' "$label"; cprint "N/A" "$YELLOW"; return
  fi
  geo=$(get_geo_json "$ip")
  status=$(jq -r '.status // empty' <<<"$geo" 2>/dev/null)
  if [[ "$status" != "success" ]]; then
    printf '   |-- %-24s: %-15s | Geo lookup failed\n' "$label" "$ip"; return
  fi
  cc=$(jq -r '.countryCode // "--"' <<<"$geo")
  country=$(jq -r '.country // "Unknown"' <<<"$geo")
  city=$(jq -r '.city // "Unknown"' <<<"$geo")
  isp=$(jq -r '.isp // "Unknown"' <<<"$geo")
  asn=$(jq -r '.as // "Unknown"' <<<"$geo")
  hosting=$(jq -r '.hosting // false' <<<"$geo")
  proxy=$(jq -r '.proxy // false' <<<"$geo")
  property="√ not flagged as hosting/proxy by ip-api"; color="$GREEN"
  if [[ "$hosting" == "true" && "$proxy" == "true" ]]; then property="× flagged as hosting/datacenter + proxy by ip-api"; color="$RED";
  elif [[ "$hosting" == "true" ]]; then property="× flagged as hosting/datacenter by ip-api"; color="$RED";
  elif [[ "$proxy" == "true" ]]; then property="× flagged as proxy by ip-api"; color="$RED"; fi
  printf '   |-- %-24s: %s %-15s | %s - %s | ISP: %s | ' "$label" "$cc" "$ip" "$country" "$city" "$isp"
  cprint "$property" "$color"
  printf '       %-24s  %s\n' 'ASN:' "$asn"
}

get_system_dns_servers() {
  local servers=()
  if has_cmd resolvectl; then
    while IFS= read -r s; do [[ "$s" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && servers+=("$s"); done < <(resolvectl dns 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' || true)
  fi
  if ((${#servers[@]} == 0)) && [[ -f /etc/resolv.conf ]]; then
    while read -r _ s _; do [[ "$s" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && servers+=("$s"); done < <(grep -E '^nameserver[[:space:]]+' /etc/resolv.conf || true)
  fi
  if ((${#servers[@]} == 0)) && [[ "$(uname -s)" == "Darwin" ]] && has_cmd scutil; then
    while IFS= read -r s; do [[ "$s" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && servers+=("$s"); done < <(scutil --dns 2>/dev/null | awk '/nameserver\[[0-9]+\]/{print $3}' || true)
  fi
  printf '%s\n' "${servers[@]}" | awk '!seen[$0]++'
}

get_default_routes_snapshot() {
  if has_cmd ip; then
    ip route show default 2>/dev/null | sed 's/^/   |-- Default route: /'
    ip -6 route show default 2>/dev/null | sed 's/^/   |-- IPv6 default route: /'
  elif [[ "$(uname -s)" == "Darwin" ]]; then
    route -n get default 2>/dev/null | awk '/gateway|interface/{gsub(/^[ \t]+/,""); print "   |-- Default route: "$0}'
    route -n get -inet6 default 2>/dev/null | awk '/gateway|interface/{gsub(/^[ \t]+/,""); print "   |-- IPv6 default route: "$0}'
  fi
}

get_dns_snapshot() {
  if has_cmd resolvectl; then
    resolvectl dns 2>/dev/null | sed 's/^/   |-- /'
  elif [[ -f /etc/resolv.conf ]]; then
    grep -E '^nameserver[[:space:]]+' /etc/resolv.conf | sed 's/^/   |-- /'
  fi
  if [[ "$(uname -s)" == "Darwin" ]] && has_cmd scutil; then
    scutil --dns 2>/dev/null | awk '/resolver #|nameserver\[[0-9]+\]/{gsub(/^[ \t]+/,""); print "   |-- "$0}'
  fi
}

# DNS detail format: STATUS|ip1,ip2
resolve_dns_detailed() {
  local domain="$1" type="$2" server="${3:-}" out status ips
  if has_cmd dig; then
    if [[ -n "$server" ]]; then
      out=$(dig +time=3 +tries=1 "$domain" "$type" "@$server" 2>&1 || true)
      ips=$(dig +time=3 +tries=1 +short "$domain" "$type" "@$server" 2>/dev/null | grep -E '^[0-9a-fA-F:.]+$' | paste -sd, -)
    else
      out=$(dig +time=3 +tries=1 "$domain" "$type" 2>&1 || true)
      ips=$(dig +time=3 +tries=1 +short "$domain" "$type" 2>/dev/null | grep -E '^[0-9a-fA-F:.]+$' | paste -sd, -)
    fi
    status=$(awk -F'status: ' '/status:/{split($2,a,","); print a[1]; exit}' <<<"$out")
    [[ -z "$status" ]] && status="NO_ANSWER"
    if [[ -n "$ips" ]]; then status="NOERROR"; fi
    case "$status" in NOERROR|NXDOMAIN|SERVFAIL|REFUSED) ;; *)
      if grep -qi 'timed out\|no servers could be reached' <<<"$out"; then status="TIMEOUT"; fi
      ;;
    esac
    printf '%s|%s' "$status" "$ips"
    return
  fi

  if has_cmd nslookup; then
    if [[ -n "$server" ]]; then out=$(nslookup -type="$type" "$domain" "$server" 2>&1 || true); else out=$(nslookup -type="$type" "$domain" 2>&1 || true); fi
    # Parse only lines after Name:, avoiding Server/Address resolver lines.
    ips=$(awk -v t="$type" '
      BEGIN{inans=0}
      /^[[:space:]]*(Name|名稱)[[:space:]]*[:：]/{inans=1; next}
      inans && t=="A" && $0 ~ /([0-9]{1,3}\.){3}[0-9]{1,3}/ { while (match($0,/([0-9]{1,3}\.){3}[0-9]{1,3}/)) { print substr($0,RSTART,RLENGTH); $0=substr($0,RSTART+RLENGTH) } }
      inans && t=="AAAA" && $0 ~ /([0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}/ { while (match($0,/([0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}/)) { print substr($0,RSTART,RLENGTH); $0=substr($0,RSTART+RLENGTH) } }
    ' <<<"$out" | awk '!seen[$0]++' | paste -sd, -)
    if [[ -n "$ips" ]]; then status="NOERROR"
    elif grep -qiE 'NXDOMAIN|Non-existent domain|can.t find|不存在|找不到' <<<"$out"; then status="NXDOMAIN"
    elif grep -qiE 'SERVFAIL|server failed' <<<"$out"; then status="SERVFAIL"
    elif grep -qiE 'REFUSED' <<<"$out"; then status="REFUSED"
    elif grep -qiE 'timed out|timeout|No response' <<<"$out"; then status="TIMEOUT"
    else status="NO_ANSWER"; fi
    printf '%s|%s' "$status" "$ips"
    return
  fi
  printf 'ERROR|'
}

format_dns_detailed() {
  local result="$1" server="${2:-}" status ips invalid real=()
  status="${result%%|*}"; ips="${result#*|}"
  [[ -z "$ips" || "$ips" == "$result" ]] && { printf '%s' "$status"; return; }
  IFS=',' read -r -a arr <<<"$ips"
  invalid=("1.1.1.1" "8.8.8.8")
  [[ -n "$server" ]] && invalid+=("$server")
  for ip in "${arr[@]}"; do
    local isbad=0
    for bad in "${invalid[@]}"; do [[ "$ip" == "$bad" ]] && isbad=1; done
    ((isbad == 0)) && real+=("$ip")
  done
  if ((${#real[@]} == 0)); then printf 'INVALID(%s) / %s' "$ips" "$status"; else printf '%s / %s' "$ips" "$status"; fi
}

dns_verdict() {
  local all="$*" ips=() statuses=() resolver_ips=() invalid=()
  resolver_ips=("${SystemDns[@]}" "${PublicDns[@]}")
  for r in "$@"; do
    local st="${r%%|*}" ipstr="${r#*|}"
    [[ -n "$st" ]] && statuses+=("$st")
    if [[ -n "$ipstr" && "$ipstr" != "$r" ]]; then IFS=',' read -r -a tmp <<<"$ipstr"; ips+=("${tmp[@]}"); fi
  done
  mapfile -t ips < <(printf '%s\n' "${ips[@]:-}" | awk 'NF && !seen[$0]++')
  mapfile -t statuses < <(printf '%s\n' "${statuses[@]:-}" | awk 'NF && !seen[$0]++')
  if ((${#ips[@]} == 0)); then
    if ((${#statuses[@]} > 0)); then
      local only_nx=1
      for s in "${statuses[@]}"; do [[ "$s" != "NXDOMAIN" ]] && only_nx=0; done
      ((only_nx == 1)) && { printf 'NXDOMAIN'; return; }
      printf '%s' "$(IFS=/; echo "${statuses[*]}")"; return
    fi
    printf 'NO_ANSWER'; return
  fi
  for ip in "${ips[@]}"; do for r in "${resolver_ips[@]}"; do [[ "$ip" == "$r" ]] && invalid+=("$ip"); done; done
  mapfile -t invalid < <(printf '%s\n' "${invalid[@]:-}" | awk 'NF && !seen[$0]++')
  if ((${#invalid[@]} > 0)); then printf 'DNS_REWRITE_SUSPECT (%s)' "$(IFS=,; echo "${invalid[*]}")"; return; fi
  if ((${#ips[@]} == 1)); then printf 'CONSISTENT'; else printf 'MULTI_ANSWER / CDN_OR_INCONSISTENT'; fi
}

test_sinkhole() {
  local s="$1"
  [[ "$s" =~ (^|,)(0\.0\.0\.0|127\.|::1|::|5\.6\.7\.8)(,|[[:space:]]|$) ]]
}

http_probe() {
  local domain="$1" fam="$2" farg=()
  [[ "$fam" == "v4" ]] && farg=(-4)
  [[ "$fam" == "v6" ]] && farg=(-6)
  local out
  out=$(curl "${farg[@]}" -sS -o /dev/null -w '%{http_code} %{time_total} %{remote_ip}' --max-time "$TIMEOUT_SEC" -A "$UA" "https://${domain}" 2>/dev/null || true)
  if [[ "$out" =~ ^([0-9]{3})[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+) ]]; then
    printf '%s|%s|%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
  else
    printf '000|N/A|N/A'
  fi
}

http_label_color() {
  local code="$1"
  if [[ -z "$code" || "$code" == "000" ]]; then printf 'FAIL|%s' "$RED"; return; fi
  if [[ "$code" =~ ^[0-9]+$ ]]; then
    if ((code >= 200 && code < 400)); then printf '%s|%s' "$code" "$GREEN"; return; fi
    case "$code" in 401|403|404|405|406|409|421|425|429) printf '%s WARN|%s' "$code" "$YELLOW"; return;; esac
    if ((code >= 500 && code <= 599)); then printf '%s ERR|%s' "$code" "$RED"; return; fi
  fi
  printf '%s WARN|%s' "$code" "$YELLOW"
}

ntp_probe() {
  local server="$1"
  if has_cmd perl; then
    perl -MIO::Socket::INET -MTime::HiRes=time -e '
      my $h=shift; my $t=shift || 8;
      my $s=IO::Socket::INET->new(PeerAddr=>$h,PeerPort=>123,Proto=>"udp",Timeout=>$t);
      if(!$s){print "FAIL|N/A|N/A"; exit}
      my $p=chr(0x1b).("\0" x 47); my $st=time(); $s->send($p); eval { local $SIG{ALRM}=sub{die "timeout"}; alarm($t); my $buf=""; my $peer=$s->recv($buf,48); alarm(0); my $dt=time()-$st; if(length($buf)>=48){print "OK|".sprintf("%.3f",$dt)."|$h:123"} else {print "BAD_REPLY|".sprintf("%.3f",$dt)."|$h:123"} }; if($@){print "FAIL|N/A|N/A"}
    ' "$server" "$TIMEOUT_SEC" 2>/dev/null
  else
    printf 'SKIP|N/A|perl-not-found'
  fi
}

tls_fingerprint() {
  local json
  json=$(web_text https://tls.peet.ws/api/all)
  [[ -z "$json" ]] && return 1
  jq -r '[.tls.ja3_hash // "N/A", .tls.ja3 // "N/A", .tls.ja4 // "N/A", .http_version // "N/A"] | @tsv' <<<"$json" 2>/dev/null || return 1
}

make_browser_fingerprint_html() {
  local path="$PWD/ClaudeCheck.browser-fingerprint.html"
  cat > "$path" <<'HTML'
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
HTML
  printf '%s' "$path"
}

open_file() {
  local path="$1"
  if [[ "$(uname -s)" == "Darwin" ]] && has_cmd open; then open "$path" >/dev/null 2>&1 || true
  elif has_cmd xdg-open; then xdg-open "$path" >/dev/null 2>&1 || true
  fi
}

domain_group() {
  local d="$1"
  for x in "${CoreDomains[@]}"; do [[ "$d" == "$x" ]] && echo core && return; done
  for x in "${CdnDomains[@]}"; do [[ "$d" == "$x" ]] && echo cdn && return; done
  for x in "${AuthContentDomains[@]}"; do [[ "$d" == "$x" ]] && echo auth/content && return; done
  for x in "${TelemetryDomains[@]}"; do [[ "$d" == "$x" ]] && echo telemetry && return; done
  for x in "${ThirdPartyWidgetDomains[@]}"; do [[ "$d" == "$x" ]] && echo widget && return; done
  echo other
}

cprint "============================================================" "$CYAN"
cprint "   ClaudeCheck v2.8 - Network Environment Self-Test for Linux/macOS" "$CYAN"
cprint "   Report Generated: $(date '+%Y-%m-%d %H:%M:%S %z')" "$CYAN"
cprint "============================================================" "$CYAN"
cprint "Note: This tool helps troubleshoot routing/DNS/reachability. It cannot certify account safety or IP purity." "$GRAY"
cprint "Domain gold-set loaded: ${#DomainList[@]} exact HTTPS domains; plus $((${#KeywordFallbackRules[@]} + ${#IpFallbackRules[@]})) keyword/geosite/IP fallback references and ${#NtpServers[@]} NTP servers." "$GRAY"

echo -e "\n[1/7] Public egress compare: IPv4 / IPv6 / Cloudflare Trace"
IPv4=$(get_public_ip v4)
IPv6=$(get_public_ip v6)
CfIp=$(get_cf_trace_ip 1.1.1.1)
ClaudeCfIp=$(get_cf_trace_ip claude.ai)
write_geo_line "IPv4 egress" "$IPv4"
write_geo_line "IPv6 egress" "$IPv6"
write_geo_line "Cloudflare trace" "$CfIp"
write_geo_line "claude.ai CF trace" "$ClaudeCfIp"
cprint "      Note: claude.ai /cdn-cgi/trace only shows what that Cloudflare request sees. It is not Anthropic's internal risk-control result." "$GRAY"

echo -e "\n[2/7] Local DNS configuration snapshot"
get_dns_snapshot || true
get_default_routes_snapshot || true
mapfile -t SystemDns < <(get_system_dns_servers)
if ((${#SystemDns[@]} > 0)); then printf '   |-- Preferred IPv4 DNS for active routes: %s\n' "$(IFS=,; echo "${SystemDns[*]}")"; fi

echo -e "\n[3/7] DNS compare: system resolver / active DNS server / public DNS"
for dm in "${DomainList[@]}"; do
  sysAObj=$(resolve_dns_detailed "$dm" A)
  sysAAAAObj=$(resolve_dns_detailed "$dm" AAAA)
  sysA=$(format_dns_detailed "$sysAObj")
  sysAAAA=$(format_dns_detailed "$sysAAAAObj")
  printf '   |-- %-38s\n' "$dm"
  printf '       %-10s A:    %s\n' system "$sysA"
  printf '       %-10s AAAA: %s\n' system "$sysAAAA"
  verdict_inputs=("$sysAObj" "$sysAAAAObj")
  if ((${#SystemDns[@]} > 0)); then
    active="${SystemDns[0]}"
    activeAObj=$(resolve_dns_detailed "$dm" A "$active")
    activeA=$(format_dns_detailed "$activeAObj" "$active")
    verdict_inputs+=("$activeAObj")
    printf '       @%-9s A:    %s  [active DNS]\n' "$active" "$activeA"
  fi
  for dns in "${PublicDns[@]}"; do
    pubAObj=$(resolve_dns_detailed "$dm" A "$dns")
    pubA=$(format_dns_detailed "$pubAObj" "$dns")
    verdict_inputs+=("$pubAObj")
    printf '       @%-9s A:    %s\n' "$dns" "$pubA"
  done
  verdict=$(dns_verdict "${verdict_inputs[@]}")
  printf '       %-10s %s\n' 'result:' "$verdict"
done
cprint "      Note: DNS section shows returned records plus resolver status code (NOERROR / NXDOMAIN / SERVFAIL / REFUSED / TIMEOUT / ERROR)." "$GRAY"
cprint "      Note: NXDOMAIN is only shown when the resolver explicitly reports non-existent domain; generic failures are not converted to NXDOMAIN." "$GRAY"
cprint "      Note: A records equal to resolver IPs like 10.0.0.3 / 1.1.1.1 / 8.8.8.8 are marked INVALID/DNS_REWRITE_SUSPECT." "$GRAY"

echo -e "\n[4/7] Telemetry/monitoring domain DNS status"
for td in "${TelemetryDomains[@]}"; do
  rawAObj=$(resolve_dns_detailed "$td" A); rawAAAAObj=$(resolve_dns_detailed "$td" AAAA)
  rawA=$(format_dns_detailed "$rawAObj"); rawAAAA=$(format_dns_detailed "$rawAAAAObj")
  printf '   |-- %-38s: ' "$td"
  if [[ "$rawA" == "NO_ANSWER" && "$rawAAAA" == "NO_ANSWER" ]]; then cprint "NO_ANSWER" "$YELLOW"
  elif [[ "$rawA" == "NXDOMAIN" && "$rawAAAA" == "NXDOMAIN" ]]; then printf '%bNXDOMAIN%b | A=%s AAAA=%s\n' "$YELLOW" "$PLAIN" "$rawA" "$rawAAAA"
  elif test_sinkhole "$rawA,$rawAAAA"; then printf '%bINTERCEPTED/SINKHOLED%b | A=%s AAAA=%s\n' "$GREEN" "$PLAIN" "$rawA" "$rawAAAA"
  else printf '%bRESOLVES%b | A=%s AAAA=%s\n' "$YELLOW" "$PLAIN" "$rawA" "$rawAAAA"; fi
done
cprint "      Note: RESOLVES only means DNS returns records. Whether to block it depends on your privacy policy and service requirements." "$GRAY"

echo -e "\n[5/7] Claude / Anthropic HTTPS reachability scan (gold-standard domain set)"
printf '   |-- %-35s %-12s %-6s %-10s %-10s %-15s\n' Domain Group Stack HTTP 'Total(s)' 'Remote IP'
for dm in "${DomainList[@]}"; do
  group=$(domain_group "$dm")
  for fam in v4 v6; do
    [[ "$fam" == "v6" && -z "$IPv6" ]] && continue
    probe=$(http_probe "$dm" "$fam")
    IFS='|' read -r code total remote <<<"$probe"
    lblcol=$(http_label_color "$code")
    label="${lblcol%%|*}"; color="${lblcol#*|}"
    printf '   |-- %-35s %-12s %-6s ' "$dm" "$group" "$fam"
    printf '%b%-10s%b' "$color" "$label" "$PLAIN"
    printf ' %-10s %-15s\n' "$total" "$remote"
  done
done
cprint "      Legend: green=normal success/redirect (2xx/3xx), yellow=reachable but abnormal/warning (401/403/404/405/429 etc.), red=no response or 5xx/failure." "$GRAY"
cprint "      Fallback references not probed as HTTPS domains: ${KeywordFallbackRules[*]}, ${IpFallbackRules[*]}" "$GRAY"

echo -e "\n[6/7] UDP/NTP reachability probe"
printf '   |-- %-28s %-10s %-10s %-24s\n' Server Status 'RTT(s)' Remote
for ntp in "${NtpServers[@]}"; do
  r=$(ntp_probe "$ntp")
  IFS='|' read -r st rtt remote <<<"$r"
  color="$YELLOW"; [[ "$st" == "OK" ]] && color="$GREEN"; [[ "$st" == "FAIL" ]] && color="$RED"
  printf '   |-- %-28s ' "$ntp"
  printf '%b%-10s%b' "$color" "$st" "$PLAIN"
  printf ' %-10s %-24s\n' "$rtt" "$remote"
done
cprint "      Note: This only tests UDP/123 reachability from this OS. It cannot prove your proxy client actually forwards NTP unless your proxy stack supports UDP and you verify its logs." "$GRAY"

echo -e "\n[7/7] Local metadata / TLS / browser fingerprint helpers"
kv "User-Agent used" "$UA"
if has_cmd timedatectl; then kv "System timezone" "$(timedatectl 2>/dev/null | awk -F': ' '/Time zone/{print $2; exit}')"; else kv "System timezone" "$(date +%Z)"; fi
if tlsline=$(tls_fingerprint); then
  IFS=$'\t' read -r ja3h ja3 ja4 httpv <<<"$tlsline"
  kv "JA3 hash" "$ja3h"; kv "JA3" "$ja3"; kv "JA4" "$ja4"; kv "TLS probe HTTP" "$httpv"
  cprint "      Note: JA3/JA4 above belongs to this curl TLS request, not necessarily Chrome/Edge/Claude Code." "$GRAY"
else
  kv "JA3/JA4" "N/A - tls.peet.ws probe failed"
fi
fpPath=$(make_browser_fingerprint_html)
kv "Canvas/WebGL" "Shell cannot measure browser Canvas/WebGL directly. Local browser test generated."
kv "Browser test file" "$fpPath"
open_file "$fpPath"
kv "Geo DB caveat" "hosting=false is not equal to residential; it only means this DB did not flag hosting"
kv "Shell" "${BASH_VERSION}"

echo -e "\n------------------------------------------------------------"
echo "Final Notes:"
echo "  1. Read IPv4/IPv6 egress, DNS records, NTP/UDP behavior, TLS fingerprint, and HTTPS reachability together."
echo "  2. 403/404/429 only means this single request was rejected, not found, or rate-limited. It does not prove account risk-control status."
echo "  3. Canvas/WebGL fingerprints must be checked in a real browser; this script creates a local HTML helper for that."
echo "------------------------------------------------------------"
