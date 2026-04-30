# 🕵️ Claude IP Check

> **Network consistency & DNS behavior diagnostics for Claude / Anthropic environments**
>  A practical tool to inspect **real network behavior (DNS / HTTP / TLS)** for routing and consistency troubleshooting.

------

## ⚠️ Scope & Disclaimer

- ❌ Does **not** determine account risk or bans
- ❌ Does **not** guarantee IP “cleanliness”
- ❌ Not a bypass or evasion tool

✔️ Designed for:

- Proxy / routing validation
- DNS behavior inspection (actual responses)
- Egress consistency analysis
- Claude-related connectivity debugging

------

## 🎯 Design Goals

- **Show, don’t guess** — report actual responses
- **Cross-validate** — system, active, and public resolvers
- **Deterministic output** — clear, explainable results
- **Minimal assumptions** — avoid “should be” logic

------

## ✨ Features

------

### 🌍 1. Egress Detection

- IPv4 / IPv6 public IP
- Cloudflare trace (`/cdn-cgi/trace`)
- `claude.ai` edge perspective (Cloudflare layer)

**Purpose:**

- Verify routing is applied
- Detect IPv6 leaks
- Confirm consistent exit region

------

### 🌐 2. Local DNS Snapshot

- System DNS per interface
- Default route DNS
- Active resolver

**Purpose:**

- Detect internal DNS (e.g. `10.x.x.x`)
- Identify mixed resolvers
- Spot virtual adapter interference

------

### 🔍 3. DNS Behavior Inspection (Core Feature)

Displays **actual responses** from multiple resolvers:

```
anthropic.com
  system    → 160.79.104.10
  active    → 160.79.104.10
  1.1.1.1   → 160.79.104.10
  8.8.8.8   → 160.79.104.10
  result    → CONSISTENT
```

------

### 🧠 Result Types

| Result                | Meaning                                      |
| --------------------- | -------------------------------------------- |
| `CONSISTENT`          | All resolvers agree                          |
| `NXDOMAIN`            | All resolvers report non-existent domain     |
| `INCONSISTENT`        | Different resolvers return different results |
| `DNS_REWRITE_SUSPECT` | Resolver returns its own IP / reserved IP    |
| `MULTI_ANSWER`        | Multiple IPs (CDN / load balancing)          |

> This tool reports **observed DNS behavior**, not assumptions.

------

### 🛰️ 4. Telemetry Domain Check

Checks:

- `sentry.io`
- `statsigapi.net`
- `browser-intake-us5-datadoghq.com`

**Purpose:**

- Detect sinkhole (e.g. `5.6.7.8`)
- Verify monitoring endpoints routing

> Blocking or proxying depends on your policy

------

### 🔗 5. HTTPS Reachability Scan

Scans full Claude domain set:

- core
- CDN
- auth/content
- telemetry
- third-party widgets

| Status       | Meaning                |
| ------------ | ---------------------- |
| 🟢 2xx / 3xx  | OK                     |
| 🟡 4xx        | Reachable but abnormal |
| 🔴 FAIL / 5xx | Unreachable or error   |

------

### ⏱️ 6. UDP / NTP Probe

Tests:

- `time.cloudflare.com`
- `time.google.com`
- `pool.ntp.org`
- `time.windows.com`

**Purpose:**

- Verify UDP reachability
- Detect potential timezone leakage path

> Does not guarantee proxy handles UDP

------

### 🧬 7. Metadata & TLS Fingerprint

Includes:

- User-Agent
- System timezone
- JA3 / JA4 (from current TLS request)

------

### 🖥️ Browser Fingerprint Helper

Generates local HTML for:

- Canvas fingerprint
- WebGL fingerprint

> Must be opened in a real browser

------

## 🧩 Domain Coverage

Aligned with full routing rule set:

- **Core**: `anthropic.com`, `claude.ai`, `claude.com`, `clau.de`
- **MCP / content**: `claudeusercontent.com`, `claudemcp*`
- **CDN**: `cdn.anthropic.com`, `*.cloudflare.net`, `*.b-cdn.net`
- **Auth/content**: `auth0`, `console`, `ghost`, `mcp`, `workbench`
- **Telemetry**: `datadog`, `sentry`, `statsig`
- **Widgets**: `intercom`, `fathom`

Fallback (not probed directly):

- keyword rules
- geosite rules
- IP-CIDR / ASN

------

## 🚀 Usage

### 🪟 Windows

```
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force; .\ClaudeCheck.v2.8.fixed.ps1
```

------

### 🐧 Linux

```
chmod +x ClaudeCheck.v2.8.linux.sh && ./ClaudeCheck.v2.8.linux.sh
```

------

### 🍎 macOS

```
brew install bash curl jq bind coreutils && chmod +x ClaudeCheck.v2.8.linux.sh && "$(brew --prefix)/bin/bash" ./ClaudeCheck.v2.8.linux.sh
```

------

## 📦 Dependencies

- **Linux**: curl, jq, dig, openssl
- **macOS**: Homebrew, bash (modern), bind, coreutils
- **Windows**: built-in PowerShell + nslookup

------

## 🧠 Interpreting Results

Avoid single-point conclusions.

Evaluate together:

- Egress IP (IPv4 / IPv6)
- DNS behavior consistency
- HTTPS reachability
- TLS fingerprint
- Timezone / NTP

------

### ❌ Common Misconceptions

- “Foreign IP = safe”
- “403 = blocked by risk control”
- “NXDOMAIN = error”

------

### ✅ Reality

This is a **consistency problem**, not a single signal.

------

## 📌 Limitations

- Cloudflare trace ≠ Anthropic backend view
- Geo/IP DB ≠ authoritative classification
- JA3/JA4 ≠ browser fingerprint
- Cannot detect:
  - browser extensions
  - fingerprint spoofing
- UDP probe ≠ proxy verification

------

## 🧾 Philosophy

- Measure **what happens**, not what should happen
- Prefer **consistency over theory**
- Provide **actionable diagnostics**
