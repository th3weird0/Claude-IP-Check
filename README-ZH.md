- # 🕵️ Claude IP Check

  > **Network consistency & DNS behavior diagnostics for Claude / Anthropic environments**
  >  面向工程排查的自检工具：展示**真实返回结果（DNS / HTTP / TLS）**，用于定位分流与连通性问题。

  ------

  ## ⚠️ Scope & Disclaimer

  - ❌ 不判断账号是否会被风控
  - ❌ 不承诺 IP “纯净/安全”
  - ❌ 不是绕过/解封工具

  ✔️ 适用场景：

  - 分流规则验证（Clash / sing-box / Surge 等）
  - DNS 行为排查（真实返回 vs 预期）
  - 出口一致性（IPv4/IPv6 / CF 边缘）
  - Claude 相关域名连通性诊断

  ------

  ## 🎯 Design Goals

  - **Show, don’t guess**：展示每个解析器/请求的**实际返回**
  - **Cross-check**：系统解析、活动 DNS、公共 DNS 对比
  - **Deterministic output**：给出明确的 `result`（一致/异常类型）
  - **Low assumptions**：避免把“理论正确”当成“现实结果”

  ------

  ## ✨ Features

  ### 1) Egress Detection（出口对比）

  - IPv4 / IPv6 出口
  - Cloudflare `/cdn-cgi/trace`
  - `claude.ai` 边缘视角（CF 层）

  **用途**：确认分流是否生效、是否存在 IPv6 泄露、出口是否一致

  ------

  ### 2) Local DNS Snapshot（本地 DNS 快照）

  - 各接口 DNS（含虚拟网卡）
  - 默认路由与活动 DNS

  **用途**：识别内网 DNS（如 `10.x.x.x`）、多 DNS 混用、网卡干扰

  ------

  ### 3) DNS Behavior Inspection（核心能力）

  对同一域名，展示多解析路径的**实际返回**：

  ```
  anthropic.com
    system    → 160.79.104.10
    active    → 160.79.104.10
    1.1.1.1   → 160.79.104.10
    8.8.8.8   → 160.79.104.10
    result    → CONSISTENT
  ```

  #### Result 定义

  | Result                | 含义                                      |
  | --------------------- | ----------------------------------------- |
  | `CONSISTENT`          | 各解析器结果一致                          |
  | `NXDOMAIN`            | 各解析器一致返回不存在                    |
  | `INCONSISTENT`        | 不同解析器返回不同 IP                     |
  | `DNS_REWRITE_SUSPECT` | 返回 DNS 服务器/保留地址（疑似污染/重写） |
  | `MULTI_ANSWER`        | CDN 多节点（多 IP）                       |

  > 设计原则：**只报告观测到的行为**，不推测“是否应该存在”。

  ------

  ### 4) Telemetry Domain Check（监控域名）

  检测：

  - `sentry.io`
  - `statsigapi.net`
  - `browser-intake-us5-datadoghq.com`

  **用途**：识别是否被 sinkhole（如 `5.6.7.8`）或被拦截

  > 是否拦截取决于你的策略，本工具不做价值判断

  ------

  ### 5) HTTPS Reachability（连通性扫描）

  对 Claude 全量域名（core / cdn / auth / telemetry / widget）做 HTTPS 探测：

  | 标记           | 含义                         |
  | -------------- | ---------------------------- |
  | 🟢 `2xx / 3xx`  | 正常                         |
  | 🟡 `4xx`        | 可达但异常（如 403/404/429） |
  | 🔴 `FAIL / 5xx` | 不可达或错误                 |

  ------

  ### 6) UDP / NTP Probe

  测试：

  - `time.cloudflare.com`
  - `time.google.com`
  - `pool.ntp.org`
  - `time.windows.com`

  **用途**：验证 UDP/123 可达性（是否可能存在时区侧信号）

  > 仅验证连通性，不等价于“代理已接管 UDP”

  ------

  ### 7) Metadata & TLS Fingerprint

  - User-Agent
  - System Timezone
  - JA3 / JA4（基于当前 TLS 请求）

  **附加**：生成本地 HTML 用于浏览器 **Canvas / WebGL** 指纹检测

  > 需在浏览器中打开

  ------

  ## 🧩 Domain Set（与分流规则对齐）

  脚本内置与“Claude Code 分流规则”一致的域名集合：

  - Core：`anthropic.com`, `claude.ai`, `claude.com`, `clau.de`, `claudeusercontent.com`, `claudemcp*`
  - CDN：`cdn.anthropic.com`, `anthropic.com.cdn.cloudflare.net`, `*.b-cdn.net`
  - Auth/Content：`anthropic.auth0.com`, `console.anthropic.com`, `*.ghost.io`, `mcp.*`, `workbench.*`
  - Telemetry：`sentry.io`, `statsigapi.net`, `browser-intake-us5-datadoghq.com`
  - Widget：`intercom.io`, `intercomcdn.com`, `cdn.usefathom.com`

  > 关键词 / geosite / IP-CIDR / ASN 作为**规则引擎兜底**，不作为 HTTPS 探测目标。

  ------

  ## 🚀 Usage

  ### Windows

  ```
  powershell -ExecutionPolicy Bypass -File .\ClaudeCheck.v2.8.ps1
  ```

  ### Linux

  ```
  chmod +x ClaudeCheck.v2.8.linux.sh && ./ClaudeCheck.v2.8.linux.sh
  ```

  ### macOS

  ```
  brew install bash curl jq bind coreutils && chmod +x ClaudeCheck.v2.8.linux.sh && "$(brew --prefix)/bin/bash" ./ClaudeCheck.v2.8.linux.sh
  ```

  ------

  ## 📦 Dependencies

  - **Linux**: `curl`, `jq`, `dig` (bind/dnsutils), `openssl`
  - **macOS**: Homebrew, `bash`(新版本), `bind`, `coreutils`
  - **Windows**: 内置 `nslookup` / PowerShell

  ------

  ## 🧠 Interpreting Results

  **不要单点判断**。建议联合查看：

  - 出口（IPv4/IPv6 / CF）
  - DNS 行为（是否一致 / 是否重写）
  - HTTPS 连通性
  - TLS / 时区 / NTP

  常见误区：

  - “IP 在海外 = 一切正常”
  - “403 = 风控”
  - “NXDOMAIN = 错误（很多子域本就不存在）”

  ------

  ## 📌 Limitations

  - CF trace ≠ Anthropic 内部视角
  - Geo/IP 数据库 ≠ 权威 ISP 分类
  - JA3/JA4 ≠ 浏览器真实指纹
  - 无法检测浏览器插件或指纹伪装
  - UDP 仅做连通性验证（非代理接管证明）

  ------

  ## 🧪 Typical Signals

  - **DNS_REWRITE_SUSPECT**：解析返回 DNS 服务器/保留地址（污染/劫持/策略重写）
  - **INCONSISTENT**：系统与公共 DNS 返回不同（分流/DoH/策略差异）
  - **NXDOMAIN（全部一致）**：通常是正常（该子域不存在）
  - **HTTPS FAIL + DNS 正常**：更可能是分流/防火墙/规则问题

  ------

  ## 🧾 Philosophy

  - Prefer **observed behavior** over assumptions
  - Diagnose **consistency**, not “purity”
  - Keep output **deterministic and actionable**