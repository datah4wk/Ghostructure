# Threat Model

## Overview

This document describes the threat model for Ghostructure — a wildcard subdomain anti-enumeration infrastructure designed to eliminate reconnaissance signal from subdomain discovery attacks.

## Threat Actors

### Script Kiddies (Low Sophistication)

- **Tools:** amass, subfinder, gobuster, ffuf, dnsx
- **Behavior:** Automated wordlist-based subdomain enumeration, no manual analysis
- **Goal:** Quickly map exposed services to find low-hanging fruit (default creds, known CVEs)
- **Ghostructure effect:** Complete neutralization. Automated tools receive 100% identical responses and cannot differentiate real from fake subdomains.

### Targeted Attackers (Medium-High Sophistication)

- **Tools:** Custom scripts, passive DNS databases, CT log scrapers, Shodan/Censys
- **Behavior:** Combine active scanning with passive OSINT, analyze timing differences, inspect TLS certificates
- **Goal:** Map the full attack surface of a specific target for a focused campaign
- **Ghostructure effect:** Near-complete neutralization. Passive DNS shows only wildcard records. CT logs show only the wildcard certificate. Active scanning returns uniform responses. The only remaining signal is the VPN management endpoint, which is a known and hardened surface.

### Bug Bounty Hunters (Variable Sophistication)

- **Tools:** Mix of automated and manual, often creative/unconventional approaches
- **Behavior:** Attempt to enumerate subdomains to find in-scope assets, often try timing attacks and header analysis
- **Goal:** Find vulnerabilities in exposed services to claim bounties
- **Ghostructure effect:** Effective neutralization. Without the ability to discover internal services, the attack surface available for testing is reduced to only intentionally public endpoints.

## Attack Vectors

### 1. DNS Subdomain Bruteforce

- **Method:** Resolve thousands of subdomain names against the authoritative DNS server
- **Standard signal:** Real subdomains return A records, non-existent ones return NXDOMAIN
- **Ghostructure mitigation:** Wildcard A record ensures every possible subdomain resolves to the same IP. No NXDOMAIN responses ever.

### 2. Certificate Transparency Log Scraping

- **Method:** Query CT log aggregators (crt.sh, Censys) for all certificates issued to a domain
- **Standard signal:** Individual certificates reveal subdomain names (e.g., `grafana.example.com`, `vault.example.com`)
- **Ghostructure mitigation:** Single wildcard certificate (`*.example.com`) via DNS-01 challenge. No individual subdomain names appear in CT logs. Previously exposed names have been rotated.

### 3. HTTP Response Fingerprinting

- **Method:** Send HTTP requests to discovered subdomains and compare response characteristics (status code, body size, headers, content)
- **Standard signal:** Real services return distinct responses (200, 301, 302) with service-specific content. Non-existent subdomains may return different error pages.
- **Ghostructure mitigation:** All non-VPN requests receive an identical 403 response — same status code, same body (2,618 bytes), same headers — regardless of whether the subdomain hosts a real service or not.

### 4. TLS/SNI Analysis

- **Method:** Perform TLS handshakes with different SNI values and compare the returned certificates
- **Standard signal:** Different certificates for different subdomains reveal which ones are configured
- **Ghostructure mitigation:** The same wildcard certificate is returned for every SNI value. No differentiation possible.

### 5. Timing-Based Fingerprinting

- **Method:** Measure response times across subdomains. Real services with backend processing may respond slower than static error pages.
- **Standard signal:** Backend services take 50-500ms, static error pages respond in <5ms
- **Ghostructure mitigation:** Rate limiting middleware on the catch-all route adds processing overhead that normalizes timing. Both paths go through Traefik's middleware chain before reaching nginx.

### 6. Response Header Analysis

- **Method:** Compare HTTP headers across subdomains to identify different backend technologies
- **Standard signal:** Different services return different headers (`X-Powered-By`, `Server`, custom headers)
- **Ghostructure mitigation:** Security headers middleware applied to all routes (catch-all and VPN-blocked services). All responses return the same header set from nginx with no server identification.

## Assets Protected

| Asset | Sensitivity | Protection Mechanism |
|---|---|---|
| Internal service names | High | Wildcard DNS + uniform HTTP response |
| Infrastructure topology | High | No service differentiation possible |
| Technology stack details | Medium | No server/version headers, uniform responses |
| Number of internal services | Medium | Impossible to count what you can't see |
| VPN peer IP ranges | High | VPN traffic encrypted in WireGuard tunnel |

## Assumptions

1. **Attacker has no VPN access** — They are not a member of the NetBird mesh network and do not possess valid Google Workspace credentials for the organization.
2. **Attacker can make unlimited DNS/HTTP requests** — Rate limiting and fail2ban mitigate this but do not assume they cannot work around IP bans (rotating proxies, cloud functions).
3. **Attacker has access to public CT logs** — CT logs are public by design. The mitigation is using only wildcard certificates.
4. **Attacker can perform passive OSINT** — Historical DNS records, Wayback Machine, search engine caches may contain traces of old subdomain names.
5. **DNS provider API credentials are secure** — Compromise of DNS provider credentials would allow the attacker to modify DNS records and issue certificates.

## Residual Risks

### 1. VPN Management Dashboard (Known, Accepted)

The VPN management dashboard (`vpn.example.com`) is necessarily public — VPN peers need to reach it to authenticate and join the network. This is the only intentionally public attack surface beyond the main domain.

**Mitigations applied:**
- Rate limiting (10 req/s per IP)
- Security headers (HSTS, X-Frame-Options: DENY, Permissions-Policy)
- fail2ban jail (20 failed requests in 60s = 1 hour IP ban)
- Google SSO restricted to organization domain

### 2. Main Domain Known

The primary domain itself is publicly known. An attacker knows the organization exists and has infrastructure.

**Mitigation:** This is inherent and accepted. The goal is not to hide the organization's existence but to prevent discovery of internal service topology.

### 3. Historical CT Log Entries

Old certificates with individual subdomain names may still exist in CT log archives. These names have been rotated and now return the same 403 as any other subdomain.

**Mitigation:** Subdomain names were changed after switching to wildcard certificates. Old names now hit the catch-all and return identical 403 responses.

### 4. Network-Level Timing (Theoretical)

TCP handshake timing at the network level could theoretically vary if the server handles connections differently for known vs unknown hostnames. In practice, TLS termination happens at Traefik for all connections identically, making this impractical to exploit.

### 5. Traffic Volume Analysis

An attacker monitoring network traffic volume could potentially infer that certain subdomains receive more traffic (from VPN-connected users). This requires a privileged network position (ISP-level or upstream network tap).

**Mitigation:** WireGuard VPN encryption makes internal traffic indistinguishable from any other encrypted traffic.
