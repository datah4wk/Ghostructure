# Ghostructure

### Wildcard Subdomain Anti-Enumeration Infrastructure

> Zero-signal reconnaissance hardening — making subdomain bruteforcing return 100% identical responses across infinite subdomains

---

## The Problem

Subdomain enumeration is the first phase of any targeted attack. Tools like **amass**, **subfinder**, and **gobuster** resolve thousands of subdomains per second, fingerprinting responses to map an organization's attack surface. Standard setups leak information in two ways:

1. **DNS layer** — Real subdomains return A records, fake ones return NXDOMAIN
2. **HTTP layer** — Real services return distinct responses (status codes, headers, body size), even when access-denied

This gives attackers a **binary oracle**: real or fake. With enough requests, every internal service is discoverable.

## How Ghostructure Solves This

Ghostructure eliminates every signal an attacker can use to differentiate real subdomains from fake ones, across four layers:

| Layer | What It Does |
|-------|-------------|
| **1. DNS Normalization** | Wildcard A record (`*.example.com → IP`). No subdomain ever returns NXDOMAIN. Every possible subdomain resolves. |
| **2. TLS Normalization** | Single wildcard certificate via DNS-01 challenge. No per-subdomain certs in CT logs. No SNI fingerprinting. |
| **3. HTTP Response Normalization** | Identical 403 response — same status code, same body, same byte count (2,618 bytes) — for *everything* without VPN access. |
| **4. Zero-Trust Access** | NetBird/WireGuard mesh VPN + Google Workspace SSO. Services only respond to authenticated VPN peers via Traefik `ipAllowList`. |

The result: an attacker scanning 100,000 subdomains gets 100,000 identical responses. Zero signal. Zero differentiation. Nothing to work with.

## Architecture

```
                    *.example.com → Server IP
                    (Wildcard DNS, no NXDOMAIN ever)
                            │
                            ▼
                   ┌────────────────┐
                   │  Traefik v3.6  │
                   │ TLS Termination│ ← Wildcard cert (*.example.com)
                   │   + Routing    │   via DNS-01 / Let's Encrypt
                   └───────┬────────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
     Without VPN      With VPN        Catch-All
     (known host)    (NetBird)     (unknown host)
           │               │               │
      ipAllowList      ipAllowList         │
        FAILS           PASSES             │
           │               │               │
        nginx           Service          nginx
      403 page         Content ✓       403 page
      2,618 B          200 OK          2,618 B
           │                               │
           └─────── IDENTICAL ─────────────┘
```

**Key insight:** When a known subdomain is accessed without VPN, the `ipAllowList` middleware rejects it — but Traefik's error-pages middleware catches that rejection and serves the *same nginx 403 page* as the catch-all. The attacker sees no difference.

## Attack Surface Analysis

| Reconnaissance Technique | Before (Standard Setup) | After (Ghostructure) |
|---|---|---|
| **DNS Subdomain Bruteforce** | Real → A record, Fake → NXDOMAIN | All → identical A record |
| **HTTP Response Fingerprinting** | Different status codes and bodies | All → identical 403, 2,618 bytes |
| **Certificate Transparency (crt.sh)** | Individual certs leak every subdomain | Single wildcard cert, old names rotated |
| **TLS Handshake / SNI Analysis** | Different certs per subdomain | Same wildcard cert for all |
| **Timing-Based Fingerprinting** | Backend processing time varies | Rate-limited catch-all normalizes timing |
| **Response Header Analysis** | Service-specific headers leak stack | All 403s from same nginx instance, security headers on all routes |

## Verification

```bash
# Test that every subdomain returns identical responses
for sub in admin staging test db api jenkins fake nonexistent; do
  curl -sk https://${sub}.example.com/ \
    -w "${sub}: %{http_code} %{size_download}B\n" -o /dev/null
done
```

Expected output — all identical:

```
admin:       403 2618B
staging:     403 2618B
test:        403 2618B
db:          403 2618B
api:         403 2618B
jenkins:     403 2618B
fake:        403 2618B
nonexistent: 403 2618B
```

Check response headers:

```bash
curl -sI https://anything.example.com/ -k
```

Expected — no server identification, full security headers:

```
HTTP/2 403
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
content-type: text/html
content-length: 2618
```

## Technology Stack

| Component | Role |
|---|---|
| **Traefik v3.6** | Reverse proxy, TLS termination, routing, rate limiting |
| **Let's Encrypt (DNS-01)** | Wildcard certificate issuance |
| **DNS Provider API** | Automated DNS challenge resolution |
| **NetBird (WireGuard)** | Zero-trust mesh VPN overlay |
| **Google Workspace SSO** | Identity provider via Dex IdP |
| **nginx** | Static 403 error page serving |
| **fail2ban** | Automated IP banning for enumeration and brute force |
| **Docker Compose** | Service orchestration |
| **Ubuntu 24.04** | Single VPS host |

## MITRE ATT&CK Coverage

| Technique ID | Name | Mitigation |
|---|---|---|
| **T1595.003** | Active Scanning: Wordlist Scanning | Wildcard DNS + uniform 403 response eliminates signal |
| **T1596.002** | Search Open Technical Databases: DNS/Passive DNS | Wildcard DNS — no unique records to discover |
| **T1596.003** | Search Open Technical Databases: Digital Certificates | Single wildcard cert, old subdomain names rotated out |
| **T1590.002** | Gather Victim Network Information: DNS | No signal differentiation possible across any subdomain |

## Additional Hardening

Beyond the core anti-enumeration layers, Ghostructure includes:

- **Rate limiting on catch-all** — 5 req/s per IP. Scanning 100k subdomains takes 5.5 hours instead of seconds.
- **Rate limiting on public services** — 10 req/s per IP with burst allowance.
- **fail2ban integration** — Automatic IP banning for subdomain enumeration (50 catch-all hits in 60s = 1 hour ban) and authentication brute force.
- **JSON access logs** — Structured logging for SIEM integration (Wazuh, Splunk, ELK).
- **Security headers everywhere** — HSTS, X-Content-Type-Options, X-Frame-Options, Permissions-Policy on all responses including the catch-all.

## Getting Started

1. Clone this repo
2. Review the configs in `configs/` — all use `example.com` as a placeholder
3. Replace `example.com` with your domain throughout
4. Set up your DNS provider API credentials for DNS-01 challenges
5. Deploy with Docker Compose
6. Run `scripts/verify-uniformity.sh yourdomain.com` to verify

See [`docs/architecture.md`](docs/architecture.md) for the full technical deep-dive.

> **Note:** No real secrets, IPs, or domain names are included in this repository. All config files use `.example.` in the filename to signal they are templates.

## Documentation

- [`docs/threat-model.md`](docs/threat-model.md) — Threat actors, attack vectors, and residual risks
- [`docs/attack-surface-analysis.md`](docs/attack-surface-analysis.md) — Detailed before/after analysis for each reconnaissance technique
- [`docs/architecture.md`](docs/architecture.md) — Full architecture, network flows, and routing logic

## License

MIT — See [LICENSE](LICENSE) for details.
