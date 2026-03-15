# Attack Surface Analysis

Detailed before/after analysis for each reconnaissance technique that Ghostructure defends against.

---

## 1. DNS Subdomain Bruteforce

### How the Attack Works

Attackers use wordlists containing thousands of common subdomain names (admin, staging, dev, api, grafana, jenkins, etc.) and resolve each one against the target's DNS. Standard DNS configurations return an A record for configured subdomains and NXDOMAIN for everything else — a clear binary signal.

Tools: `amass`, `subfinder`, `gobuster dns`, `dnsx`, `massdns`, `puredns`

### What Leaks (Standard Setup)

```
$ dig admin.example.com +short
93.184.216.34                          # ← Real subdomain, A record returned

$ dig fakename.example.com +short
                                       # ← NXDOMAIN, no result
```

The attacker now knows `admin.example.com` exists. Repeat for 100,000 names and build a complete map.

### How Ghostructure Eliminates the Signal

A wildcard DNS record (`*.example.com → server IP`) ensures every possible subdomain resolves:

```
$ dig admin.example.com +short
93.184.216.34

$ dig fakename.example.com +short
93.184.216.34

$ dig literally-anything.example.com +short
93.184.216.34
```

No NXDOMAIN ever. Every name resolves. The binary oracle is destroyed.

### Verification

```bash
# Both real and fake subdomains resolve identically
dig +short real-service.example.com
dig +short completely-made-up-name.example.com
# Output should be identical
```

---

## 2. HTTP Response Fingerprinting

### How the Attack Works

After discovering resolving subdomains via DNS, attackers send HTTP requests and compare responses. Different services return different status codes, body sizes, headers, and content — allowing attackers to identify which subdomains host real services.

Tools: `httpx`, `httprobe`, `curl`, `nuclei`

### What Leaks (Standard Setup)

```
admin.example.com     → 401 Unauthorized (1,204 bytes)    # Real service!
api.example.com       → 200 OK (45 bytes, JSON)           # Real API!
grafana.example.com   → 302 → /login (0 bytes)            # Grafana!
fake.example.com      → 502 Bad Gateway (580 bytes)       # No backend
random.example.com    → Connection refused                 # Nothing there
```

Each unique response fingerprint reveals a real service and often its technology stack.

### How Ghostructure Eliminates the Signal

Every subdomain returns the exact same response:

```
admin.example.com     → 403 Forbidden (2,618 bytes)
api.example.com       → 403 Forbidden (2,618 bytes)
grafana.example.com   → 403 Forbidden (2,618 bytes)
fake.example.com      → 403 Forbidden (2,618 bytes)
random.example.com    → 403 Forbidden (2,618 bytes)
```

Same status code. Same body. Same byte count. Same headers. Zero differentiation.

This is achieved through two mechanisms:
1. **Catch-all router** — Unknown subdomains route to nginx serving a static 403 page
2. **Error-pages middleware** — Known subdomains without VPN access are rejected by `ipAllowList`, and the error is caught and served by the same nginx 403 page

### Verification

```bash
for sub in admin api grafana fake random; do
  curl -sk https://${sub}.example.com/ \
    -w "${sub}: %{http_code} %{size_download}B\n" -o /dev/null
done
# All should show: 403 2618B
```

---

## 3. Certificate Transparency (CT) Log Scraping

### How the Attack Works

Certificate Transparency is a public logging system that records all TLS certificates issued by public CAs. Attackers query CT log aggregators to find every certificate ever issued for a domain, revealing subdomain names.

Tools: `crt.sh`, `certspotter`, `Censys`, `ctfr`

### What Leaks (Standard Setup)

```
$ curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value'
admin.example.com
api.example.com
grafana.example.com
vault.example.com
jenkins.example.com
```

Every individually-issued certificate permanently records the subdomain name in public logs.

### How Ghostructure Eliminates the Signal

A single wildcard certificate (`*.example.com`) issued via DNS-01 challenge:

```
$ curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u
*.example.com
example.com
```

No individual subdomain names appear. Historical entries for old names may exist but those names have been rotated — they now return the same 403 as any random subdomain.

### Verification

```bash
# Check CT logs for your domain
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
  jq -r '.[].name_value' | sort -u
# Should only show *.example.com and example.com
```

---

## 4. TLS Handshake / SNI Analysis

### How the Attack Works

During the TLS handshake, the client sends the Server Name Indication (SNI) field. Servers that use different certificates for different subdomains will return different certificate details, revealing which subdomains are configured.

Tools: `openssl s_client`, `sslyze`, `testssl.sh`, custom scripts

### What Leaks (Standard Setup)

```
$ echo | openssl s_client -connect 93.184.216.34:443 -servername admin.example.com 2>/dev/null | openssl x509 -noout -subject
subject=CN = admin.example.com

$ echo | openssl s_client -connect 93.184.216.34:443 -servername fake.example.com 2>/dev/null | openssl x509 -noout -subject
# Error: no certificate returned, or default cert with different CN
```

Different certificate responses per SNI value reveal configured subdomains.

### How Ghostructure Eliminates the Signal

The same wildcard certificate is returned regardless of SNI value:

```
$ echo | openssl s_client -connect 93.184.216.34:443 -servername admin.example.com 2>/dev/null | openssl x509 -noout -subject
subject=CN = *.example.com

$ echo | openssl s_client -connect 93.184.216.34:443 -servername fake.example.com 2>/dev/null | openssl x509 -noout -subject
subject=CN = *.example.com
```

### Verification

```bash
for sub in admin api fake random; do
  echo | openssl s_client -connect YOUR_IP:443 -servername ${sub}.example.com 2>/dev/null | \
    openssl x509 -noout -subject
done
# All should show: subject=CN = *.example.com
```

---

## 5. Timing-Based Fingerprinting

### How the Attack Works

Attackers measure HTTP response times across subdomains. Services with backend processing (database queries, authentication, template rendering) typically respond in 50-500ms, while static error pages respond in <5ms. This timing difference can reveal which subdomains have active backends.

Tools: `curl -w "%{time_total}"`, custom scripts, `httpx -response-time`

### What Leaks (Standard Setup)

```
admin.example.com:    0.250s  (backend processing)
api.example.com:      0.180s  (backend processing)
fake.example.com:     0.003s  (static error page)
```

The timing gap (3ms vs 250ms) clearly identifies real services.

### How Ghostructure Eliminates the Signal

Two mechanisms normalize timing:

1. **Rate limiting middleware** on the catch-all router adds token bucket processing overhead (~1-3ms), bringing the catch-all response time closer to the middleware-chain processing time of VPN-blocked services.
2. **Both paths go through Traefik's middleware chain** — the catch-all processes through `securityHeaders` and `catchall-ratelimit` middlewares before reaching nginx, similar to VPN-blocked services processing through `ipAllowList` and `securityHeaders` before the error-pages redirect.

```
admin.example.com:    0.008s  (middleware chain → nginx 403)
api.example.com:      0.009s  (middleware chain → nginx 403)
fake.example.com:     0.007s  (middleware chain → nginx 403)
```

### Verification

```bash
for sub in admin api fake random; do
  curl -sk https://${sub}.example.com/ \
    -w "${sub}: %{time_total}s\n" -o /dev/null
done
# All times should be within a few milliseconds of each other
```

---

## 6. Response Header Analysis

### How the Attack Works

Different web services include different HTTP headers that reveal the technology stack. Headers like `X-Powered-By: Express`, `Server: nginx/1.21`, `X-Drupal-Cache`, or `X-AspNet-Version` fingerprint the backend technology.

Tools: `curl -I`, `httpx`, `whatweb`, `wappalyzer`

### What Leaks (Standard Setup)

```
admin.example.com:
  Server: nginx/1.25.3
  X-Powered-By: Express

api.example.com:
  Server: gunicorn
  X-Request-Id: abc123

fake.example.com:
  Server: nginx/1.25.3
  # (default error page headers)
```

Each unique header set identifies a different service and its technology.

### How Ghostructure Eliminates the Signal

Security headers middleware is applied to all routes. All responses return the same header set:

```
admin.example.com:
  strict-transport-security: max-age=31536000; includeSubDomains; preload
  x-content-type-options: nosniff
  x-frame-options: DENY
  content-type: text/html
  content-length: 2618

fake.example.com:
  strict-transport-security: max-age=31536000; includeSubDomains; preload
  x-content-type-options: nosniff
  x-frame-options: DENY
  content-type: text/html
  content-length: 2618
```

No `Server` header. No `X-Powered-By`. No identifying information. Identical across all subdomains.

### Verification

```bash
diff <(curl -sI https://admin.example.com/ -k | sort) \
     <(curl -sI https://fake.example.com/ -k | sort)
# No differences expected (except Date header which changes per-second)
```
