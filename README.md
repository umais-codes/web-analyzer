# 🚀 Web Analyzer v3.0

> An enterprise-grade, high-performance website diagnostics, security auditing, and SEO analysis suite built with Go. Evaluate network latency waterfalls, TLS certificates, DNS/Email hygiene (SPF/DMARC), HTTP security headers, Schema.org structured data, and accessibility in milliseconds.

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Docker-blue.svg)]()
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success.svg)]()
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)]()

---

## 🌟 Key Features

### ⚡ 1. Network Performance & Latency Waterfall
- **Time to First Byte (TTFB)** tracing via `httptrace.ClientTrace`.
- Granular network breakdown: **DNS Lookup**, **TCP Connect**, **TLS Handshake**, and **Content Download**.
- HTTP protocol negotiation detection (**HTTP/1.1** vs **HTTP/2**).
- Compression detection (**Gzip**, **Brotli**, Deflate) and byte weight formatting.

### 🔒 2. Enterprise Security & SSL/TLS Audit
- **Certificate Inspection**: Expiration countdown, Common Name, Subject Alternative Names (SANs), TLS Version, and Cipher Suite.
- **Security Headers Scorecard**: Evaluates adherence to:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options` (Clickjacking protection)
  - `X-Content-Type-Options` (MIME sniffing defence)
  - `Referrer-Policy` & `Permissions-Policy`
- **Cookie Security Evaluation**: Inspects `Secure`, `HttpOnly`, and `SameSite` flags on response cookies.

### 🛡️ 3. DNS Hygiene & Email Security (SPF / DMARC / MX)
- **Email Security Auditing**: Real-time resolution and validation of `SPF` (`v=spf1 ...`) and `DMARC` (`_dmarc.<domain>`) records.
- **MX Record Verification**: Validates mail server configuration and priority.
- **CAA Governance**: Validates domain certificate issuance policies.

### 🔍 4. SEO, Structured Data (JSON-LD) & Crawl Discovery
- **Structured Data Validator**: Extracts `<script type="application/ld+json">` schemas and validates Schema.org types (`Organization`, `WebSite`, `Article`, `Product`, `FAQPage`).
- **Crawl Discovery**: Automatically verifies `/robots.txt` and `/sitemap.xml` presence.
- **Google SERP Snippet Simulator**: Live search preview with character length checks for `<title>` and `<meta name="description">`.
- **Social Media Card Preview**: Displays Open Graph (`og:image`, `og:title`) and Twitter card previews.
- **Headings Architecture**: Validates `<h1>`, `<h2>`, and `<h3>` distribution and flags missing or duplicate H1 tags.

### 📊 5. Comparison Engine & GitHub Readme Badges
- **Side-by-Side URL Comparison**: Compare 2 websites head-to-head with delta scoring (`/api/compare`).
- **Dynamic README Badges**: Generate live SVG shields for your repositories (`/api/badge?url=...`).
- **One-Click PDF/Print Reports**: Generate executive-ready deliverables with clean print styling.

---

## 🏛️ Architecture & Folder Structure

```
web-analyzer/
├── .github/
│   └── workflows/
│       └── ci.yml             # Automated CI, testing & Docker validation
├── internal/
│   ├── analyzer/
│   │   ├── analyzer.go        # Audit orchestrator & network tracing
│   │   ├── analyzer_test.go   # Comprehensive automated unit tests
│   │   ├── scorer.go          # Multi-factor scoring & recommendation engine
│   │   ├── security.go        # SSL/TLS, DNS hygiene & Cookie inspection
│   │   └── seo.go             # HTML DOM parsing, JSON-LD schemas & crawl checks
│   └── model/
│       └── report.go          # Structured audit report schemas
├── index.html                 # Glassmorphism dashboard UI with compare & badge tools
├── main.go                    # CLI & REST API server entrypoint
├── Dockerfile                 # Multi-stage production container
├── render.yaml                # 1-Click cloud deployment blueprint
├── go.mod                     # Go module definition
└── README.md                  # Documentation
```

---

## 🚀 Getting Started

### Prerequisites
- [Go 1.21+](https://go.dev/dl/) installed, OR [Docker](https://www.docker.com/).

### Installation

Clone the repository:
```bash
git clone https://github.com/umais-codes/web-analyzer.git
cd web-analyzer
```

---

## 💻 Usage

### 1. Web Dashboard & REST API Server (Default)

Start the built-in server:
```bash
go run main.go
```
Open your browser and navigate to:
```
http://localhost:8080
```

To specify a custom port:
```bash
go run main.go -port=3000
```

### 2. Docker Container Mode

Build and run with Docker:
```bash
docker build -t web-analyzer .
docker run -p 8080:8080 web-analyzer
```

### 3. Command-Line CLI Mode

Analyze any website directly from your terminal:
```bash
go run main.go https://github.com
```

**Example CLI Output:**
```text
╔══════════════════════════════════════════════════════════════════╗
║  WEB ANALYZER v3.0.0                                             ║
╚══════════════════════════════════════════════════════════════════╝
 Target URL:     https://github.com
 Final URL:      https://github.com/
 Status Code:    200 OK
 Overall Grade:  [A] (Score: 92/100)
────────────────────────────────────────────────────────────────────
 ⚡ Performance:  95/100 | TTFB: 82 ms | Total: 145 ms | Size: 184.2 KB
 🔒 Security:     90/100 | HTTPS: true | HSTS: pass | CSP: pass
    SSL Cert:    Valid (245 days remaining, TLS 1.3)
    DNS/Email:   SPF: true | DMARC: true | MX: true
 🔍 SEO:          90/100 | Title: GitHub: Let's build from here
    Headings:    H1: 1, H2: 8, H3: 14
    Structured:  JSON-LD: true (2 schemas)
 🔗 Content:      95/100 | Words: 1240 | Images: 12 (Missing Alt: 0)
 🛠️  Tech Stack:   GitHub.com, Next.js
────────────────────────────────────────────────────────────────────
 Built by Umais | @umais-codes
```

---

## 🌐 REST API Endpoints

### 1. `GET /api/analyze?url={target_url}`
Runs a complete audit and returns structured JSON.

```bash
curl -X GET "http://localhost:8080/api/analyze?url=https://stripe.com"
```

### 2. `GET /api/compare?url1={url1}&url2={url2}`
Runs dual concurrent audits and returns side-by-side comparison metrics.

```bash
curl -X GET "http://localhost:8080/api/compare?url1=https://stripe.com&url2=https://paypal.com"
```

### 3. `GET /api/badge?url={target_url}`
Returns a dynamic SVG shield badge for GitHub READMEs.

**Markdown Example:**
```markdown
[![Web Audit](http://localhost:8080/api/badge?url=https://github.com)](https://github.com/umais-codes/web-analyzer)
```

### 4. `GET /api/health`
Health check endpoint verifying server status and version.

---

## 🧪 Testing

Run automated unit tests:
```bash
go test -v ./...
```

---

## ☁️ Live Cloud Deployment Guide

### Deploying to Render (Free Tier):
1. Push this repository to your GitHub account (`umais-codes/web-analyzer`).
2. Log in to [Render.com](https://render.com) and click **New + > Web Service**.
3. Select your repository `web-analyzer`.
4. Render will automatically detect `render.yaml` or you can configure:
   - **Runtime**: `Go`
   - **Build Command**: `go build -o web-analyzer main.go`
   - **Start Command**: `./web-analyzer -serve`
5. Your app will be live at `https://<your-app-name>.onrender.com` with free automated HTTPS and continuous deployment!

---

## 👨‍💻 Author & Maintainer

**Umais**  
*Full-Stack & Backend Engineer*  
GitHub: [@umais-codes](https://github.com/umais-codes)  
Repository: [web-analyzer](https://github.com/umais-codes/web-analyzer)
