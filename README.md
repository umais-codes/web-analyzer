# 🚀 Go Website Analyzer v2.0.0

> An enterprise-grade, high-performance website audit and diagnostics suite built with Go. Evaluate network latency waterfalls, SSL/TLS certificate health, protective HTTP security headers, SEO hierarchy, social share previews, and accessibility in milliseconds.

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-blue.svg)]()
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success.svg)]()

---

## 🌟 Key Features

### ⚡ 1. Network & Performance Waterfall
- **Time to First Byte (TTFB)** tracing via `httptrace.ClientTrace`.
- Granular breakdown: **DNS Lookup**, **TCP Connect**, **TLS Handshake**, and **Content Download** timing.
- Protocol negotiation detection (**HTTP/1.1** vs **HTTP/2**).
- Compression detection (**Gzip**, **Brotli**, Deflate) and byte weight formatting.

### 🔒 2. Enterprise Security & SSL/TLS Audit
- **Certificate Inspection**: Expiration countdown, Common Name, Subject Alternative Names (SANs), TLS Version, and Cipher Suite.
- **Security Headers Scorecard**: Evaluates adherence to:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options` (Clickjacking protection)
  - `X-Content-Type-Options` (MIME sniffing defence)
  - `Referrer-Policy`
  - `Permissions-Policy`

### 🔍 3. SEO Hierarchy & Social Previews
- **Google SERP Snippet Simulator**: Live preview of search results with character length checks for `<title>` and `<meta name="description">`.
- **Social Media Card Preview**: Displays Open Graph (`og:image`, `og:title`) and Twitter card cards.
- **Headings Architecture**: Validates `<h1>`, `<h2>`, and `<h3>` distribution and flags missing or duplicate H1 tags.
- **Metadata Verification**: Checks for canonical URLs, mobile viewports, charset encoding, and robots directives.

### 🔗 4. Content & Accessibility Diagnostics
- **Image Alt Attribute Audit**: Detects total images and flags images missing `alt` attributes.
- **Link Topology**: Quantifies total links, distinguishing **Internal** vs **External** links.
- **Copy Metrics**: Computes exact text word count and estimated reading time.

### 🛠️ 5. Platform & Technology Fingerprinting
- Detects web servers (`Nginx`, `Apache`, `Cloudflare`, `Caddy`).
- Identifies CMS, libraries, and frameworks (`WordPress`, `Shopify`, `Next.js`, `React`, `Vue.js`, `Tailwind CSS`, `Google Tag Manager`).

### 💡 6. Actionable Optimization Engine
- Calculates category scores (0–100) and an overall Health Grade (**A+**, **A**, **B**, **C**, **D**, **F**).
- Generates prioritized recommendations (**High**, **Medium**, **Low**) with clear step-by-step remediation advice.

---

## 🏛️ Architecture & Folder Structure

```
web-analyzer/
├── cmd/
│   └── (optional CLI tools)
├── internal/
│   ├── analyzer/
│   │   ├── analyzer.go        # Main audit orchestrator & HTTP tracing
│   │   ├── analyzer_test.go   # Automated unit tests
│   │   ├── scorer.go          # Multi-factor health scoring algorithm
│   │   ├── security.go        # SSL/TLS inspection & HTTP security headers
│   │   └── seo.go             # HTML DOM parsing, OpenGraph, and link analysis
│   └── model/
│       └── report.go          # Data structures for audit reports
├── index.html                 # Modern glassmorphism dashboard UI
├── main.go                    # Dual CLI & REST API web server entrypoint
├── go.mod                     # Go module definition
└── README.md                  # Comprehensive documentation
```

---

## 🚀 Getting Started

### Prerequisites
- [Go 1.21+](https://go.dev/dl/) installed on your machine.

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

### 2. Command-Line CLI Mode

Analyze any website directly from your terminal:
```bash
go run main.go https://github.com
```

**Example CLI Output:**
```text
╔══════════════════════════════════════════════════════════════════╗
║  GO WEBSITE ANALYZER v2.0.0                                      ║
╚══════════════════════════════════════════════════════════════════╝
 Target URL:     https://github.com
 Final URL:      https://github.com/
 Status Code:    200 OK
 Overall Grade:  [A] (Score: 92/100)
────────────────────────────────────────────────────────────────────
 ⚡ Performance:  95/100 | TTFB: 82 ms | Total: 145 ms | Size: 184.2 KB
 🔒 Security:     90/100 | HTTPS: true | HSTS: pass | CSP: pass
    SSL Cert:    Valid (245 days remaining, TLS 1.3)
 🔍 SEO:          90/100 | Title: GitHub: Let's build from here
    Headings:    H1: 1, H2: 8, H3: 14
 🔗 Content:      95/100 | Words: 1240 | Images: 12 (Missing Alt: 0)
 🛠️  Tech Stack:   GitHub.com, Next.js
────────────────────────────────────────────────────────────────────
 Built by Umais | @umais-codes
```

---

## 🌐 REST API Endpoints

### `GET /api/analyze?url={target_url}`
Runs a complete audit and returns structured JSON.

**Example Request:**
```bash
curl -X GET "http://localhost:8080/api/analyze?url=https://stripe.com"
```

**Response Format:**
```json
{
  "url": "https://stripe.com",
  "final_url": "https://stripe.com/",
  "overall_score": 94,
  "grade": "A",
  "performance": {
    "score": 95,
    "status_code": 200,
    "time_to_first_byte_ms": 68,
    "total_time_ms": 132,
    "content_length_formatted": "92.4 KB"
  },
  "security": {
    "score": 95,
    "https": true,
    "ssl_certificate": {
      "valid": true,
      "issuer": "DigiCert Inc",
      "days_remaining": 198,
      "tls_version": "TLS 1.3"
    }
  },
  "recommendations": [
    {
      "category": "SEO",
      "priority": "low",
      "title": "Suboptimal Title Tag Length",
      "action": "Adjust page title to be between 40-60 characters."
    }
  ]
}
```

### `GET /api/health`
Health check endpoint verifying server status and version.

---

## 🧪 Testing

Run automated unit tests:
```bash
go test -v ./...
```

---

## 👨‍💻 Author & Maintainer

**Umais**  
*Full-Stack & Backend Engineer*  
GitHub: [@umais-codes](https://github.com/umais-codes)  
Repository: [web-analyzer](https://github.com/umais-codes/web-analyzer)
