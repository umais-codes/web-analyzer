package analyzer

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/umais-codes/web-analyzer/internal/model"
)

// Analyze performs a full-spectrum technical, performance, security, and SEO analysis on a URL.
func Analyze(rawURL string) (*model.AnalysisReport, error) {
	overallStart := time.Now()

	normalizedURL, err := NormalizeURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	report := &model.AnalysisReport{
		URL:           rawURL,
		NormalizedURL: normalizedURL,
		FinalURL:      normalizedURL,
		Timestamp:     time.Now().UTC(),
		RedirectChain: []model.RedirectHop{},
	}

	// Channel for SSL inspection result
	type sslResult struct {
		info *model.SSLCertInfo
		err  error
	}
	sslChan := make(chan sslResult, 1)

	// Launch SSL inspection concurrently if HTTPS
	parsedURL, _ := url.Parse(normalizedURL)
	isHTTPS := parsedURL != nil && strings.ToLower(parsedURL.Scheme) == "https"
	report.Security.HTTPS = isHTTPS

	if isHTTPS {
		go func() {
			certInfo, err := InspectSSL(normalizedURL)
			sslChan <- sslResult{info: certInfo, err: err}
		}()
	} else {
		sslChan <- sslResult{info: nil, err: nil}
	}

	// Trace network metrics
	var (
		dnsStart, dnsDone       time.Time
		connStart, connDone     time.Time
		tlsStart, tlsDone       time.Time
		gotFirstByte            time.Time
		reqStart                time.Time
		mu                      sync.Mutex
	)

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			mu.Lock()
			dnsStart = time.Now()
			mu.Unlock()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			mu.Lock()
			dnsDone = time.Now()
			mu.Unlock()
		},
		ConnectStart: func(_, _ string) {
			mu.Lock()
			connStart = time.Now()
			mu.Unlock()
		},
		ConnectDone: func(_, _ string, _ error) {
			mu.Lock()
			connDone = time.Now()
			mu.Unlock()
		},
		TLSHandshakeStart: func() {
			mu.Lock()
			tlsStart = time.Now()
			mu.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			mu.Lock()
			tlsDone = time.Now()
			mu.Unlock()
		},
		GotFirstResponseByte: func() {
			mu.Lock()
			gotFirstByte = time.Now()
			mu.Unlock()
		},
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			report.IsRedirected = true
			if len(via) > 0 {
				lastReq := via[len(via)-1]
				report.RedirectChain = append(report.RedirectChain, model.RedirectHop{
					URL:        lastReq.URL.String(),
					StatusCode: 301, // approximate redirect code
				})
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", normalizedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build HTTP request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	reqStart = time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach website: %w", err)
	}
	defer resp.Body.Close()

	bodyReadStart := time.Now()
	// Read with 5MB limit
	const maxBodySize = 5 * 1024 * 1024
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	bodyReadDone := time.Now()

	totalTime := time.Since(reqStart)

	// Calculate timing durations
	var dnsTime, tcpTime, tlsTime, ttfbTime, downloadTime int64
	if !dnsDone.IsZero() && !dnsStart.IsZero() {
		dnsTime = dnsDone.Sub(dnsStart).Milliseconds()
	}
	if !connDone.IsZero() && !connStart.IsZero() {
		tcpTime = connDone.Sub(connStart).Milliseconds()
	}
	if !tlsDone.IsZero() && !tlsStart.IsZero() {
		tlsTime = tlsDone.Sub(tlsStart).Milliseconds()
	}
	if !gotFirstByte.IsZero() {
		ttfbTime = gotFirstByte.Sub(reqStart).Milliseconds()
	} else {
		ttfbTime = bodyReadStart.Sub(reqStart).Milliseconds()
	}
	downloadTime = bodyReadDone.Sub(bodyReadStart).Milliseconds()

	// Update FinalURL
	report.FinalURL = resp.Request.URL.String()
	if report.IsRedirected && len(report.RedirectChain) > 0 {
		report.RedirectChain[len(report.RedirectChain)-1].StatusCode = resp.StatusCode
	}

	// Performance Metrics
	encoding := resp.Header.Get("Content-Encoding")
	contentLength := int64(len(bodyBytes))
	if resp.ContentLength > 0 {
		contentLength = resp.ContentLength
	}

	report.Performance = model.PerformanceMetrics{
		StatusCode:             resp.StatusCode,
		StatusText:             http.StatusText(resp.StatusCode),
		Protocol:               resp.Proto,
		TotalTimeMs:            totalTime.Milliseconds(),
		DNSLookupTimeMs:        dnsTime,
		TCPConnectTimeMs:       tcpTime,
		TLSHandshakeTimeMs:     tlsTime,
		TimeToFirstByteMs:      ttfbTime,
		ContentDownloadTimeMs:  downloadTime,
		ContentLengthBytes:     contentLength,
		ContentLengthFormatted: formatBytes(contentLength),
		ContentType:            resp.Header.Get("Content-Type"),
		ContentEncoding:        encoding,
		IsCompressed:           encoding != "",
	}

	// Security Headers Audit
	report.Security.Headers = AuditSecurityHeaders(resp.Header)

	// Receive SSL cert result
	sslRes := <-sslChan
	if sslRes.info != nil {
		report.Security.SSLCertificate = sslRes.info
	}

	// Decompress payload if compressed for accurate HTML and SEO inspection
	htmlBytes := bodyBytes
	enc := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if strings.Contains(enc, "gzip") {
		if gzReader, err := gzip.NewReader(bytes.NewReader(bodyBytes)); err == nil {
			if decompressed, err := io.ReadAll(io.LimitReader(gzReader, maxBodySize)); err == nil {
				htmlBytes = decompressed
			}
			gzReader.Close()
		}
	} else if strings.Contains(enc, "deflate") {
		flateReader := flate.NewReader(bytes.NewReader(bodyBytes))
		if decompressed, err := io.ReadAll(io.LimitReader(flateReader, maxBodySize)); err == nil {
			htmlBytes = decompressed
		}
		flateReader.Close()
	}

	htmlString := string(htmlBytes)
	seoReport, contentReport, techReport := ExtractSEOAndContent(htmlString, report.FinalURL)

	report.SEO = seoReport
	report.Content = contentReport

	// Add Server & Powered-By headers to TechReport
	if srv := resp.Header.Get("Server"); srv != "" {
		techReport.Server = srv
		techReport.DetectedStack = appendStack(techReport.DetectedStack, srv)
	}
	if pb := resp.Header.Get("X-Powered-By"); pb != "" {
		techReport.PoweredBy = pb
		techReport.DetectedStack = appendStack(techReport.DetectedStack, pb)
	}
	report.Technology = techReport

	// Calculate Multi-Factor Health Scores and Actionable Recommendations
	CalculateScores(report)

	report.ExecutionDurationMs = time.Since(overallStart).Milliseconds()
	return report, nil
}

// NormalizeURL cleans and ensures an explicit HTTP/HTTPS scheme.
func NormalizeURL(input string) (string, error) {
	u := strings.TrimSpace(input)
	if u == "" {
		return "", fmt.Errorf("URL cannot be empty")
	}

	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "https://" + u
	}

	parsed, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("hostname could not be determined")
	}

	return parsed.String(), nil
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
