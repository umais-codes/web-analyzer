package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/umais-codes/web-analyzer/internal/analyzer"
	"github.com/umais-codes/web-analyzer/internal/model"
)

const version = "3.0.0"

func main() {
	serveFlag := flag.Bool("serve", false, "Start the web dashboard server")
	portFlag := flag.String("port", "8080", "Port to listen on for web server")
	urlFlag := flag.String("url", "", "Target website URL to analyze via CLI")
	flag.Parse()

	// Direct CLI analysis if URL provided via flag or first positional argument
	targetURL := *urlFlag
	if targetURL == "" && len(flag.Args()) > 0 && !*serveFlag {
		targetURL = flag.Args()[0]
	}

	if targetURL != "" && !*serveFlag {
		runCLI(targetURL)
		return
	}

	// Read PORT from environment if available (for cloud hosting like Render/Fly/Heroku)
	port := *portFlag
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	// Start web server mode
	runServer(port)
}

func runCLI(targetURL string) {
	fmt.Printf("\n🚀 Analyzing %s ...\n\n", targetURL)
	report, err := analyzer.Analyze(targetURL)
	if err != nil {
		fmt.Printf("❌ Analysis Error: %v\n", err)
		os.Exit(1)
	}

	printCLIReport(report)
}

func printCLIReport(r *model.AnalysisReport) {
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Printf("║  WEB ANALYZER v%-47s   ║\n", version)
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf(" Target URL:     %s\n", r.URL)
	fmt.Printf(" Final URL:      %s\n", r.FinalURL)
	fmt.Printf(" Status Code:    %d %s\n", r.Performance.StatusCode, r.Performance.StatusText)
	fmt.Printf(" Overall Grade:  [%s] (Score: %d/100)\n", r.Grade, r.OverallScore)
	fmt.Println("────────────────────────────────────────────────────────────────────")
	fmt.Printf(" ⚡ Performance:  %d/100 | TTFB: %d ms | Total: %d ms | Size: %s\n",
		r.Performance.Score, r.Performance.TimeToFirstByteMs, r.Performance.TotalTimeMs, r.Performance.ContentLengthFormatted)
	fmt.Printf(" 🔒 Security:     %d/100 | HTTPS: %v | HSTS: %s | CSP: %s\n",
		r.Security.Score, r.Security.HTTPS, r.Security.Headers.HSTS.Status, r.Security.Headers.CSP.Status)
	if r.Security.SSLCertificate != nil {
		fmt.Printf("    SSL Cert:    Valid (%d days remaining, %s)\n",
			r.Security.SSLCertificate.DaysRemaining, r.Security.SSLCertificate.TLSVersion)
	}
	fmt.Printf("    DNS/Email:   SPF: %v | DMARC: %v | MX: %v\n",
		r.Security.DNS.HasSPF, r.Security.DNS.HasDMARC, r.Security.DNS.HasMX)
	fmt.Printf(" 🔍 SEO:          %d/100 | Title: %s\n", r.SEO.Score, r.SEO.Title.Value)
	fmt.Printf("    Headings:    H1: %d, H2: %d, H3: %d\n", r.SEO.H1Count, r.SEO.H2Count, r.SEO.H3Count)
	fmt.Printf("    Structured:  JSON-LD: %v (%d schemas)\n", r.StructuredData.Present, r.StructuredData.Count)
	fmt.Printf(" 🔗 Content:      %d/100 | Words: %d | Images: %d (Missing Alt: %d)\n",
		r.Content.Score, r.Content.WordCount, r.Content.TotalImages, r.Content.ImagesMissingAlt)

	if len(r.Technology.DetectedStack) > 0 {
		fmt.Printf(" 🛠️  Tech Stack:   %s\n", strings.Join(r.Technology.DetectedStack, ", "))
	}

	if len(r.Recommendations) > 0 {
		fmt.Println("\n💡 Actionable Recommendations:")
		for i, rec := range r.Recommendations {
			if i >= 5 {
				fmt.Printf("   ... and %d more recommendations (view in Web UI)\n", len(r.Recommendations)-5)
				break
			}
			fmt.Printf("   • [%s] %s: %s\n", strings.ToUpper(rec.Priority), rec.Title, rec.Action)
		}
	}
	fmt.Println("────────────────────────────────────────────────────────────────────")
	fmt.Println(" Built by Umais | @umais-codes")
	fmt.Println()
}

func runServer(port string) {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/analyze", handleAnalyze)
	mux.HandleFunc("/api/compare", handleCompare)
	mux.HandleFunc("/api/badge", handleBadge)
	mux.HandleFunc("/api/health", handleHealth)

	// Serve index.html and static files
	mux.HandleFunc("/", handleIndex)

	addr := ":" + port
	fmt.Println()
	fmt.Println("╔═════════════════════════════════════════════════════════════════════╗")
	fmt.Printf("║                 🚀 WEB ANALYZER v%-34s ║\n", version)
	fmt.Println("║        Professional Performance, Security & SEO Auditing            ║")
	fmt.Println("║                                                                     ║")
	fmt.Printf("║  🌐 Web Dashboard: http://localhost:%-5s                           ║\n", port)
	fmt.Printf("║  ⚡ REST API:      http://localhost:%-5s/api/analyze?url=...       ║\n", port)
	fmt.Printf("║  🛡️  Badge API:     http://localhost:%-5s/api/badge?url=...         ║\n", port)
	fmt.Println("║                                                                     ║")
	fmt.Println("║  Author: Umais | https://github.com/umais-codes                     ║")
	fmt.Println("╚═════════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  35 * time.Second,
		WriteTimeout: 35 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "index.html")
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": version,
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	target := r.URL.Query().Get("url")
	if strings.TrimSpace(target) == "" {
		writeJSONError(w, http.StatusBadRequest, "Parameter 'url' is required (e.g., /api/analyze?url=https://github.com)")
		return
	}

	report, err := analyzer.Analyze(target)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("Failed to analyze website: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(report)
}

func handleCompare(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	url1 := strings.TrimSpace(r.URL.Query().Get("url1"))
	url2 := strings.TrimSpace(r.URL.Query().Get("url2"))

	if url1 == "" || url2 == "" {
		writeJSONError(w, http.StatusBadRequest, "Both 'url1' and 'url2' parameters are required for comparison.")
		return
	}

	var rep1, rep2 *model.AnalysisReport
	var err1, err2 error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		rep1, err1 = analyzer.Analyze(url1)
	}()
	go func() {
		defer wg.Done()
		rep2, err2 = analyzer.Analyze(url2)
	}()
	wg.Wait()

	if err1 != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("Failed to analyze url1 (%s): %v", url1, err1))
		return
	}
	if err2 != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("Failed to analyze url2 (%s): %v", url2, err2))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"target1": rep1,
		"target2": rep2,
	})
}

// handleBadge returns dynamic SVG shield badges for GitHub READMEs
func handleBadge(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w)
	target := r.URL.Query().Get("url")
	if strings.TrimSpace(target) == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return
	}

	report, err := analyzer.Analyze(target)
	grade := "N/A"
	score := 0
	color := "#9e9e9e"

	if err == nil {
		grade = report.Grade
		score = report.OverallScore
		switch {
		case score >= 90:
			color = "#10b981" // green
		case score >= 75:
			color = "#0ea5e9" // blue
		case score >= 60:
			color = "#f59e0b" // amber
		default:
			color = "#ef4444" // red
		}
	}

	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="130" height="20">
  <linearGradient id="b" x2="0" y2="100%%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a">
    <rect width="130" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#a)">
    <path fill="#2c2e3b" d="M0 0h80v20H0z"/>
    <path fill="%s" d="M80 0h50v20H80z"/>
    <path fill="url(#b)" d="M0 0h130v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="40" y="15" fill="#010101" fill-opacity=".3">web audit</text>
    <text x="40" y="14">web audit</text>
    <text x="105" y="15" fill="#010101" fill-opacity=".3">%s (%d)</text>
    <text x="105" y="14">%s (%d)</text>
  </g>
</svg>`, color, grade, score, grade, score)

	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(svg))
}

func setCorsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  msg,
		"status": status,
	})
}
