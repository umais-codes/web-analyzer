package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/umais-codes/web-analyzer/internal/analyzer"
	"github.com/umais-codes/web-analyzer/internal/model"
)

const version = "2.0.0"

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

	// Otherwise start web server mode
	runServer(*portFlag)
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
	fmt.Printf("║  GO WEBSITE ANALYZER v%-40s   ║\n", version)
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
	fmt.Printf(" 🔍 SEO:          %d/100 | Title: %s\n", r.SEO.Score, r.SEO.Title.Value)
	fmt.Printf("    Headings:    H1: %d, H2: %d, H3: %d\n", r.SEO.H1Count, r.SEO.H2Count, r.SEO.H3Count)
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
	mux.HandleFunc("/api/health", handleHealth)

	// Serve index.html and static files
	mux.HandleFunc("/", handleIndex)

	addr := ":" + port
	fmt.Println()
	fmt.Println("╔═════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                 🚀 GO WEBSITE ANALYZER v2.0.0                       ║")
	fmt.Println("║        Professional Performance, Security & SEO Auditing            ║")
	fmt.Println("║                                                                     ║")
	fmt.Printf("║  🌐 Web Dashboard: http://localhost:%-5s                           ║\n", port)
	fmt.Printf("║  ⚡ REST API:      http://localhost:%-5s/api/analyze?url=...       ║\n", port)
	fmt.Println("║                                                                     ║")
	fmt.Println("║  Author: Umais | https://github.com/umais-codes                     ║")
	fmt.Println("╚═════════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
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
	// Enable CORS for API consumers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

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

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  msg,
		"status": status,
	})
}
