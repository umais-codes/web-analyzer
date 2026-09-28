package analyzer

import (
	"strings"
	"testing"

	"github.com/umais-codes/web-analyzer/internal/model"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"google.com", "https://google.com", false},
		{"http://example.com/test", "http://example.com/test", false},
		{"https://github.com", "https://github.com", false},
		{"", "", true},
	}

	for _, tt := range tests {
		got, err := NormalizeURL(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("NormalizeURL(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if !tt.wantErr && got != tt.expected {
			t.Errorf("NormalizeURL(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractSEOAndContent(t *testing.T) {
	sampleHTML := `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<title>Professional Web Analyzer - Fast & Secure</title>
		<meta name="description" content="A comprehensive open-source website audit tool providing deep performance, security, and SEO insights.">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta property="og:title" content="OpenGraph Title Sample">
		<meta property="og:image" content="https://example.com/og.jpg">
		<link rel="canonical" href="https://example.com">
	</head>
	<body>
		<h1>Primary Page Headline</h1>
		<h2>Subheading 1</h2>
		<h2>Subheading 2</h2>
		<h3>Sub-subheading</h3>
		<p>This is a paragraph with several words to test the word counter logic and reading time accurately.</p>
		<img src="/img1.png" alt="Valid Alt Tag">
		<img src="/img2.png">
		<a href="/internal-page">Internal Link</a>
		<a href="https://google.com">External Link</a>
	</body>
	</html>
	`

	seo, content, _ := ExtractSEOAndContent(sampleHTML, "https://example.com")

	if !strings.Contains(seo.Title.Value, "Professional Web Analyzer") {
		t.Errorf("expected title to match, got %q", seo.Title.Value)
	}
	if seo.Title.Status != "good" {
		t.Errorf("expected title status to be 'good', got %s", seo.Title.Status)
	}
	if seo.H1Count != 1 {
		t.Errorf("expected 1 H1, got %d", seo.H1Count)
	}
	if seo.H2Count != 2 {
		t.Errorf("expected 2 H2s, got %d", seo.H2Count)
	}
	if content.TotalImages != 2 {
		t.Errorf("expected 2 images, got %d", content.TotalImages)
	}
	if content.ImagesMissingAlt != 1 {
		t.Errorf("expected 1 image missing alt, got %d", content.ImagesMissingAlt)
	}
	if content.InternalLinks != 1 {
		t.Errorf("expected 1 internal link, got %d", content.InternalLinks)
	}
	if content.ExternalLinks != 1 {
		t.Errorf("expected 1 external link, got %d", content.ExternalLinks)
	}
}

func TestCalculateScores(t *testing.T) {
	report := &model.AnalysisReport{
		Performance: model.PerformanceMetrics{
			TimeToFirstByteMs: 150,
			StatusCode:        200,
			IsCompressed:      true,
		},
		Security: model.SecurityReport{
			HTTPS: true,
			SSLCertificate: &model.SSLCertInfo{
				Valid:         true,
				DaysRemaining: 180,
			},
			Headers: model.SecurityHeadersCheck{
				HSTS:                model.HeaderItem{Status: "pass"},
				CSP:                 model.HeaderItem{Status: "pass"},
				XFrameOptions:       model.HeaderItem{Status: "pass"},
				XContentTypeOptions: model.HeaderItem{Status: "pass"},
			},
		},
		SEO: model.SEOReport{
			Title:       model.SEOItem{Status: "good"},
			Description: model.SEOItem{Status: "good"},
			Viewport:    model.SEOItem{Status: "good"},
			H1Count:     1,
			Canonical:   model.SEOItem{Status: "good"},
			OpenGraph:   model.OpenGraphData{Title: "Title", Image: "img.png"},
		},
		Content: model.ContentReport{
			TotalImages:      5,
			ImagesMissingAlt: 0,
			WordCount:        500,
		},
	}

	CalculateScores(report)

	if report.OverallScore < 90 {
		t.Errorf("expected high score for healthy report, got %d", report.OverallScore)
	}
	if report.Grade != "A+" && report.Grade != "A" {
		t.Errorf("expected Grade A or A+, got %s", report.Grade)
	}
}
