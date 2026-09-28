package analyzer

import (
	"fmt"
	"math"

	"github.com/umais-codes/web-analyzer/internal/model"
)

// CalculateScores evaluates raw metrics, computes category scores, overall grade, and prioritized recommendations.
func CalculateScores(report *model.AnalysisReport) {
	var recs []model.Recommendation

	// 1. Performance Score
	perfScore := 100
	ttfb := report.Performance.TimeToFirstByteMs
	if ttfb > 2000 {
		perfScore -= 40
		recs = append(recs, model.Recommendation{
			Category:    "Performance",
			Priority:    "high",
			Title:       "High Time to First Byte (TTFB)",
			Description: fmt.Sprintf("TTFB was %d ms. Server response time is very slow (>2s).", ttfb),
			Action:      "Optimize backend database queries, implement caching (Redis/CDN), and consider closer server locations.",
		})
	} else if ttfb > 800 {
		perfScore -= 20
		recs = append(recs, model.Recommendation{
			Category:    "Performance",
			Priority:    "medium",
			Title:       "Moderate TTFB Delay",
			Description: fmt.Sprintf("TTFB was %d ms. Optimal TTFB should be under 400 ms.", ttfb),
			Action:      "Use an edge CDN such as Cloudflare or Fastly to serve cached assets faster.",
		})
	} else if ttfb > 400 {
		perfScore -= 10
	}

	if !report.Performance.IsCompressed && report.Performance.ContentLengthBytes > 50000 {
		perfScore -= 15
		recs = append(recs, model.Recommendation{
			Category:    "Performance",
			Priority:    "high",
			Title:       "Enable Gzip or Brotli Compression",
			Description: "The response payload is uncompressed, resulting in slower transfer speeds.",
			Action:      "Enable Gzip or Brotli compression on your web server (Nginx/Apache/Cloudflare).",
		})
	}

	if report.Performance.StatusCode >= 400 {
		perfScore -= 30
		recs = append(recs, model.Recommendation{
			Category:    "Performance",
			Priority:    "high",
			Title:       fmt.Sprintf("HTTP Error Status: %d", report.Performance.StatusCode),
			Description: "The target page returned a client or server error response.",
			Action:      "Verify page availability, routing configurations, and server health.",
		})
	}

	if perfScore < 0 {
		perfScore = 0
	}
	report.Performance.Score = perfScore

	// 2. Security Score
	secScore := 0
	if report.Security.HTTPS {
		secScore += 20
	} else {
		recs = append(recs, model.Recommendation{
			Category:    "Security",
			Priority:    "high",
			Title:       "Unencrypted HTTP Connection",
			Description: "The website does not enforce HTTPS. Data in transit is vulnerable to interception.",
			Action:      "Install an SSL/TLS certificate (e.g. Let's Encrypt) and force HTTPS redirection.",
		})
	}

	if report.Security.SSLCertificate != nil && report.Security.SSLCertificate.Valid {
		secScore += 15
		if report.Security.SSLCertificate.DaysRemaining < 15 {
			recs = append(recs, model.Recommendation{
				Category:    "Security",
				Priority:    "high",
				Title:       "SSL Certificate Expiring Soon",
				Description: fmt.Sprintf("Certificate expires in %d days.", report.Security.SSLCertificate.DaysRemaining),
				Action:      "Renew your SSL/TLS certificate immediately to avoid browser warnings.",
			})
		}
	} else if report.Security.HTTPS {
		recs = append(recs, model.Recommendation{
			Category:    "Security",
			Priority:    "high",
			Title:       "Invalid or Untrusted SSL Certificate",
			Description: "The TLS certificate is invalid, untrusted, or has expired.",
			Action:      "Check certificate authority chain and ensure your certificate covers this hostname.",
		})
	}

	// Security Headers Checks
	h := report.Security.Headers
	if h.HSTS.Status == "pass" {
		secScore += 15
	} else {
		recs = append(recs, model.Recommendation{
			Category:    "Security",
			Priority:    "medium",
			Title:       "Missing HSTS Header",
			Description: "Strict-Transport-Security enforces HTTPS connections in modern browsers.",
			Action:      h.HSTS.Recommendation,
		})
	}

	if h.CSP.Status == "pass" {
		secScore += 15
	} else if h.CSP.Status == "warning" {
		secScore += 8
	} else {
		recs = append(recs, model.Recommendation{
			Category:    "Security",
			Priority:    "medium",
			Title:       "Missing Content-Security-Policy",
			Description: "CSP helps prevent Cross-Site Scripting (XSS) and code injection attacks.",
			Action:      h.CSP.Recommendation,
		})
	}

	if h.XFrameOptions.Status == "pass" {
		secScore += 10
	} else {
		recs = append(recs, model.Recommendation{
			Category:    "Security",
			Priority:    "medium",
			Title:       "Missing X-Frame-Options Header",
			Description: "Defends against clickjacking attacks by controlling iframe embeds.",
			Action:      h.XFrameOptions.Recommendation,
		})
	}

	if h.XContentTypeOptions.Status == "pass" {
		secScore += 10
	} else {
		recs = append(recs, model.Recommendation{
			Category:    "Security",
			Priority:    "low",
			Title:       "Missing X-Content-Type-Options",
			Description: "Prevents MIME sniffing attacks by telling browsers to trust content-type.",
			Action:      h.XContentTypeOptions.Recommendation,
		})
	}

	// DNS & Email Hygiene Checks
	if report.Security.DNS.HasSPF {
		secScore += 5
	} else if report.Security.DNS.HasMX {
		recs = append(recs, model.Recommendation{
			Category:    "Security",
			Priority:    "medium",
			Title:       "Missing SPF DNS Record",
			Description: "Domain has active email (MX) records but no SPF record configured.",
			Action:      "Publish a TXT record with 'v=spf1 ...' to prevent email address spoofing.",
		})
	}

	if report.Security.DNS.HasDMARC {
		secScore += 5
	} else if report.Security.DNS.HasMX {
		recs = append(recs, model.Recommendation{
			Category:    "Security",
			Priority:    "medium",
			Title:       "Missing DMARC Email Security Policy",
			Description: "DMARC helps protect against email phishing and executive impersonation.",
			Action:      "Configure a DMARC policy at '_dmarc.yourdomain.com'.",
		})
	}

	if len(report.Security.Cookies.Issues) > 0 {
		secScore -= 5
		for _, issue := range report.Security.Cookies.Issues {
			recs = append(recs, model.Recommendation{
				Category:    "Security",
				Priority:    "medium",
				Title:       "Insecure Cookie Flag",
				Description: issue,
				Action:      "Ensure all sensitive cookies specify 'Secure; HttpOnly; SameSite=Lax'.",
			})
		}
	}

	if secScore > 100 {
		secScore = 100
	}
	if secScore < 0 {
		secScore = 0
	}
	report.Security.Score = secScore

	// 3. SEO Score
	seoScore := 0
	if report.SEO.Title.Status == "good" {
		seoScore += 20
	} else if report.SEO.Title.Status == "warning" {
		seoScore += 10
		recs = append(recs, model.Recommendation{
			Category:    "SEO",
			Priority:    "low",
			Title:       "Suboptimal Title Tag Length",
			Description: report.SEO.Title.Message,
			Action:      "Adjust page title to be between 40-60 characters for best search display.",
		})
	} else {
		recs = append(recs, model.Recommendation{
			Category:    "SEO",
			Priority:    "high",
			Title:       "Missing or Empty Title Tag",
			Description: "Search engines require an accurate <title> tag to identify and rank the page.",
			Action:      "Add a descriptive <title> tag summarizing the page contents.",
		})
	}

	if report.SEO.Description.Status == "good" {
		seoScore += 20
	} else if report.SEO.Description.Status == "warning" {
		seoScore += 10
		recs = append(recs, model.Recommendation{
			Category:    "SEO",
			Priority:    "medium",
			Title:       "Suboptimal Meta Description Length",
			Description: report.SEO.Description.Message,
			Action:      "Refine meta description length to 120-160 characters.",
		})
	} else {
		recs = append(recs, model.Recommendation{
			Category:    "SEO",
			Priority:    "high",
			Title:       "Missing Meta Description",
			Description: "A compelling meta description is critical for search engine click-through rates.",
			Action:      "Add a <meta name=\"description\" content=\"...\"> tag.",
		})
	}

	if report.SEO.Viewport.Status == "good" {
		seoScore += 15
	} else {
		recs = append(recs, model.Recommendation{
			Category:    "SEO",
			Priority:    "high",
			Title:       "Missing Mobile Viewport Meta Tag",
			Description: "Without a viewport meta tag, mobile devices will render at desktop dimensions.",
			Action:      "Include <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">.",
		})
	}

	if report.SEO.H1Count == 1 {
		seoScore += 15
	} else if report.SEO.H1Count == 0 {
		recs = append(recs, model.Recommendation{
			Category:    "SEO",
			Priority:    "medium",
			Title:       "Missing H1 Heading",
			Description: "No <h1> tag was found. H1 headings establish page topic hierarchy.",
			Action:      "Add a single, clear <h1> tag representing the primary subject.",
		})
	} else {
		seoScore += 10
	}

	if report.SEO.Canonical.Status == "good" {
		seoScore += 10
	}

	if report.StructuredData.Present {
		seoScore += 10
	} else {
		recs = append(recs, model.Recommendation{
			Category:    "SEO",
			Priority:    "low",
			Title:       "No Structured Data (Schema.org / JSON-LD)",
			Description: "Rich snippets and Schema.org markup enhance organic search visibility.",
			Action:      "Add JSON-LD structured data (e.g. WebSite, Organization, Article) into your HTML <head>.",
		})
	}

	if report.SEO.Discovery.HasRobotsTxt {
		seoScore += 5
	}
	if report.SEO.Discovery.HasSitemap {
		seoScore += 5
	}

	if seoScore > 100 {
		seoScore = 100
	}
	report.SEO.Score = seoScore

	// 4. Content & Best Practices Score
	contentScore := 100
	if report.Content.TotalImages > 0 && report.Content.ImagesMissingAlt > 0 {
		missingRatio := float64(report.Content.ImagesMissingAlt) / float64(report.Content.TotalImages)
		penalty := int(math.Round(missingRatio * 30))
		contentScore -= penalty
		recs = append(recs, model.Recommendation{
			Category:    "Content",
			Priority:    "medium",
			Title:       fmt.Sprintf("%d Images Missing Alt Attributes", report.Content.ImagesMissingAlt),
			Description: "Alt tags provide essential context for accessibility screen readers and image SEO.",
			Action:      "Add informative alt=\"...\" descriptions to all meaningful image elements.",
		})
	}

	if report.Content.WordCount < 50 {
		contentScore -= 20
		recs = append(recs, model.Recommendation{
			Category:    "Content",
			Priority:    "low",
			Title:       "Thin Content Detected",
			Description: fmt.Sprintf("Page has only %d words. Low word count can hurt organic search rankings.", report.Content.WordCount),
			Action:      "Expand content with informative, original text.",
		})
	}

	if contentScore < 0 {
		contentScore = 0
	}
	report.Content.Score = contentScore

	// Overall Score Calculation (Weighted)
	overall := int(math.Round(
		float64(report.Performance.Score)*0.25 +
			float64(report.Security.Score)*0.35 +
			float64(report.SEO.Score)*0.25 +
			float64(report.Content.Score)*0.15,
	))

	if overall > 100 {
		overall = 100
	}
	if overall < 0 {
		overall = 0
	}
	report.OverallScore = overall

	// Grade calculation
	switch {
	case overall >= 95:
		report.Grade = "A+"
	case overall >= 88:
		report.Grade = "A"
	case overall >= 78:
		report.Grade = "B"
	case overall >= 65:
		report.Grade = "C"
	case overall >= 50:
		report.Grade = "D"
	default:
		report.Grade = "F"
	}

	report.Recommendations = recs
}
