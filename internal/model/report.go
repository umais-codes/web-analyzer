package model

import "time"

// AnalysisReport represents the complete analysis result of a website.
type AnalysisReport struct {
	URL                 string             `json:"url"`
	NormalizedURL       string             `json:"normalized_url"`
	FinalURL            string             `json:"final_url"`
	IsRedirected        bool               `json:"is_redirected"`
	RedirectChain       []RedirectHop      `json:"redirect_chain"`
	Timestamp           time.Time          `json:"timestamp"`
	OverallScore        int                `json:"overall_score"`
	Grade               string             `json:"grade"`
	ExecutionDurationMs int64              `json:"execution_duration_ms"`
	Performance         PerformanceMetrics `json:"performance"`
	Security            SecurityReport     `json:"security"`
	SEO                 SEOReport          `json:"seo"`
	Content             ContentReport      `json:"content"`
	Technology          TechnologyReport   `json:"technology"`
	Recommendations     []Recommendation   `json:"recommendations"`
}

// RedirectHop stores info for each redirection step.
type RedirectHop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

// PerformanceMetrics captures timing and payload metrics.
type PerformanceMetrics struct {
	Score                  int    `json:"score"`
	StatusCode             int    `json:"status_code"`
	StatusText             string `json:"status_text"`
	Protocol               string `json:"protocol"`
	TotalTimeMs            int64  `json:"total_time_ms"`
	DNSLookupTimeMs        int64  `json:"dns_lookup_time_ms"`
	TCPConnectTimeMs       int64  `json:"tcp_connect_time_ms"`
	TLSHandshakeTimeMs     int64  `json:"tls_handshake_time_ms"`
	TimeToFirstByteMs      int64  `json:"time_to_first_byte_ms"`
	ContentDownloadTimeMs  int64  `json:"content_download_time_ms"`
	ContentLengthBytes     int64  `json:"content_length_bytes"`
	ContentLengthFormatted string `json:"content_length_formatted"`
	ContentType            string `json:"content_type"`
	ContentEncoding        string `json:"content_encoding"`
	IsCompressed           bool   `json:"is_compressed"`
}

// SecurityReport details SSL/TLS and security headers.
type SecurityReport struct {
	Score          int                  `json:"score"`
	HTTPS          bool                 `json:"https"`
	SSLCertificate *SSLCertInfo         `json:"ssl_certificate,omitempty"`
	Headers        SecurityHeadersCheck `json:"headers"`
	MixedContent   bool                 `json:"mixed_content"`
}

// SSLCertInfo contains details of the TLS certificate.
type SSLCertInfo struct {
	Valid         bool      `json:"valid"`
	Issuer        string    `json:"issuer"`
	Subject       string    `json:"subject"`
	ExpiryDate    time.Time `json:"expiry_date"`
	DaysRemaining int       `json:"days_remaining"`
	TLSVersion    string    `json:"tls_version"`
	CipherSuite   string    `json:"cipher_suite"`
	SANs          []string  `json:"sans"`
	ErrorMessage  string    `json:"error_message,omitempty"`
}

// SecurityHeadersCheck tracks critical protective HTTP response headers.
type SecurityHeadersCheck struct {
	HSTS                HeaderItem `json:"hsts"`
	CSP                 HeaderItem `json:"csp"`
	XFrameOptions       HeaderItem `json:"x_frame_options"`
	XContentTypeOptions HeaderItem `json:"x_content_type_options"`
	ReferrerPolicy      HeaderItem `json:"referrer_policy"`
	PermissionsPolicy   HeaderItem `json:"permissions_policy"`
}

// HeaderItem holds status and remediation advice for an individual header.
type HeaderItem struct {
	Name           string `json:"name"`
	Present        bool   `json:"present"`
	Value          string `json:"value"`
	Status         string `json:"status"` // pass, warning, fail
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// SEOReport contains metadata, heading hierarchy, and social card previews.
type SEOReport struct {
	Score        int             `json:"score"`
	Title        SEOItem         `json:"title"`
	Description  SEOItem         `json:"description"`
	Canonical    SEOItem         `json:"canonical"`
	Robots       string          `json:"robots"`
	Viewport     SEOItem         `json:"viewport"`
	Charset      string          `json:"charset"`
	Language     string          `json:"language"`
	Favicon      string          `json:"favicon"`
	H1Count      int             `json:"h1_count"`
	H1List       []string        `json:"h1_list"`
	H2Count      int             `json:"h2_count"`
	H2List       []string        `json:"h2_list"`
	H3Count      int             `json:"h3_count"`
	OpenGraph    OpenGraphData   `json:"open_graph"`
	TwitterCard  TwitterCardData `json:"twitter_card"`
}

// SEOItem represents an individual SEO element with evaluation.
type SEOItem struct {
	Value   string `json:"value"`
	Length  int    `json:"length"`
	Status  string `json:"status"` // good, warning, fail
	Message string `json:"message"`
}

// OpenGraphData captures social sharing meta tags.
type OpenGraphData struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Image       string `json:"image"`
	URL         string `json:"url"`
	SiteName    string `json:"site_name"`
	Type        string `json:"type"`
}

// TwitterCardData captures Twitter/X sharing card meta tags.
type TwitterCardData struct {
	Card        string `json:"card"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Image       string `json:"image"`
}

// ContentReport holds statistics about on-page assets and copy.
type ContentReport struct {
	Score               int         `json:"score"`
	WordCount           int         `json:"word_count"`
	ReadingTimeMinutes  int         `json:"reading_time_minutes"`
	TotalImages         int         `json:"total_images"`
	ImagesMissingAlt    int         `json:"images_missing_alt"`
	SampleImages        []ImageInfo `json:"sample_images"`
	TotalLinks          int         `json:"total_links"`
	InternalLinks       int         `json:"internal_links"`
	ExternalLinks       int         `json:"external_links"`
	HasBrokenLinks      bool        `json:"has_broken_links"`
}

// ImageInfo captures details of an image tag.
type ImageInfo struct {
	Src    string `json:"src"`
	Alt    string `json:"alt"`
	HasAlt bool   `json:"has_alt"`
}

// TechnologyReport reveals server and tech stack fingerprints.
type TechnologyReport struct {
	Server        string   `json:"server"`
	PoweredBy     string   `json:"powered_by"`
	DetectedStack []string `json:"detected_stack"`
}

// Recommendation holds prioritized remediation guidance.
type Recommendation struct {
	Category    string `json:"category"` // Performance, Security, SEO, Content
	Priority    string `json:"priority"` // high, medium, low
	Title       string `json:"title"`
	Description string `json:"description"`
	Action      string `json:"action"`
}
