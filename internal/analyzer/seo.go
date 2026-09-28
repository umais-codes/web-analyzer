package analyzer

import (
	"html"
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/umais-codes/web-analyzer/internal/model"
)

var (
	titleRegex     = regexp.MustCompile(`(?i)<title[^>]*>([\s\S]*?)<\/title>`)
	metaRegex      = regexp.MustCompile(`(?i)<meta\s+([^>]+)>`)
	linkTagRegex   = regexp.MustCompile(`(?i)<link\s+([^>]+)>`)
	htmlTagRegex   = regexp.MustCompile(`(?i)<html\s+([^>]+)>`)
	h1Regex        = regexp.MustCompile(`(?i)<h1[^>]*>([\s\S]*?)<\/h1>`)
	h2Regex        = regexp.MustCompile(`(?i)<h2[^>]*>([\s\S]*?)<\/h2>`)
	h3Regex        = regexp.MustCompile(`(?i)<h3[^>]*>([\s\S]*?)<\/h3>`)
	imgRegex       = regexp.MustCompile(`(?i)<img\s+([^>]+)>`)
	aHrefRegex     = regexp.MustCompile(`(?i)<a\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*>`)
	scriptReg      = regexp.MustCompile(`(?is)<script[^>]*>.*?<\/script>`)
	styleReg       = regexp.MustCompile(`(?is)<style[^>]*>.*?<\/style>`)
	svgReg         = regexp.MustCompile(`(?is)<svg[^>]*>.*?<\/svg>`)
	noscriptReg    = regexp.MustCompile(`(?is)<noscript[^>]*>.*?<\/noscript>`)
	commentsReg    = regexp.MustCompile(`<!--[\s\S]*?-->`)
	allTagsReg     = regexp.MustCompile(`<[^>]+>`)
	attrRegex      = regexp.MustCompile(`(?i)([a-zA-Z0-9_\-:]+)\s*=\s*["']([^"']*)["']`)
)

// ExtractSEOAndContent parses HTML text and extracts rich SEO, content, and tech fingerprint metrics.
func ExtractSEOAndContent(htmlBody string, pageURL string) (model.SEOReport, model.ContentReport, model.TechnologyReport) {
	seo := model.SEOReport{
		H1List: []string{},
		H2List: []string{},
	}
	content := model.ContentReport{
		SampleImages: []model.ImageInfo{},
	}
	tech := model.TechnologyReport{
		DetectedStack: []string{},
	}

	baseParsed, _ := url.Parse(pageURL)
	baseDomain := ""
	if baseParsed != nil {
		baseDomain = strings.ToLower(baseParsed.Hostname())
	}

	// 1. Title Extraction & Evaluation
	if m := titleRegex.FindStringSubmatch(htmlBody); len(m) > 1 {
		cleanTitle := strings.TrimSpace(html.UnescapeString(stripTags(m[1])))
		length := len(cleanTitle)
		seo.Title = model.SEOItem{
			Value:  cleanTitle,
			Length: length,
		}
		if length == 0 {
			seo.Title.Status = "fail"
			seo.Title.Message = "Title tag is empty."
		} else if length < 30 {
			seo.Title.Status = "warning"
			seo.Title.Message = "Title is shorter than recommended (30-60 characters)."
		} else if length > 65 {
			seo.Title.Status = "warning"
			seo.Title.Message = "Title is longer than 65 characters and may be truncated in search results."
		} else {
			seo.Title.Status = "good"
			seo.Title.Message = "Title length is optimal for search engines."
		}
	} else {
		seo.Title = model.SEOItem{
			Status:  "fail",
			Message: "No <title> tag found on page.",
		}
	}

	// 2. HTML tag attributes (Language)
	if m := htmlTagRegex.FindStringSubmatch(htmlBody); len(m) > 1 {
		attrs := parseAttributes(m[1])
		if lang, ok := attrs["lang"]; ok {
			seo.Language = lang
		}
	}

	// 3. Meta Tags (Description, Viewport, Robots, Charset, OG, Twitter)
	metaMatches := metaRegex.FindAllStringSubmatch(htmlBody, -1)
	for _, match := range metaMatches {
		if len(match) < 2 {
			continue
		}
		attrs := parseAttributes(match[1])
		name := strings.ToLower(attrs["name"])
		property := strings.ToLower(attrs["property"])
		contentVal := attrs["content"]
		charsetVal := attrs["charset"]

		if charsetVal != "" {
			seo.Charset = charsetVal
		}

		switch name {
		case "description":
			cleanDesc := strings.TrimSpace(html.UnescapeString(contentVal))
			length := len(cleanDesc)
			seo.Description = model.SEOItem{
				Value:  cleanDesc,
				Length: length,
			}
			if length == 0 {
				seo.Description.Status = "fail"
				seo.Description.Message = "Meta description is empty."
			} else if length < 70 {
				seo.Description.Status = "warning"
				seo.Description.Message = "Meta description is short (<70 chars). Aim for 120-160 characters."
			} else if length > 165 {
				seo.Description.Status = "warning"
				seo.Description.Message = "Meta description exceeds 165 characters and may be truncated by search engines."
			} else {
				seo.Description.Status = "good"
				seo.Description.Message = "Meta description length is optimal."
			}
		case "viewport":
			seo.Viewport = model.SEOItem{
				Value:   contentVal,
				Status:  "good",
				Message: "Mobile viewport tag is configured.",
			}
		case "robots":
			seo.Robots = contentVal
		case "generator":
			if contentVal != "" {
				tech.DetectedStack = appendStack(tech.DetectedStack, contentVal)
			}
		case "twitter:card":
			seo.TwitterCard.Card = contentVal
		case "twitter:title":
			seo.TwitterCard.Title = contentVal
		case "twitter:description":
			seo.TwitterCard.Description = contentVal
		case "twitter:image":
			seo.TwitterCard.Image = contentVal
		}

		switch property {
		case "og:title":
			seo.OpenGraph.Title = contentVal
		case "og:description":
			seo.OpenGraph.Description = contentVal
		case "og:image":
			seo.OpenGraph.Image = contentVal
		case "og:url":
			seo.OpenGraph.URL = contentVal
		case "og:site_name":
			seo.OpenGraph.SiteName = contentVal
		case "og:type":
			seo.OpenGraph.Type = contentVal
		}
	}

	if seo.Description.Value == "" && seo.Description.Status == "" {
		seo.Description = model.SEOItem{
			Status:  "fail",
			Message: "No meta description tag found.",
		}
	}
	if seo.Viewport.Value == "" {
		seo.Viewport = model.SEOItem{
			Status:  "fail",
			Message: "Missing viewport meta tag. Mobile responsiveness may be compromised.",
		}
	}

	// 4. Link Tags (Canonical, Favicon)
	linkMatches := linkTagRegex.FindAllStringSubmatch(htmlBody, -1)
	for _, match := range linkMatches {
		if len(match) < 2 {
			continue
		}
		attrs := parseAttributes(match[1])
		rel := strings.ToLower(attrs["rel"])
		href := attrs["href"]

		if rel == "canonical" {
			seo.Canonical = model.SEOItem{
				Value:   href,
				Status:  "good",
				Message: "Canonical URL specified.",
			}
		} else if strings.Contains(rel, "icon") && seo.Favicon == "" {
			seo.Favicon = resolveURL(pageURL, href)
		}
	}
	if seo.Canonical.Value == "" {
		seo.Canonical = model.SEOItem{
			Status:  "warning",
			Message: "Canonical URL tag is not defined.",
		}
	}

	// 5. Headings Hierarchy
	for _, m := range h1Regex.FindAllStringSubmatch(htmlBody, -1) {
		text := strings.TrimSpace(stripTags(m[1]))
		if text != "" {
			seo.H1List = append(seo.H1List, text)
		}
	}
	seo.H1Count = len(seo.H1List)

	for _, m := range h2Regex.FindAllStringSubmatch(htmlBody, -1) {
		text := strings.TrimSpace(stripTags(m[1]))
		if text != "" {
			seo.H2List = append(seo.H2List, text)
		}
	}
	seo.H2Count = len(seo.H2List)

	h3Matches := h3Regex.FindAllStringSubmatch(htmlBody, -1)
	seo.H3Count = len(h3Matches)

	// 6. Image Analysis (Alt tags)
	imgMatches := imgRegex.FindAllStringSubmatch(htmlBody, -1)
	content.TotalImages = len(imgMatches)
	missingAltCount := 0

	for i, match := range imgMatches {
		attrs := parseAttributes(match[1])
		src := attrs["src"]
		alt, hasAlt := attrs["alt"]
		altTrimmed := strings.TrimSpace(alt)

		if !hasAlt || altTrimmed == "" {
			missingAltCount++
		}

		if i < 10 && src != "" {
			content.SampleImages = append(content.SampleImages, model.ImageInfo{
				Src:    resolveURL(pageURL, src),
				Alt:    altTrimmed,
				HasAlt: hasAlt && altTrimmed != "",
			})
		}
	}
	content.ImagesMissingAlt = missingAltCount

	// 7. Links Analysis (Internal vs External)
	linkMatches2 := aHrefRegex.FindAllStringSubmatch(htmlBody, -1)
	content.TotalLinks = len(linkMatches2)
	internalCount := 0
	externalCount := 0

	for _, match := range linkMatches2 {
		href := strings.TrimSpace(match[1])
		if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") {
			continue
		}
		if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
			linkURL, err := url.Parse(href)
			if err == nil && strings.ToLower(linkURL.Hostname()) != baseDomain && !strings.HasSuffix(strings.ToLower(linkURL.Hostname()), "."+baseDomain) {
				externalCount++
			} else {
				internalCount++
			}
		} else {
			// Relative link -> Internal
			internalCount++
		}
	}
	content.InternalLinks = internalCount
	content.ExternalLinks = externalCount

	// 8. Word Count & Reading Time
	textContent := scriptReg.ReplaceAllString(htmlBody, " ")
	textContent = styleReg.ReplaceAllString(textContent, " ")
	textContent = svgReg.ReplaceAllString(textContent, " ")
	textContent = noscriptReg.ReplaceAllString(textContent, " ")
	textContent = commentsReg.ReplaceAllString(textContent, " ")
	textContent = allTagsReg.ReplaceAllString(textContent, " ")
	textContent = html.UnescapeString(textContent)
	words := strings.Fields(textContent)
	content.WordCount = len(words)
	content.ReadingTimeMinutes = int(math.Ceil(float64(content.WordCount) / 200.0))
	if content.ReadingTimeMinutes == 0 && content.WordCount > 0 {
		content.ReadingTimeMinutes = 1
	}

	// 9. Tech Stack Fingerprinting
	lowerBody := strings.ToLower(htmlBody)
	if strings.Contains(lowerBody, "wp-content") || strings.Contains(lowerBody, "wp-includes") {
		tech.DetectedStack = appendStack(tech.DetectedStack, "WordPress")
	}
	if strings.Contains(lowerBody, "_next/static") || strings.Contains(lowerBody, "__next") {
		tech.DetectedStack = appendStack(tech.DetectedStack, "Next.js")
	}
	if strings.Contains(lowerBody, "react") || strings.Contains(lowerBody, "data-reactroot") {
		tech.DetectedStack = appendStack(tech.DetectedStack, "React")
	}
	if strings.Contains(lowerBody, "vue") || strings.Contains(lowerBody, "v-") {
		tech.DetectedStack = appendStack(tech.DetectedStack, "Vue.js")
	}
	if strings.Contains(lowerBody, "cdn.shopify.com") || strings.Contains(lowerBody, "shopify") {
		tech.DetectedStack = appendStack(tech.DetectedStack, "Shopify")
	}
	if strings.Contains(lowerBody, "tailwindcss") || strings.Contains(lowerBody, "tailwind") {
		tech.DetectedStack = appendStack(tech.DetectedStack, "Tailwind CSS")
	}
	if strings.Contains(lowerBody, "bootstrap") {
		tech.DetectedStack = appendStack(tech.DetectedStack, "Bootstrap")
	}
	if strings.Contains(lowerBody, "googletagmanager.com/gtm.js") {
		tech.DetectedStack = appendStack(tech.DetectedStack, "Google Tag Manager")
	}
	if strings.Contains(lowerBody, "google-analytics.com") || strings.Contains(lowerBody, "gtag(") {
		tech.DetectedStack = appendStack(tech.DetectedStack, "Google Analytics")
	}
	if strings.Contains(lowerBody, "cloudflare") {
		tech.DetectedStack = appendStack(tech.DetectedStack, "Cloudflare")
	}

	return seo, content, tech
}

func parseAttributes(tagContent string) map[string]string {
	attrs := make(map[string]string)
	matches := attrRegex.FindAllStringSubmatch(tagContent, -1)
	for _, m := range matches {
		if len(m) > 2 {
			attrs[strings.ToLower(m[1])] = m[2]
		}
	}
	return attrs
}

func stripTags(input string) string {
	return allTagsReg.ReplaceAllString(input, "")
}

func appendStack(stack []string, item string) []string {
	for _, s := range stack {
		if strings.EqualFold(s, item) {
			return stack
		}
	}
	return append(stack, item)
}

func resolveURL(base, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "//") {
		if strings.HasPrefix(ref, "//") {
			return "https:" + ref
		}
		return ref
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return baseURL.ResolveReference(refURL).String()
}
