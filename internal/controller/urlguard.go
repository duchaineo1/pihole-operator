package controller

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// validateOutboundURL applies baseline SSRF guardrails for dynamic outbound requests.
//
// Policy:
//   - Always allow HTTPS
//   - Allow HTTP when allowHTTP is true
//   - Reject empty host, localhost, and obviously unsafe IP literals
func validateOutboundURL(rawURL string, allowHTTP bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}

	switch strings.ToLower(u.Scheme) {
	case "https":
		// always allowed
	case "http":
		if !allowHTTP {
			return fmt.Errorf("http URL is not allowed: %q", rawURL)
		}
	default:
		return fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}

	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return fmt.Errorf("URL host is required: %q", rawURL)
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("localhost is not allowed for outbound requests")
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("unsafe IP target is not allowed: %s", ip.String())
		}
	}

	return nil
}

func doValidatedHTTPRequest(httpClient *http.Client, req *http.Request, allowHTTP bool) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("request URL is required")
	}
	if err := validateOutboundURL(req.URL.String(), allowHTTP); err != nil {
		return nil, err
	}
	//nolint:gosec // URL is validated by validateOutboundURL before request execution.
	return httpClient.Do(req)
}
