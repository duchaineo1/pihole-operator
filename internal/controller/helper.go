package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"time"

	v1alpha1 "github.com/duchaineo1/pihole-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PiholeAPIClient handles communication with Pi-hole API
type PiholeAPIClient struct {
	BaseURL  string
	Password string
	Client   *http.Client
	SID      string // Session ID after authentication
}

func (c *PiholeAPIClient) doRequest(req *http.Request) (*http.Response, error) {
	return doValidatedHTTPRequest(c.Client, req, true)
}

// buildTLSConfig constructs a *tls.Config from a PiholeAPITLSConfig and optional CA PEM bytes.
//
// Semantics:
//   - cfg nil OR cfg.Enabled == false → InsecureSkipVerify: true (default, Pi-hole self-signed certs)
//   - cfg.Enabled == true, no caData  → InsecureSkipVerify: false, system CA pool
//   - cfg.Enabled == true, caData set → InsecureSkipVerify: false, custom CA pool
func buildTLSConfig(cfg *v1alpha1.PiholeAPITLSConfig, caData []byte) *tls.Config {
	// Default: skip verification (backward-compatible, Pi-hole uses self-signed certs)
	if cfg == nil || !cfg.Enabled {
		return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // intentional default for self-signed certs
	}

	// TLS verification enabled
	tlsCfg := &tls.Config{InsecureSkipVerify: false}
	if len(caData) > 0 {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caData)
		tlsCfg.RootCAs = pool
	}
	return tlsCfg
}

// buildHTTPClient builds an *http.Client with the given TLS configuration.
func buildHTTPClient(tlsCfg *tls.Config) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// getCAData reads the CA certificate bytes from the secret referenced in cfg.
// Returns nil if cfg is nil or CASecretRef is nil (no CA configured).
// The key field on CASecretRef is required — no default is applied.
func getCAData(ctx context.Context, c client.Client, namespace string, cfg *v1alpha1.PiholeAPITLSConfig) ([]byte, error) {
	if cfg == nil || cfg.CASecretRef == nil {
		return nil, nil
	}
	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: cfg.CASecretRef.Name, Namespace: namespace}, secret); err != nil {
		return nil, fmt.Errorf("failed to get CA secret %q: %w", cfg.CASecretRef.Name, err)
	}
	data, ok := secret.Data[cfg.CASecretRef.Key]
	if !ok {
		return nil, fmt.Errorf("key %q not found in CA secret %q", cfg.CASecretRef.Key, cfg.CASecretRef.Name)
	}
	return data, nil
}

// NewPiholeAPIClient creates a new Pi-hole API client with the given HTTP client.
// Use buildHTTPClient(buildTLSConfig(...)) to construct the client with appropriate TLS settings.
func NewPiholeAPIClient(baseURL, password string, httpClient *http.Client) *PiholeAPIClient {
	return &PiholeAPIClient{
		BaseURL:  baseURL,
		Password: password,
		Client:   httpClient,
	}
}

// AuthRequest represents the authentication request
type AuthRequest struct {
	Password string `json:"password"`
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	Session struct {
		Valid bool   `json:"valid"`
		SID   string `json:"sid"`
	} `json:"session"`
}

// Authenticate logs into Pi-hole and gets a session ID
func (c *PiholeAPIClient) Authenticate(ctx context.Context) error {
	authReq := AuthRequest{Password: c.Password}
	jsonData, err := json.Marshal(authReq)
	if err != nil {
		return fmt.Errorf("failed to marshal auth request: %w", err)
	}

	url := fmt.Sprintf("%s/api/auth", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return fmt.Errorf("failed to parse auth response: %w", err)
	}

	if !authResp.Session.Valid {
		return fmt.Errorf("authentication failed: invalid session")
	}

	c.SID = authResp.Session.SID
	return nil
}

// BlocklistCreateRequest represents a blocklist creation request
type BlocklistCreateRequest struct {
	Address string `json:"address"`
	Comment string `json:"comment,omitempty"`
	Groups  []int  `json:"groups,omitempty"`
	Enabled bool   `json:"enabled"`
}

// BlocklistResponse represents a blocklist API response
type BlocklistResponse struct {
	ID      int    `json:"id"`
	Address string `json:"address"`
	Comment string `json:"comment"`
	Enabled bool   `json:"enabled"`
}

// AddBlocklist adds a blocklist to Pi-hole
func (c *PiholeAPIClient) AddBlocklist(ctx context.Context, req BlocklistCreateRequest) (*BlocklistResponse, error) {
	if c.SID == "" {
		if err := c.Authenticate(ctx); err != nil {
			return nil, err
		}
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/lists?type=block", c.BaseURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-FTL-SID", c.SID)

	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("API error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var blocklistResp BlocklistResponse
	if err := json.Unmarshal(body, &blocklistResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &blocklistResp, nil
}

// ListBlocklists retrieves all blocklists from Pi-hole
func (c *PiholeAPIClient) ListBlocklists(ctx context.Context) ([]BlocklistResponse, error) {
	if c.SID == "" {
		if err := c.Authenticate(ctx); err != nil {
			return nil, err
		}
	}

	url := fmt.Sprintf("%s/api/lists?type=block", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-FTL-SID", c.SID)

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var lists []BlocklistResponse
	if err := json.Unmarshal(body, &lists); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return lists, nil
}

// DeleteBlocklist deletes a blocklist from Pi-hole by ID
func (c *PiholeAPIClient) DeleteBlocklist(ctx context.Context, listID int) error {
	if c.SID == "" {
		if err := c.Authenticate(ctx); err != nil {
			return err
		}
	}

	url := fmt.Sprintf("%s/api/lists/%d", c.BaseURL, listID)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-FTL-SID", c.SID)

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to call API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return nil
}

// DNSHostsResponse represents the response from /api/config/dns/hosts
type DNSHostsResponse struct {
	Config struct {
		DNS struct {
			Hosts []string `json:"hosts"`
		} `json:"dns"`
	} `json:"config"`
}

// DNSCNAMEResponse represents the response from /api/config/dns/cnameRecords
type DNSCNAMEResponse struct {
	Config struct {
		DNS struct {
			CNAMERecords []string `json:"cnameRecords"`
		} `json:"dns"`
	} `json:"config"`
}

// ListDNSHosts retrieves all DNS host records from Pi-hole
func (c *PiholeAPIClient) ListDNSHosts(ctx context.Context) ([]string, error) {
	if c.SID == "" {
		if err := c.Authenticate(ctx); err != nil {
			return nil, err
		}
	}

	url := fmt.Sprintf("%s/api/config/dns/hosts", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-FTL-SID", c.SID)

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var hostsResp DNSHostsResponse
	if err := json.Unmarshal(body, &hostsResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return hostsResp.Config.DNS.Hosts, nil
}

// AddDNSHost adds a DNS host record (A/AAAA) to Pi-hole
func (c *PiholeAPIClient) AddDNSHost(ctx context.Context, entry string) error {
	if c.SID == "" {
		if err := c.Authenticate(ctx); err != nil {
			return err
		}
	}

	url := fmt.Sprintf("%s/api/config/dns/hosts/%s", c.BaseURL, urlEncode(entry))
	req, err := http.NewRequestWithContext(ctx, "PUT", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-FTL-SID", c.SID)

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to call API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteDNSHost removes a DNS host record (A/AAAA) from Pi-hole
func (c *PiholeAPIClient) DeleteDNSHost(ctx context.Context, entry string) error {
	if c.SID == "" {
		if err := c.Authenticate(ctx); err != nil {
			return err
		}
	}

	url := fmt.Sprintf("%s/api/config/dns/hosts/%s", c.BaseURL, urlEncode(entry))
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-FTL-SID", c.SID)

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to call API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return nil
}

// ListDNSCNAMEs retrieves all DNS CNAME records from Pi-hole
func (c *PiholeAPIClient) ListDNSCNAMEs(ctx context.Context) ([]string, error) {
	if c.SID == "" {
		if err := c.Authenticate(ctx); err != nil {
			return nil, err
		}
	}

	url := fmt.Sprintf("%s/api/config/dns/cnameRecords", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-FTL-SID", c.SID)

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var cnameResp DNSCNAMEResponse
	if err := json.Unmarshal(body, &cnameResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return cnameResp.Config.DNS.CNAMERecords, nil
}

// AddDNSCNAME adds a DNS CNAME record to Pi-hole
func (c *PiholeAPIClient) AddDNSCNAME(ctx context.Context, entry string) error {
	if c.SID == "" {
		if err := c.Authenticate(ctx); err != nil {
			return err
		}
	}

	url := fmt.Sprintf("%s/api/config/dns/cnameRecords/%s", c.BaseURL, urlEncode(entry))
	req, err := http.NewRequestWithContext(ctx, "PUT", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-FTL-SID", c.SID)

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to call API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteDNSCNAME removes a DNS CNAME record from Pi-hole
func (c *PiholeAPIClient) DeleteDNSCNAME(ctx context.Context, entry string) error {
	if c.SID == "" {
		if err := c.Authenticate(ctx); err != nil {
			return err
		}
	}

	url := fmt.Sprintf("%s/api/config/dns/cnameRecords/%s", c.BaseURL, urlEncode(entry))
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-FTL-SID", c.SID)

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to call API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return nil
}

// StatsSummaryResponse represents the response from /api/stats/summary
type StatsSummaryResponse struct {
	Queries struct {
		Total          int64   `json:"total"`
		Blocked        int64   `json:"blocked"`
		PercentBlocked float64 `json:"percent_blocked"`
		UniqueDomains  int64   `json:"unique_domains"`
		Forwarded      int64   `json:"forwarded"`
		Cached         int64   `json:"cached"`
	} `json:"queries"`
	Clients struct {
		Active int32 `json:"active"`
		Total  int32 `json:"total"`
	} `json:"clients"`
	Gravity struct {
		DomainsBeingBlocked int64 `json:"domains_being_blocked"`
		LastUpdate          int64 `json:"last_update"`
	} `json:"gravity"`
}

// GetStats retrieves DNS statistics from the Pi-hole API.
// It authenticates if no session exists, then calls GET /api/stats/summary.
func (c *PiholeAPIClient) GetStats(ctx context.Context) (*StatsSummaryResponse, error) {
	if c.SID == "" {
		if err := c.Authenticate(ctx); err != nil {
			return nil, err
		}
	}

	url := fmt.Sprintf("%s/api/stats/summary", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create stats request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-FTL-SID", c.SID)

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call stats API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read stats response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stats API error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var stats StatsSummaryResponse
	if err := json.Unmarshal(body, &stats); err != nil {
		return nil, fmt.Errorf("failed to parse stats response: %w", err)
	}

	return &stats, nil
}

// PodBaseURL returns the HTTPS base URL for an individual StatefulSet pod.
func PodBaseURL(piholeName, namespace string, ordinal int32) string {
	return fmt.Sprintf("https://%s-%d.%s-headless.%s.svc.cluster.local",
		piholeName, ordinal, piholeName, namespace)
}

// PodCacheKey returns a cache key scoped to an individual StatefulSet pod.
func PodCacheKey(namespace, piholeName string, ordinal int32) string {
	return fmt.Sprintf("%s/%s-%d", namespace, piholeName, ordinal)
}

// urlEncode encodes a string for use in a URL path segment
func urlEncode(s string) string {
	// Use net/url PathEscape for proper encoding
	return neturl.PathEscape(s)
}

// UpdateBlocklist updates a blocklist in Pi-hole
func (c *PiholeAPIClient) UpdateBlocklist(ctx context.Context, listID int, req BlocklistCreateRequest) error {
	if c.SID == "" {
		if err := c.Authenticate(ctx); err != nil {
			return err
		}
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/lists/%d", c.BaseURL, listID)
	httpReq, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-FTL-SID", c.SID)

	resp, err := c.doRequest(httpReq)
	if err != nil {
		return fmt.Errorf("failed to call API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return nil
}

// listPiholesForNamespaces returns all Pihole instances across the given target namespaces.
// If targetNamespaces is empty, only the fallback namespace is searched.
// If targetNamespaces contains "*", all namespaces are searched.
func listPiholesForNamespaces(ctx context.Context, c client.Client, fallbackNamespace string, targetNamespaces []string) ([]v1alpha1.Pihole, error) {
	// Default: same-namespace only (backward-compatible)
	if len(targetNamespaces) == 0 {
		list := &v1alpha1.PiholeList{}
		if err := c.List(ctx, list, client.InNamespace(fallbackNamespace)); err != nil {
			return nil, err
		}
		return list.Items, nil
	}

	// Wildcard: all namespaces
	for _, ns := range targetNamespaces {
		if ns == "*" {
			list := &v1alpha1.PiholeList{}
			if err := c.List(ctx, list); err != nil {
				return nil, err
			}
			return list.Items, nil
		}
	}

	// Specific namespaces: accumulate and deduplicate by namespace/name
	seen := make(map[string]struct{})
	var result []v1alpha1.Pihole
	for _, ns := range targetNamespaces {
		list := &v1alpha1.PiholeList{}
		if err := c.List(ctx, list, client.InNamespace(ns)); err != nil {
			return nil, err
		}
		for _, p := range list.Items {
			key := p.Namespace + "/" + p.Name
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				result = append(result, p)
			}
		}
	}
	return result, nil
}
