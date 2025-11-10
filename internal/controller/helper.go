package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PiholeAPIClient handles communication with Pi-hole API
type PiholeAPIClient struct {
	BaseURL  string
	Password string
	Client   *http.Client
	SID      string // Session ID after authentication
}

// NewPiholeAPIClient creates a new Pi-hole API client
func NewPiholeAPIClient(baseURL, password string) *PiholeAPIClient {
	return &PiholeAPIClient{
		BaseURL:  baseURL,
		Password: password,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
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

	resp, err := c.Client.Do(req)
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

	resp, err := c.Client.Do(httpReq)
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

	resp, err := c.Client.Do(req)
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

	resp, err := c.Client.Do(req)
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

	resp, err := c.Client.Do(httpReq)
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
