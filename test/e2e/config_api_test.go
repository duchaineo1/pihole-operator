//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// configAPITestHelper contains shared logic for config API e2e tests
type configAPITestHelper struct {
	piholeName string
	namespace  string
	podIP      string
	password   string
	client     *http.Client
	sid        string
}

func (h *configAPITestHelper) authenticate() error {
	baseURL := fmt.Sprintf("https://%s", h.podIP)
	authPayload := map[string]string{"password": h.password}
	authBody, err := json.Marshal(authPayload)
	if err != nil {
		return err
	}

	authResp, err := h.client.Post(baseURL+"/api/auth", "application/json", bytes.NewReader(authBody))
	if err != nil {
		return err
	}
	defer authResp.Body.Close()

	if authResp.StatusCode != 200 {
		return fmt.Errorf("auth failed with status %d", authResp.StatusCode)
	}

	authRespBody, err := io.ReadAll(authResp.Body)
	if err != nil {
		return err
	}

	var authResult struct {
		Session struct {
			SID string `json:"sid"`
		} `json:"session"`
	}
	if err := json.Unmarshal(authRespBody, &authResult); err != nil {
		return err
	}

	h.sid = authResult.Session.SID
	return nil
}

func (h *configAPITestHelper) getConfig(key string) (string, error) {
	baseURL := fmt.Sprintf("https://%s", h.podIP)
	req, err := http.NewRequest("GET", baseURL+"/api/config/"+key, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-FTL-SID", h.sid)

	resp, err := h.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GET /api/config/%s returned %d", key, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var configResp struct {
		Config struct {
			Value string `json:"value"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &configResp); err != nil {
		return "", err
	}

	return configResp.Config.Value, nil
}

func (h *configAPITestHelper) setConfig(key, value string) error {
	baseURL := fmt.Sprintf("https://%s", h.podIP)
	patchPayload := map[string]string{"value": value}
	patchBody, err := json.Marshal(patchPayload)
	if err != nil {
		return err
	}

	patchReq, err := http.NewRequest("PATCH", baseURL+"/api/config/"+key, bytes.NewReader(patchBody))
	if err != nil {
		return err
	}
	patchReq.Header.Set("Content-Type", "application/json")
	patchReq.Header.Set("X-FTL-SID", h.sid)

	patchResp, err := h.client.Do(patchReq)
	if err != nil {
		return err
	}
	defer patchResp.Body.Close()

	if patchResp.StatusCode != 200 {
		return fmt.Errorf("PATCH /api/config/%s returned %d", key, patchResp.StatusCode)
	}

	return nil
}

// newConfigAPITestHelper creates a helper for testing Pi-hole config API
func newConfigAPITestHelper(piholeName, namespace, podIP, password string) *configAPITestHelper {
	return &configAPITestHelper{
		piholeName: piholeName,
		namespace:  namespace,
		podIP:      podIP,
		password:   password,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}
