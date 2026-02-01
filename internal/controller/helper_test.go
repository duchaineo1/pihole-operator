package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- generateRandomPassword tests ---

func TestGenerateRandomPassword_Length(t *testing.T) {
	for _, length := range []int{0, 1, 8, 16, 32, 64} {
		pw := generateRandomPassword(length)
		if len(pw) != length {
			t.Errorf("generateRandomPassword(%d) returned length %d", length, len(pw))
		}
	}
}

func TestGenerateRandomPassword_Charset(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	pw := generateRandomPassword(1000) // large sample
	for i, ch := range pw {
		if !strings.ContainsRune(charset, ch) {
			t.Errorf("character at index %d (%c) not in charset", i, ch)
		}
	}
}

func TestGenerateRandomPassword_NotDeterministic(t *testing.T) {
	a := generateRandomPassword(32)
	b := generateRandomPassword(32)
	if a == b {
		t.Error("two consecutive calls returned the same password")
	}
}

// --- getEnvOrDefault tests ---

func TestGetEnvOrDefault(t *testing.T) {
	tests := []struct {
		value, def, want string
	}{
		{"hello", "default", "hello"},
		{"", "default", "default"},
		{"", "", ""},
		{"value", "", "value"},
	}
	for _, tt := range tests {
		got := getEnvOrDefault(tt.value, tt.def)
		if got != tt.want {
			t.Errorf("getEnvOrDefault(%q, %q) = %q, want %q", tt.value, tt.def, got, tt.want)
		}
	}
}

// --- PiholeAPIClient tests ---

func TestAuthenticate_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth" || r.Method != "POST" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}

		var req AuthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("bad request body: %v", err)
		}
		if req.Password != "test-password" {
			t.Errorf("unexpected password: %s", req.Password)
		}

		resp := AuthResponse{}
		resp.Session.Valid = true
		resp.Session.SID = "test-sid-12345"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewPiholeAPIClient(srv.URL, "test-password")
	err := client.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}
	if client.SID != "test-sid-12345" {
		t.Errorf("SID = %q, want %q", client.SID, "test-sid-12345")
	}
}

func TestAuthenticate_InvalidSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := AuthResponse{}
		resp.Session.Valid = false
		resp.Session.SID = ""
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewPiholeAPIClient(srv.URL, "wrong")
	err := client.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid session")
	}
	if !strings.Contains(err.Error(), "invalid session") {
		t.Errorf("error = %q, want to contain 'invalid session'", err.Error())
	}
}

func TestAuthenticate_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("unauthorized"))
	}))
	defer srv.Close()

	client := NewPiholeAPIClient(srv.URL, "bad")
	err := client.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %q, want to contain '401'", err.Error())
	}
}

func TestAuthenticate_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	client := NewPiholeAPIClient(srv.URL, "test")
	err := client.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

// helper: create a pre-authenticated client against a test server
func newAuthenticatedClient(srv *httptest.Server) *PiholeAPIClient {
	c := NewPiholeAPIClient(srv.URL, "test")
	c.SID = "pre-auth-sid"
	c.Client = srv.Client()
	return c
}

func TestAddBlocklist_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/lists" || r.Method != "POST" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-FTL-SID") != "pre-auth-sid" {
			t.Errorf("missing or wrong SID header: %s", r.Header.Get("X-FTL-SID"))
		}

		var req BlocklistCreateRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Address != "https://example.com/list.txt" {
			t.Errorf("address = %q", req.Address)
		}

		resp := BlocklistResponse{ID: 42, Address: req.Address, Enabled: true}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := newAuthenticatedClient(srv)
	resp, err := client.AddBlocklist(context.Background(), BlocklistCreateRequest{
		Address: "https://example.com/list.txt",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("AddBlocklist() error: %v", err)
	}
	if resp.ID != 42 {
		t.Errorf("ID = %d, want 42", resp.ID)
	}
}

func TestAddBlocklist_AutoAuthenticates(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call should be auth
			if r.URL.Path != "/api/auth" {
				t.Errorf("first call should be auth, got %s", r.URL.Path)
			}
			resp := AuthResponse{}
			resp.Session.Valid = true
			resp.Session.SID = "new-sid"
			json.NewEncoder(w).Encode(resp)
			return
		}
		// Second call is the actual add
		if r.Header.Get("X-FTL-SID") != "new-sid" {
			t.Errorf("SID = %q, want 'new-sid'", r.Header.Get("X-FTL-SID"))
		}
		resp := BlocklistResponse{ID: 1, Address: "https://example.com/list.txt", Enabled: true}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewPiholeAPIClient(srv.URL, "test")
	_, err := client.AddBlocklist(context.Background(), BlocklistCreateRequest{
		Address: "https://example.com/list.txt",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("AddBlocklist() error: %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected 2 calls (auth + add), got %d", callCount)
	}
}

func TestAddBlocklist_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer srv.Close()

	client := newAuthenticatedClient(srv)
	_, err := client.AddBlocklist(context.Background(), BlocklistCreateRequest{Address: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want to contain '500'", err.Error())
	}
}

func TestListBlocklists_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/lists" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		lists := []BlocklistResponse{
			{ID: 1, Address: "https://a.com/list.txt", Enabled: true},
			{ID: 2, Address: "https://b.com/list.txt", Enabled: false},
		}
		json.NewEncoder(w).Encode(lists)
	}))
	defer srv.Close()

	client := newAuthenticatedClient(srv)
	lists, err := client.ListBlocklists(context.Background())
	if err != nil {
		t.Fatalf("ListBlocklists() error: %v", err)
	}
	if len(lists) != 2 {
		t.Errorf("got %d lists, want 2", len(lists))
	}
	if lists[0].Address != "https://a.com/list.txt" {
		t.Errorf("lists[0].Address = %q", lists[0].Address)
	}
}

func TestListBlocklists_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	client := newAuthenticatedClient(srv)
	_, err := client.ListBlocklists(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestListBlocklists_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{invalid"))
	}))
	defer srv.Close()

	client := newAuthenticatedClient(srv)
	_, err := client.ListBlocklists(context.Background())
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestDeleteBlocklist_Success(t *testing.T) {
	for _, statusCode := range []int{http.StatusOK, http.StatusNoContent} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "DELETE" || r.URL.Path != "/api/lists/99" {
					t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(statusCode)
			}))
			defer srv.Close()

			client := newAuthenticatedClient(srv)
			err := client.DeleteBlocklist(context.Background(), 99)
			if err != nil {
				t.Fatalf("DeleteBlocklist() error: %v", err)
			}
		})
	}
}

func TestDeleteBlocklist_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := newAuthenticatedClient(srv)
	err := client.DeleteBlocklist(context.Background(), 999)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error = %q, want to contain '404'", err.Error())
	}
}

func TestUpdateBlocklist_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/api/lists/5" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		var req BlocklistCreateRequest
		json.NewDecoder(r.Body).Decode(&req)
		if !req.Enabled {
			t.Error("expected Enabled=true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newAuthenticatedClient(srv)
	err := client.UpdateBlocklist(context.Background(), 5, BlocklistCreateRequest{
		Address: "https://example.com/list.txt",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("UpdateBlocklist() error: %v", err)
	}
}

func TestUpdateBlocklist_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer srv.Close()

	client := newAuthenticatedClient(srv)
	err := client.UpdateBlocklist(context.Background(), 5, BlocklistCreateRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
}
