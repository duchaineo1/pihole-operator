package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cachev1alpha1 "github.com/duchaineo1/pihole-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

const (
	typeAvailableBlocklist = "Available"
	blocklistFinalizer     = "cache.duchaine.dev/blocklist-finalizer"
)

// BlocklistReconciler reconciles a Blocklist object
type BlocklistReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	httpClient *http.Client
	sidCache   map[string]*cachedSID
	mu         sync.Mutex
}

// cachedSID stores session information
type cachedSID struct {
	SID      string
	Obtained time.Time
	Valid    time.Duration
}

// PiholeAuthResponse is the response from Pi-hole auth endpoint
type PiholeAuthResponse struct {
	Session struct {
		Valid    bool   `json:"valid"`
		SID      string `json:"sid"`
		Message  string `json:"message,omitempty"`
		Validity int    `json:"validity"` // seconds
	} `json:"session"`
}

// PiholeListRequest represents a blocklist entry
type PiholeListRequest struct {
	Address string `json:"address"`
	Comment string `json:"comment,omitempty"`
	Groups  []int  `json:"groups,omitempty"`
	Enabled bool   `json:"enabled"`
}

// PiholeListResponse represents a blocklist from Pi-hole
type PiholeListResponse struct {
	ID      int    `json:"id"`
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
	Comment string `json:"comment"`
}

// Init initializes the reconciler
func (r *BlocklistReconciler) Init() {
	if r.httpClient == nil {
		r.httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Pi-hole uses self-signed certs
				},
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		}
	}
	if r.sidCache == nil {
		r.sidCache = make(map[string]*cachedSID)
	}
}

// +kubebuilder:rbac:groups=cache.duchaine.dev,resources=blocklists,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cache.duchaine.dev,resources=blocklists/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cache.duchaine.dev,resources=blocklists/finalizers,verbs=update
// +kubebuilder:rbac:groups=cache.duchaine.dev,resources=piholes,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch

func (r *BlocklistReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	blocklist := &cachev1alpha1.Blocklist{}
	if err := r.Get(ctx, req.NamespacedName, blocklist); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Blocklist resource not found, ignoring")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Blocklist")
		return ctrl.Result{}, err
	}

	// Find Piholes in same namespace
	piholeList := &cachev1alpha1.PiholeList{}
	if err := r.List(ctx, piholeList, client.InNamespace(blocklist.Namespace)); err != nil {
		log.Error(err, "Failed to list Piholes")
		return ctrl.Result{}, err
	}

	if len(piholeList.Items) == 0 {
		log.Info("No Pihole instances found", "namespace", blocklist.Namespace)
		meta.SetStatusCondition(&blocklist.Status.Conditions, metav1.Condition{
			Type:    typeAvailableBlocklist,
			Status:  metav1.ConditionFalse,
			Reason:  "NoPihole",
			Message: "No Pihole instance found in namespace",
		})
		_ = r.Status().Update(ctx, blocklist)
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	// Handle deletion
	if !blocklist.ObjectMeta.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(blocklist, blocklistFinalizer) {
			for _, pihole := range piholeList.Items {
				if err := r.removeBlocklistFromPihole(ctx, &pihole, blocklist, log); err != nil {
					log.Error(err, "Failed to remove blocklist", "pihole", pihole.Name)
					// Continue trying others
				}
			}
			controllerutil.RemoveFinalizer(blocklist, blocklistFinalizer)
			if err := r.Update(ctx, blocklist); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(blocklist, blocklistFinalizer) {
		controllerutil.AddFinalizer(blocklist, blocklistFinalizer)
		if err := r.Update(ctx, blocklist); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Initialize status
	if len(blocklist.Status.Conditions) == 0 {
		meta.SetStatusCondition(&blocklist.Status.Conditions, metav1.Condition{
			Type:    typeAvailableBlocklist,
			Status:  metav1.ConditionUnknown,
			Reason:  "Reconciling",
			Message: "Starting reconciliation",
		})
		_ = r.Status().Update(ctx, blocklist)
	}

	// Apply to all Piholes
	successCount := 0
	var lastError error
	for _, pihole := range piholeList.Items {
		if err := r.applyBlocklistToPihole(ctx, &pihole, blocklist, log); err != nil {
			log.Error(err, "Failed to apply blocklist", "pihole", pihole.Name)
			lastError = err
		} else {
			successCount++
		}
	}

	// Update status
	if lastError != nil && successCount == 0 {
		meta.SetStatusCondition(&blocklist.Status.Conditions, metav1.Condition{
			Type:    typeAvailableBlocklist,
			Status:  metav1.ConditionFalse,
			Reason:  "ApplyFailed",
			Message: fmt.Sprintf("Failed to apply: %s", lastError.Error()),
		})
	} else {
		meta.SetStatusCondition(&blocklist.Status.Conditions, metav1.Condition{
			Type:    typeAvailableBlocklist,
			Status:  metav1.ConditionTrue,
			Reason:  "Applied",
			Message: fmt.Sprintf("Applied to %d Pihole(s)", successCount),
		})
		now := metav1.Now()
		blocklist.Status.LastSyncTime = &now
	}

	_ = r.Status().Update(ctx, blocklist)

	requeueAfter := time.Duration(blocklist.Spec.SyncInterval) * time.Minute
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// authenticatePihole authenticates with Pi-hole and returns a session ID
func (r *BlocklistReconciler) authenticatePihole(ctx context.Context, baseURL, password string, log logr.Logger) (string, error) {
	authURL := fmt.Sprintf("%s/api/auth", baseURL)

	authReq := map[string]string{"password": password}
	jsonData, err := json.Marshal(authReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", authURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	log.Info("Authenticating with Pi-hole", "url", authURL)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read auth response: %w", err)
	}

	log.Info("Auth response", "status", resp.StatusCode, "body", string(body))

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var authResp PiholeAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", fmt.Errorf("failed to parse auth response: %w, body=%s", err, string(body))
	}

	if !authResp.Session.Valid || authResp.Session.SID == "" {
		return "", fmt.Errorf("invalid session: valid=%v, sid=%s, msg=%s",
			authResp.Session.Valid, authResp.Session.SID, authResp.Session.Message)
	}

	return authResp.Session.SID, nil
}

// getSID gets or refreshes a session ID
func (r *BlocklistReconciler) getSID(ctx context.Context, baseURL, password, cacheKey string, log logr.Logger) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check cache
	if cached, ok := r.sidCache[cacheKey]; ok {
		if time.Since(cached.Obtained) < cached.Valid {
			log.Info("Using cached SID", "age", time.Since(cached.Obtained))
			return cached.SID, nil
		}
		log.Info("Cached SID expired", "age", time.Since(cached.Obtained))
	}

	// Authenticate
	sid, err := r.authenticatePihole(ctx, baseURL, password, log)
	if err != nil {
		return "", err
	}

	// Cache for 8 minutes (Pi-hole sessions usually valid for 10 min)
	r.sidCache[cacheKey] = &cachedSID{
		SID:      sid,
		Obtained: time.Now(),
		Valid:    8 * time.Minute,
	}

	log.Info("Successfully authenticated", "sid", sid[:8]+"...")
	return sid, nil
}

// applyBlocklistToPihole applies blocklist via Pi-hole API
func (r *BlocklistReconciler) applyBlocklistToPihole(ctx context.Context, pihole *cachev1alpha1.Pihole, blocklist *cachev1alpha1.Blocklist, log logr.Logger) error {
	// Get service and secret
	serviceName := pihole.Name + "-web"
	secretName := pihole.Name + "-admin"

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: pihole.Namespace}, secret); err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	password := string(secret.Data["password"])
	if password == "" {
		return fmt.Errorf("password not found in secret")
	}

	baseURL := fmt.Sprintf("https://%s.%s.svc.cluster.local", serviceName, pihole.Namespace)
	cacheKey := fmt.Sprintf("%s/%s", pihole.Namespace, pihole.Name)

	// Get session
	sid, err := r.getSID(ctx, baseURL, password, cacheKey, log)
	if err != nil {
		return fmt.Errorf("failed to get SID: %w", err)
	}

	// Get existing lists
	existingLists, err := r.getBlocklists(ctx, baseURL, sid, log)
	if err != nil {
		log.Error(err, "Failed to get existing lists, will try to add anyway")
		existingLists = []PiholeListResponse{}
	}

	// Apply each source
	for _, source := range blocklist.Spec.Sources {
		// Check if already exists
		found := false
		for _, existing := range existingLists {
			if existing.Address == source {
				log.Info("Blocklist source already exists", "source", source, "id", existing.ID)
				found = true
				// TODO: Update if needed (enabled status, comment, etc.)
				break
			}
		}

		if !found {
			if err := r.addBlocklistSource(ctx, baseURL, sid, source, blocklist, log); err != nil {
				return fmt.Errorf("failed to add source %s: %w", source, err)
			}
		}
	}

	return nil
}

// getBlocklists retrieves current blocklists from Pi-hole
func (r *BlocklistReconciler) getBlocklists(ctx context.Context, baseURL, sid string, log logr.Logger) ([]PiholeListResponse, error) {
	url := fmt.Sprintf("%s/api/lists?type=block", baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-FTL-SID", sid)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get lists failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var lists []PiholeListResponse
	if err := json.Unmarshal(body, &lists); err != nil {
		return nil, fmt.Errorf("failed to parse lists: %w", err)
	}

	return lists, nil
}

// addBlocklistSource adds a single blocklist source
func (r *BlocklistReconciler) addBlocklistSource(ctx context.Context, baseURL, sid, source string, blocklist *cachev1alpha1.Blocklist, log logr.Logger) error {
	url := fmt.Sprintf("%s/api/lists?type=block", baseURL)

	listReq := PiholeListRequest{
		Address: source,
		Comment: fmt.Sprintf("%s (managed)", blocklist.Spec.Description),
		Groups:  []int{0},
		Enabled: blocklist.Spec.Enabled,
	}

	jsonData, err := json.Marshal(listReq)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-FTL-SID", sid)

	log.Info("Adding blocklist source", "source", source)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusTooManyRequests {
		log.Info("Rate limited, will retry", "status", resp.StatusCode)
		time.Sleep(2 * time.Second)
		return fmt.Errorf("rate limited")
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("add failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	log.Info("Successfully added source", "source", source, "status", resp.StatusCode)
	return nil
}

// removeBlocklistFromPihole removes blocklist sources from Pi-hole
func (r *BlocklistReconciler) removeBlocklistFromPihole(ctx context.Context, pihole *cachev1alpha1.Pihole, blocklist *cachev1alpha1.Blocklist, log logr.Logger) error {
	serviceName := pihole.Name + "-web"
	secretName := pihole.Name + "-admin"

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: pihole.Namespace}, secret); err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	password := string(secret.Data["password"])
	baseURL := fmt.Sprintf("https://%s.%s.svc.cluster.local", serviceName, pihole.Namespace)
	cacheKey := fmt.Sprintf("%s/%s", pihole.Namespace, pihole.Name)

	sid, err := r.getSID(ctx, baseURL, password, cacheKey, log)
	if err != nil {
		return fmt.Errorf("failed to get SID: %w", err)
	}

	// Get existing lists
	existingLists, err := r.getBlocklists(ctx, baseURL, sid, log)
	if err != nil {
		return fmt.Errorf("failed to get lists: %w", err)
	}

	// Delete matching sources
	for _, source := range blocklist.Spec.Sources {
		for _, existing := range existingLists {
			if existing.Address == source {
				deleteURL := fmt.Sprintf("%s/api/lists/%d", baseURL, existing.ID)
				req, _ := http.NewRequestWithContext(ctx, "DELETE", deleteURL, nil)
				req.Header.Set("X-FTL-SID", sid)

				resp, err := r.httpClient.Do(req)
				if err != nil {
					log.Error(err, "Failed to delete", "source", source)
					continue
				}
				resp.Body.Close()

				log.Info("Deleted blocklist source", "source", source, "id", existing.ID)
			}
		}
	}

	return nil
}

// SetupWithManager sets up the controller
func (r *BlocklistReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Init()
	return ctrl.NewControllerManagedBy(mgr).
		For(&cachev1alpha1.Blocklist{}).
		Complete(r)
}

