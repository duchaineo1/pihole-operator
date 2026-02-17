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
	typeAvailableWhitelist = "Available"
	whitelistFinalizer     = "pihole-operator.org/whitelist-finalizer"
)

// WhitelistReconciler reconciles a Whitelist object
type WhitelistReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	httpClient *http.Client
	sidCache   map[string]*cachedSID
	mu         sync.Mutex

	// BaseURLOverride maps "namespace/name" to a base URL. Used in tests.
	BaseURLOverride map[string]string
}

// WhitelistDomainRequest represents a domain allow-list entry for the Pi-hole API
type WhitelistDomainRequest struct {
	Domain  string `json:"domain"`
	Comment string `json:"comment,omitempty"`
	Groups  []int  `json:"groups,omitempty"`
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"`
}

// WhitelistDomainResponse represents a domain from Pi-hole's domain API
type WhitelistDomainResponse struct {
	ID      int    `json:"id"`
	Domain  string `json:"domain"`
	Enabled bool   `json:"enabled"`
	Comment string `json:"comment"`
	Type    string `json:"type"`
}

// WhitelistDomainsWrapper wraps the domains response
type WhitelistDomainsWrapper struct {
	Domains []WhitelistDomainResponse `json:"domains"`
}

// Init initializes the reconciler
func (r *WhitelistReconciler) Init() {
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

// +kubebuilder:rbac:groups=pihole-operator.org,resources=whitelists,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pihole-operator.org,resources=whitelists/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pihole-operator.org,resources=whitelists/finalizers,verbs=update
// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholes,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch

func (r *WhitelistReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	whitelist := &cachev1alpha1.Whitelist{}
	if err := r.Get(ctx, req.NamespacedName, whitelist); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Whitelist resource not found, ignoring")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Whitelist")
		return ctrl.Result{}, err
	}

	// Find Piholes in same namespace
	piholeList := &cachev1alpha1.PiholeList{}
	if err := r.List(ctx, piholeList, client.InNamespace(whitelist.Namespace)); err != nil {
		log.Error(err, "Failed to list Piholes")
		return ctrl.Result{}, err
	}

	if len(piholeList.Items) == 0 {
		log.Info("No Pihole instances found", "namespace", whitelist.Namespace)
		meta.SetStatusCondition(&whitelist.Status.Conditions, metav1.Condition{
			Type:    typeAvailableWhitelist,
			Status:  metav1.ConditionFalse,
			Reason:  "NoPihole",
			Message: "No Pihole instance found in namespace",
		})
		_ = r.Status().Update(ctx, whitelist)
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	// Handle deletion
	if !whitelist.ObjectMeta.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(whitelist, whitelistFinalizer) {
			for _, pihole := range piholeList.Items {
				password, err := r.getPiholePassword(ctx, &pihole)
				if err != nil {
					log.Error(err, "Failed to get password for removal", "pihole", pihole.Name)
					continue
				}

				replicas := int32(1)
				if pihole.Spec.Size != nil {
					replicas = *pihole.Spec.Size
				}

				for i := int32(0); i < replicas; i++ {
					baseURL := PodBaseURL(pihole.Name, pihole.Namespace, i)
					cacheKey := PodCacheKey(pihole.Namespace, pihole.Name, i)
					if override, ok := r.BaseURLOverride[cacheKey]; ok {
						baseURL = override
					} else if override, ok := r.BaseURLOverride[fmt.Sprintf("%s/%s", pihole.Namespace, pihole.Name)]; ok {
						baseURL = override
					}

					if err := r.removeWhitelistFromPod(ctx, baseURL, password, cacheKey, whitelist, log); err != nil {
						log.Error(err, "Failed to remove whitelist", "pihole", pihole.Name, "pod", i)
					}
				}
			}
			controllerutil.RemoveFinalizer(whitelist, whitelistFinalizer)
			if err := r.Update(ctx, whitelist); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(whitelist, whitelistFinalizer) {
		controllerutil.AddFinalizer(whitelist, whitelistFinalizer)
		if err := r.Update(ctx, whitelist); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Initialize status
	if len(whitelist.Status.Conditions) == 0 {
		meta.SetStatusCondition(&whitelist.Status.Conditions, metav1.Condition{
			Type:    typeAvailableWhitelist,
			Status:  metav1.ConditionUnknown,
			Reason:  "Reconciling",
			Message: "Starting reconciliation",
		})
		_ = r.Status().Update(ctx, whitelist)
	}

	// Apply to all Pihole pods
	successCount := 0
	var lastError error
	for _, pihole := range piholeList.Items {
		password, err := r.getPiholePassword(ctx, &pihole)
		if err != nil {
			log.Error(err, "Failed to get password", "pihole", pihole.Name)
			lastError = err
			continue
		}

		replicas := int32(1)
		if pihole.Spec.Size != nil {
			replicas = *pihole.Spec.Size
		}

		for i := int32(0); i < replicas; i++ {
			baseURL := PodBaseURL(pihole.Name, pihole.Namespace, i)
			cacheKey := PodCacheKey(pihole.Namespace, pihole.Name, i)
			if override, ok := r.BaseURLOverride[cacheKey]; ok {
				baseURL = override
			} else if override, ok := r.BaseURLOverride[fmt.Sprintf("%s/%s", pihole.Namespace, pihole.Name)]; ok {
				baseURL = override
			}

			if err := r.applyWhitelistToPod(ctx, baseURL, password, cacheKey, whitelist, log); err != nil {
				log.Error(err, "Failed to apply whitelist", "pihole", pihole.Name, "pod", i)
				lastError = err
			} else {
				successCount++
			}
		}
	}

	// Update status
	if lastError != nil && successCount == 0 {
		meta.SetStatusCondition(&whitelist.Status.Conditions, metav1.Condition{
			Type:    typeAvailableWhitelist,
			Status:  metav1.ConditionFalse,
			Reason:  "ApplyFailed",
			Message: fmt.Sprintf("Failed to apply: %s", lastError.Error()),
		})
	} else {
		meta.SetStatusCondition(&whitelist.Status.Conditions, metav1.Condition{
			Type:    typeAvailableWhitelist,
			Status:  metav1.ConditionTrue,
			Reason:  "Applied",
			Message: fmt.Sprintf("Applied to %d Pihole(s)", successCount),
		})
		now := metav1.Now()
		whitelist.Status.LastSyncTime = &now
		whitelist.Status.DomainsCount = int32(len(whitelist.Spec.Domains))
	}

	_ = r.Status().Update(ctx, whitelist)

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// authenticatePihole authenticates with Pi-hole and returns a session ID
func (r *WhitelistReconciler) authenticatePihole(ctx context.Context, baseURL, password string, log logr.Logger) (string, error) {
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
func (r *WhitelistReconciler) getSID(ctx context.Context, baseURL, password, cacheKey string, log logr.Logger) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check cache
	if cached, ok := r.sidCache[cacheKey]; ok {
		if time.Since(cached.Obtained) < cached.Valid {
			return cached.SID, nil
		}
	}

	// Authenticate
	sid, err := r.authenticatePihole(ctx, baseURL, password, log)
	if err != nil {
		return "", err
	}

	// Cache for 8 minutes
	r.sidCache[cacheKey] = &cachedSID{
		SID:      sid,
		Obtained: time.Now(),
		Valid:    8 * time.Minute,
	}

	log.Info("Successfully authenticated", "sid", sid[:8]+"...")
	return sid, nil
}

// getPiholePassword retrieves the admin password for a Pihole instance.
func (r *WhitelistReconciler) getPiholePassword(ctx context.Context, pihole *cachev1alpha1.Pihole) (string, error) {
	secretName := piholeAdminSecretName(pihole)

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: pihole.Namespace}, secret); err != nil {
		return "", fmt.Errorf("failed to get secret: %w", err)
	}

	password := string(secret.Data["password"])
	if password == "" {
		return "", fmt.Errorf("password not found in secret")
	}
	return password, nil
}

func (r *WhitelistReconciler) applyWhitelistToPod(ctx context.Context, baseURL, password, cacheKey string, whitelist *cachev1alpha1.Whitelist, log logr.Logger) error {
	sid, err := r.getSID(ctx, baseURL, password, cacheKey, log)
	if err != nil {
		return fmt.Errorf("failed to get SID: %w", err)
	}

	// Get existing allow-list domains
	existingDomains, err := r.getWhitelistDomains(ctx, baseURL, sid, log)
	if err != nil {
		log.Error(err, "Failed to get existing whitelist domains, will try to add anyway")
		existingDomains = []WhitelistDomainResponse{}
	}

	// Apply each domain
	for _, domain := range whitelist.Spec.Domains {
		found := false
		for _, existing := range existingDomains {
			if existing.Domain == domain {
				log.Info("Whitelist domain already exists", "domain", domain, "id", existing.ID)
				found = true
				break
			}
		}

		if !found {
			if err := r.addWhitelistDomain(ctx, baseURL, sid, domain, whitelist, log); err != nil {
				return fmt.Errorf("failed to add domain %s: %w", domain, err)
			}
		}
	}

	return nil
}

// getWhitelistDomains retrieves current allow-list domains from Pi-hole
func (r *WhitelistReconciler) getWhitelistDomains(ctx context.Context, baseURL, sid string, log logr.Logger) ([]WhitelistDomainResponse, error) {
	url := fmt.Sprintf("%s/api/domains/allow/exact", baseURL)

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
		return nil, fmt.Errorf("get domains failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// Parse as wrapped response (Pi-hole v6 returns {"domains":[...], "took":...})
	var wrapper WhitelistDomainsWrapper
	if err := json.Unmarshal(body, &wrapper); err == nil {
		return wrapper.Domains, nil
	}

	// Fallback: try direct array
	var domains []WhitelistDomainResponse
	if err := json.Unmarshal(body, &domains); err != nil {
		log.Error(err, "Failed to parse domains response", "body", string(body))
		return nil, fmt.Errorf("failed to parse domains: %w", err)
	}

	return domains, nil
}

// addWhitelistDomain adds a single domain to the allow list
func (r *WhitelistReconciler) addWhitelistDomain(ctx context.Context, baseURL, sid, domain string, whitelist *cachev1alpha1.Whitelist, log logr.Logger) error {
	url := fmt.Sprintf("%s/api/domains/allow/exact", baseURL)

	domainReq := WhitelistDomainRequest{
		Domain:  domain,
		Comment: fmt.Sprintf("%s (managed)", whitelist.Spec.Description),
		Groups:  []int{0},
		Enabled: whitelist.Spec.Enabled,
		Type:    "allow",
	}

	jsonData, err := json.Marshal(domainReq)
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

	log.Info("Adding whitelist domain", "domain", domain)

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

	log.Info("Successfully added whitelist domain", "domain", domain, "status", resp.StatusCode)
	return nil
}

// removeWhitelistFromPod removes whitelist domains from a single Pi-hole pod
func (r *WhitelistReconciler) removeWhitelistFromPod(ctx context.Context, baseURL, password, cacheKey string, whitelist *cachev1alpha1.Whitelist, log logr.Logger) error {
	sid, err := r.getSID(ctx, baseURL, password, cacheKey, log)
	if err != nil {
		return fmt.Errorf("failed to get SID: %w", err)
	}

	// Delete each domain
	for _, domain := range whitelist.Spec.Domains {
		deleteURL := fmt.Sprintf("%s/api/domains/allow/exact/%s", baseURL, urlEncode(domain))
		req, _ := http.NewRequestWithContext(ctx, "DELETE", deleteURL, nil)
		req.Header.Set("X-FTL-SID", sid)
		req.Header.Set("Accept", "application/json")

		resp, err := r.httpClient.Do(req)
		if err != nil {
			log.Error(err, "Failed to delete whitelist domain", "domain", domain)
			continue
		}
		resp.Body.Close()

		log.Info("Deleted whitelist domain", "domain", domain, "status", resp.StatusCode)
	}

	return nil
}

// SetupWithManager sets up the controller
func (r *WhitelistReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Init()
	return ctrl.NewControllerManagedBy(mgr).
		For(&cachev1alpha1.Whitelist{}).
		Complete(r)
}
