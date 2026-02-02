package controller

import (
	"context"
	"crypto/tls"
	"fmt"
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
	typeAvailableDNSRecord = "Available"
	dnsRecordFinalizer     = "cache.duchaine.dev/dnsrecord-finalizer"
	lastAppliedEntryAnnotation = "cache.duchaine.dev/last-applied-entry"
)

// PiholeDNSRecordReconciler reconciles a PiholeDNSRecord object
type PiholeDNSRecordReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	httpClient *http.Client
	sidCache   map[string]*cachedSID
	mu         sync.Mutex

	// BaseURLOverride maps "namespace/name" to a base URL. Used in tests.
	BaseURLOverride map[string]string
}

// Init initializes the reconciler
func (r *PiholeDNSRecordReconciler) Init() {
	if r.httpClient == nil {
		r.httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
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

// +kubebuilder:rbac:groups=cache.duchaine.dev,resources=piholednsrecords,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cache.duchaine.dev,resources=piholednsrecords/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cache.duchaine.dev,resources=piholednsrecords/finalizers,verbs=update
// +kubebuilder:rbac:groups=cache.duchaine.dev,resources=piholes,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch

func (r *PiholeDNSRecordReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	dnsRecord := &cachev1alpha1.PiholeDNSRecord{}
	if err := r.Get(ctx, req.NamespacedName, dnsRecord); err != nil {
		if errors.IsNotFound(err) {
			log.Info("PiholeDNSRecord resource not found, ignoring")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get PiholeDNSRecord")
		return ctrl.Result{}, err
	}

	// Validate spec
	if err := r.validateSpec(dnsRecord); err != nil {
		meta.SetStatusCondition(&dnsRecord.Status.Conditions, metav1.Condition{
			Type:    typeAvailableDNSRecord,
			Status:  metav1.ConditionFalse,
			Reason:  "ValidationFailed",
			Message: err.Error(),
		})
		_ = r.Status().Update(ctx, dnsRecord)
		return ctrl.Result{}, nil
	}

	// Find Piholes in same namespace
	piholeList := &cachev1alpha1.PiholeList{}
	if err := r.List(ctx, piholeList, client.InNamespace(dnsRecord.Namespace)); err != nil {
		log.Error(err, "Failed to list Piholes")
		return ctrl.Result{}, err
	}

	if len(piholeList.Items) == 0 {
		log.Info("No Pihole instances found", "namespace", dnsRecord.Namespace)
		meta.SetStatusCondition(&dnsRecord.Status.Conditions, metav1.Condition{
			Type:    typeAvailableDNSRecord,
			Status:  metav1.ConditionFalse,
			Reason:  "NoPihole",
			Message: "No Pihole instance found in namespace",
		})
		_ = r.Status().Update(ctx, dnsRecord)
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	// Handle deletion
	if !dnsRecord.ObjectMeta.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(dnsRecord, dnsRecordFinalizer) {
			for _, pihole := range piholeList.Items {
				if err := r.removeDNSRecordFromPihole(ctx, &pihole, dnsRecord, log); err != nil {
					log.Error(err, "Failed to remove DNS record", "pihole", pihole.Name)
				}
			}
			controllerutil.RemoveFinalizer(dnsRecord, dnsRecordFinalizer)
			if err := r.Update(ctx, dnsRecord); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(dnsRecord, dnsRecordFinalizer) {
		controllerutil.AddFinalizer(dnsRecord, dnsRecordFinalizer)
		if err := r.Update(ctx, dnsRecord); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Initialize status
	if len(dnsRecord.Status.Conditions) == 0 {
		meta.SetStatusCondition(&dnsRecord.Status.Conditions, metav1.Condition{
			Type:    typeAvailableDNSRecord,
			Status:  metav1.ConditionUnknown,
			Reason:  "Reconciling",
			Message: "Starting reconciliation",
		})
		_ = r.Status().Update(ctx, dnsRecord)
	}

	// Check if spec changed (for update handling)
	currentEntry := r.buildEntry(dnsRecord)
	lastApplied := ""
	if dnsRecord.Annotations != nil {
		lastApplied = dnsRecord.Annotations[lastAppliedEntryAnnotation]
	}

	// If the entry changed, remove the old one first
	if lastApplied != "" && lastApplied != currentEntry {
		for _, pihole := range piholeList.Items {
			if err := r.removeEntryFromPihole(ctx, &pihole, dnsRecord.Spec.RecordType, lastApplied, log); err != nil {
				log.Error(err, "Failed to remove old DNS entry", "pihole", pihole.Name, "entry", lastApplied)
			}
		}
	}

	// Apply to all Piholes
	successCount := 0
	var lastError error
	for _, pihole := range piholeList.Items {
		if err := r.applyDNSRecordToPihole(ctx, &pihole, dnsRecord, log); err != nil {
			log.Error(err, "Failed to apply DNS record", "pihole", pihole.Name)
			lastError = err
		} else {
			successCount++
		}
	}

	// Store the last-applied entry annotation
	if successCount > 0 {
		if dnsRecord.Annotations == nil {
			dnsRecord.Annotations = make(map[string]string)
		}
		dnsRecord.Annotations[lastAppliedEntryAnnotation] = currentEntry
		if err := r.Update(ctx, dnsRecord); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Update status
	if lastError != nil && successCount == 0 {
		meta.SetStatusCondition(&dnsRecord.Status.Conditions, metav1.Condition{
			Type:    typeAvailableDNSRecord,
			Status:  metav1.ConditionFalse,
			Reason:  "ApplyFailed",
			Message: fmt.Sprintf("Failed to apply: %s", lastError.Error()),
		})
	} else {
		meta.SetStatusCondition(&dnsRecord.Status.Conditions, metav1.Condition{
			Type:    typeAvailableDNSRecord,
			Status:  metav1.ConditionTrue,
			Reason:  "Applied",
			Message: fmt.Sprintf("Applied to %d Pihole(s)", successCount),
		})
		now := metav1.Now()
		dnsRecord.Status.LastSyncTime = &now
	}

	_ = r.Status().Update(ctx, dnsRecord)

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// validateSpec validates the PiholeDNSRecord spec
func (r *PiholeDNSRecordReconciler) validateSpec(record *cachev1alpha1.PiholeDNSRecord) error {
	switch record.Spec.RecordType {
	case "A", "AAAA":
		if record.Spec.IPAddress == "" {
			return fmt.Errorf("ipAddress is required for %s records", record.Spec.RecordType)
		}
	case "CNAME":
		if record.Spec.CNAMETarget == "" {
			return fmt.Errorf("cnameTarget is required for CNAME records")
		}
	}
	return nil
}

// buildEntry constructs the Pi-hole API entry string from the spec
func (r *PiholeDNSRecordReconciler) buildEntry(record *cachev1alpha1.PiholeDNSRecord) string {
	switch record.Spec.RecordType {
	case "A", "AAAA":
		return fmt.Sprintf("%s %s", record.Spec.IPAddress, record.Spec.Hostname)
	case "CNAME":
		return fmt.Sprintf("%s,%s", record.Spec.Hostname, record.Spec.CNAMETarget)
	}
	return ""
}

// authenticatePihole authenticates with Pi-hole and returns a session ID
func (r *PiholeDNSRecordReconciler) authenticatePihole(ctx context.Context, baseURL, password string, log logr.Logger) (string, error) {
	client := NewPiholeAPIClient(baseURL, password)
	client.Client = r.httpClient
	if err := client.Authenticate(ctx); err != nil {
		return "", err
	}
	return client.SID, nil
}

// getSID gets or refreshes a session ID
func (r *PiholeDNSRecordReconciler) getSID(ctx context.Context, baseURL, password, cacheKey string, log logr.Logger) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if cached, ok := r.sidCache[cacheKey]; ok {
		if time.Since(cached.Obtained) < cached.Valid {
			return cached.SID, nil
		}
	}

	sid, err := r.authenticatePihole(ctx, baseURL, password, log)
	if err != nil {
		return "", err
	}

	r.sidCache[cacheKey] = &cachedSID{
		SID:      sid,
		Obtained: time.Now(),
		Valid:    8 * time.Minute,
	}

	return sid, nil
}

// getPiholeConnection returns baseURL, SID for a given Pihole
func (r *PiholeDNSRecordReconciler) getPiholeConnection(ctx context.Context, pihole *cachev1alpha1.Pihole, log logr.Logger) (string, string, error) {
	serviceName := pihole.Name + "-web"
	secretName := piholeAdminSecretName(pihole)

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: pihole.Namespace}, secret); err != nil {
		return "", "", fmt.Errorf("failed to get secret: %w", err)
	}

	password := string(secret.Data["password"])
	if password == "" {
		return "", "", fmt.Errorf("password not found in secret")
	}

	cacheKey := fmt.Sprintf("%s/%s", pihole.Namespace, pihole.Name)
	baseURL := fmt.Sprintf("https://%s.%s.svc.cluster.local", serviceName, pihole.Namespace)
	if override, ok := r.BaseURLOverride[cacheKey]; ok {
		baseURL = override
	}

	sid, err := r.getSID(ctx, baseURL, password, cacheKey, log)
	if err != nil {
		return "", "", fmt.Errorf("failed to get SID: %w", err)
	}

	return baseURL, sid, nil
}

// applyDNSRecordToPihole applies a DNS record to a single Pi-hole instance
func (r *PiholeDNSRecordReconciler) applyDNSRecordToPihole(ctx context.Context, pihole *cachev1alpha1.Pihole, record *cachev1alpha1.PiholeDNSRecord, log logr.Logger) error {
	baseURL, sid, err := r.getPiholeConnection(ctx, pihole, log)
	if err != nil {
		return err
	}

	apiClient := &PiholeAPIClient{
		BaseURL: baseURL,
		Client:  r.httpClient,
		SID:     sid,
	}

	entry := r.buildEntry(record)

	switch record.Spec.RecordType {
	case "A", "AAAA":
		existing, err := apiClient.ListDNSHosts(ctx)
		if err != nil {
			log.Error(err, "Failed to list DNS hosts, will try to add anyway")
			existing = []string{}
		}

		for _, e := range existing {
			if e == entry {
				log.Info("DNS host record already exists", "entry", entry)
				return nil
			}
		}

		log.Info("Adding DNS host record", "entry", entry)
		return apiClient.AddDNSHost(ctx, entry)

	case "CNAME":
		existing, err := apiClient.ListDNSCNAMEs(ctx)
		if err != nil {
			log.Error(err, "Failed to list DNS CNAMEs, will try to add anyway")
			existing = []string{}
		}

		for _, e := range existing {
			if e == entry {
				log.Info("DNS CNAME record already exists", "entry", entry)
				return nil
			}
		}

		log.Info("Adding DNS CNAME record", "entry", entry)
		return apiClient.AddDNSCNAME(ctx, entry)
	}

	return fmt.Errorf("unsupported record type: %s", record.Spec.RecordType)
}

// removeDNSRecordFromPihole removes a DNS record from a single Pi-hole instance
func (r *PiholeDNSRecordReconciler) removeDNSRecordFromPihole(ctx context.Context, pihole *cachev1alpha1.Pihole, record *cachev1alpha1.PiholeDNSRecord, log logr.Logger) error {
	entry := r.buildEntry(record)
	return r.removeEntryFromPihole(ctx, pihole, record.Spec.RecordType, entry, log)
}

// removeEntryFromPihole removes a specific DNS entry from a Pi-hole instance
func (r *PiholeDNSRecordReconciler) removeEntryFromPihole(ctx context.Context, pihole *cachev1alpha1.Pihole, recordType, entry string, log logr.Logger) error {
	baseURL, sid, err := r.getPiholeConnection(ctx, pihole, log)
	if err != nil {
		return err
	}

	apiClient := &PiholeAPIClient{
		BaseURL: baseURL,
		Client:  r.httpClient,
		SID:     sid,
	}

	switch recordType {
	case "A", "AAAA":
		log.Info("Deleting DNS host record", "entry", entry)
		return apiClient.DeleteDNSHost(ctx, entry)
	case "CNAME":
		log.Info("Deleting DNS CNAME record", "entry", entry)
		return apiClient.DeleteDNSCNAME(ctx, entry)
	}

	return fmt.Errorf("unsupported record type: %s", recordType)
}

// SetupWithManager sets up the controller
func (r *PiholeDNSRecordReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Init()
	return ctrl.NewControllerManagedBy(mgr).
		For(&cachev1alpha1.PiholeDNSRecord{}).
		Complete(r)
}
