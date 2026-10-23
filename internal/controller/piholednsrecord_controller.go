package controller

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"net/http"
	"strings"
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
	typeAvailableDNSRecord     = "Available"
	dnsRecordFinalizer         = "pihole-operator.org/dnsrecord-finalizer"
	lastAppliedEntryAnnotation = "pihole-operator.org/last-applied-entry"
)

// PiholeDNSRecordReconciler reconciles a PiholeDNSRecord object
type PiholeDNSRecordReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	sidCache map[string]*cachedSID
	mu       sync.Mutex

	// BaseURLOverride maps "namespace/name" to a base URL. Used in tests.
	BaseURLOverride map[string]string
}

// Init initializes the reconciler
func (r *PiholeDNSRecordReconciler) Init() {
	if r.sidCache == nil {
		r.sidCache = make(map[string]*cachedSID)
	}
}

// httpClientForPihole builds a per-Pihole HTTP client using TLS config from the spec.
// Clients are cached to avoid creating new connection pools on every reconcile.
func (r *PiholeDNSRecordReconciler) httpClientForPihole(ctx context.Context, pihole *cachev1alpha1.Pihole) (*http.Client, error) {
	caData, err := getCAData(ctx, r.Client, pihole.Namespace, pihole.Spec.TLS)
	if err != nil {
		return nil, err
	}

	cacheKey := fmt.Sprintf("%s/%s", pihole.Namespace, pihole.Name)
	return sharedHTTPClientCache.Get(cacheKey, func() *http.Client {
		return buildHTTPClient(buildTLSConfig(pihole.Spec.TLS, caData))
	}), nil
}

// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholednsrecords,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholednsrecords/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholednsrecords/finalizers,verbs=update
// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholes,verbs=get;list;watch
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

	// Handle deletion before validation and the NoPihole early return: a record
	// whose Pihole is gone (or whose spec was edited into an invalid state) must
	// still release its finalizer, otherwise it can never be deleted.
	if !dnsRecord.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, dnsRecord, log)
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

	// Find Piholes across target namespaces
	piholes, err := listPiholesForNamespaces(ctx, r.Client, dnsRecord.Namespace, dnsRecord.Spec.TargetNamespaces)
	if err != nil {
		log.Error(err, "Failed to list Piholes")
		return ctrl.Result{}, err
	}

	if len(piholes) == 0 {
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
		for _, pihole := range piholes {
			password, err := r.getPiholePassword(ctx, &pihole)
			if err != nil {
				log.Error(err, "Failed to get password for old entry removal", "pihole", pihole.Name)
				continue
			}

			httpClient, err := r.httpClientForPihole(ctx, &pihole)
			if err != nil {
				log.Error(err, "Failed to build HTTP client for pihole", "pihole", pihole.Name)
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

				if err := r.removeEntryFromPod(ctx, httpClient, baseURL, password, cacheKey, dnsRecord.Spec.RecordType, lastApplied, log); err != nil {
					log.Error(err, "Failed to remove old DNS entry", "pihole", pihole.Name, "pod", i, "entry", lastApplied)
				}
			}
		}
	}

	// Total pods we must apply to across every matched Pihole. Computed up front
	// (independent of per-Pihole password/client errors) so the success count is
	// compared against the true target count — otherwise a Pihole that failed
	// before its replicas were counted would make a partial apply look complete.
	totalTargets := 0
	for _, pihole := range piholes {
		replicas := int32(1)
		if pihole.Spec.Size != nil {
			replicas = *pihole.Spec.Size
		}
		totalTargets += int(replicas)
	}

	// Apply to all Pihole pods
	successCount := 0
	mutated := false
	var lastError error
	var conflict *dnsConflictError
	for _, pihole := range piholes {
		password, err := r.getPiholePassword(ctx, &pihole)
		if err != nil {
			log.Error(err, "Failed to get password", "pihole", pihole.Name)
			lastError = err
			continue
		}

		httpClient, err := r.httpClientForPihole(ctx, &pihole)
		if err != nil {
			log.Error(err, "Failed to build HTTP client for pihole", "pihole", pihole.Name)
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

			added, err := r.applyDNSRecordToPod(ctx, httpClient, baseURL, password, cacheKey, dnsRecord, log)
			if err != nil {
				log.Error(err, "Failed to apply DNS record", "pihole", pihole.Name, "pod", i)
				lastError = err
				if conflict == nil {
					stderrors.As(err, &conflict)
				}
			} else {
				successCount++
				if added {
					mutated = true
				}
			}
		}
	}

	// Store the last-applied entry annotation, but only when it actually changed.
	// An unconditional Update here would be a write on every pass.
	if successCount > 0 && lastApplied != currentEntry {
		if dnsRecord.Annotations == nil {
			dnsRecord.Annotations = make(map[string]string)
		}
		dnsRecord.Annotations[lastAppliedEntryAnnotation] = currentEntry
		if err := r.Update(ctx, dnsRecord); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Update status and choose the requeue cadence. A partial apply (some pods
	// reachable, others not — e.g. a replica mid-restart whose per-pod DNS name
	// is briefly unresolvable) must be reported as not-Available and retried
	// quickly, not masked as success and left until the next 5-minute resync.
	// Masking + slow retry is exactly what left a record on only one of two
	// replicas, so the LoadBalancer returned inconsistent answers.
	//
	// The status write MUST stay conditional. This controller watches its own kind,
	// so any write here bumps resourceVersion and immediately re-triggers Reconcile.
	// LastSyncTime was previously stamped with metav1.Now() on every pass, which made
	// every write a real change and turned that watch into an unbounded hot loop
	// (~22 reconciles/sec against 25 records) that starved the k3s control plane.
	// Steady state — record already present, condition unchanged — must issue zero
	// writes and let RequeueAfter alone drive the resync.
	requeueAfter := 5 * time.Minute
	var statusChanged bool
	switch {
	case conflict != nil:
		// Another entry already owns this hostname on at least one pod. It was not
		// overwritten; retry slowly so the record picks up once the other entry
		// is removed.
		statusChanged = meta.SetStatusCondition(&dnsRecord.Status.Conditions, metav1.Condition{
			Type:    typeAvailableDNSRecord,
			Status:  metav1.ConditionFalse,
			Reason:  "Conflict",
			Message: conflict.Error(),
		})
		requeueAfter = 1 * time.Minute
	case successCount == 0:
		msg := "Failed to apply to any Pihole pod"
		if lastError != nil {
			msg = fmt.Sprintf("Failed to apply: %s", lastError.Error())
		}
		statusChanged = meta.SetStatusCondition(&dnsRecord.Status.Conditions, metav1.Condition{
			Type:    typeAvailableDNSRecord,
			Status:  metav1.ConditionFalse,
			Reason:  "ApplyFailed",
			Message: msg,
		})
		requeueAfter = 30 * time.Second
	case successCount < totalTargets:
		statusChanged = meta.SetStatusCondition(&dnsRecord.Status.Conditions, metav1.Condition{
			Type:    typeAvailableDNSRecord,
			Status:  metav1.ConditionFalse,
			Reason:  "PartiallyApplied",
			Message: fmt.Sprintf("Applied to %d/%d Pihole pod(s); retrying", successCount, totalTargets),
		})
		requeueAfter = 30 * time.Second
	default:
		statusChanged = meta.SetStatusCondition(&dnsRecord.Status.Conditions, metav1.Condition{
			Type:    typeAvailableDNSRecord,
			Status:  metav1.ConditionTrue,
			Reason:  "Applied",
			Message: fmt.Sprintf("Applied to %d/%d Pihole pod(s)", successCount, totalTargets),
		})
	}

	// LastSyncTime marks the last reconcile that actually changed something, so it
	// cannot be the thing that makes every write "changed". Stamping it on no-op
	// passes is what created the loop.
	if statusChanged || mutated {
		now := metav1.Now()
		dnsRecord.Status.LastSyncTime = &now
		_ = r.Status().Update(ctx, dnsRecord)
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// reconcileDelete removes the record from every reachable Pihole pod and releases
// the finalizer. Removal is best-effort: if no Pihole matches anymore there is
// nothing left to clean up, and an unreachable pod must not block deletion.
func (r *PiholeDNSRecordReconciler) reconcileDelete(ctx context.Context, dnsRecord *cachev1alpha1.PiholeDNSRecord, log logr.Logger) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(dnsRecord, dnsRecordFinalizer) {
		return ctrl.Result{}, nil
	}

	piholes, err := listPiholesForNamespaces(ctx, r.Client, dnsRecord.Namespace, dnsRecord.Spec.TargetNamespaces)
	if err != nil {
		log.Error(err, "Failed to list Piholes for removal")
		return ctrl.Result{}, err
	}

	// Prefer the entry that was actually written: if the spec was edited after
	// the last successful apply, the spec-derived entry is not what Pi-hole holds.
	entry := r.buildEntry(dnsRecord)
	if lastApplied := dnsRecord.Annotations[lastAppliedEntryAnnotation]; lastApplied != "" {
		entry = lastApplied
	}

	for _, pihole := range piholes {
		password, err := r.getPiholePassword(ctx, &pihole)
		if err != nil {
			log.Error(err, "Failed to get password for removal", "pihole", pihole.Name)
			continue
		}

		httpClient, err := r.httpClientForPihole(ctx, &pihole)
		if err != nil {
			log.Error(err, "Failed to build HTTP client for pihole", "pihole", pihole.Name)
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

			if err := r.removeEntryFromPod(ctx, httpClient, baseURL, password, cacheKey, dnsRecord.Spec.RecordType, entry, log); err != nil {
				log.Error(err, "Failed to remove DNS record", "pihole", pihole.Name, "pod", i)
			}
		}
	}

	controllerutil.RemoveFinalizer(dnsRecord, dnsRecordFinalizer)
	if err := r.Update(ctx, dnsRecord); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
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
func (r *PiholeDNSRecordReconciler) authenticatePihole(ctx context.Context, httpClient *http.Client, baseURL, password string, log logr.Logger) (string, error) {
	client := NewPiholeAPIClient(baseURL, password, httpClient)
	if err := client.Authenticate(ctx); err != nil {
		return "", err
	}
	return client.SID, nil
}

// getSID gets or refreshes a session ID
func (r *PiholeDNSRecordReconciler) getSID(ctx context.Context, httpClient *http.Client, baseURL, password, cacheKey string, log logr.Logger) (string, error) {
	return sharedSIDManager.GetOrAuthenticate(ctx, cacheKey, 8*time.Minute, log, func(ctx context.Context) (string, error) {
		return r.authenticatePihole(ctx, httpClient, baseURL, password, log)
	})
}

// getPiholePassword retrieves the admin password for a Pihole instance.
func (r *PiholeDNSRecordReconciler) getPiholePassword(ctx context.Context, pihole *cachev1alpha1.Pihole) (string, error) {
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

// getPodConnection returns baseURL, SID for a given pod
func (r *PiholeDNSRecordReconciler) getPodConnection(ctx context.Context, httpClient *http.Client, baseURL, password, cacheKey string, log logr.Logger) (string, string, error) {
	sid, err := r.getSID(ctx, httpClient, baseURL, password, cacheKey, log)
	if err != nil {
		return "", "", fmt.Errorf("failed to get SID: %w", err)
	}

	return baseURL, sid, nil
}

// dnsConflictError reports that Pi-hole already holds a different entry for the
// record's hostname that this record did not write (a manual entry, or one
// owned by another PiholeDNSRecord). The operator never overwrites such entries.
type dnsConflictError struct {
	hostname string
	existing string
}

func (e *dnsConflictError) Error() string {
	return fmt.Sprintf("hostname %s is already defined by another entry (%q); not overwriting", e.hostname, e.existing)
}

// findConflictingEntry returns an existing Pi-hole entry that defines the same
// name as entry but differs from it, ignoring ownEntries (entries this record
// wrote itself). An empty string means there is no conflict.
//
// Host entries use hosts-file syntax ("IP name [alias...]"). An entry that maps
// the same name to the same IP is not a conflict (it already resolves as
// desired), nor is one in the other address family: an A and an AAAA record for
// the same name coexist. CNAME entries are "alias,target[,ttl]" and conflict
// when the alias matches with a different target.
func findConflictingEntry(recordType, entry string, existing []string, ownEntries ...string) string {
	isOwn := func(e string) bool {
		for _, o := range ownEntries {
			if o != "" && e == o {
				return true
			}
		}
		return false
	}

	switch recordType {
	case "A", "AAAA":
		fields := strings.Fields(entry)
		if len(fields) < 2 {
			return ""
		}
		ip, hostname := net.ParseIP(fields[0]), fields[1]
		if ip == nil {
			return ""
		}
		for _, e := range existing {
			if isOwn(e) {
				continue
			}
			ef := strings.Fields(e)
			if len(ef) < 2 {
				continue
			}
			eip := net.ParseIP(ef[0])
			if eip == nil || (eip.To4() == nil) != (ip.To4() == nil) || eip.Equal(ip) {
				continue
			}
			for _, name := range ef[1:] {
				if strings.EqualFold(name, hostname) {
					return e
				}
			}
		}

	case "CNAME":
		alias, target, _ := strings.Cut(entry, ",")
		for _, e := range existing {
			if isOwn(e) {
				continue
			}
			ealias, erest, _ := strings.Cut(e, ",")
			etarget, _, _ := strings.Cut(erest, ",")
			if strings.EqualFold(ealias, alias) && !strings.EqualFold(etarget, target) {
				return e
			}
		}
	}
	return ""
}

// entryCoveredBy reports whether an existing host entry already maps the
// record's hostname to the record's IP, e.g. a manual "IP name alias" line.
// Adding our own line on top would only create a duplicate.
func entryCoveredBy(entry string, existing []string) bool {
	fields := strings.Fields(entry)
	if len(fields) < 2 {
		return false
	}
	ip := net.ParseIP(fields[0])
	for _, e := range existing {
		ef := strings.Fields(e)
		if len(ef) < 2 {
			continue
		}
		if eip := net.ParseIP(ef[0]); eip == nil || !eip.Equal(ip) {
			continue
		}
		for _, name := range ef[1:] {
			if strings.EqualFold(name, fields[1]) {
				return true
			}
		}
	}
	return false
}

// applyDNSRecordToPod applies a DNS record to a single Pi-hole pod, re-authenticating
// once if the cached session was rejected. It reports whether the pod was actually
// mutated; an entry that was already present is a no-op and must report false, so
// the caller can skip the status write.
func (r *PiholeDNSRecordReconciler) applyDNSRecordToPod(ctx context.Context, httpClient *http.Client, baseURL, password, cacheKey string, record *cachev1alpha1.PiholeDNSRecord, log logr.Logger) (bool, error) {
	added, err := r.applyDNSRecordToPodImpl(ctx, httpClient, baseURL, password, cacheKey, record, log)
	if err != nil && isAuthError(err) {
		log.Info("Auth error detected in applyDNSRecordToPod, invalidating SID and retrying")
		sharedSIDManager.Invalidate(cacheKey)
		return r.applyDNSRecordToPodImpl(ctx, httpClient, baseURL, password, cacheKey, record, log)
	}
	return added, err
}

func (r *PiholeDNSRecordReconciler) applyDNSRecordToPodImpl(ctx context.Context, httpClient *http.Client, baseURL, password, cacheKey string, record *cachev1alpha1.PiholeDNSRecord, log logr.Logger) (bool, error) {
	baseURL, sid, err := r.getPodConnection(ctx, httpClient, baseURL, password, cacheKey, log)
	if err != nil {
		return false, err
	}

	apiClient := &PiholeAPIClient{
		BaseURL: baseURL,
		Client:  httpClient,
		SID:     sid,
	}

	entry := r.buildEntry(record)
	lastApplied := record.Annotations[lastAppliedEntryAnnotation]

	// The existing entries must be readable: without them a conflicting entry
	// can't be detected, and adding blindly could shadow someone else's record.
	var existing []string
	switch record.Spec.RecordType {
	case "A", "AAAA":
		existing, err = apiClient.ListDNSHosts(ctx)
	case "CNAME":
		existing, err = apiClient.ListDNSCNAMEs(ctx)
	default:
		return false, fmt.Errorf("unsupported record type: %s", record.Spec.RecordType)
	}
	if err != nil {
		return false, fmt.Errorf("failed to list existing DNS entries: %w", err)
	}

	for _, e := range existing {
		if e == entry {
			log.V(1).Info("DNS record already exists", "entry", entry)
			return false, nil
		}
	}

	if c := findConflictingEntry(record.Spec.RecordType, entry, existing, lastApplied); c != "" {
		return false, &dnsConflictError{hostname: record.Spec.Hostname, existing: c}
	}

	if record.Spec.RecordType != "CNAME" && entryCoveredBy(entry, existing) {
		log.V(1).Info("DNS host record already covered by an existing entry", "entry", entry)
		return false, nil
	}

	switch record.Spec.RecordType {
	case "A", "AAAA":
		log.Info("Adding DNS host record", "entry", entry)
		err = apiClient.AddDNSHost(ctx, entry)
	case "CNAME":
		log.Info("Adding DNS CNAME record", "entry", entry)
		err = apiClient.AddDNSCNAME(ctx, entry)
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// removeEntryFromPod removes a specific DNS entry from a single Pi-hole pod,
// re-authenticating once if the cached session was rejected.
func (r *PiholeDNSRecordReconciler) removeEntryFromPod(ctx context.Context, httpClient *http.Client, baseURL, password, cacheKey, recordType, entry string, log logr.Logger) error {
	err := r.removeEntryFromPodImpl(ctx, httpClient, baseURL, password, cacheKey, recordType, entry, log)
	if err != nil && isAuthError(err) {
		log.Info("Auth error detected in removeEntryFromPod, invalidating SID and retrying")
		sharedSIDManager.Invalidate(cacheKey)
		return r.removeEntryFromPodImpl(ctx, httpClient, baseURL, password, cacheKey, recordType, entry, log)
	}
	return err
}

func (r *PiholeDNSRecordReconciler) removeEntryFromPodImpl(ctx context.Context, httpClient *http.Client, baseURL, password, cacheKey, recordType, entry string, log logr.Logger) error {
	baseURL, sid, err := r.getPodConnection(ctx, httpClient, baseURL, password, cacheKey, log)
	if err != nil {
		return err
	}

	apiClient := &PiholeAPIClient{
		BaseURL: baseURL,
		Client:  httpClient,
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
