package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"net"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	cachev1alpha1 "github.com/duchaineo1/pihole-operator/api/v1alpha1"
)

const (
	// Service annotations read by ServiceDNSReconciler.
	serviceHostnamesAnnotation        = "pihole-operator.org/hostnames"
	serviceTargetNamespacesAnnotation = "pihole-operator.org/target-namespaces"
	serviceIPAnnotation               = "pihole-operator.org/ip"
	serviceUseClusterIPAnnotation     = "pihole-operator.org/use-cluster-ip"

	// Labels set on the PiholeDNSRecords generated from a Service.
	serviceUIDLabel     = "pihole-operator.org/service-uid"
	managedByLabel      = "pihole-operator.org/managed-by"
	managedByServiceDNS = "service-dns"

	// maxObjectNameLength is the DNS-1123 subdomain limit for object names.
	maxObjectNameLength = 253
)

var errNameCollision = stderrors.New("a PiholeDNSRecord with this name exists and is not managed by this Service")

// ServiceDNSReconciler generates PiholeDNSRecords from annotated Services. It
// only manages the records; PiholeDNSRecordReconciler pushes them to Pi-hole.
// Each record is owned by its Service, so deleting the Service garbage-collects
// the records and their finalizer removes the entries from Pi-hole.
type ServiceDNSReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	// DefaultTargetNamespaces is used for Services without the
	// target-namespaces annotation. Empty means the Service's own namespace.
	DefaultTargetNamespaces []string
}

// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=services/finalizers,verbs=update
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholednsrecords,verbs=get;list;watch;create;update;patch;delete

func (r *ServiceDNSReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	svc := &corev1.Service{}
	if err := r.Get(ctx, req.NamespacedName, svc); err != nil {
		// A deleted Service's records are garbage-collected through their ownerRef.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !svc.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	existing := &cachev1alpha1.PiholeDNSRecordList{}
	if err := r.List(ctx, existing, client.InNamespace(svc.Namespace), client.MatchingLabels{serviceUIDLabel: string(svc.UID)}); err != nil {
		return ctrl.Result{}, err
	}

	hostnames, invalid := parseHostnames(svc.Annotations[serviceHostnamesAnnotation])
	for _, h := range invalid {
		r.Recorder.Eventf(svc, nil, corev1.EventTypeWarning, "InvalidHostname", "Reconcile",
			"Ignoring invalid hostname %q in %s", h, serviceHostnamesAnnotation)
	}

	desired := make(map[string]string, len(hostnames)) // record name -> hostname
	for _, h := range hostnames {
		desired[serviceRecordName(svc.Name, h)] = h
	}

	// Records for hostnames no longer in the annotation are deleted even when
	// the IP can't be resolved right now.
	for i := range existing.Items {
		rec := &existing.Items[i]
		if _, ok := desired[rec.Name]; ok {
			continue
		}
		log.Info("Deleting PiholeDNSRecord no longer requested by Service", "record", rec.Name)
		if err := r.Delete(ctx, rec); client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		r.Recorder.Eventf(svc, rec, corev1.EventTypeNormal, "Deleted", "Reconcile",
			"Deleted PiholeDNSRecord %s for %s", rec.Name, rec.Spec.Hostname)
	}

	if len(desired) == 0 {
		return ctrl.Result{}, nil
	}

	ip, reason, msg := resolveServiceIP(svc)
	if ip == "" {
		// Existing records keep their last IP: an address that briefly disappears
		// (e.g. MetalLB restarting) must not delete and re-create DNS entries.
		// No requeue is needed, since the Service status update that brings the
		// address triggers a new reconcile.
		if reason != "" {
			r.Recorder.Eventf(svc, nil, corev1.EventTypeWarning, reason, "Reconcile", "%s", msg)
		}
		log.V(1).Info("No address for Service yet, not creating DNS records", "reason", reason)
		return ctrl.Result{}, nil
	}

	targetNamespaces := r.DefaultTargetNamespaces
	if v, ok := svc.Annotations[serviceTargetNamespacesAnnotation]; ok {
		targetNamespaces = splitList(v)
	}

	names := make([]string, 0, len(desired))
	for name := range desired {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		rec := &cachev1alpha1.PiholeDNSRecord{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: svc.Namespace},
		}
		op, err := controllerutil.CreateOrUpdate(ctx, r.Client, rec, func() error {
			// Never take over a record someone else created under this name.
			if !rec.CreationTimestamp.IsZero() && rec.Labels[serviceUIDLabel] != string(svc.UID) {
				return errNameCollision
			}
			if rec.Labels == nil {
				rec.Labels = map[string]string{}
			}
			rec.Labels[serviceUIDLabel] = string(svc.UID)
			rec.Labels[managedByLabel] = managedByServiceDNS
			rec.Spec = cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:         desired[name],
				RecordType:       "A",
				IPAddress:        ip,
				Description:      fmt.Sprintf("Managed by Service %s/%s", svc.Namespace, svc.Name),
				TargetNamespaces: targetNamespaces,
			}
			return controllerutil.SetControllerReference(svc, rec, r.Scheme)
		})
		if stderrors.Is(err, errNameCollision) {
			r.Recorder.Eventf(svc, nil, corev1.EventTypeWarning, "NameCollision", "Reconcile",
				"PiholeDNSRecord %s already exists and is not managed by this Service; skipping %s", name, desired[name])
			continue
		}
		if err != nil {
			return ctrl.Result{}, err
		}
		switch op {
		case controllerutil.OperationResultCreated:
			log.Info("Created PiholeDNSRecord for Service", "record", name, "hostname", desired[name], "ip", ip)
			r.Recorder.Eventf(svc, rec, corev1.EventTypeNormal, "Created", "Reconcile",
				"Created PiholeDNSRecord %s: %s -> %s", name, desired[name], ip)
		case controllerutil.OperationResultUpdated:
			log.Info("Updated PiholeDNSRecord for Service", "record", name, "hostname", desired[name], "ip", ip)
			r.Recorder.Eventf(svc, rec, corev1.EventTypeNormal, "Updated", "Reconcile",
				"Updated PiholeDNSRecord %s: %s -> %s", name, desired[name], ip)
		}
	}

	return ctrl.Result{}, nil
}

// parseHostnames splits the hostnames annotation into lowercased, de-duplicated
// valid hostnames, and returns the entries that are not valid DNS names.
func parseHostnames(value string) (valid, invalid []string) {
	seen := map[string]struct{}{}
	for _, h := range splitList(value) {
		h = strings.TrimSuffix(strings.ToLower(h), ".")
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		if len(validation.IsDNS1123Subdomain(h)) > 0 {
			invalid = append(invalid, h)
			continue
		}
		valid = append(valid, h)
	}
	return valid, invalid
}

// splitList splits a comma-separated annotation value, dropping empty items.
func splitList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// resolveServiceIP picks the IPv4 address a Service's hostnames should resolve
// to. Only IPv4 is used: publishing AAAA records for LAN services has caused
// clients to prefer unreachable IPv6 addresses.
//
// Order: the ip annotation, then the first IPv4 LoadBalancer ingress IP, then
// spec.clusterIP when use-cluster-ip is "true". When nothing applies, ip is
// empty and reason/msg describe why; reason is empty when the Service is a
// LoadBalancer still waiting for its address, which is not worth a warning.
func resolveServiceIP(svc *corev1.Service) (ip, reason, msg string) {
	if v, ok := svc.Annotations[serviceIPAnnotation]; ok {
		if parsed := net.ParseIP(strings.TrimSpace(v)); parsed != nil && parsed.To4() != nil {
			return parsed.String(), "", ""
		}
		return "", "InvalidIP", fmt.Sprintf("%s=%q is not an IPv4 address", serviceIPAnnotation, v)
	}

	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
		for _, ingress := range svc.Status.LoadBalancer.Ingress {
			if parsed := net.ParseIP(ingress.IP); parsed != nil && parsed.To4() != nil {
				return parsed.String(), "", ""
			}
		}
	}

	if svc.Annotations[serviceUseClusterIPAnnotation] == "true" {
		if parsed := net.ParseIP(svc.Spec.ClusterIP); parsed != nil && parsed.To4() != nil {
			return parsed.String(), "", ""
		}
	}

	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
		return "", "", ""
	}
	return "", "NoAddress", fmt.Sprintf(
		"Service type %s has no address reachable from the LAN; use a LoadBalancer, or set %s or %s=\"true\"",
		svc.Spec.Type, serviceIPAnnotation, serviceUseClusterIPAnnotation)
}

// serviceRecordName returns the PiholeDNSRecord name for a Service hostname:
// "<service>-<hostname>". Both parts are valid DNS-1123 subdomains, so the
// result is too; overlong names are truncated with a hash suffix to stay unique.
func serviceRecordName(serviceName, hostname string) string {
	name := serviceName + "-" + hostname
	if len(name) <= maxObjectNameLength {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	suffix := hex.EncodeToString(sum[:])[:8]
	prefix := strings.TrimRight(name[:maxObjectNameLength-len(suffix)-1], ".-")
	return prefix + "-" + suffix
}

// hasServiceDNSAnnotation reports whether obj opts into Service DNS.
func hasServiceDNSAnnotation(obj client.Object) bool {
	_, ok := obj.GetAnnotations()[serviceHostnamesAnnotation]
	return ok
}

// serviceDNSPredicate filters Service events down to the ones that can change
// generated records. Create events always pass so that, on startup, Services
// whose annotation was removed while the operator was down get cleaned up.
// Deletes are handled by garbage collection.
func serviceDNSPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			return hasServiceDNSAnnotation(e.ObjectOld) || hasServiceDNSAnnotation(e.ObjectNew)
		},
		DeleteFunc:  func(event.DeleteEvent) bool { return false },
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

// SetupWithManager sets up the controller
func (r *ServiceDNSReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("service-dns").
		For(&corev1.Service{}, builder.WithPredicates(serviceDNSPredicate())).
		// Recreate or revert generated records that were deleted or edited by
		// hand. Status and annotation writes from the record controller don't
		// change the generation and are ignored.
		Owns(&cachev1alpha1.PiholeDNSRecord{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
