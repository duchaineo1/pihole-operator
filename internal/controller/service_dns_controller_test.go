package controller

import (
	"context"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cachev1alpha1 "github.com/duchaineo1/pihole-operator/api/v1alpha1"
)

var _ = Describe("ServiceDNS Controller", func() {
	const ns = "default"

	var (
		ctx        context.Context
		recorder   *events.FakeRecorder
		reconciler *ServiceDNSReconciler
	)

	BeforeEach(func() {
		ctx = context.Background()
		recorder = events.NewFakeRecorder(100)
		reconciler = &ServiceDNSReconciler{
			Client:   k8sClient,
			Scheme:   k8sClient.Scheme(),
			Recorder: recorder,
		}
	})

	createService := func(name string, svcType corev1.ServiceType, annotations map[string]string) *corev1.Service {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: annotations},
			Spec: corev1.ServiceSpec{
				Type:  svcType,
				Ports: []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080)}},
			},
		}
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, svc)
			// envtest has no garbage collector: remove generated records by hand.
			_ = k8sClient.DeleteAllOf(ctx, &cachev1alpha1.PiholeDNSRecord{},
				client.InNamespace(ns), client.MatchingLabels{serviceUIDLabel: string(svc.UID)})
		})
		return svc
	}

	setLoadBalancerIP := func(svc *corev1.Service, ips ...string) {
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(svc), svc)).To(Succeed())
		svc.Status.LoadBalancer.Ingress = nil
		for _, ip := range ips {
			svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, corev1.LoadBalancerIngress{IP: ip})
		}
		Expect(k8sClient.Status().Update(ctx, svc)).To(Succeed())
	}

	setAnnotation := func(svc *corev1.Service, key, value string) {
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(svc), svc)).To(Succeed())
		if value == "" {
			delete(svc.Annotations, key)
		} else {
			svc.Annotations[key] = value
		}
		Expect(k8sClient.Update(ctx, svc)).To(Succeed())
	}

	doReconcile := func(svc *corev1.Service) {
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(svc)})
		Expect(err).NotTo(HaveOccurred())
	}

	recordsFor := func(svc *corev1.Service) []cachev1alpha1.PiholeDNSRecord {
		list := &cachev1alpha1.PiholeDNSRecordList{}
		Expect(k8sClient.List(ctx, list, client.InNamespace(ns),
			client.MatchingLabels{serviceUIDLabel: string(svc.UID)})).To(Succeed())
		return list.Items
	}

	getRecord := func(name string) *cachev1alpha1.PiholeDNSRecord {
		rec := &cachev1alpha1.PiholeDNSRecord{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, rec)).To(Succeed())
		return rec
	}

	// drainEvents returns every event recorded so far.
	drainEvents := func() []string {
		var out []string
		for {
			select {
			case e := <-recorder.Events:
				out = append(out, e)
			default:
				return out
			}
		}
	}

	It("waits for a LoadBalancer IP, then creates an owned A record", func() {
		svc := createService("sdns-lb", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnamesAnnotation: "Jellyfin.example.com, tv.example.com",
		})

		doReconcile(svc)
		Expect(recordsFor(svc)).To(BeEmpty())
		Expect(drainEvents()).To(BeEmpty(), "a pending LoadBalancer is not worth a warning")

		setLoadBalancerIP(svc, "10.0.0.50")
		doReconcile(svc)

		Expect(recordsFor(svc)).To(HaveLen(2))
		rec := getRecord("sdns-lb-jellyfin.example.com")
		Expect(rec.Spec.Hostname).To(Equal("jellyfin.example.com"))
		Expect(rec.Spec.RecordType).To(Equal("A"))
		Expect(rec.Spec.IPAddress).To(Equal("10.0.0.50"))
		Expect(rec.Spec.Description).To(Equal("Managed by Service default/sdns-lb"))
		Expect(rec.Labels).To(HaveKeyWithValue(managedByLabel, managedByServiceDNS))
		Expect(rec.OwnerReferences).To(HaveLen(1))
		Expect(rec.OwnerReferences[0].UID).To(Equal(svc.UID))
		Expect(*rec.OwnerReferences[0].Controller).To(BeTrue())
		getRecord("sdns-lb-tv.example.com")

		Expect(drainEvents()).To(ContainElement(HavePrefix("Normal Created")))
	})

	It("uses the first IPv4 ingress address", func() {
		svc := createService("sdns-ipv4", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnamesAnnotation: "dual.example.com",
		})
		setLoadBalancerIP(svc, "fd00::50", "10.0.0.51")
		doReconcile(svc)

		Expect(getRecord("sdns-ipv4-dual.example.com").Spec.IPAddress).To(Equal("10.0.0.51"))
	})

	It("updates the record when the IP changes and keeps it when the IP disappears", func() {
		svc := createService("sdns-ipchange", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnamesAnnotation: "move.example.com",
		})
		setLoadBalancerIP(svc, "10.0.0.60")
		doReconcile(svc)

		setLoadBalancerIP(svc, "10.0.0.61")
		doReconcile(svc)
		Expect(getRecord("sdns-ipchange-move.example.com").Spec.IPAddress).To(Equal("10.0.0.61"))
		Expect(drainEvents()).To(ContainElement(HavePrefix("Normal Updated")))

		setLoadBalancerIP(svc)
		doReconcile(svc)
		Expect(getRecord("sdns-ipchange-move.example.com").Spec.IPAddress).To(Equal("10.0.0.61"))
	})

	It("deletes records for hostnames removed from the annotation", func() {
		svc := createService("sdns-remove", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnamesAnnotation: "a.example.com,b.example.com",
		})
		setLoadBalancerIP(svc, "10.0.0.70")
		doReconcile(svc)
		Expect(recordsFor(svc)).To(HaveLen(2))

		setAnnotation(svc, serviceHostnamesAnnotation, "a.example.com")
		doReconcile(svc)
		Expect(recordsFor(svc)).To(HaveLen(1))
		Expect(recordsFor(svc)[0].Spec.Hostname).To(Equal("a.example.com"))

		setAnnotation(svc, serviceHostnamesAnnotation, "")
		doReconcile(svc)
		Expect(recordsFor(svc)).To(BeEmpty())
	})

	It("deletes removed hostnames even while the IP is unknown", func() {
		svc := createService("sdns-remove-noip", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnamesAnnotation: "a.example.com,b.example.com",
		})
		setLoadBalancerIP(svc, "10.0.0.71")
		doReconcile(svc)

		setLoadBalancerIP(svc)
		setAnnotation(svc, serviceHostnamesAnnotation, "a.example.com")
		doReconcile(svc)
		Expect(recordsFor(svc)).To(HaveLen(1))
	})

	It("prefers the ip annotation over the LoadBalancer IP", func() {
		svc := createService("sdns-override", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnamesAnnotation: "override.example.com",
			serviceIPAnnotation:        "192.168.1.10",
		})
		setLoadBalancerIP(svc, "10.0.0.80")
		doReconcile(svc)

		Expect(getRecord("sdns-override-override.example.com").Spec.IPAddress).To(Equal("192.168.1.10"))
	})

	It("warns and creates nothing for a ClusterIP Service without an address opt-in", func() {
		svc := createService("sdns-clusterip", corev1.ServiceTypeClusterIP, map[string]string{
			serviceHostnamesAnnotation: "internal.example.com",
		})
		doReconcile(svc)

		Expect(recordsFor(svc)).To(BeEmpty())
		Expect(drainEvents()).To(ContainElement(HavePrefix("Warning NoAddress")))
	})

	It("uses spec.clusterIP when use-cluster-ip is true", func() {
		svc := createService("sdns-useclusterip", corev1.ServiceTypeClusterIP, map[string]string{
			serviceHostnamesAnnotation:    "internal.example.com",
			serviceUseClusterIPAnnotation: "true",
		})
		doReconcile(svc)

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(svc), svc)).To(Succeed())
		Expect(getRecord("sdns-useclusterip-internal.example.com").Spec.IPAddress).To(Equal(svc.Spec.ClusterIP))
	})

	It("warns about an invalid ip annotation", func() {
		svc := createService("sdns-badip", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnamesAnnotation: "bad.example.com",
			serviceIPAnnotation:        "fd00::1",
		})
		doReconcile(svc)

		Expect(recordsFor(svc)).To(BeEmpty())
		Expect(drainEvents()).To(ContainElement(HavePrefix("Warning InvalidIP")))
	})

	It("skips invalid hostnames and applies the valid ones", func() {
		svc := createService("sdns-badhost", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnamesAnnotation: "good.example.com,bad_host.example.com",
		})
		setLoadBalancerIP(svc, "10.0.0.90")
		doReconcile(svc)

		Expect(recordsFor(svc)).To(HaveLen(1))
		Expect(drainEvents()).To(ContainElement(SatisfyAll(
			HavePrefix("Warning InvalidHostname"), ContainSubstring("bad_host.example.com"))))
	})

	It("sets targetNamespaces from the annotation, falling back to the default", func() {
		reconciler.DefaultTargetNamespaces = []string{"pihole-system"}

		withDefault := createService("sdns-tns-default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnamesAnnotation: "default.example.com",
		})
		setLoadBalancerIP(withDefault, "10.0.0.100")
		doReconcile(withDefault)
		Expect(getRecord("sdns-tns-default-default.example.com").Spec.TargetNamespaces).To(Equal([]string{"pihole-system"}))

		withAnnotation := createService("sdns-tns-annotated", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnamesAnnotation:        "annotated.example.com",
			serviceTargetNamespacesAnnotation: "team-a, team-b",
		})
		setLoadBalancerIP(withAnnotation, "10.0.0.101")
		doReconcile(withAnnotation)
		Expect(getRecord("sdns-tns-annotated-annotated.example.com").Spec.TargetNamespaces).To(Equal([]string{"team-a", "team-b"}))
	})

	It("reverts manual edits to a generated record", func() {
		svc := createService("sdns-revert", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnamesAnnotation: "revert.example.com",
		})
		setLoadBalancerIP(svc, "10.0.0.110")
		doReconcile(svc)

		rec := getRecord("sdns-revert-revert.example.com")
		rec.Spec.IPAddress = "1.2.3.4"
		Expect(k8sClient.Update(ctx, rec)).To(Succeed())

		doReconcile(svc)
		Expect(getRecord("sdns-revert-revert.example.com").Spec.IPAddress).To(Equal("10.0.0.110"))
	})

	It("never takes over a hand-written record with the same name", func() {
		manual := &cachev1alpha1.PiholeDNSRecord{
			ObjectMeta: metav1.ObjectMeta{Name: "sdns-collide-nas.example.com", Namespace: ns},
			Spec: cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:   "nas.example.com",
				RecordType: "A",
				IPAddress:  "192.168.1.5",
			},
		}
		Expect(k8sClient.Create(ctx, manual)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, manual) })

		svc := createService("sdns-collide", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnamesAnnotation: "nas.example.com",
		})
		setLoadBalancerIP(svc, "10.0.0.120")
		doReconcile(svc)

		rec := getRecord("sdns-collide-nas.example.com")
		Expect(rec.Spec.IPAddress).To(Equal("192.168.1.5"))
		Expect(rec.OwnerReferences).To(BeEmpty())
		Expect(rec.Labels).NotTo(HaveKey(serviceUIDLabel))
		Expect(drainEvents()).To(ContainElement(HavePrefix("Warning NameCollision")))
	})

	It("ignores Services without the annotation", func() {
		svc := createService("sdns-plain", corev1.ServiceTypeLoadBalancer, nil)
		setLoadBalancerIP(svc, "10.0.0.130")
		doReconcile(svc)

		Expect(recordsFor(svc)).To(BeEmpty())
		Expect(drainEvents()).To(BeEmpty())
	})

	It("returns cleanly for a deleted Service", func() {
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "sdns-missing", Namespace: ns},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: "sdns-missing", Namespace: ns}, &corev1.Service{}))).To(BeTrue())
	})
})

func TestParseHostnames(t *testing.T) {
	valid, invalid := parseHostnames(" Jellyfin.Example.com, tv.example.com.,,jellyfin.example.com, bad_host.example.com, *.example.com ")
	wantValid := []string{"jellyfin.example.com", "tv.example.com"}
	wantInvalid := []string{"bad_host.example.com", "*.example.com"}
	if strings.Join(valid, ",") != strings.Join(wantValid, ",") {
		t.Errorf("valid = %v, want %v", valid, wantValid)
	}
	if strings.Join(invalid, ",") != strings.Join(wantInvalid, ",") {
		t.Errorf("invalid = %v, want %v", invalid, wantInvalid)
	}

	if valid, invalid := parseHostnames(""); valid != nil || invalid != nil {
		t.Errorf("empty annotation: valid = %v, invalid = %v", valid, invalid)
	}
}

func TestResolveServiceIP(t *testing.T) {
	lb := func(annotations map[string]string, ingressIPs ...string) *corev1.Service {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Annotations: annotations},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ClusterIP: "10.43.0.10"},
		}
		for _, ip := range ingressIPs {
			svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, corev1.LoadBalancerIngress{IP: ip})
		}
		return svc
	}
	clusterIP := func(annotations map[string]string, ip string) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Annotations: annotations},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: ip},
		}
	}

	tests := []struct {
		name       string
		svc        *corev1.Service
		wantIP     string
		wantReason string
	}{
		{"ip annotation wins", lb(map[string]string{serviceIPAnnotation: " 192.168.1.10 "}, "10.0.0.1"), "192.168.1.10", ""},
		{"ip annotation must be IPv4", lb(map[string]string{serviceIPAnnotation: "fd00::1"}, "10.0.0.1"), "", "InvalidIP"},
		{"ip annotation must parse", lb(map[string]string{serviceIPAnnotation: "nope"}), "", "InvalidIP"},
		{"first IPv4 ingress", lb(nil, "fd00::1", "10.0.0.2", "10.0.0.3"), "10.0.0.2", ""},
		{"pending LoadBalancer", lb(nil), "", ""},
		{"IPv6-only LoadBalancer", lb(nil, "fd00::1"), "", ""},
		{"pending LoadBalancer falls back to cluster IP", lb(map[string]string{serviceUseClusterIPAnnotation: "true"}), "10.43.0.10", ""},
		{"LoadBalancer IP beats cluster IP", lb(map[string]string{serviceUseClusterIPAnnotation: "true"}, "10.0.0.4"), "10.0.0.4", ""},
		{"ClusterIP without opt-in", clusterIP(nil, "10.43.0.11"), "", "NoAddress"},
		{"ClusterIP with opt-in", clusterIP(map[string]string{serviceUseClusterIPAnnotation: "true"}, "10.43.0.11"), "10.43.0.11", ""},
		{"opt-in must be exactly true", clusterIP(map[string]string{serviceUseClusterIPAnnotation: "yes"}, "10.43.0.11"), "", "NoAddress"},
		{"headless Service", clusterIP(map[string]string{serviceUseClusterIPAnnotation: "true"}, corev1.ClusterIPNone), "", "NoAddress"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, reason, _ := resolveServiceIP(tt.svc)
			if ip != tt.wantIP || reason != tt.wantReason {
				t.Errorf("resolveServiceIP() = (%q, %q), want (%q, %q)", ip, reason, tt.wantIP, tt.wantReason)
			}
		})
	}
}

func TestServiceRecordName(t *testing.T) {
	if got := serviceRecordName("jellyfin", "tv.example.com"); got != "jellyfin-tv.example.com" {
		t.Errorf("short name = %q", got)
	}

	longHost := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60)
	got := serviceRecordName(strings.Repeat("s", 63), longHost)
	if len(got) > maxObjectNameLength {
		t.Errorf("name length %d exceeds %d", len(got), maxObjectNameLength)
	}
	if errs := validation.IsDNS1123Subdomain(got); len(errs) > 0 {
		t.Errorf("name %q is not a valid object name: %v", got, errs)
	}
	if other := serviceRecordName(strings.Repeat("s", 63), longHost+"x"); other == got {
		t.Errorf("distinct long hostnames produced the same name %q", got)
	}
	if again := serviceRecordName(strings.Repeat("s", 63), longHost); again != got {
		t.Errorf("name is not deterministic: %q vs %q", got, again)
	}
}
