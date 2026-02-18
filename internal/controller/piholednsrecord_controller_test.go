/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cachev1alpha1 "github.com/duchaineo1/pihole-operator/api/v1alpha1"
)

// mockDNSAPI tracks calls made to the mock Pi-hole DNS API server.
type mockDNSAPI struct {
	mu             sync.Mutex
	authCalls      int
	existingHosts  []string
	existingCNAMEs []string
	addedHosts     []string
	deletedHosts   []string
	addedCNAMEs    []string
	deletedCNAMEs  []string
	failAuth       bool
}

func (m *mockDNSAPI) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		switch {
		case r.URL.Path == "/api/auth" && r.Method == "POST":
			m.authCalls++
			if m.failAuth {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"session":{"valid":false}}`))
				return
			}
			resp := PiholeAuthResponse{}
			resp.Session.Valid = true
			resp.Session.SID = "test-sid"
			resp.Session.Validity = 600
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/api/config/dns/hosts" && r.Method == "GET":
			resp := DNSHostsResponse{}
			resp.Config.DNS.Hosts = m.existingHosts
			json.NewEncoder(w).Encode(resp)

		case strings.HasPrefix(r.URL.Path, "/api/config/dns/hosts/") && r.Method == "PUT":
			entry, _ := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/api/config/dns/hosts/"))
			m.addedHosts = append(m.addedHosts, entry)
			w.WriteHeader(http.StatusCreated)

		case strings.HasPrefix(r.URL.Path, "/api/config/dns/hosts/") && r.Method == "DELETE":
			entry, _ := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/api/config/dns/hosts/"))
			m.deletedHosts = append(m.deletedHosts, entry)
			w.WriteHeader(http.StatusNoContent)

		case r.URL.Path == "/api/config/dns/cnameRecords" && r.Method == "GET":
			resp := DNSCNAMEResponse{}
			resp.Config.DNS.CNAMERecords = m.existingCNAMEs
			json.NewEncoder(w).Encode(resp)

		case strings.HasPrefix(r.URL.Path, "/api/config/dns/cnameRecords/") && r.Method == "PUT":
			entry, _ := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/api/config/dns/cnameRecords/"))
			m.addedCNAMEs = append(m.addedCNAMEs, entry)
			w.WriteHeader(http.StatusCreated)

		case strings.HasPrefix(r.URL.Path, "/api/config/dns/cnameRecords/") && r.Method == "DELETE":
			entry, _ := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/api/config/dns/cnameRecords/"))
			m.deletedCNAMEs = append(m.deletedCNAMEs, entry)
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

var _ = Describe("PiholeDNSRecord Controller", func() {
	var (
		ctx        context.Context
		reconciler *PiholeDNSRecordReconciler
		mock       *mockDNSAPI
		srv        *httptest.Server
	)

	const (
		piholeNS   = "default"
		piholeName = "test-pihole-dns"
	)

	setupPihole := func() {
		pihole := &cachev1alpha1.Pihole{
			ObjectMeta: metav1.ObjectMeta{Name: piholeName, Namespace: piholeNS},
			Spec:       cachev1alpha1.PiholeSpec{},
		}
		Expect(k8sClient.Create(ctx, pihole)).To(Succeed())

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      piholeName + "-admin",
				Namespace: piholeNS,
			},
			StringData: map[string]string{"password": "test-password"},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	}

	cleanupPihole := func() {
		pihole := &cachev1alpha1.Pihole{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: piholeName, Namespace: piholeNS}, pihole); err == nil {
			k8sClient.Delete(ctx, pihole)
		}
		secret := &corev1.Secret{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: piholeName + "-admin", Namespace: piholeNS}, secret); err == nil {
			k8sClient.Delete(ctx, secret)
		}
	}

	createDNSRecord := func(name string, spec cachev1alpha1.PiholeDNSRecordSpec) types.NamespacedName {
		nn := types.NamespacedName{Name: name, Namespace: piholeNS}
		rec := &cachev1alpha1.PiholeDNSRecord{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: piholeNS},
			Spec:       spec,
		}
		Expect(k8sClient.Create(ctx, rec)).To(Succeed())
		return nn
	}

	deleteDNSRecord := func(nn types.NamespacedName) {
		rec := &cachev1alpha1.PiholeDNSRecord{}
		if err := k8sClient.Get(ctx, nn, rec); err == nil {
			controllerutil.RemoveFinalizer(rec, dnsRecordFinalizer)
			k8sClient.Update(ctx, rec)
			k8sClient.Delete(ctx, rec)
		}
	}

	doReconcile := func(nn types.NamespacedName) (reconcile.Result, error) {
		return reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
	}

	BeforeEach(func() {
		ctx = context.Background()
		mock = &mockDNSAPI{}
		srv = httptest.NewServer(mock.handler())

		cacheKey := fmt.Sprintf("%s/%s", piholeNS, piholeName)
		reconciler = &PiholeDNSRecordReconciler{
			Client:   k8sClient,
			Scheme:   k8sClient.Scheme(),
			sidCache: make(map[string]*cachedSID),
			BaseURLOverride: map[string]string{
				cacheKey: srv.URL,
			},
		}
	})

	AfterEach(func() {
		srv.Close()
	})

	Context("No Pihole in namespace", func() {
		It("should set NoPihole condition and requeue", func() {
			nn := createDNSRecord("dns-no-pihole", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:   "test.local",
				RecordType: "A",
				IPAddress:  "192.168.1.100",
			})
			defer deleteDNSRecord(nn)

			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(1 * time.Minute))

			rec := &cachev1alpha1.PiholeDNSRecord{}
			Expect(k8sClient.Get(ctx, nn, rec)).To(Succeed())
			Expect(rec.Status.Conditions).NotTo(BeEmpty())
			Expect(rec.Status.Conditions[0].Reason).To(Equal("NoPihole"))
		})
	})

	Context("With a Pihole present", func() {
		BeforeEach(func() { setupPihole() })
		AfterEach(func() { cleanupPihole() })

		It("should add the finalizer on first reconcile", func() {
			nn := createDNSRecord("dns-finalizer", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:   "test.local",
				RecordType: "A",
				IPAddress:  "192.168.1.100",
			})
			defer deleteDNSRecord(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			rec := &cachev1alpha1.PiholeDNSRecord{}
			Expect(k8sClient.Get(ctx, nn, rec)).To(Succeed())
			Expect(controllerutil.ContainsFinalizer(rec, dnsRecordFinalizer)).To(BeTrue())
		})

		It("should add an A record via API", func() {
			nn := createDNSRecord("dns-add-a", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:   "myhost.local",
				RecordType: "A",
				IPAddress:  "192.168.1.50",
			})
			defer deleteDNSRecord(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			defer mock.mu.Unlock()
			Expect(mock.addedHosts).To(ContainElement("192.168.1.50 myhost.local"))
		})

		It("should add an AAAA record via API", func() {
			nn := createDNSRecord("dns-add-aaaa", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:   "myhost.local",
				RecordType: "AAAA",
				IPAddress:  "fd00::1",
			})
			defer deleteDNSRecord(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			defer mock.mu.Unlock()
			Expect(mock.addedHosts).To(ContainElement("fd00::1 myhost.local"))
		})

		It("should add a CNAME record via API", func() {
			nn := createDNSRecord("dns-add-cname", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:    "alias.local",
				RecordType:  "CNAME",
				CNAMETarget: "target.local",
			})
			defer deleteDNSRecord(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			defer mock.mu.Unlock()
			Expect(mock.addedCNAMEs).To(ContainElement("alias.local,target.local"))
		})

		It("should skip existing A record", func() {
			mock.existingHosts = []string{"192.168.1.50 myhost.local"}

			nn := createDNSRecord("dns-skip-a", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:   "myhost.local",
				RecordType: "A",
				IPAddress:  "192.168.1.50",
			})
			defer deleteDNSRecord(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			defer mock.mu.Unlock()
			Expect(mock.addedHosts).To(BeEmpty())
		})

		It("should skip existing CNAME record", func() {
			mock.existingCNAMEs = []string{"alias.local,target.local"}

			nn := createDNSRecord("dns-skip-cname", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:    "alias.local",
				RecordType:  "CNAME",
				CNAMETarget: "target.local",
			})
			defer deleteDNSRecord(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			defer mock.mu.Unlock()
			Expect(mock.addedCNAMEs).To(BeEmpty())
		})

		It("should set Available=True status after successful apply", func() {
			nn := createDNSRecord("dns-status-ok", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:   "status.local",
				RecordType: "A",
				IPAddress:  "10.0.0.1",
			})
			defer deleteDNSRecord(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			rec := &cachev1alpha1.PiholeDNSRecord{}
			Expect(k8sClient.Get(ctx, nn, rec)).To(Succeed())

			var found bool
			for _, c := range rec.Status.Conditions {
				if c.Type == typeAvailableDNSRecord {
					Expect(c.Status).To(Equal(metav1.ConditionTrue))
					Expect(c.Reason).To(Equal("Applied"))
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "Available condition not found")
			Expect(rec.Status.LastSyncTime).NotTo(BeNil())
		})

		It("should set ApplyFailed status when auth fails", func() {
			mock.failAuth = true

			nn := createDNSRecord("dns-fail-auth", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:   "fail.local",
				RecordType: "A",
				IPAddress:  "10.0.0.1",
			})
			defer deleteDNSRecord(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			rec := &cachev1alpha1.PiholeDNSRecord{}
			Expect(k8sClient.Get(ctx, nn, rec)).To(Succeed())

			var found bool
			for _, c := range rec.Status.Conditions {
				if c.Type == typeAvailableDNSRecord {
					Expect(c.Status).To(Equal(metav1.ConditionFalse))
					Expect(c.Reason).To(Equal("ApplyFailed"))
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "Available condition not found")
		})

		It("should requeue after 5 minutes", func() {
			nn := createDNSRecord("dns-requeue", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:   "requeue.local",
				RecordType: "A",
				IPAddress:  "10.0.0.1",
			})
			defer deleteDNSRecord(nn)

			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))
		})

		It("should fail validation when A record missing ipAddress", func() {
			nn := createDNSRecord("dns-val-no-ip", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:   "noip.local",
				RecordType: "A",
			})
			defer deleteDNSRecord(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			rec := &cachev1alpha1.PiholeDNSRecord{}
			Expect(k8sClient.Get(ctx, nn, rec)).To(Succeed())

			var found bool
			for _, c := range rec.Status.Conditions {
				if c.Type == typeAvailableDNSRecord {
					Expect(c.Status).To(Equal(metav1.ConditionFalse))
					Expect(c.Reason).To(Equal("ValidationFailed"))
					Expect(c.Message).To(ContainSubstring("ipAddress is required"))
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "ValidationFailed condition not found")
		})

		It("should fail validation when CNAME record missing cnameTarget", func() {
			nn := createDNSRecord("dns-val-no-cname", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:   "nocname.local",
				RecordType: "CNAME",
			})
			defer deleteDNSRecord(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			rec := &cachev1alpha1.PiholeDNSRecord{}
			Expect(k8sClient.Get(ctx, nn, rec)).To(Succeed())

			var found bool
			for _, c := range rec.Status.Conditions {
				if c.Type == typeAvailableDNSRecord {
					Expect(c.Status).To(Equal(metav1.ConditionFalse))
					Expect(c.Reason).To(Equal("ValidationFailed"))
					Expect(c.Message).To(ContainSubstring("cnameTarget is required"))
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "ValidationFailed condition not found")
		})
	})

	Context("Deletion", func() {
		BeforeEach(func() { setupPihole() })
		AfterEach(func() { cleanupPihole() })

		It("should delete A record and remove finalizer on deletion", func() {
			nn := createDNSRecord("dns-delete-a", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:   "todelete.local",
				RecordType: "A",
				IPAddress:  "192.168.1.99",
			})

			// Reconcile to add finalizer and apply
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Mark for deletion
			rec := &cachev1alpha1.PiholeDNSRecord{}
			Expect(k8sClient.Get(ctx, nn, rec)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rec)).To(Succeed())

			// Re-fetch after delete marks DeletionTimestamp
			Expect(k8sClient.Get(ctx, nn, rec)).To(Succeed())
			Expect(rec.DeletionTimestamp).NotTo(BeNil())

			// Reconcile handles deletion
			_, err = doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			Expect(mock.deletedHosts).To(ContainElement("192.168.1.99 todelete.local"))
			mock.mu.Unlock()

			Eventually(func() bool {
				err := k8sClient.Get(ctx, nn, &cachev1alpha1.PiholeDNSRecord{})
				return err != nil
			}).Should(BeTrue())
		})

		It("should delete CNAME record and remove finalizer on deletion", func() {
			nn := createDNSRecord("dns-delete-cname", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:    "alias-del.local",
				RecordType:  "CNAME",
				CNAMETarget: "target-del.local",
			})

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			rec := &cachev1alpha1.PiholeDNSRecord{}
			Expect(k8sClient.Get(ctx, nn, rec)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rec)).To(Succeed())

			Expect(k8sClient.Get(ctx, nn, rec)).To(Succeed())
			Expect(rec.DeletionTimestamp).NotTo(BeNil())

			_, err = doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			Expect(mock.deletedCNAMEs).To(ContainElement("alias-del.local,target-del.local"))
			mock.mu.Unlock()

			Eventually(func() bool {
				err := k8sClient.Get(ctx, nn, &cachev1alpha1.PiholeDNSRecord{})
				return err != nil
			}).Should(BeTrue())
		})
	})

	Context("Not-found PiholeDNSRecord", func() {
		It("should return cleanly", func() {
			result, err := doReconcile(types.NamespacedName{
				Name: "nonexistent-dns", Namespace: piholeNS,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
		})
	})

	Context("Cross-namespace targeting", func() {
		const (
			dnsOtherNS     = "dns-other-ns"
			dnsOtherPihole = "pihole-dns-other"
			dnsAllNS1      = "dns-all-ns1"
			dnsAllNS2      = "dns-all-ns2"
			dnsAllPihole1  = "pihole-dns-all-1"
			dnsAllPihole2  = "pihole-dns-all-2"
		)

		createNamespace := func(ns string) {
			nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}
			_ = k8sClient.Create(ctx, nsObj)
		}

		setupPiholeInNS := func(ns, name, url string) {
			createNamespace(ns)
			pihole := &cachev1alpha1.Pihole{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec:       cachev1alpha1.PiholeSpec{},
			}
			Expect(k8sClient.Create(ctx, pihole)).To(Succeed())
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name + "-admin", Namespace: ns},
				StringData: map[string]string{"password": "test-password"},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			reconciler.BaseURLOverride[ns+"/"+name] = url
		}

		cleanupPiholeInNS := func(ns, name string) {
			pihole := &cachev1alpha1.Pihole{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, pihole); err == nil {
				k8sClient.Delete(ctx, pihole)
			}
			secret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: name + "-admin", Namespace: ns}, secret); err == nil {
				k8sClient.Delete(ctx, secret)
			}
		}

		It("no targetNamespaces uses same-namespace Piholes only", func() {
			setupPihole() // Pihole in piholeNS
			defer cleanupPihole()

			// Foreign pihole — must NOT be called
			mock2 := &mockDNSAPI{}
			srv2 := httptest.NewServer(mock2.handler())
			defer srv2.Close()
			setupPiholeInNS(dnsOtherNS, dnsOtherPihole, srv2.URL)
			defer cleanupPiholeInNS(dnsOtherNS, dnsOtherPihole)

			nn := createDNSRecord("dns-default-ns-only", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:   "default-ns.local",
				RecordType: "A",
				IPAddress:  "10.1.1.1",
				// no TargetNamespaces
			})
			defer deleteDNSRecord(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			Expect(mock.authCalls).To(BeNumerically(">=", 1))
			mock.mu.Unlock()

			mock2.mu.Lock()
			Expect(mock2.authCalls).To(Equal(0))
			mock2.mu.Unlock()
		})

		It("targetNamespaces: [specific-ns] targets only that namespace", func() {
			setupPihole() // piholeNS — should NOT be called
			defer cleanupPihole()

			mock2 := &mockDNSAPI{}
			srv2 := httptest.NewServer(mock2.handler())
			defer srv2.Close()
			setupPiholeInNS(dnsOtherNS, dnsOtherPihole, srv2.URL)
			defer cleanupPiholeInNS(dnsOtherNS, dnsOtherPihole)

			nn := createDNSRecord("dns-specific-ns", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:         "cross-ns.local",
				RecordType:       "A",
				IPAddress:        "10.2.2.2",
				TargetNamespaces: []string{dnsOtherNS},
			})
			defer deleteDNSRecord(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Foreign Pihole was called
			mock2.mu.Lock()
			Expect(mock2.authCalls).To(BeNumerically(">=", 1))
			Expect(mock2.addedHosts).To(ContainElement("10.2.2.2 cross-ns.local"))
			mock2.mu.Unlock()

			// Same-ns Pihole was NOT called (not in targetNamespaces)
			mock.mu.Lock()
			Expect(mock.authCalls).To(Equal(0))
			mock.mu.Unlock()
		})

		It("targetNamespaces: [\"*\"] targets Piholes in all namespaces", func() {
			mock1 := &mockDNSAPI{}
			srv1 := httptest.NewServer(mock1.handler())
			defer srv1.Close()
			setupPiholeInNS(dnsAllNS1, dnsAllPihole1, srv1.URL)
			defer cleanupPiholeInNS(dnsAllNS1, dnsAllPihole1)

			mock2 := &mockDNSAPI{}
			srv2 := httptest.NewServer(mock2.handler())
			defer srv2.Close()
			setupPiholeInNS(dnsAllNS2, dnsAllPihole2, srv2.URL)
			defer cleanupPiholeInNS(dnsAllNS2, dnsAllPihole2)

			nn := createDNSRecord("dns-all-ns", cachev1alpha1.PiholeDNSRecordSpec{
				Hostname:         "fleet.local",
				RecordType:       "A",
				IPAddress:        "10.3.3.3",
				TargetNamespaces: []string{"*"},
			})
			defer deleteDNSRecord(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock1.mu.Lock()
			Expect(mock1.authCalls).To(BeNumerically(">=", 1))
			mock1.mu.Unlock()

			mock2.mu.Lock()
			Expect(mock2.authCalls).To(BeNumerically(">=", 1))
			mock2.mu.Unlock()
		})
	})
})
