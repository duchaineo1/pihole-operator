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

// mockPiholeAPI tracks calls made to the mock Pi-hole API server.
type mockPiholeAPI struct {
	mu            sync.Mutex
	authCalls     int
	addCalls      []string // source addresses added
	updateCalls   []int    // list IDs updated
	deleteCalls   []int    // list IDs deleted
	gravityCalls  int
	existingLists []PiholeListResponse
	failAuth      bool
	failAdd       bool
	failGravity   bool
}

func (m *mockPiholeAPI) handler() http.HandlerFunc {
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

		case r.URL.Path == "/api/lists" && r.Method == "GET":
			wrapper := PiholeListsWrapper{Lists: m.existingLists}
			json.NewEncoder(w).Encode(wrapper)

		case r.URL.Path == "/api/lists" && r.Method == "POST":
			if m.failAdd {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("add failed"))
				return
			}
			var req PiholeListRequest
			json.NewDecoder(r.Body).Decode(&req)
			m.addCalls = append(m.addCalls, req.Address)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(PiholeListResponse{
				ID: len(m.existingLists) + len(m.addCalls), Address: req.Address, Enabled: req.Enabled,
			})

		case strings.HasPrefix(r.URL.Path, "/api/lists/") && r.Method == "PUT":
			var id int
			fmt.Sscanf(r.URL.Path, "/api/lists/%d", &id)
			m.updateCalls = append(m.updateCalls, id)
			w.WriteHeader(http.StatusOK)

		case strings.HasPrefix(r.URL.Path, "/api/lists/") && r.Method == "DELETE":
			var id int
			fmt.Sscanf(r.URL.Path, "/api/lists/%d", &id)
			m.deleteCalls = append(m.deleteCalls, id)
			w.WriteHeader(http.StatusNoContent)

		case r.URL.Path == "/api/action/gravity" && r.Method == "POST":
			m.gravityCalls++
			if m.failGravity {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

var _ = Describe("Blocklist Controller", func() {
	var (
		ctx        context.Context
		reconciler *BlocklistReconciler
		mock       *mockPiholeAPI
		srv        *httptest.Server
	)

	const (
		piholeNS   = "default"
		piholeName = "test-pihole"
	)

	// Create the Pihole CR + its admin secret (required by BlocklistReconciler)
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

	createBlocklist := func(name string, spec cachev1alpha1.BlocklistSpec) types.NamespacedName {
		nn := types.NamespacedName{Name: name, Namespace: piholeNS}
		bl := &cachev1alpha1.Blocklist{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: piholeNS},
			Spec:       spec,
		}
		Expect(k8sClient.Create(ctx, bl)).To(Succeed())
		return nn
	}

	deleteBlocklist := func(nn types.NamespacedName) {
		bl := &cachev1alpha1.Blocklist{}
		if err := k8sClient.Get(ctx, nn, bl); err == nil {
			// Remove finalizer so we can delete
			controllerutil.RemoveFinalizer(bl, blocklistFinalizer)
			k8sClient.Update(ctx, bl)
			k8sClient.Delete(ctx, bl)
		}
	}

	doReconcile := func(nn types.NamespacedName) (reconcile.Result, error) {
		return reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
	}

	BeforeEach(func() {
		ctx = context.Background()
		mock = &mockPiholeAPI{}
		srv = httptest.NewServer(mock.handler())

		cacheKey := fmt.Sprintf("%s/%s", piholeNS, piholeName)
		reconciler = &BlocklistReconciler{
			Client:     k8sClient,
			Scheme:     k8sClient.Scheme(),
			httpClient: srv.Client(),
			sidCache:   make(map[string]*cachedSID),
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
			nn := createBlocklist("bl-no-pihole", cachev1alpha1.BlocklistSpec{
				Sources:      []string{"https://example.com/list.txt"},
				Enabled:      true,
				SyncInterval: 60,
			})
			defer deleteBlocklist(nn)

			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(1 * time.Minute))

			bl := &cachev1alpha1.Blocklist{}
			Expect(k8sClient.Get(ctx, nn, bl)).To(Succeed())
			Expect(bl.Status.Conditions).NotTo(BeEmpty())
			Expect(bl.Status.Conditions[0].Reason).To(Equal("NoPihole"))
		})
	})

	Context("With a Pihole present", func() {
		BeforeEach(func() { setupPihole() })
		AfterEach(func() { cleanupPihole() })

		It("should add the finalizer on first reconcile", func() {
			nn := createBlocklist("bl-finalizer", cachev1alpha1.BlocklistSpec{
				Sources:      []string{"https://example.com/list.txt"},
				Enabled:      true,
				SyncInterval: 60,
			})
			defer deleteBlocklist(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			bl := &cachev1alpha1.Blocklist{}
			Expect(k8sClient.Get(ctx, nn, bl)).To(Succeed())
			Expect(controllerutil.ContainsFinalizer(bl, blocklistFinalizer)).To(BeTrue())
		})

		It("should add new blocklist sources via API", func() {
			nn := createBlocklist("bl-add", cachev1alpha1.BlocklistSpec{
				Sources:      []string{"https://a.com/list.txt", "https://b.com/list.txt"},
				Enabled:      true,
				SyncInterval: 120,
			})
			defer deleteBlocklist(nn)

			// Single reconcile adds finalizer and applies blocklists
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			defer mock.mu.Unlock()
			Expect(mock.addCalls).To(ConsistOf("https://a.com/list.txt", "https://b.com/list.txt"))
			Expect(mock.gravityCalls).To(Equal(1))
		})

		It("should skip existing sources and not reload gravity", func() {
			mock.existingLists = []PiholeListResponse{
				{ID: 1, Address: "https://existing.com/list.txt", Enabled: true},
			}

			nn := createBlocklist("bl-skip", cachev1alpha1.BlocklistSpec{
				Sources:      []string{"https://existing.com/list.txt"},
				Enabled:      true,
				SyncInterval: 60,
			})
			defer deleteBlocklist(nn)

			// Single reconcile: adds finalizer + applies (skip existing)
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			defer mock.mu.Unlock()
			Expect(mock.addCalls).To(BeEmpty())
			Expect(mock.gravityCalls).To(Equal(0))
		})

		It("should update enabled status when different", func() {
			// Mock has source disabled; CR defaults Enabled to true
			mock.existingLists = []PiholeListResponse{
				{ID: 10, Address: "https://update.com/list.txt", Enabled: false},
			}

			nn := createBlocklist("bl-update", cachev1alpha1.BlocklistSpec{
				Sources:      []string{"https://update.com/list.txt"},
				Enabled:      true, // different from existing (false)
				SyncInterval: 60,
			})
			defer deleteBlocklist(nn)

			// Single reconcile: adds finalizer + detects enabled mismatch
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			defer mock.mu.Unlock()
			Expect(mock.updateCalls).To(ContainElement(10))
			Expect(mock.gravityCalls).To(Equal(1))
		})

		It("should requeue based on syncInterval", func() {
			nn := createBlocklist("bl-requeue", cachev1alpha1.BlocklistSpec{
				Sources:      []string{"https://example.com/list.txt"},
				Enabled:      true,
				SyncInterval: 120,
			})
			defer deleteBlocklist(nn)

			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(120 * time.Minute))
		})

		It("should set Available=True status after successful apply", func() {
			nn := createBlocklist("bl-status", cachev1alpha1.BlocklistSpec{
				Sources:      []string{"https://example.com/list.txt"},
				Enabled:      true,
				SyncInterval: 60,
			})
			defer deleteBlocklist(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			bl := &cachev1alpha1.Blocklist{}
			Expect(k8sClient.Get(ctx, nn, bl)).To(Succeed())

			var found bool
			for _, c := range bl.Status.Conditions {
				if c.Type == typeAvailableBlocklist {
					Expect(c.Status).To(Equal(metav1.ConditionTrue))
					Expect(c.Reason).To(Equal("Applied"))
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "Available condition not found")
			Expect(bl.Status.LastSyncTime).NotTo(BeNil())
		})

		It("should set ApplyFailed status when all Piholes fail", func() {
			mock.failAuth = true

			nn := createBlocklist("bl-fail", cachev1alpha1.BlocklistSpec{
				Sources:      []string{"https://example.com/list.txt"},
				Enabled:      true,
				SyncInterval: 60,
			})
			defer deleteBlocklist(nn)

			// Single reconcile: adds finalizer, then fails on apply (auth fails)
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred()) // reconcile itself doesn't error

			bl := &cachev1alpha1.Blocklist{}
			Expect(k8sClient.Get(ctx, nn, bl)).To(Succeed())

			var found bool
			for _, c := range bl.Status.Conditions {
				if c.Type == typeAvailableBlocklist {
					Expect(c.Status).To(Equal(metav1.ConditionFalse))
					Expect(c.Reason).To(Equal("ApplyFailed"))
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "Available condition not found")
		})
	})

	Context("Deletion", func() {
		BeforeEach(func() { setupPihole() })
		AfterEach(func() { cleanupPihole() })

		It("should delete sources and remove finalizer on deletion", func() {
			mock.existingLists = []PiholeListResponse{
				{ID: 5, Address: "https://todelete.com/list.txt", Enabled: true},
			}

			nn := createBlocklist("bl-delete", cachev1alpha1.BlocklistSpec{
				Sources:      []string{"https://todelete.com/list.txt"},
				Enabled:      true,
				SyncInterval: 60,
			})

			// Reconcile to add finalizer
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Mark for deletion
			bl := &cachev1alpha1.Blocklist{}
			Expect(k8sClient.Get(ctx, nn, bl)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bl)).To(Succeed())

			// Re-fetch after delete marks DeletionTimestamp
			Expect(k8sClient.Get(ctx, nn, bl)).To(Succeed())
			Expect(bl.DeletionTimestamp).NotTo(BeNil())

			// Reconcile handles deletion
			_, err = doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			Expect(mock.deleteCalls).To(ContainElement(5))
			Expect(mock.gravityCalls).To(BeNumerically(">=", 1))
			mock.mu.Unlock()

			// Finalizer should be removed, object should be gone
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nn, &cachev1alpha1.Blocklist{})
				return err != nil
			}).Should(BeTrue())
		})
	})

	Context("With a Pihole using adminPasswordSecretRef", func() {
		const customSecretName = "custom-admin-secret"

		BeforeEach(func() {
			// Create pihole with status pointing to custom secret
			pihole := &cachev1alpha1.Pihole{
				ObjectMeta: metav1.ObjectMeta{Name: piholeName, Namespace: piholeNS},
				Spec: cachev1alpha1.PiholeSpec{
					AdminPasswordSecretRef: &cachev1alpha1.SecretKeyRef{
						Name: customSecretName,
					},
				},
			}
			Expect(k8sClient.Create(ctx, pihole)).To(Succeed())

			// Set status to point at the custom secret
			pihole.Status.AdminPasswordSecret = customSecretName
			Expect(k8sClient.Status().Update(ctx, pihole)).To(Succeed())

			// Create the custom secret
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      customSecretName,
					Namespace: piholeNS,
				},
				StringData: map[string]string{"password": "test-password"},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		})

		AfterEach(func() {
			pihole := &cachev1alpha1.Pihole{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: piholeName, Namespace: piholeNS}, pihole); err == nil {
				k8sClient.Delete(ctx, pihole)
			}
			secret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: customSecretName, Namespace: piholeNS}, secret); err == nil {
				k8sClient.Delete(ctx, secret)
			}
		})

		It("should read the secret name from pihole status", func() {
			nn := createBlocklist("bl-custom-secret", cachev1alpha1.BlocklistSpec{
				Sources:      []string{"https://example.com/list.txt"},
				Enabled:      true,
				SyncInterval: 60,
			})
			defer deleteBlocklist(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Verify authentication happened (which means the custom secret was read)
			mock.mu.Lock()
			defer mock.mu.Unlock()
			Expect(mock.authCalls).To(BeNumerically(">=", 1))
		})
	})

	Context("Not-found Blocklist", func() {
		It("should return cleanly", func() {
			result, err := doReconcile(types.NamespacedName{
				Name: "nonexistent-bl", Namespace: piholeNS,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
		})
	})

	Context("Cross-namespace targeting", func() {
		const (
			otherNS      = "bl-other-ns"
			otherPihole  = "pihole-other"
			allNS1       = "bl-all-ns1"
			allNS2       = "bl-all-ns2"
			allPihole1   = "pihole-all-1"
			allPihole2   = "pihole-all-2"
		)

		// createNamespace ensures a Namespace object exists in envtest.
		createNamespace := func(ns string) {
			nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}
			_ = k8sClient.Create(ctx, nsObj) // ignore AlreadyExists
		}

		// setupPiholeInNS creates a Pihole + secret in any namespace and registers
		// the URL override so the reconciler can reach the mock server.
		setupPiholeInNS := func(ns, name string, url string) {
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
			setupPihole() // Pihole in piholeNS ("default")
			defer cleanupPihole()

			// Create a Pihole in a foreign namespace — it must NOT be called
			mock2 := &mockPiholeAPI{}
			srv2 := httptest.NewServer(mock2.handler())
			defer srv2.Close()
			setupPiholeInNS(otherNS, otherPihole, srv2.URL)
			defer cleanupPiholeInNS(otherNS, otherPihole)

			nn := createBlocklist("bl-default-ns", cachev1alpha1.BlocklistSpec{
				Sources:      []string{"https://example.com/list.txt"},
				Enabled:      true,
				SyncInterval: 60,
				// no TargetNamespaces — default behaviour
			})
			defer deleteBlocklist(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Primary mock (same ns) was called; foreign mock was NOT
			mock.mu.Lock()
			Expect(mock.authCalls).To(BeNumerically(">=", 1))
			mock.mu.Unlock()

			mock2.mu.Lock()
			Expect(mock2.authCalls).To(Equal(0))
			mock2.mu.Unlock()
		})

		It("targetNamespaces: [specific-ns] targets only that namespace", func() {
			// Pihole in the default ns — should NOT be used
			setupPihole()
			defer cleanupPihole()

			// Pihole in the target namespace — SHOULD be used
			mock2 := &mockPiholeAPI{}
			srv2 := httptest.NewServer(mock2.handler())
			defer srv2.Close()
			setupPiholeInNS(otherNS, otherPihole, srv2.URL)
			defer cleanupPiholeInNS(otherNS, otherPihole)

			nn := createBlocklist("bl-specific-ns", cachev1alpha1.BlocklistSpec{
				Sources:          []string{"https://example.com/list.txt"},
				Enabled:          true,
				SyncInterval:     60,
				TargetNamespaces: []string{otherNS},
			})
			defer deleteBlocklist(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Foreign (target) mock was called
			mock2.mu.Lock()
			Expect(mock2.authCalls).To(BeNumerically(">=", 1))
			Expect(mock2.addCalls).To(ContainElement("https://example.com/list.txt"))
			mock2.mu.Unlock()

			// Default-ns mock was NOT called (blocklist targets otherNS, not default)
			mock.mu.Lock()
			Expect(mock.authCalls).To(Equal(0))
			mock.mu.Unlock()
		})

		It("targetNamespaces: [\"*\"] targets Piholes in all namespaces", func() {
			// Set up two Piholes in two different namespaces
			mock1 := &mockPiholeAPI{}
			srv1 := httptest.NewServer(mock1.handler())
			defer srv1.Close()
			setupPiholeInNS(allNS1, allPihole1, srv1.URL)
			defer cleanupPiholeInNS(allNS1, allPihole1)

			mock2 := &mockPiholeAPI{}
			srv2 := httptest.NewServer(mock2.handler())
			defer srv2.Close()
			setupPiholeInNS(allNS2, allPihole2, srv2.URL)
			defer cleanupPiholeInNS(allNS2, allPihole2)

			nn := createBlocklist("bl-all-ns", cachev1alpha1.BlocklistSpec{
				Sources:          []string{"https://example.com/list.txt"},
				Enabled:          true,
				SyncInterval:     60,
				TargetNamespaces: []string{"*"},
			})
			defer deleteBlocklist(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Both Piholes were reached
			mock1.mu.Lock()
			Expect(mock1.authCalls).To(BeNumerically(">=", 1))
			mock1.mu.Unlock()

			mock2.mu.Lock()
			Expect(mock2.authCalls).To(BeNumerically(">=", 1))
			mock2.mu.Unlock()
		})
	})
})
