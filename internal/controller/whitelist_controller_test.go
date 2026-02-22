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

// mockWhitelistAPI tracks calls made to the mock Pi-hole whitelist API server.
type mockWhitelistAPI struct {
	mu              sync.Mutex
	authCalls       int
	existingDomains []WhitelistDomainResponse
	addedDomains    []string
	deletedDomains  []string
	failAuth        bool
	failAdd         bool
}

func (m *mockWhitelistAPI) handler() http.HandlerFunc {
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

		case r.URL.Path == "/api/domains/allow/exact" && r.Method == "GET":
			wrapper := WhitelistDomainsWrapper{Domains: m.existingDomains}
			json.NewEncoder(w).Encode(wrapper)

		case r.URL.Path == "/api/domains/allow/exact" && r.Method == "POST":
			if m.failAdd {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("add failed"))
				return
			}
			var req WhitelistDomainRequest
			json.NewDecoder(r.Body).Decode(&req)
			m.addedDomains = append(m.addedDomains, req.Domain)

			resp := WhitelistDomainsWrapper{
				Processed: &WhitelistProcessed{
					Success: []WhitelistProcessedItem{{Item: req.Domain}},
				},
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)

		case strings.HasPrefix(r.URL.Path, "/api/domains/allow/exact/") && r.Method == "DELETE":
			domain, _ := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/api/domains/allow/exact/"))
			m.deletedDomains = append(m.deletedDomains, domain)
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

var _ = Describe("Whitelist Controller", func() {
	var (
		ctx        context.Context
		reconciler *WhitelistReconciler
		mock       *mockWhitelistAPI
		srv        *httptest.Server
	)

	const (
		piholeNS   = "default"
		piholeName = "test-pihole-whitelist"
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

	createWhitelist := func(name string, spec cachev1alpha1.WhitelistSpec) types.NamespacedName {
		nn := types.NamespacedName{Name: name, Namespace: piholeNS}
		wl := &cachev1alpha1.Whitelist{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: piholeNS},
			Spec:       spec,
		}
		Expect(k8sClient.Create(ctx, wl)).To(Succeed())
		return nn
	}

	deleteWhitelist := func(nn types.NamespacedName) {
		wl := &cachev1alpha1.Whitelist{}
		if err := k8sClient.Get(ctx, nn, wl); err == nil {
			controllerutil.RemoveFinalizer(wl, whitelistFinalizer)
			k8sClient.Update(ctx, wl)
			k8sClient.Delete(ctx, wl)
		}
	}

	doReconcile := func(nn types.NamespacedName) (reconcile.Result, error) {
		return reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
	}

	BeforeEach(func() {
		ctx = context.Background()
		mock = &mockWhitelistAPI{}
		srv = httptest.NewServer(mock.handler())

		cacheKey := fmt.Sprintf("%s/%s", piholeNS, piholeName)
		reconciler = &WhitelistReconciler{
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
			nn := createWhitelist("wl-no-pihole", cachev1alpha1.WhitelistSpec{
				Domains: []string{"example.com"},
				Enabled: true,
			})
			defer deleteWhitelist(nn)

			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(1 * time.Minute))

			wl := &cachev1alpha1.Whitelist{}
			Expect(k8sClient.Get(ctx, nn, wl)).To(Succeed())
			Expect(wl.Status.Conditions).NotTo(BeEmpty())
			Expect(wl.Status.Conditions[0].Reason).To(Equal("NoPihole"))
		})
	})

	Context("With a Pihole present", func() {
		BeforeEach(func() { setupPihole() })
		AfterEach(func() { cleanupPihole() })

		It("should add the finalizer on first reconcile", func() {
			nn := createWhitelist("wl-finalizer", cachev1alpha1.WhitelistSpec{
				Domains: []string{"example.com"},
				Enabled: true,
			})
			defer deleteWhitelist(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			wl := &cachev1alpha1.Whitelist{}
			Expect(k8sClient.Get(ctx, nn, wl)).To(Succeed())
			Expect(controllerutil.ContainsFinalizer(wl, whitelistFinalizer)).To(BeTrue())
		})

		It("should add new whitelist domains via API", func() {
			nn := createWhitelist("wl-add", cachev1alpha1.WhitelistSpec{
				Domains:     []string{"a.example", "b.example"},
				Enabled:     true,
				Description: "managed in tests",
			})
			defer deleteWhitelist(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			defer mock.mu.Unlock()
			Expect(mock.addedDomains).To(ConsistOf("a.example", "b.example"))
		})

		It("should skip domains that already exist", func() {
			mock.existingDomains = []WhitelistDomainResponse{
				{ID: 1, Domain: "existing.example"},
			}

			nn := createWhitelist("wl-skip-existing", cachev1alpha1.WhitelistSpec{
				Domains: []string{"existing.example", "new.example"},
				Enabled: true,
			})
			defer deleteWhitelist(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			defer mock.mu.Unlock()
			Expect(mock.addedDomains).To(ConsistOf("new.example"))
		})

		It("should set Available=True status after successful apply", func() {
			nn := createWhitelist("wl-status-ok", cachev1alpha1.WhitelistSpec{
				Domains: []string{"ok.example", "ok2.example"},
				Enabled: true,
			})
			defer deleteWhitelist(nn)

			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))

			wl := &cachev1alpha1.Whitelist{}
			Expect(k8sClient.Get(ctx, nn, wl)).To(Succeed())
			Expect(wl.Status.Conditions).NotTo(BeEmpty())
			Expect(wl.Status.Conditions[0].Type).To(Equal(typeAvailableWhitelist))
			Expect(wl.Status.Conditions[0].Status).To(Equal(metav1.ConditionTrue))
			Expect(wl.Status.Conditions[0].Reason).To(Equal("Applied"))
			Expect(wl.Status.LastSyncTime).NotTo(BeNil())
			Expect(wl.Status.DomainsCount).To(Equal(int32(2)))
		})

		It("should set ApplyFailed status when auth fails", func() {
			mock.failAuth = true

			nn := createWhitelist("wl-auth-fails", cachev1alpha1.WhitelistSpec{
				Domains: []string{"fail.example"},
				Enabled: true,
			})
			defer deleteWhitelist(nn)

			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))

			wl := &cachev1alpha1.Whitelist{}
			Expect(k8sClient.Get(ctx, nn, wl)).To(Succeed())
			Expect(wl.Status.Conditions).NotTo(BeEmpty())
			Expect(wl.Status.Conditions[0].Type).To(Equal(typeAvailableWhitelist))
			Expect(wl.Status.Conditions[0].Status).To(Equal(metav1.ConditionFalse))
			Expect(wl.Status.Conditions[0].Reason).To(Equal("ApplyFailed"))
		})
	})

	Context("Deletion", func() {
		BeforeEach(func() { setupPihole() })
		AfterEach(func() { cleanupPihole() })

		It("should delete domains and remove finalizer on deletion", func() {
			nn := createWhitelist("wl-delete", cachev1alpha1.WhitelistSpec{
				Domains: []string{"gone.example", "gone2.example"},
				Enabled: true,
			})

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			wl := &cachev1alpha1.Whitelist{}
			Expect(k8sClient.Get(ctx, nn, wl)).To(Succeed())
			Expect(controllerutil.ContainsFinalizer(wl, whitelistFinalizer)).To(BeTrue())

			Expect(k8sClient.Delete(ctx, wl)).To(Succeed())

			_, err = doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			mock.mu.Lock()
			defer mock.mu.Unlock()
			Expect(mock.deletedDomains).To(ContainElements("gone.example", "gone2.example"))
		})
	})

	Context("Not-found Whitelist", func() {
		It("should return cleanly", func() {
			nn := types.NamespacedName{Name: "does-not-exist", Namespace: piholeNS}
			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
		})
	})
})
