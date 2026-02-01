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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cachev1alpha1 "github.com/duchaineo1/pihole-operator/api/v1alpha1"
)

var _ = Describe("Pihole Controller", func() {
	var (
		ctx        context.Context
		reconciler *PiholeReconciler
	)

	BeforeEach(func() {
		ctx = context.Background()
		reconciler = &PiholeReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
	})

	// Helper to create a Pihole CR and return its NamespacedName
	createPihole := func(name string, spec cachev1alpha1.PiholeSpec) types.NamespacedName {
		nn := types.NamespacedName{Name: name, Namespace: "default"}
		pihole := &cachev1alpha1.Pihole{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec:       spec,
		}
		Expect(k8sClient.Create(ctx, pihole)).To(Succeed())
		return nn
	}

	// Helper to clean up a Pihole CR
	deletePihole := func(nn types.NamespacedName) {
		pihole := &cachev1alpha1.Pihole{}
		if err := k8sClient.Get(ctx, nn, pihole); err == nil {
			Expect(k8sClient.Delete(ctx, pihole)).To(Succeed())
		}
	}

	// Helper to reconcile
	doReconcile := func(nn types.NamespacedName) (reconcile.Result, error) {
		return reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
	}

	Context("Default reconciliation", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-default", cachev1alpha1.PiholeSpec{})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should create a Secret with a generated password", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-default-admin", Namespace: "default",
			}, secret)).To(Succeed())
			Expect(secret.Data).To(HaveKey("password"))
			Expect(len(secret.Data["password"])).To(Equal(16))
		})

		It("should create a PVC with default 1Gi storage", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			pvc := &corev1.PersistentVolumeClaim{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-default-data", Namespace: "default",
			}, pvc)).To(Succeed())

			qty := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
			Expect(qty.Cmp(resource.MustParse("1Gi"))).To(Equal(0))
			Expect(pvc.Spec.AccessModes).To(ContainElement(corev1.ReadWriteOnce))
		})

		It("should create a DNS service with NodePort type", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			svc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-default-dns", Namespace: "default",
			}, svc)).To(Succeed())

			Expect(svc.Spec.Type).To(Equal(corev1.ServiceTypeNodePort))
			Expect(svc.Spec.Ports).To(HaveLen(2))
		})

		It("should create a Web service with ClusterIP type", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			svc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-default-web", Namespace: "default",
			}, svc)).To(Succeed())

			Expect(svc.Spec.Type).To(Equal(corev1.ServiceTypeClusterIP))
			Expect(svc.Spec.Ports).To(HaveLen(2))
		})

		It("should create a Deployment with correct defaults", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, nn, dep)).To(Succeed())

			Expect(*dep.Spec.Replicas).To(Equal(int32(1)))
			Expect(dep.Spec.Template.Spec.Containers).To(HaveLen(1))

			container := dep.Spec.Template.Spec.Containers[0]
			Expect(container.Image).To(Equal("docker.io/pihole/pihole:2025.11.0"))
			Expect(container.Name).To(Equal("pihole"))

			// Check env vars
			envNames := make([]string, len(container.Env))
			for i, e := range container.Env {
				envNames[i] = e.Name
			}
			Expect(envNames).To(ContainElements("TZ", "FTLCONF_webserver_api_password", "DNSMASQ_USER"))

			// Check probes
			Expect(container.LivenessProbe).NotTo(BeNil())
			Expect(container.ReadinessProbe).NotTo(BeNil())

			// Check volume mounts
			Expect(container.VolumeMounts).To(HaveLen(1))
			Expect(container.VolumeMounts[0].MountPath).To(Equal("/etc/pihole"))
		})

		It("should set owner references on all created resources", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())

			checkOwnerRef := func(obj metav1.ObjectMeta) {
				Expect(obj.OwnerReferences).To(HaveLen(1))
				Expect(obj.OwnerReferences[0].Name).To(Equal(pihole.Name))
				Expect(*obj.OwnerReferences[0].Controller).To(BeTrue())
			}

			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nn.Name + "-admin", Namespace: "default"}, secret)).To(Succeed())
			checkOwnerRef(secret.ObjectMeta)

			pvc := &corev1.PersistentVolumeClaim{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nn.Name + "-data", Namespace: "default"}, pvc)).To(Succeed())
			checkOwnerRef(pvc.ObjectMeta)

			dnsSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nn.Name + "-dns", Namespace: "default"}, dnsSvc)).To(Succeed())
			checkOwnerRef(dnsSvc.ObjectMeta)

			webSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nn.Name + "-web", Namespace: "default"}, webSvc)).To(Succeed())
			checkOwnerRef(webSvc.ObjectMeta)

			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, nn, dep)).To(Succeed())
			checkOwnerRef(dep.ObjectMeta)
		})

	})

	// Use a dedicated Context with a unique name so envtest leftover
	// resources from other tests don't interfere with the deployment
	// creation branch (which sets AdminPasswordSecret/ServiceName).
	Context("Status fields", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-status-fields", cachev1alpha1.PiholeSpec{})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should set status conditions and fields after reconcile", func() {
			// First reconcile creates all resources including deployment
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile finds deployment, sets Available=True
			_, err = doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())

			Expect(pihole.Status.Conditions).NotTo(BeEmpty())
			Expect(pihole.Status.AdminPasswordSecret).To(Equal("test-status-fields-admin"))
			Expect(pihole.Status.ServiceName).To(Equal("test-status-fields"))
		})
	})

	Context("Custom password", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-custom-pw", cachev1alpha1.PiholeSpec{
				AdminPassword: "my-secret-password",
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should use the specified password in the Secret", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-custom-pw-admin", Namespace: "default",
			}, secret)).To(Succeed())
			Expect(string(secret.Data["password"])).To(Equal("my-secret-password"))
		})
	})

	Context("Secret idempotency", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-idempotent", cachev1alpha1.PiholeSpec{})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should not overwrite the secret on second reconcile", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-idempotent-admin", Namespace: "default",
			}, secret)).To(Succeed())
			originalPassword := string(secret.Data["password"])

			// Reconcile again
			_, err = doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-idempotent-admin", Namespace: "default",
			}, secret)).To(Succeed())
			Expect(string(secret.Data["password"])).To(Equal(originalPassword))
		})
	})

	Context("Custom storage", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-storage", cachev1alpha1.PiholeSpec{
				StorageSize:  "5Gi",
				StorageClass: "fast-ssd",
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should create PVC with custom size and storage class", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			pvc := &corev1.PersistentVolumeClaim{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-storage-data", Namespace: "default",
			}, pvc)).To(Succeed())

			qty := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
			Expect(qty.Cmp(resource.MustParse("5Gi"))).To(Equal(0))
			Expect(pvc.Spec.StorageClassName).NotTo(BeNil())
			Expect(*pvc.Spec.StorageClassName).To(Equal("fast-ssd"))
		})
	})

	Context("LoadBalancer services with static IPs", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-lb", cachev1alpha1.PiholeSpec{
				DnsServiceType:    "LoadBalancer",
				DnsLoadBalancerIP: "10.0.0.53",
				WebServiceType:    "LoadBalancer",
				WebLoadBalancerIP: "10.0.0.80",
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should create DNS LoadBalancer service with static IP", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			svc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-lb-dns", Namespace: "default",
			}, svc)).To(Succeed())

			Expect(svc.Spec.Type).To(Equal(corev1.ServiceTypeLoadBalancer))
			Expect(svc.Spec.LoadBalancerIP).To(Equal("10.0.0.53"))
		})

		It("should create Web LoadBalancer service with static IP", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			svc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-lb-web", Namespace: "default",
			}, svc)).To(Succeed())

			Expect(svc.Spec.Type).To(Equal(corev1.ServiceTypeLoadBalancer))
			Expect(svc.Spec.LoadBalancerIP).To(Equal("10.0.0.80"))
		})
	})

	Context("Custom image", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-image", cachev1alpha1.PiholeSpec{
				Image: "docker.io/pihole/pihole:2024.01.0",
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should use custom image in the Deployment", func() {
			// First reconcile creates deployment with default image
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile detects image mismatch and updates
			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, nn, dep)).To(Succeed())
			Expect(dep.Spec.Template.Spec.Containers[0].Image).To(Equal("docker.io/pihole/pihole:2024.01.0"))
		})
	})

	Context("Scaling replicas", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-scale", cachev1alpha1.PiholeSpec{
				Size: ptr.To(int32(1)),
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should update deployment replicas when spec.size changes", func() {
			// Initial reconcile
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, nn, dep)).To(Succeed())
			Expect(*dep.Spec.Replicas).To(Equal(int32(1)))

			// Update size
			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())
			pihole.Spec.Size = ptr.To(int32(3))
			Expect(k8sClient.Update(ctx, pihole)).To(Succeed())

			// Reconcile again
			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue()) // requeue after update

			Expect(k8sClient.Get(ctx, nn, dep)).To(Succeed())
			Expect(*dep.Spec.Replicas).To(Equal(int32(3)))
		})
	})

	Context("Not-found CR", func() {
		It("should return cleanly when the resource does not exist", func() {
			result, err := doReconcile(types.NamespacedName{
				Name: "nonexistent", Namespace: "default",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
		})
	})

	Context("Deployment security context", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-security", cachev1alpha1.PiholeSpec{})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should set correct security context and capabilities", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, nn, dep)).To(Succeed())

			podSec := dep.Spec.Template.Spec.SecurityContext
			Expect(podSec).NotTo(BeNil())
			Expect(*podSec.RunAsUser).To(Equal(int64(0)))

			container := dep.Spec.Template.Spec.Containers[0]
			Expect(container.SecurityContext).NotTo(BeNil())
			Expect(container.SecurityContext.Capabilities).NotTo(BeNil())
			Expect(container.SecurityContext.Capabilities.Add).To(ContainElement(corev1.Capability("NET_BIND_SERVICE")))
			Expect(container.SecurityContext.Capabilities.Drop).To(ContainElement(corev1.Capability("ALL")))
		})
	})

	Context("Custom timezone", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-tz", cachev1alpha1.PiholeSpec{
				Timezone: "America/New_York",
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should set the TZ env var in the Deployment", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, nn, dep)).To(Succeed())

			var tzValue string
			for _, e := range dep.Spec.Template.Spec.Containers[0].Env {
				if e.Name == "TZ" {
					tzValue = e.Value
					break
				}
			}
			Expect(tzValue).To(Equal("America/New_York"))
		})
	})

	// Verify labels are set correctly
	Context("Labels", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-labels", cachev1alpha1.PiholeSpec{})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should set standard labels on all resources", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			expectedLabels := map[string]string{
				"app.kubernetes.io/name":       "pihole",
				"app.kubernetes.io/instance":   "test-labels",
				"app.kubernetes.io/managed-by": "pihole-operator",
			}

			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, nn, dep)).To(Succeed())
			for k, v := range expectedLabels {
				Expect(dep.Labels).To(HaveKeyWithValue(k, v))
			}

			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nn.Name + "-admin", Namespace: "default"}, secret)).To(Succeed())
			for k, v := range expectedLabels {
				Expect(secret.Labels).To(HaveKeyWithValue(k, v))
			}
		})
	})

	Context("Existing secret ref", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			// Pre-create the existing secret
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-existing-secret",
					Namespace: "default",
				},
				StringData: map[string]string{"password": "existing-pw"},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			nn = createPihole("test-secret-ref", cachev1alpha1.PiholeSpec{
				AdminPasswordSecretRef: &cachev1alpha1.SecretKeyRef{
					Name: "my-existing-secret",
				},
			})
		})
		AfterEach(func() {
			deletePihole(nn)
			secret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: "my-existing-secret", Namespace: "default"}, secret); err == nil {
				k8sClient.Delete(ctx, secret)
			}
		})

		It("should not create a new admin secret", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// The operator-managed secret should NOT exist
			secret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-secret-ref-admin", Namespace: "default",
			}, secret)
			Expect(errors.IsNotFound(err)).To(BeTrue())
		})

		It("should reference the existing secret in the deployment", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, nn, dep)).To(Succeed())

			var envVar corev1.EnvVar
			for _, e := range dep.Spec.Template.Spec.Containers[0].Env {
				if e.Name == "FTLCONF_webserver_api_password" {
					envVar = e
					break
				}
			}
			Expect(envVar.ValueFrom).NotTo(BeNil())
			Expect(envVar.ValueFrom.SecretKeyRef.Name).To(Equal("my-existing-secret"))
			Expect(envVar.ValueFrom.SecretKeyRef.Key).To(Equal("password"))
		})

		It("should set status.adminPasswordSecret to the referenced secret name", func() {
			// First reconcile creates deployment and sets status
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile ensures status is fully settled
			_, err = doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())
			Expect(pihole.Status.AdminPasswordSecret).To(Equal("my-existing-secret"))
		})
	})

	Context("Existing secret ref with custom key", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-custom-key-secret",
					Namespace: "default",
				},
				StringData: map[string]string{"admin-pass": "custom-key-pw"},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			nn = createPihole("test-custom-key", cachev1alpha1.PiholeSpec{
				AdminPasswordSecretRef: &cachev1alpha1.SecretKeyRef{
					Name: "my-custom-key-secret",
					Key:  "admin-pass",
				},
			})
		})
		AfterEach(func() {
			deletePihole(nn)
			secret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: "my-custom-key-secret", Namespace: "default"}, secret); err == nil {
				k8sClient.Delete(ctx, secret)
			}
		})

		It("should use the custom key in the deployment env var", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, nn, dep)).To(Succeed())

			var envVar corev1.EnvVar
			for _, e := range dep.Spec.Template.Spec.Containers[0].Env {
				if e.Name == "FTLCONF_webserver_api_password" {
					envVar = e
					break
				}
			}
			Expect(envVar.ValueFrom).NotTo(BeNil())
			Expect(envVar.ValueFrom.SecretKeyRef.Name).To(Equal("my-custom-key-secret"))
			Expect(envVar.ValueFrom.SecretKeyRef.Key).To(Equal("admin-pass"))
		})
	})

	Context("Missing secret ref", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-missing-ref", cachev1alpha1.PiholeSpec{
				AdminPasswordSecretRef: &cachev1alpha1.SecretKeyRef{
					Name: "nonexistent-secret",
				},
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should return an error when the referenced secret does not exist", func() {
			_, err := doReconcile(nn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("nonexistent-secret"))
		})
	})

	// Clean up: verify that the reconciler handles deletion during reconciliation
	Context("Deletion during reconcile", func() {
		It("should handle a resource deleted between Get calls", func() {
			nn := createPihole("test-delete-race", cachev1alpha1.PiholeSpec{})

			// Delete before reconcile
			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())
			Expect(k8sClient.Delete(ctx, pihole)).To(Succeed())

			// Wait for deletion
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, nn, &cachev1alpha1.Pihole{}))
			}).Should(BeTrue())

			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
		})
	})
})
