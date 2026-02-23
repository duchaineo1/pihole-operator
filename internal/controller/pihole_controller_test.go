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
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
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

		It("should create a headless Service with ClusterIP None", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			svc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-default-headless", Namespace: "default",
			}, svc)).To(Succeed())

			Expect(svc.Spec.ClusterIP).To(Equal(corev1.ClusterIPNone))
			Expect(svc.Spec.Ports).To(HaveLen(4))
		})

		It("should create a StatefulSet with correct defaults", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			Expect(*sts.Spec.Replicas).To(Equal(int32(1)))
			Expect(sts.Spec.ServiceName).To(Equal("test-default-headless"))
			Expect(sts.Spec.Template.Spec.Containers).To(HaveLen(1))

			container := sts.Spec.Template.Spec.Containers[0]
			Expect(container.Image).To(Equal("docker.io/pihole/pihole:2025.11.0"))
			Expect(container.Name).To(Equal("pihole"))

			// Check env vars
			envNames := make([]string, len(container.Env))
			for i, e := range container.Env {
				envNames[i] = e.Name
			}
			Expect(envNames).To(ContainElements("TZ", "FTLCONF_webserver_api_password", "DNSMASQ_USER", "FTLCONF_dns_listeningMode", "FTLCONF_webserver_api_max_sessions"))
			for _, e := range container.Env {
				if e.Name == "FTLCONF_dns_listeningMode" {
					Expect(e.Value).To(Equal("all"))
				}
				if e.Name == "FTLCONF_webserver_api_max_sessions" {
					Expect(e.Value).To(Equal("64"))
				}
			}

			// Check liveness probe uses HTTP GET against the web UI
			Expect(container.LivenessProbe).NotTo(BeNil())
			Expect(container.LivenessProbe.HTTPGet).NotTo(BeNil())
			Expect(container.LivenessProbe.HTTPGet.Path).To(Equal("/admin/"))

			// Check readiness probe uses DNS exec probe (not HTTP)
			Expect(container.ReadinessProbe).NotTo(BeNil())
			Expect(container.ReadinessProbe.Exec).NotTo(BeNil())
			Expect(container.ReadinessProbe.Exec.Command).To(Equal([]string{
				"dig", "@127.0.0.1", "-p", "53", "localhost", "+short", "+time=2", "+tries=1",
			}))

			// Check volume mounts
			Expect(container.VolumeMounts).To(HaveLen(1))
			Expect(container.VolumeMounts[0].MountPath).To(Equal("/etc/pihole"))

			// Check VolumeClaimTemplates instead of standalone PVC
			Expect(sts.Spec.VolumeClaimTemplates).To(HaveLen(1))
			vct := sts.Spec.VolumeClaimTemplates[0]
			Expect(vct.Name).To(Equal("etc-pihole"))
			qty := vct.Spec.Resources.Requests[corev1.ResourceStorage]
			Expect(qty.Cmp(resource.MustParse("1Gi"))).To(Equal(0))
			Expect(vct.Spec.AccessModes).To(ContainElement(corev1.ReadWriteOnce))
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

			dnsSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nn.Name + "-dns", Namespace: "default"}, dnsSvc)).To(Succeed())
			checkOwnerRef(dnsSvc.ObjectMeta)

			webSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nn.Name + "-web", Namespace: "default"}, webSvc)).To(Succeed())
			checkOwnerRef(webSvc.ObjectMeta)

			headlessSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nn.Name + "-headless", Namespace: "default"}, headlessSvc)).To(Succeed())
			checkOwnerRef(headlessSvc.ObjectMeta)

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())
			checkOwnerRef(sts.ObjectMeta)
		})

	})

	// Use a dedicated Context with a unique name so envtest leftover
	// resources from other tests don't interfere with the StatefulSet
	// creation branch (which sets AdminPasswordSecret/ServiceName).
	Context("Status fields", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-status-fields", cachev1alpha1.PiholeSpec{})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should set status conditions and fields after reconcile", func() {
			// First reconcile creates all resources including StatefulSet
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile finds StatefulSet, sets Available=True
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

		It("should create StatefulSet with custom size and storage class in VolumeClaimTemplates", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			Expect(sts.Spec.VolumeClaimTemplates).To(HaveLen(1))
			vct := sts.Spec.VolumeClaimTemplates[0]
			qty := vct.Spec.Resources.Requests[corev1.ResourceStorage]
			Expect(qty.Cmp(resource.MustParse("5Gi"))).To(Equal(0))
			Expect(vct.Spec.StorageClassName).NotTo(BeNil())
			Expect(*vct.Spec.StorageClassName).To(Equal("fast-ssd"))
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

	Context("LoadBalancer DNS without static IP", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-lb-no-ip", cachev1alpha1.PiholeSpec{
				DnsServiceType: "LoadBalancer",
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should create a DNS LoadBalancer service without loadBalancerIP set", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			svc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-lb-no-ip-dns", Namespace: "default",
			}, svc)).To(Succeed())

			Expect(svc.Spec.Type).To(Equal(corev1.ServiceTypeLoadBalancer))
			Expect(svc.Spec.LoadBalancerIP).To(BeEmpty())
			Expect(svc.Spec.Ports).To(HaveLen(2))

			portNames := []string{svc.Spec.Ports[0].Name, svc.Spec.Ports[1].Name}
			Expect(portNames).To(ContainElements("dns-tcp", "dns-udp"))
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

		It("should use custom image in the StatefulSet", func() {
			// First reconcile creates StatefulSet with default image
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile detects image mismatch and updates
			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())
			Expect(sts.Spec.Template.Spec.Containers[0].Image).To(Equal("docker.io/pihole/pihole:2024.01.0"))
		})
	})

	// ---------------------------------------------------------------
	// Readiness probe reconciliation tests (follow-up to PR #20)
	// ---------------------------------------------------------------
	Context("Readiness probe reconciliation", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-probe-reconcile", cachev1alpha1.PiholeSpec{})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should update an existing StatefulSet that has the old HTTP GET readiness probe to the DNS exec probe", func() {
			// First reconcile creates the StatefulSet with the correct exec probe
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Simulate a pre-PR-#20 StatefulSet by patching the readiness probe back to
			// the old HTTP GET style, so we can verify the reconciler corrects it.
			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			oldHTTPProbe := &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/admin/",
						Port: intstr.FromInt(80),
					},
				},
				InitialDelaySeconds: 60,
				PeriodSeconds:       30,
				TimeoutSeconds:      5,
				FailureThreshold:    3,
			}
			sts.Spec.Template.Spec.Containers[0].ReadinessProbe = oldHTTPProbe
			Expect(k8sClient.Update(ctx, sts)).To(Succeed())

			// Verify the probe was actually stored as HTTP GET
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())
			Expect(sts.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet).NotTo(BeNil())
			Expect(sts.Spec.Template.Spec.Containers[0].ReadinessProbe.Exec).To(BeNil())

			// Reconcile — the controller should detect the probe mismatch and update it
			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue(), "reconciler should requeue after updating the probe")

			// Confirm the probe is now the DNS exec probe
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())
			probe := sts.Spec.Template.Spec.Containers[0].ReadinessProbe
			Expect(probe).NotTo(BeNil())
			Expect(probe.HTTPGet).To(BeNil(), "HTTP GET probe should have been replaced")
			Expect(probe.Exec).NotTo(BeNil(), "exec probe must be set")
			Expect(probe.Exec.Command).To(Equal([]string{
				"dig", "@127.0.0.1", "-p", "53", "localhost", "+short", "+time=2", "+tries=1",
			}))
			Expect(probe.InitialDelaySeconds).To(Equal(int32(30)))
			Expect(probe.PeriodSeconds).To(Equal(int32(10)))
			Expect(probe.TimeoutSeconds).To(Equal(int32(5)))
			Expect(probe.FailureThreshold).To(Equal(int32(3)))
			Expect(probe.SuccessThreshold).To(Equal(int32(1)))
		})

		It("should NOT trigger an update when the readiness probe is already correct", func() {
			// First reconcile creates the StatefulSet with the correct exec probe
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile: probe matches → no update, no requeue
			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse(), "no requeue when probe is already correct")
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

		It("should update StatefulSet replicas when spec.size changes", func() {
			// Initial reconcile
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())
			Expect(*sts.Spec.Replicas).To(Equal(int32(1)))

			// Update size
			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())
			pihole.Spec.Size = ptr.To(int32(3))
			Expect(k8sClient.Update(ctx, pihole)).To(Succeed())

			// Reconcile again
			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue()) // requeue after update

			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())
			Expect(*sts.Spec.Replicas).To(Equal(int32(3)))
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

	Context("StatefulSet security context", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-security", cachev1alpha1.PiholeSpec{})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should set correct security context and capabilities", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			podSec := sts.Spec.Template.Spec.SecurityContext
			Expect(podSec).NotTo(BeNil())
			Expect(*podSec.RunAsUser).To(Equal(int64(0)))

			container := sts.Spec.Template.Spec.Containers[0]
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

		It("should set the TZ env var in the StatefulSet", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			var tzValue string
			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
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

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())
			for k, v := range expectedLabels {
				Expect(sts.Labels).To(HaveKeyWithValue(k, v))
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

		It("should reference the existing secret in the StatefulSet", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			var envVar corev1.EnvVar
			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
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
			// First reconcile creates StatefulSet and sets status
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

		It("should use the custom key in the StatefulSet env var", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			var envVar corev1.EnvVar
			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
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

	// ---------------------------------------------------------------
	// Upstream DNS tests
	// ---------------------------------------------------------------
	Context("Custom upstream DNS", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-upstream-dns", cachev1alpha1.PiholeSpec{
				UpstreamDNS: []string{"1.1.1.1", "1.0.0.1"},
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should set FTLCONF_dns_upstreams env var in the StatefulSet", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			var upstreamValue string
			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
				if e.Name == "FTLCONF_dns_upstreams" {
					upstreamValue = e.Value
					break
				}
			}
			Expect(upstreamValue).To(Equal("1.1.1.1;1.0.0.1"))
		})

		It("should update FTLCONF_dns_upstreams when upstream DNS servers change", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Update upstream DNS
			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())
			pihole.Spec.UpstreamDNS = []string{"8.8.8.8", "8.8.4.4", "9.9.9.9"}
			Expect(k8sClient.Update(ctx, pihole)).To(Succeed())

			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			var upstreamValue string
			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
				if e.Name == "FTLCONF_dns_upstreams" {
					upstreamValue = e.Value
					break
				}
			}
			Expect(upstreamValue).To(Equal("8.8.8.8;8.8.4.4;9.9.9.9"))
		})
	})

	Context("No upstream DNS (default)", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-no-upstream", cachev1alpha1.PiholeSpec{})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should NOT set FTLCONF_dns_upstreams env var when upstreamDNS is unset", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
				Expect(e.Name).NotTo(Equal("FTLCONF_dns_upstreams"),
					"FTLCONF_dns_upstreams should not be set when upstreamDNS is empty")
			}
		})
	})

	Context("Upstream DNS removal", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-upstream-removal", cachev1alpha1.PiholeSpec{
				UpstreamDNS: []string{"1.1.1.1"},
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should remove FTLCONF_dns_upstreams when upstreamDNS is cleared", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			// Verify env var is set initially
			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())
			found := false
			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
				if e.Name == "FTLCONF_dns_upstreams" {
					found = true
				}
			}
			Expect(found).To(BeTrue())

			// Clear upstream DNS
			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())
			pihole.Spec.UpstreamDNS = nil
			Expect(k8sClient.Update(ctx, pihole)).To(Succeed())

			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())
			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
				Expect(e.Name).NotTo(Equal("FTLCONF_dns_upstreams"),
					"FTLCONF_dns_upstreams should be removed when upstreamDNS is cleared")
			}
		})
	})

	// ---------------------------------------------------------------
	// PodDisruptionBudget tests
	// ---------------------------------------------------------------
	Context("PodDisruptionBudget - size > 1", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-pdb-multi", cachev1alpha1.PiholeSpec{
				Size: ptr.To(int32(3)),
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should create a PDB with minAvailable=1 when size > 1", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			pdb := &policyv1.PodDisruptionBudget{}
			Expect(k8sClient.Get(ctx, nn, pdb)).To(Succeed())

			Expect(pdb.Spec.MinAvailable).NotTo(BeNil())
			Expect(pdb.Spec.MinAvailable.IntValue()).To(Equal(1))

			// Selector should match Pihole pods
			Expect(pdb.Spec.Selector).NotTo(BeNil())
			Expect(pdb.Spec.Selector.MatchLabels).To(HaveKeyWithValue(
				"app.kubernetes.io/instance", "test-pdb-multi",
			))
		})

		It("should set owner reference on the PDB", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())

			pdb := &policyv1.PodDisruptionBudget{}
			Expect(k8sClient.Get(ctx, nn, pdb)).To(Succeed())

			Expect(pdb.OwnerReferences).To(HaveLen(1))
			Expect(pdb.OwnerReferences[0].Name).To(Equal(pihole.Name))
			Expect(*pdb.OwnerReferences[0].Controller).To(BeTrue())
		})
	})

	Context("PodDisruptionBudget - size = 1 (default)", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-pdb-single", cachev1alpha1.PiholeSpec{
				Size: ptr.To(int32(1)),
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should NOT create a PDB when size == 1", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			pdb := &policyv1.PodDisruptionBudget{}
			err = k8sClient.Get(ctx, nn, pdb)
			Expect(errors.IsNotFound(err)).To(BeTrue(), "PDB should not exist for size=1")
		})
	})

	Context("PodDisruptionBudget - deletion when scaling down to 1", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-pdb-scaledown", cachev1alpha1.PiholeSpec{
				Size: ptr.To(int32(3)),
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should delete the PDB when size is scaled down to 1", func() {
			// First reconcile at size=3 creates PDB
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			pdb := &policyv1.PodDisruptionBudget{}
			Expect(k8sClient.Get(ctx, nn, pdb)).To(Succeed())

			// Scale down to 1
			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())
			pihole.Spec.Size = ptr.To(int32(1))
			Expect(k8sClient.Update(ctx, pihole)).To(Succeed())

			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue()) // StatefulSet update triggers requeue

			// PDB should now be gone
			err = k8sClient.Get(ctx, nn, pdb)
			Expect(errors.IsNotFound(err)).To(BeTrue(), "PDB should be deleted when size scales to 1")
		})
	})

	Context("PodDisruptionBudget - no spec.size (defaults to 1)", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-pdb-default", cachev1alpha1.PiholeSpec{})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should NOT create a PDB when spec.size is nil (defaults to 1)", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			pdb := &policyv1.PodDisruptionBudget{}
			err = k8sClient.Get(ctx, nn, pdb)
			Expect(errors.IsNotFound(err)).To(BeTrue(), "PDB should not exist when size defaults to 1")
		})
	})

	Context("DNS listening mode defaults", func() {
		It("should default listening mode to local when DNS service type is ClusterIP", func() {
			nn := createPihole("test-dns-listen-clusterip", cachev1alpha1.PiholeSpec{
				DnsServiceType: "ClusterIP",
			})
			defer deletePihole(nn)

			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			found := false
			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
				if e.Name == "FTLCONF_dns_listeningMode" {
					Expect(e.Value).To(Equal("local"))
					found = true
				}
			}
			Expect(found).To(BeTrue())
		})
	})

	// ---------------------------------------------------------------
	// Service drift / update detection tests
	// ---------------------------------------------------------------

	Context("StatefulSet drift - DNS listening mode follows DNS service type", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-drift-dns-listening", cachev1alpha1.PiholeSpec{
				DnsServiceType: "NodePort",
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should update listening mode when DNS service type changes to ClusterIP", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())
			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
				if e.Name == "FTLCONF_dns_listeningMode" {
					Expect(e.Value).To(Equal("all"))
				}
			}

			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())
			pihole.Spec.DnsServiceType = "ClusterIP"
			Expect(k8sClient.Update(ctx, pihole)).To(Succeed())

			_, err = doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())
			found := false
			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
				if e.Name == "FTLCONF_dns_listeningMode" {
					Expect(e.Value).To(Equal("local"))
					found = true
				}
			}
			Expect(found).To(BeTrue())
		})
	})

	Context("Service drift - DNS type change (NodePort → LoadBalancer)", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			// Start with default DNS service type (NodePort)
			nn = createPihole("test-drift-dns-type", cachev1alpha1.PiholeSpec{
				DnsServiceType: "NodePort",
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should update the DNS service when type changes from NodePort to LoadBalancer", func() {
			// First reconcile: create DNS service as NodePort
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			svc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-drift-dns-type-dns", Namespace: "default",
			}, svc)).To(Succeed())
			Expect(svc.Spec.Type).To(Equal(corev1.ServiceTypeNodePort))

			// Update the Pihole spec to LoadBalancer
			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())
			pihole.Spec.DnsServiceType = "LoadBalancer"
			Expect(k8sClient.Update(ctx, pihole)).To(Succeed())

			// Second reconcile: should detect drift and update the service
			_, err = doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-drift-dns-type-dns", Namespace: "default",
			}, svc)).To(Succeed())
			// The service type must have changed
			Expect(svc.Spec.Type).To(Equal(corev1.ServiceTypeLoadBalancer))
			// Note: LoadBalancer services also allocate nodePort values in Kubernetes,
			// so nodePort may be non-zero here — that's correct and expected behavior.
		})
	})

	Context("Service drift - DNS LoadBalancer IP change", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-drift-dns-lbip", cachev1alpha1.PiholeSpec{
				DnsServiceType:    "LoadBalancer",
				DnsLoadBalancerIP: "10.0.0.53",
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should update the DNS service when LoadBalancerIP changes", func() {
			// First reconcile: create DNS service with initial LB IP
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			svc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-drift-dns-lbip-dns", Namespace: "default",
			}, svc)).To(Succeed())
			Expect(svc.Spec.LoadBalancerIP).To(Equal("10.0.0.53"))

			// Update the Pihole spec with new LB IP
			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())
			pihole.Spec.DnsLoadBalancerIP = "10.0.0.100"
			Expect(k8sClient.Update(ctx, pihole)).To(Succeed())

			// Second reconcile: should detect drift and update the service
			_, err = doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-drift-dns-lbip-dns", Namespace: "default",
			}, svc)).To(Succeed())
			Expect(svc.Spec.LoadBalancerIP).To(Equal("10.0.0.100"))
		})
	})

	Context("Service drift - Web type change (ClusterIP → LoadBalancer)", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-drift-web-type", cachev1alpha1.PiholeSpec{
				WebServiceType: "ClusterIP",
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should update the Web service when type changes from ClusterIP to LoadBalancer", func() {
			// First reconcile: create Web service as ClusterIP
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			svc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-drift-web-type-web", Namespace: "default",
			}, svc)).To(Succeed())
			Expect(svc.Spec.Type).To(Equal(corev1.ServiceTypeClusterIP))

			// Update the Pihole spec to LoadBalancer with a static IP
			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())
			pihole.Spec.WebServiceType = "LoadBalancer"
			pihole.Spec.WebLoadBalancerIP = "10.0.0.80"
			Expect(k8sClient.Update(ctx, pihole)).To(Succeed())

			// Second reconcile: should detect drift and update the service
			_, err = doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-drift-web-type-web", Namespace: "default",
			}, svc)).To(Succeed())
			Expect(svc.Spec.Type).To(Equal(corev1.ServiceTypeLoadBalancer))
			Expect(svc.Spec.LoadBalancerIP).To(Equal("10.0.0.80"))
		})
	})

	Context("Service drift - no-op when service already matches desired state", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = createPihole("test-drift-noop", cachev1alpha1.PiholeSpec{
				DnsServiceType:    "LoadBalancer",
				DnsLoadBalancerIP: "10.0.0.53",
				WebServiceType:    "ClusterIP",
			})
		})
		AfterEach(func() { deletePihole(nn) })

		It("should NOT update the service when it already matches the desired state", func() {
			// First reconcile: create services
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			dnsSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-drift-noop-dns", Namespace: "default",
			}, dnsSvc)).To(Succeed())
			originalDNSVersion := dnsSvc.ResourceVersion

			webSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-drift-noop-web", Namespace: "default",
			}, webSvc)).To(Succeed())
			originalWebVersion := webSvc.ResourceVersion

			// Second reconcile: no spec changes → services must not be updated
			_, err = doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-drift-noop-dns", Namespace: "default",
			}, dnsSvc)).To(Succeed())
			Expect(dnsSvc.ResourceVersion).To(Equal(originalDNSVersion),
				"DNS service ResourceVersion should not change when already up to date")

			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "test-drift-noop-web", Namespace: "default",
			}, webSvc)).To(Succeed())
			Expect(webSvc.ResourceVersion).To(Equal(originalWebVersion),
				"Web service ResourceVersion should not change when already up to date")
		})
	})

	// ---------------------------------------------------------------
	// Stats enrichment tests
	// ---------------------------------------------------------------
	Context("Stats enrichment via mock Pi-hole API", func() {
		var (
			nn         types.NamespacedName
			mockServer *httptest.Server
		)

		BeforeEach(func() {
			// Set up a mock Pi-hole API server that handles auth and stats.
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/api/auth":
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"session": map[string]interface{}{
							"valid": true,
							"sid":   "test-sid-12345",
						},
					})

				case r.Method == http.MethodGet && r.URL.Path == "/api/stats/summary":
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(StatsSummaryResponse{
						Queries: struct {
							Total          int64   `json:"total"`
							Blocked        int64   `json:"blocked"`
							PercentBlocked float64 `json:"percent_blocked"`
							UniqueDomains  int64   `json:"unique_domains"`
							Forwarded      int64   `json:"forwarded"`
							Cached         int64   `json:"cached"`
						}{
							Total:          10000,
							Blocked:        999,
							PercentBlocked: 9.99,
						},
						Clients: struct {
							Active int32 `json:"active"`
							Total  int32 `json:"total"`
						}{
							Active: 7,
							Total:  10,
						},
						Gravity: struct {
							DomainsBeingBlocked int64 `json:"domains_being_blocked"`
							LastUpdate          int64 `json:"last_update"`
						}{
							DomainsBeingBlocked: 150000,
						},
					})

				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))

			// Create a Pihole CR with a known password so the reconciler can auth.
			nn = createPihole("test-stats", cachev1alpha1.PiholeSpec{
				AdminPassword: "test-password",
			})
		})

		AfterEach(func() {
			mockServer.Close()
			deletePihole(nn)
		})

		It("should populate stats fields in status after reconcile", func() {
			// Build a reconciler that routes pod-0 traffic to the mock server.
			statsReconciler := &PiholeReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				BaseURLOverride: map[string]string{
					PodCacheKey("default", "test-stats", 0): mockServer.URL,
				},
			}

			// First reconcile creates all child resources (StatefulSet, Services, Secret).
			_, err := statsReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile: StatefulSet already exists → reaches the stats-fetch path.
			_, err = statsReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())

			Expect(pihole.Status.QueriesTotal).To(Equal(int64(10000)))
			Expect(pihole.Status.QueriesBlocked).To(Equal(int64(999)))
			Expect(pihole.Status.BlockPercentage).To(Equal("9.99%"))
			Expect(pihole.Status.GravityDomains).To(Equal(int64(150000)))
			Expect(pihole.Status.UniqueClients).To(Equal(int32(7)))
			Expect(pihole.Status.StatsLastUpdated).NotTo(BeNil())
		})
	})

	// ---------------------------------------------------------------
	// ServerTLS tests
	// ---------------------------------------------------------------
	Context("ServerTLS - default key names", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			// Create a fake TLS secret
			tlsSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pihole-tls",
					Namespace: "default",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					"tls.crt": []byte("fake-cert"),
					"tls.key": []byte("fake-key"),
				},
			}
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			nn = createPihole("test-servertls", cachev1alpha1.PiholeSpec{
				ServerTLS: &cachev1alpha1.PiholeServerTLSConfig{
					SecretName: "pihole-tls",
				},
			})
		})
		AfterEach(func() {
			deletePihole(nn)
			tlsSecret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: "pihole-tls", Namespace: "default"}, tlsSecret); err == nil {
				_ = k8sClient.Delete(ctx, tlsSecret)
			}
		})

		It("should mount the TLS secret as a volume and set FTLCONF env vars", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			// Check volume exists
			var serverTLSVol *corev1.Volume
			for i := range sts.Spec.Template.Spec.Volumes {
				if sts.Spec.Template.Spec.Volumes[i].Name == "server-tls" {
					serverTLSVol = &sts.Spec.Template.Spec.Volumes[i]
					break
				}
			}
			Expect(serverTLSVol).NotTo(BeNil(), "server-tls volume should exist")
			Expect(serverTLSVol.VolumeSource.Secret).NotTo(BeNil())
			Expect(serverTLSVol.VolumeSource.Secret.SecretName).To(Equal("pihole-tls"))

			// Check volumeMount exists
			var serverTLSMount *corev1.VolumeMount
			for i := range sts.Spec.Template.Spec.Containers[0].VolumeMounts {
				if sts.Spec.Template.Spec.Containers[0].VolumeMounts[i].Name == "server-tls" {
					serverTLSMount = &sts.Spec.Template.Spec.Containers[0].VolumeMounts[i]
					break
				}
			}
			Expect(serverTLSMount).NotTo(BeNil(), "server-tls volumeMount should exist")
			Expect(serverTLSMount.MountPath).To(Equal("/etc/pihole/tls"))
			Expect(serverTLSMount.ReadOnly).To(BeTrue())

			// Check env vars
			var certPath, keyPath string
			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
				if e.Name == "FTLCONF_webserver_tls_cert" {
					certPath = e.Value
				}
				if e.Name == "FTLCONF_webserver_tls_key" {
					keyPath = e.Value
				}
			}
			Expect(certPath).To(Equal("/etc/pihole/tls/tls.crt"))
			Expect(keyPath).To(Equal("/etc/pihole/tls/tls.key"))
		})
	})

	Context("ServerTLS - custom key names", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			tlsSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-tls",
					Namespace: "default",
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"cert.pem": []byte("fake-cert"),
					"key.pem":  []byte("fake-key"),
				},
			}
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			nn = createPihole("test-servertls-custom", cachev1alpha1.PiholeSpec{
				ServerTLS: &cachev1alpha1.PiholeServerTLSConfig{
					SecretName: "my-tls",
					CertKey:    "cert.pem",
					KeyKey:     "key.pem",
				},
			})
		})
		AfterEach(func() {
			deletePihole(nn)
			tlsSecret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: "my-tls", Namespace: "default"}, tlsSecret); err == nil {
				_ = k8sClient.Delete(ctx, tlsSecret)
			}
		})

		It("should use custom certKey and keyKey in FTLCONF env vars", func() {
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			var certPath, keyPath string
			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
				if e.Name == "FTLCONF_webserver_tls_cert" {
					certPath = e.Value
				}
				if e.Name == "FTLCONF_webserver_tls_key" {
					keyPath = e.Value
				}
			}
			Expect(certPath).To(Equal("/etc/pihole/tls/cert.pem"))
			Expect(keyPath).To(Equal("/etc/pihole/tls/key.pem"))
		})
	})

	Context("ServerTLS - drift detection", func() {
		var nn types.NamespacedName

		BeforeEach(func() {
			tlsSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pihole-tls-drift",
					Namespace: "default",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					"tls.crt": []byte("fake-cert"),
					"tls.key": []byte("fake-key"),
				},
			}
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			nn = createPihole("test-servertls-drift", cachev1alpha1.PiholeSpec{
				ServerTLS: &cachev1alpha1.PiholeServerTLSConfig{
					SecretName: "pihole-tls-drift",
				},
			})
		})
		AfterEach(func() {
			deletePihole(nn)
			tlsSecret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: "pihole-tls-drift", Namespace: "default"}, tlsSecret); err == nil {
				_ = k8sClient.Delete(ctx, tlsSecret)
			}
		})

		It("should remove server-tls volume and env vars when serverTLS is cleared", func() {
			// First reconcile: create with serverTLS
			_, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			// Verify volume is present initially
			found := false
			for _, v := range sts.Spec.Template.Spec.Volumes {
				if v.Name == "server-tls" {
					found = true
				}
			}
			Expect(found).To(BeTrue(), "server-tls volume should exist initially")

			// Clear serverTLS from spec
			pihole := &cachev1alpha1.Pihole{}
			Expect(k8sClient.Get(ctx, nn, pihole)).To(Succeed())
			pihole.Spec.ServerTLS = nil
			Expect(k8sClient.Update(ctx, pihole)).To(Succeed())

			result, err := doReconcile(nn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			Expect(k8sClient.Get(ctx, nn, sts)).To(Succeed())

			// Volume should be gone
			for _, v := range sts.Spec.Template.Spec.Volumes {
				Expect(v.Name).NotTo(Equal("server-tls"), "server-tls volume should be removed")
			}

			// Env vars should be gone
			for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
				Expect(e.Name).NotTo(Equal("FTLCONF_webserver_tls_cert"), "FTLCONF_webserver_tls_cert should be removed")
				Expect(e.Name).NotTo(Equal("FTLCONF_webserver_tls_key"), "FTLCONF_webserver_tls_key should be removed")
			}
		})
	})
})
