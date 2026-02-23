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
	"fmt"
	piholev1alpha1 "github.com/duchaineo1/pihole-operator/api/v1alpha1"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"math/rand"
	"reflect"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"strings"
	"time"
)

const (
	typeAvailablePihole = "Available"
)

// PiholeReconciler reconciles a Pihole object
type PiholeReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// BaseURLOverride allows tests to substitute a mock URL for a given pod key (namespace/name-ordinal).
	BaseURLOverride map[string]string
}

// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholes/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pihole-operator.org,resources=blocklists,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pihole-operator.org,resources=blocklists/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pihole-operator.org,resources=blocklists/finalizers,verbs=update
// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholednsrecords,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholednsrecords/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholednsrecords/finalizers,verbs=update
// +kubebuilder:rbac:groups=pihole-operator.org,resources=whitelists,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pihole-operator.org,resources=whitelists/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pihole-operator.org,resources=whitelists/finalizers,verbs=update
// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholes,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete

func (r *PiholeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	pihole := &piholev1alpha1.Pihole{}

	err := r.Get(ctx, req.NamespacedName, pihole)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("pihole resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get pihole")
		return ctrl.Result{}, err
	}

	if len(pihole.Status.Conditions) == 0 {
		meta.SetStatusCondition(&pihole.Status.Conditions, metav1.Condition{
			Type:    typeAvailablePihole,
			Status:  metav1.ConditionUnknown,
			Reason:  "Reconciling",
			Message: "Starting reconciliation",
		})
		if err = r.Status().Update(ctx, pihole); err != nil {
			log.Error(err, "Failed to update Pihole status")
			return ctrl.Result{}, err
		}
		if err := r.Get(ctx, req.NamespacedName, pihole); err != nil {
			log.Error(err, "Failed to re-fetch pihole")
			return ctrl.Result{}, err
		}
	}

	if err := r.reconcileSecret(ctx, pihole, log); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileService(ctx, pihole, log); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileHeadlessService(ctx, pihole, log); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileIngress(ctx, pihole, log); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcilePDB(ctx, pihole, log); err != nil {
		return ctrl.Result{}, err
	}

	found := &appsv1.StatefulSet{}
	err = r.Get(ctx, types.NamespacedName{Name: pihole.Name, Namespace: pihole.Namespace}, found)
	if err != nil && apierrors.IsNotFound(err) {
		sts, err := r.statefulSetForPihole(pihole)
		if err != nil {
			log.Error(err, "Failed to define new StatefulSet resource for pihole")
			meta.SetStatusCondition(&pihole.Status.Conditions, metav1.Condition{
				Type:    typeAvailablePihole,
				Status:  metav1.ConditionFalse,
				Reason:  "Reconciling",
				Message: fmt.Sprintf("Failed to create StatefulSet for the custom resource (%s): (%s)", pihole.Name, err),
			})
			if err := r.Status().Update(ctx, pihole); err != nil {
				log.Error(err, "Failed to update pihole status")
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, err
		}

		log.Info("Creating a new StatefulSet",
			"StatefulSet.Namespace", sts.Namespace, "StatefulSet.Name", sts.Name)
		if err = r.Create(ctx, sts); err != nil {
			log.Error(err, "Failed to create new StatefulSet",
				"StatefulSet.Namespace", sts.Namespace, "StatefulSet.Name", sts.Name)
			return ctrl.Result{}, err
		}

		pihole.Status.AdminPasswordSecret = adminSecretName(pihole)
		pihole.Status.ServiceName = pihole.Name
		if err := r.Status().Update(ctx, pihole); err != nil {
			log.Error(err, "Failed to update pihole status")
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: time.Minute}, nil
	} else if err != nil {
		log.Error(err, "Failed to get StatefulSet")
		return ctrl.Result{}, err
	}

	var desiredReplicas int32 = 1
	if pihole.Spec.Size != nil {
		desiredReplicas = *pihole.Spec.Size
	}

	needsUpdate := false
	if found.Spec.Replicas == nil || *found.Spec.Replicas != desiredReplicas {
		found.Spec.Replicas = ptr.To(desiredReplicas)
		needsUpdate = true
	}

	desiredImage := "docker.io/pihole/pihole:2025.11.0"
	if pihole.Spec.Image != "" {
		desiredImage = pihole.Spec.Image
	}
	if len(found.Spec.Template.Spec.Containers) > 0 && found.Spec.Template.Spec.Containers[0].Image != desiredImage {
		found.Spec.Template.Spec.Containers[0].Image = desiredImage
		needsUpdate = true
	}

	// Check if resources changed
	if len(found.Spec.Template.Spec.Containers) > 0 {
		desiredResources := corev1.ResourceRequirements{}
		if pihole.Spec.Resources != nil {
			desiredResources = *pihole.Spec.Resources
		}
		if !reflect.DeepEqual(found.Spec.Template.Spec.Containers[0].Resources, desiredResources) {
			found.Spec.Template.Spec.Containers[0].Resources = desiredResources
			needsUpdate = true
		}
	}

	// Check if upstream DNS servers changed
	if len(found.Spec.Template.Spec.Containers) > 0 {
		desiredUpstream := ""
		if len(pihole.Spec.UpstreamDNS) > 0 {
			desiredUpstream = strings.Join(pihole.Spec.UpstreamDNS, ";")
		}
		currentUpstream := ""
		for _, e := range found.Spec.Template.Spec.Containers[0].Env {
			if e.Name == "FTLCONF_dns_upstreams" {
				currentUpstream = e.Value
				break
			}
		}
		if currentUpstream != desiredUpstream {
			// Remove old upstream env var (if any) and re-add if needed
			newEnv := make([]corev1.EnvVar, 0, len(found.Spec.Template.Spec.Containers[0].Env))
			for _, e := range found.Spec.Template.Spec.Containers[0].Env {
				if e.Name != "FTLCONF_dns_upstreams" {
					newEnv = append(newEnv, e)
				}
			}
			if desiredUpstream != "" {
				newEnv = append(newEnv, corev1.EnvVar{
					Name:  "FTLCONF_dns_upstreams",
					Value: desiredUpstream,
				})
			}
			found.Spec.Template.Spec.Containers[0].Env = newEnv
			needsUpdate = true
		}
	}

	// Reconcile DNS listening mode based on service exposure type.
	// ClusterIP keeps a stricter default (local), while NodePort/LoadBalancer
	// require "all" in many Kubernetes networking paths.
	if len(found.Spec.Template.Spec.Containers) > 0 {
		desiredListeningMode := dnsListeningModeForServiceType(pihole.Spec.DnsServiceType)
		currentListeningMode := ""
		for _, e := range found.Spec.Template.Spec.Containers[0].Env {
			if e.Name == "FTLCONF_dns_listeningMode" {
				currentListeningMode = e.Value
				break
			}
		}
		if currentListeningMode != desiredListeningMode {
			newEnv := make([]corev1.EnvVar, 0, len(found.Spec.Template.Spec.Containers[0].Env))
			for _, e := range found.Spec.Template.Spec.Containers[0].Env {
				if e.Name != "FTLCONF_dns_listeningMode" {
					newEnv = append(newEnv, e)
				}
			}
			newEnv = append(newEnv, corev1.EnvVar{
				Name:  "FTLCONF_dns_listeningMode",
				Value: desiredListeningMode,
			})
			found.Spec.Template.Spec.Containers[0].Env = newEnv
			needsUpdate = true
		}
	}

	// Reconcile server TLS volume, volumeMount, and env vars
	if len(found.Spec.Template.Spec.Containers) > 0 {
		desiredCertKey := ""
		desiredKeyKey := ""
		desiredSecretName := ""
		if pihole.Spec.ServerTLS != nil {
			desiredCertKey = pihole.Spec.ServerTLS.CertKey
			if desiredCertKey == "" {
				desiredCertKey = "tls.crt"
			}
			desiredKeyKey = pihole.Spec.ServerTLS.KeyKey
			if desiredKeyKey == "" {
				desiredKeyKey = "tls.key"
			}
			desiredSecretName = pihole.Spec.ServerTLS.SecretName
		}

		// Reconcile the server-tls volume
		volIdx := -1
		for i, v := range found.Spec.Template.Spec.Volumes {
			if v.Name == "server-tls" {
				volIdx = i
				break
			}
		}
		if desiredSecretName != "" {
			desiredVol := corev1.Volume{
				Name: "server-tls",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: desiredSecretName,
					},
				},
			}
			if volIdx < 0 {
				found.Spec.Template.Spec.Volumes = append(found.Spec.Template.Spec.Volumes, desiredVol)
				needsUpdate = true
			} else if found.Spec.Template.Spec.Volumes[volIdx].VolumeSource.Secret == nil ||
				found.Spec.Template.Spec.Volumes[volIdx].VolumeSource.Secret.SecretName != desiredSecretName {
				found.Spec.Template.Spec.Volumes[volIdx] = desiredVol
				needsUpdate = true
			}
		} else if volIdx >= 0 {
			// serverTLS removed — drop the volume
			found.Spec.Template.Spec.Volumes = append(
				found.Spec.Template.Spec.Volumes[:volIdx],
				found.Spec.Template.Spec.Volumes[volIdx+1:]...)
			needsUpdate = true
		}

		// Reconcile the server-tls volumeMount
		vmIdx := -1
		for i, vm := range found.Spec.Template.Spec.Containers[0].VolumeMounts {
			if vm.Name == "server-tls" {
				vmIdx = i
				break
			}
		}
		if desiredSecretName != "" {
			if vmIdx < 0 {
				found.Spec.Template.Spec.Containers[0].VolumeMounts = append(
					found.Spec.Template.Spec.Containers[0].VolumeMounts,
					corev1.VolumeMount{
						Name:      "server-tls",
						MountPath: "/etc/pihole/tls",
						ReadOnly:  true,
					},
				)
				needsUpdate = true
			}
		} else if vmIdx >= 0 {
			found.Spec.Template.Spec.Containers[0].VolumeMounts = append(
				found.Spec.Template.Spec.Containers[0].VolumeMounts[:vmIdx],
				found.Spec.Template.Spec.Containers[0].VolumeMounts[vmIdx+1:]...)
			needsUpdate = true
		}

		// Reconcile FTLCONF_webserver_tls_cert and FTLCONF_webserver_tls_key env vars
		desiredCertPath := ""
		desiredKeyPath := ""
		if desiredSecretName != "" {
			desiredCertPath = fmt.Sprintf("/etc/pihole/tls/%s", desiredCertKey)
			desiredKeyPath = fmt.Sprintf("/etc/pihole/tls/%s", desiredKeyKey)
		}
		currentCertPath := ""
		currentKeyPath := ""
		for _, e := range found.Spec.Template.Spec.Containers[0].Env {
			if e.Name == "FTLCONF_webserver_tls_cert" {
				currentCertPath = e.Value
			}
			if e.Name == "FTLCONF_webserver_tls_key" {
				currentKeyPath = e.Value
			}
		}
		if currentCertPath != desiredCertPath || currentKeyPath != desiredKeyPath {
			newEnv := make([]corev1.EnvVar, 0, len(found.Spec.Template.Spec.Containers[0].Env))
			for _, e := range found.Spec.Template.Spec.Containers[0].Env {
				if e.Name != "FTLCONF_webserver_tls_cert" && e.Name != "FTLCONF_webserver_tls_key" {
					newEnv = append(newEnv, e)
				}
			}
			if desiredSecretName != "" {
				newEnv = append(newEnv,
					corev1.EnvVar{Name: "FTLCONF_webserver_tls_cert", Value: desiredCertPath},
					corev1.EnvVar{Name: "FTLCONF_webserver_tls_key", Value: desiredKeyPath},
				)
			}
			found.Spec.Template.Spec.Containers[0].Env = newEnv
			needsUpdate = true
		}
	}

	// Reconcile readiness probe
	if len(found.Spec.Template.Spec.Containers) > 0 {
		if !reflect.DeepEqual(found.Spec.Template.Spec.Containers[0].ReadinessProbe, piholeReadinessProbe()) {
			found.Spec.Template.Spec.Containers[0].ReadinessProbe = piholeReadinessProbe()
			needsUpdate = true
		}
	}

	if needsUpdate {
		if err = r.Update(ctx, found); err != nil {
			log.Error(err, "Failed to update StatefulSet",
				"StatefulSet.Namespace", found.Namespace, "StatefulSet.Name", found.Name)

			if err := r.Get(ctx, req.NamespacedName, pihole); err != nil {
				log.Error(err, "Failed to re-fetch pihole")
				return ctrl.Result{}, err
			}

			meta.SetStatusCondition(&pihole.Status.Conditions, metav1.Condition{
				Type:    typeAvailablePihole,
				Status:  metav1.ConditionFalse,
				Reason:  "Resizing",
				Message: fmt.Sprintf("Failed to update the StatefulSet for the custom resource (%s): (%s)", pihole.Name, err),
			})
			if err := r.Status().Update(ctx, pihole); err != nil {
				log.Error(err, "Failed to update pihole status")
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	pihole.Status.ReadyReplicas = found.Status.ReadyReplicas
	pihole.Status.AdminPasswordSecret = adminSecretName(pihole)
	pihole.Status.ServiceName = pihole.Name

	// Populate DNSIP and WebURL from the DNS service.
	dnsSvc := &corev1.Service{}
	if err := r.Get(ctx, types.NamespacedName{Name: pihole.Name + "-dns", Namespace: pihole.Namespace}, dnsSvc); err == nil {
		dnsIP := dnsSvc.Spec.ClusterIP
		if dnsSvc.Spec.Type == corev1.ServiceTypeLoadBalancer && len(dnsSvc.Status.LoadBalancer.Ingress) > 0 {
			if lbIP := dnsSvc.Status.LoadBalancer.Ingress[0].IP; lbIP != "" {
				dnsIP = lbIP
			}
		}
		pihole.Status.DNSIP = dnsIP
	} else {
		log.Info("Could not fetch DNS service for DNSIP (non-fatal)", "error", err)
	}

	webSvc := &corev1.Service{}
	if err := r.Get(ctx, types.NamespacedName{Name: pihole.Name + "-web", Namespace: pihole.Namespace}, webSvc); err == nil {
		webIP := webSvc.Spec.ClusterIP
		if webSvc.Spec.Type == corev1.ServiceTypeLoadBalancer && len(webSvc.Status.LoadBalancer.Ingress) > 0 {
			if lbIP := webSvc.Status.LoadBalancer.Ingress[0].IP; lbIP != "" {
				webIP = lbIP
			}
		}
		if webIP != "" && webIP != corev1.ClusterIPNone {
			pihole.Status.WebURL = fmt.Sprintf("http://%s/admin", webIP)
		}
	} else {
		log.Info("Could not fetch Web service for WebURL (non-fatal)", "error", err)
	}

	// Fetch stats from pod 0 (best-effort; don't fail reconcile on stats error).
	if password, pwErr := r.getAdminPassword(ctx, pihole); pwErr == nil {
		baseURL := PodBaseURL(pihole.Name, pihole.Namespace, 0)
		if r.BaseURLOverride != nil {
			if override, ok := r.BaseURLOverride[PodCacheKey(pihole.Namespace, pihole.Name, 0)]; ok {
				baseURL = override
			}
		}
		caData, _ := getCAData(ctx, r.Client, pihole.Namespace, pihole.Spec.TLS)
		tlsCfg := buildTLSConfig(pihole.Spec.TLS, caData)
		apiClient := NewPiholeAPIClient(baseURL, password, buildHTTPClient(tlsCfg))
		if stats, statsErr := apiClient.GetStats(ctx); statsErr == nil {
			pihole.Status.QueriesTotal = stats.Queries.Total
			pihole.Status.QueriesBlocked = stats.Queries.Blocked
			pihole.Status.BlockPercentage = fmt.Sprintf("%.2f%%", stats.Queries.PercentBlocked)
			pihole.Status.GravityDomains = stats.Gravity.DomainsBeingBlocked
			pihole.Status.UniqueClients = stats.Clients.Active
			now := metav1.Now()
			pihole.Status.StatsLastUpdated = &now
		} else {
			log.Info("Could not fetch Pi-hole stats (non-fatal)", "error", statsErr)
		}
	} else {
		log.Info("Could not read admin password for stats fetch (non-fatal)", "error", pwErr)
	}

	meta.SetStatusCondition(&pihole.Status.Conditions, metav1.Condition{
		Type:    typeAvailablePihole,
		Status:  metav1.ConditionTrue,
		Reason:  "Reconciling",
		Message: fmt.Sprintf("StatefulSet for custom resource (%s) with %d replicas created successfully", pihole.Name, desiredReplicas),
	})

	if err := r.Status().Update(ctx, pihole); err != nil {
		log.Error(err, "Failed to update pihole status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: time.Minute}, nil
}

// adminSecretName returns the secret name to use for the admin password.
func adminSecretName(pihole *piholev1alpha1.Pihole) string {
	if pihole.Spec.AdminPasswordSecretRef != nil {
		return pihole.Spec.AdminPasswordSecretRef.Name
	}
	return pihole.Name + "-admin"
}

// adminSecretKey returns the secret key to use for the admin password.
func adminSecretKey(pihole *piholev1alpha1.Pihole) string {
	if pihole.Spec.AdminPasswordSecretRef != nil && pihole.Spec.AdminPasswordSecretRef.Key != "" {
		return pihole.Spec.AdminPasswordSecretRef.Key
	}
	return "password"
}

// getAdminPassword reads the admin password from the relevant Secret.
func (r *PiholeReconciler) getAdminPassword(ctx context.Context, pihole *piholev1alpha1.Pihole) (string, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      adminSecretName(pihole),
		Namespace: pihole.Namespace,
	}, secret); err != nil {
		return "", err
	}
	key := adminSecretKey(pihole)
	pw, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %q", key, adminSecretName(pihole))
	}
	return string(pw), nil
}

func (r *PiholeReconciler) reconcileSecret(ctx context.Context, pihole *piholev1alpha1.Pihole, log logr.Logger) error {
	// If an existing secret ref is set, validate it exists and skip creation
	if pihole.Spec.AdminPasswordSecretRef != nil {
		secret := &corev1.Secret{}
		err := r.Get(ctx, types.NamespacedName{Name: pihole.Spec.AdminPasswordSecretRef.Name, Namespace: pihole.Namespace}, secret)
		if err != nil {
			return fmt.Errorf("referenced adminPasswordSecretRef %q not found: %w", pihole.Spec.AdminPasswordSecretRef.Name, err)
		}
		log.Info("Using existing secret for admin password", "Secret.Name", pihole.Spec.AdminPasswordSecretRef.Name)
		return nil
	}

	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: adminSecretName(pihole), Namespace: pihole.Namespace}, secret)

	if err != nil && apierrors.IsNotFound(err) {
		secret, err := r.secretForPihole(pihole)
		if err != nil {
			log.Error(err, "Failed to define new Secret resource for pihole")
			return err
		}

		log.Info("Creating a new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
		if err = r.Create(ctx, secret); err != nil {
			log.Error(err, "Failed to create new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
			return err
		}
		return nil
	} else if err != nil {
		log.Error(err, "Failed to get Secret")
		return err
	}

	return nil
}

func (r *PiholeReconciler) reconcileService(ctx context.Context, pihole *piholev1alpha1.Pihole, log logr.Logger) error {
	if err := r.reconcileSingleService(ctx, pihole, log, "dns"); err != nil {
		return err
	}

	if err := r.reconcileSingleService(ctx, pihole, log, "web"); err != nil {
		return err
	}

	return nil
}

func (r *PiholeReconciler) reconcileSingleService(ctx context.Context, pihole *piholev1alpha1.Pihole, log logr.Logger, serviceKind string) error {
	serviceName := pihole.Name + "-" + serviceKind
	service := &corev1.Service{}
	err := r.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: pihole.Namespace}, service)

	if err != nil && apierrors.IsNotFound(err) {
		service, err := r.serviceForPihole(pihole, serviceKind)
		if err != nil {
			log.Error(err, "Failed to define new Service resource for pihole", "kind", serviceKind)
			return err
		}

		log.Info("Creating a new Service", "Service.Namespace", service.Namespace, "Service.Name", service.Name, "kind", serviceKind)
		if err = r.Create(ctx, service); err != nil {
			log.Error(err, "Failed to create new Service", "Service.Namespace", service.Namespace, "Service.Name", service.Name, "kind", serviceKind)
			return err
		}
		return nil
	} else if err != nil {
		log.Error(err, "Failed to get Service", "kind", serviceKind)
		return err
	}

	// Service exists — diff desired vs current state and update if needed.
	desiredType, desiredLBIP := desiredServiceSpec(pihole, serviceKind)
	needsUpdate := false

	if service.Spec.Type != desiredType {
		log.Info("Updating Service", "Service.Name", service.Name, "oldType", service.Spec.Type, "newType", desiredType)
		// When changing FROM NodePort to ClusterIP, strip auto-assigned nodePort values;
		// Kubernetes rejects explicit nodePort values for ClusterIP services.
		// LoadBalancer services also use nodePort, so no stripping is needed there.
		if service.Spec.Type == corev1.ServiceTypeNodePort && desiredType == corev1.ServiceTypeClusterIP {
			for i := range service.Spec.Ports {
				service.Spec.Ports[i].NodePort = 0
			}
		}
		service.Spec.Type = desiredType
		needsUpdate = true
	}

	if service.Spec.LoadBalancerIP != desiredLBIP {
		service.Spec.LoadBalancerIP = desiredLBIP
		needsUpdate = true
	}

	if needsUpdate {
		if err := r.Update(ctx, service); err != nil {
			log.Error(err, "Failed to update Service", "Service.Name", service.Name, "kind", serviceKind)
			return err
		}
	}
	return nil
}

func (r *PiholeReconciler) reconcileHeadlessService(ctx context.Context, pihole *piholev1alpha1.Pihole, log logr.Logger) error {
	serviceName := pihole.Name + "-headless"
	service := &corev1.Service{}
	err := r.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: pihole.Namespace}, service)

	if err != nil && apierrors.IsNotFound(err) {
		svc, err := r.headlessServiceForPihole(pihole)
		if err != nil {
			log.Error(err, "Failed to define new headless Service resource for pihole")
			return err
		}

		log.Info("Creating a new headless Service", "Service.Namespace", svc.Namespace, "Service.Name", svc.Name)
		if err = r.Create(ctx, svc); err != nil {
			log.Error(err, "Failed to create new headless Service", "Service.Namespace", svc.Namespace, "Service.Name", svc.Name)
			return err
		}
		return nil
	} else if err != nil {
		log.Error(err, "Failed to get headless Service")
		return err
	}
	return nil
}

func (r *PiholeReconciler) headlessServiceForPihole(pihole *piholev1alpha1.Pihole) (*corev1.Service, error) {
	labels := map[string]string{
		"app.kubernetes.io/name":       "pihole",
		"app.kubernetes.io/instance":   pihole.Name,
		"app.kubernetes.io/managed-by": "pihole-operator",
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pihole.Name + "-headless",
			Namespace: pihole.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Selector:  labels,
			Ports: []corev1.ServicePort{
				{
					Name:       "dns-tcp",
					Protocol:   corev1.ProtocolTCP,
					Port:       53,
					TargetPort: intstr.FromString("dns-tcp"),
				},
				{
					Name:       "dns-udp",
					Protocol:   corev1.ProtocolUDP,
					Port:       53,
					TargetPort: intstr.FromString("dns-udp"),
				},
				{
					Name:       "http",
					Protocol:   corev1.ProtocolTCP,
					Port:       80,
					TargetPort: intstr.FromString("http"),
				},
				{
					Name:       "https",
					Protocol:   corev1.ProtocolTCP,
					Port:       443,
					TargetPort: intstr.FromString("https"),
				},
			},
		},
	}

	if err := ctrl.SetControllerReference(pihole, svc, r.Scheme); err != nil {
		return nil, err
	}
	return svc, nil
}

func (r *PiholeReconciler) statefulSetForPihole(
	pihole *piholev1alpha1.Pihole) (*appsv1.StatefulSet, error) {
	image := "docker.io/pihole/pihole:2025.11.0"

	replicas := int32(1)
	if pihole.Spec.Size != nil {
		replicas = *pihole.Spec.Size
	}

	labels := map[string]string{
		"app.kubernetes.io/name":       "pihole",
		"app.kubernetes.io/instance":   pihole.Name,
		"app.kubernetes.io/managed-by": "pihole-operator",
	}

	storageSize := "1Gi"
	if pihole.Spec.StorageSize != "" {
		storageSize = pihole.Spec.StorageSize
	}

	vct := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: "etc-pihole",
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(storageSize),
				},
			},
		},
	}
	if pihole.Spec.StorageClass != "" {
		vct.Spec.StorageClassName = &pihole.Spec.StorageClass
	}

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pihole.Name,
			Namespace: pihole.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    &replicas,
			ServiceName: pihole.Name + "-headless",
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{vct},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:  ptr.To(int64(0)), // Run as root
						RunAsGroup: ptr.To(int64(0)),
						FSGroup:    ptr.To(int64(0)),
					},
					Containers: []corev1.Container{{
						Image:           image,
						Name:            "pihole",
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: &corev1.SecurityContext{
							RunAsUser:  ptr.To(int64(0)),
							RunAsGroup: ptr.To(int64(0)),
							Capabilities: &corev1.Capabilities{
								Add: []corev1.Capability{
									"NET_BIND_SERVICE", // Required for binding to port 53
									"CHOWN",
									"SETGID",
									"SETUID",
									"SETFCAP",      // Required for setting capabilities on pihole-FTL
									"DAC_OVERRIDE", // Required for file permission operations
								},
								Drop: []corev1.Capability{
									"ALL",
								},
							},
						},
						Ports: []corev1.ContainerPort{
							{
								ContainerPort: 53,
								Name:          "dns-tcp",
								Protocol:      corev1.ProtocolTCP,
							},
							{
								ContainerPort: 53,
								Name:          "dns-udp",
								Protocol:      corev1.ProtocolUDP,
							},
							{
								ContainerPort: 80,
								Name:          "http",
								Protocol:      corev1.ProtocolTCP,
							},
							{
								ContainerPort: 443,
								Name:          "https",
								Protocol:      corev1.ProtocolTCP,
							},
						},
						Env: []corev1.EnvVar{
							{
								Name:  "TZ",
								Value: getEnvOrDefault(pihole.Spec.Timezone, "UTC"),
							},
							{
								Name: "FTLCONF_webserver_api_password",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: adminSecretName(pihole),
										},
										Key: adminSecretKey(pihole),
									},
								},
							},
							{
								Name:  "DNSMASQ_USER",
								Value: "root",
							},
							{
								Name:  "FTLCONF_dns_listeningMode",
								Value: dnsListeningModeForServiceType(pihole.Spec.DnsServiceType),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "etc-pihole",
								MountPath: "/etc/pihole",
							},
						},
						LivenessProbe: &corev1.Probe{
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
						},
						ReadinessProbe: piholeReadinessProbe(),
					}},
				},
			},
		},
	}

	// Inject upstream DNS env var when custom servers are specified.
	// Pi-hole FTL v6 reads FTLCONF_dns_upstreams as a semicolon-separated list.
	if len(pihole.Spec.UpstreamDNS) > 0 {
		upstreamValue := strings.Join(pihole.Spec.UpstreamDNS, ";")
		sts.Spec.Template.Spec.Containers[0].Env = append(
			sts.Spec.Template.Spec.Containers[0].Env,
			corev1.EnvVar{
				Name:  "FTLCONF_dns_upstreams",
				Value: upstreamValue,
			},
		)
	}

	// Mount server TLS certificate when configured
	if pihole.Spec.ServerTLS != nil {
		certKey := pihole.Spec.ServerTLS.CertKey
		if certKey == "" {
			certKey = "tls.crt"
		}
		keyKey := pihole.Spec.ServerTLS.KeyKey
		if keyKey == "" {
			keyKey = "tls.key"
		}

		// Mount the TLS secret as a volume
		sts.Spec.Template.Spec.Volumes = append(sts.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "server-tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: pihole.Spec.ServerTLS.SecretName,
				},
			},
		})

		// Mount the volume into the pihole container
		sts.Spec.Template.Spec.Containers[0].VolumeMounts = append(
			sts.Spec.Template.Spec.Containers[0].VolumeMounts,
			corev1.VolumeMount{
				Name:      "server-tls",
				MountPath: "/etc/pihole/tls",
				ReadOnly:  true,
			},
		)

		// Set FTLCONF env vars to point Pi-hole at the mounted cert and key
		sts.Spec.Template.Spec.Containers[0].Env = append(
			sts.Spec.Template.Spec.Containers[0].Env,
			corev1.EnvVar{
				Name:  "FTLCONF_webserver_tls_cert",
				Value: fmt.Sprintf("/etc/pihole/tls/%s", certKey),
			},
			corev1.EnvVar{
				Name:  "FTLCONF_webserver_tls_key",
				Value: fmt.Sprintf("/etc/pihole/tls/%s", keyKey),
			},
		)
	}

	// Set resource requests/limits if specified
	if pihole.Spec.Resources != nil {
		sts.Spec.Template.Spec.Containers[0].Resources = *pihole.Spec.Resources
	}

	if err := ctrl.SetControllerReference(pihole, sts, r.Scheme); err != nil {
		return nil, err
	}
	return sts, nil
}

// piholeReadinessProbe returns the canonical readiness probe for the pihole container.
// Using a DNS exec probe (rather than HTTP) ensures the pod is only marked ready once
// the DNS resolver is fully operational — not just the web UI.
// Both the StatefulSet creation path and the reconcile/update path reference this
// function so the probe definition stays in a single place.
func piholeReadinessProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{"dig", "@127.0.0.1", "-p", "53", "localhost", "+short", "+time=2", "+tries=1"},
			},
		},
		InitialDelaySeconds: 30,
		PeriodSeconds:       10,
		TimeoutSeconds:      5,
		FailureThreshold:    3,
		SuccessThreshold:    1, // Kubernetes API server defaults this to 1; set explicitly so reflect.DeepEqual works correctly.
	}
}

func getEnvOrDefault(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

func dnsListeningModeForServiceType(serviceType string) string {
	switch serviceType {
	case string(corev1.ServiceTypeClusterIP):
		return "local"
	case "", string(corev1.ServiceTypeNodePort), string(corev1.ServiceTypeLoadBalancer):
		return "all"
	default:
		// CRD validation should prevent unknown values; keep permissive behavior.
		return "all"
	}
}

func (r *PiholeReconciler) secretForPihole(
	pihole *piholev1alpha1.Pihole) (*corev1.Secret, error) {

	labels := map[string]string{
		"app.kubernetes.io/name":       "pihole",
		"app.kubernetes.io/instance":   pihole.Name,
		"app.kubernetes.io/managed-by": "pihole-operator",
	}

	password := pihole.Spec.AdminPassword
	if password == "" {
		password = generateRandomPassword(16)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pihole.Name + "-admin",
			Namespace: pihole.Namespace,
			Labels:    labels,
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"password": password,
		},
	}

	if err := ctrl.SetControllerReference(pihole, secret, r.Scheme); err != nil {
		return nil, err
	}
	return secret, nil
}

// desiredServiceSpec returns the desired ServiceType and LoadBalancerIP for a given serviceKind.
// This is the single source of truth used by both the create path and the drift-detection update path.
func desiredServiceSpec(pihole *piholev1alpha1.Pihole, serviceKind string) (corev1.ServiceType, string) {
	if serviceKind == "web" {
		serviceType := corev1.ServiceTypeClusterIP
		if pihole.Spec.WebServiceType != "" {
			serviceType = corev1.ServiceType(pihole.Spec.WebServiceType)
		}
		lbIP := ""
		if serviceType == corev1.ServiceTypeLoadBalancer {
			lbIP = pihole.Spec.WebLoadBalancerIP
		}
		return serviceType, lbIP
	}
	// dns (default)
	serviceType := corev1.ServiceTypeNodePort
	if pihole.Spec.DnsServiceType != "" {
		serviceType = corev1.ServiceType(pihole.Spec.DnsServiceType)
	}
	lbIP := ""
	if serviceType == corev1.ServiceTypeLoadBalancer {
		lbIP = pihole.Spec.DnsLoadBalancerIP
	}
	return serviceType, lbIP
}

func (r *PiholeReconciler) serviceForPihole(
	pihole *piholev1alpha1.Pihole, serviceKind string) (*corev1.Service, error) {

	labels := map[string]string{
		"app.kubernetes.io/name":       "pihole",
		"app.kubernetes.io/instance":   pihole.Name,
		"app.kubernetes.io/managed-by": "pihole-operator",
	}

	serviceType, lbIP := desiredServiceSpec(pihole, serviceKind)

	var svc *corev1.Service

	if serviceKind == "web" {
		svc = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pihole.Name + "-web",
				Namespace: pihole.Namespace,
				Labels:    labels,
			},
			Spec: corev1.ServiceSpec{
				Type:           serviceType,
				LoadBalancerIP: lbIP,
				Selector:       labels,
				Ports: []corev1.ServicePort{
					{
						Name:       "http",
						Protocol:   corev1.ProtocolTCP,
						Port:       80,
						TargetPort: intstr.FromString("http"),
					},
					{
						Name:       "https",
						Protocol:   corev1.ProtocolTCP,
						Port:       443,
						TargetPort: intstr.FromString("https"),
					},
				},
			},
		}
	} else if serviceKind == "dns" {
		svc = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pihole.Name + "-dns",
				Namespace: pihole.Namespace,
				Labels:    labels,
			},
			Spec: corev1.ServiceSpec{
				Type:           serviceType,
				LoadBalancerIP: lbIP,
				Selector:       labels,
				Ports: []corev1.ServicePort{
					{
						Name:       "dns-tcp",
						Protocol:   corev1.ProtocolTCP,
						Port:       53,
						TargetPort: intstr.FromString("dns-tcp"),
					},
					{
						Name:       "dns-udp",
						Protocol:   corev1.ProtocolUDP,
						Port:       53,
						TargetPort: intstr.FromString("dns-udp"),
					},
				},
			},
		}
	} else {
		return nil, fmt.Errorf("invalid serviceKind: %s, must be 'web' or 'dns'", serviceKind)
	}

	if err := ctrl.SetControllerReference(pihole, svc, r.Scheme); err != nil {
		return nil, err
	}
	return svc, nil
}

func generateRandomPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func (r *PiholeReconciler) reconcileIngress(ctx context.Context, pihole *piholev1alpha1.Pihole, log logr.Logger) error {
	ingressName := pihole.Name + "-web"

	// If ingress is not enabled, delete any existing ingress and return
	if pihole.Spec.Ingress == nil || !pihole.Spec.Ingress.Enabled {
		existing := &networkingv1.Ingress{}
		err := r.Get(ctx, types.NamespacedName{Name: ingressName, Namespace: pihole.Namespace}, existing)
		if err == nil {
			log.Info("Deleting Ingress since ingress is disabled", "Ingress.Name", ingressName)
			if err := r.Delete(ctx, existing); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
		return nil
	}

	labels := map[string]string{
		"app.kubernetes.io/name":       "pihole",
		"app.kubernetes.io/instance":   pihole.Name,
		"app.kubernetes.io/managed-by": "pihole-operator",
	}

	pathType := networkingv1.PathTypePrefix
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        ingressName,
			Namespace:   pihole.Namespace,
			Labels:      labels,
			Annotations: pihole.Spec.Ingress.Annotations,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: pihole.Spec.Ingress.IngressClassName,
			Rules: []networkingv1.IngressRule{
				{
					Host: pihole.Spec.Ingress.Host,
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathType,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: pihole.Name + "-web",
											Port: networkingv1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Configure TLS if enabled
	if pihole.Spec.Ingress.TLS != nil && pihole.Spec.Ingress.TLS.Enabled {
		tlsConfig := networkingv1.IngressTLS{
			Hosts: []string{pihole.Spec.Ingress.Host},
		}
		if pihole.Spec.Ingress.TLS.SecretName != "" {
			tlsConfig.SecretName = pihole.Spec.Ingress.TLS.SecretName
		}
		ingress.Spec.TLS = []networkingv1.IngressTLS{tlsConfig}
	}

	if err := ctrl.SetControllerReference(pihole, ingress, r.Scheme); err != nil {
		return err
	}

	// Check if ingress already exists
	existing := &networkingv1.Ingress{}
	err := r.Get(ctx, types.NamespacedName{Name: ingressName, Namespace: pihole.Namespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		log.Info("Creating Ingress", "Ingress.Namespace", ingress.Namespace, "Ingress.Name", ingress.Name)
		return r.Create(ctx, ingress)
	} else if err != nil {
		return err
	}

	// Update existing ingress
	existing.Spec = ingress.Spec
	existing.Labels = ingress.Labels
	existing.Annotations = ingress.Annotations
	log.Info("Updating Ingress", "Ingress.Namespace", existing.Namespace, "Ingress.Name", existing.Name)
	return r.Update(ctx, existing)
}

// reconcilePDB creates or deletes a PodDisruptionBudget for the Pihole StatefulSet.
// A PDB with minAvailable=1 is created when size > 1, to ensure at least one
// Pi-hole pod survives voluntary disruptions (node drains, rolling updates, etc.).
// When size drops to 1 or below, any existing PDB is deleted.
func (r *PiholeReconciler) reconcilePDB(ctx context.Context, pihole *piholev1alpha1.Pihole, log logr.Logger) error {
	pdbName := pihole.Name
	size := int32(1)
	if pihole.Spec.Size != nil {
		size = *pihole.Spec.Size
	}

	existing := &policyv1.PodDisruptionBudget{}
	err := r.Get(ctx, types.NamespacedName{Name: pdbName, Namespace: pihole.Namespace}, existing)

	// If size <= 1, delete any existing PDB and return
	if size <= 1 {
		if err == nil {
			log.Info("Deleting PodDisruptionBudget since size <= 1", "PDB.Name", pdbName)
			if delErr := r.Delete(ctx, existing); delErr != nil && !apierrors.IsNotFound(delErr) {
				return delErr
			}
		}
		return nil
	}

	// size > 1: ensure the PDB exists
	labels := map[string]string{
		"app.kubernetes.io/name":       "pihole",
		"app.kubernetes.io/instance":   pihole.Name,
		"app.kubernetes.io/managed-by": "pihole-operator",
	}

	minAvailable := intstr.FromInt(1)
	desired := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pdbName,
			Namespace: pihole.Namespace,
			Labels:    labels,
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable: &minAvailable,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
		},
	}

	if err := ctrl.SetControllerReference(pihole, desired, r.Scheme); err != nil {
		return err
	}

	if apierrors.IsNotFound(err) {
		log.Info("Creating PodDisruptionBudget", "PDB.Namespace", desired.Namespace, "PDB.Name", desired.Name)
		return r.Create(ctx, desired)
	} else if err != nil {
		return err
	}

	// PDB already exists; nothing to update (minAvailable=1 is always the same)
	return nil
}

func (r *PiholeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&piholev1alpha1.Pihole{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Owns(&networkingv1.Ingress{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Complete(r)
}
