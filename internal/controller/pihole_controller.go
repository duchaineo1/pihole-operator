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
	"reflect"
	piholev1alpha1 "github.com/duchaineo1/pihole-operator/api/v1alpha1"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"math/rand"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"time"
)

const (
	typeAvailablePihole = "Available"
)

// PiholeReconciler reconciles a Pihole object
type PiholeReconciler struct {
	client.Client
	Scheme *runtime.Scheme
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
// +kubebuilder:rbac:groups=pihole-operator.org,resources=piholes,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete

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

	return ctrl.Result{}, nil
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
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/admin/",
									Port: intstr.FromInt(80),
								},
							},
							InitialDelaySeconds: 30,
							PeriodSeconds:       10,
							TimeoutSeconds:      3,
							FailureThreshold:    3,
						},
					}},
				},
			},
		},
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

func getEnvOrDefault(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
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

func (r *PiholeReconciler) serviceForPihole(
	pihole *piholev1alpha1.Pihole, serviceKind string) (*corev1.Service, error) {

	labels := map[string]string{
		"app.kubernetes.io/name":       "pihole",
		"app.kubernetes.io/instance":   pihole.Name,
		"app.kubernetes.io/managed-by": "pihole-operator",
	}

	var svc *corev1.Service
	var serviceType corev1.ServiceType

	if serviceKind == "web" {
		serviceType = corev1.ServiceTypeClusterIP
		if pihole.Spec.WebServiceType != "" {
			serviceType = corev1.ServiceType(pihole.Spec.WebServiceType)
		}

		svc = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pihole.Name + "-web",
				Namespace: pihole.Namespace,
				Labels:    labels,
			},
			Spec: corev1.ServiceSpec{
				Type:     serviceType,
				Selector: labels,
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

		if serviceType == corev1.ServiceTypeLoadBalancer && pihole.Spec.WebLoadBalancerIP != "" {
			svc.Spec.LoadBalancerIP = pihole.Spec.WebLoadBalancerIP
		}
	} else if serviceKind == "dns" {
		serviceType = corev1.ServiceTypeNodePort
		if pihole.Spec.DnsServiceType != "" {
			serviceType = corev1.ServiceType(pihole.Spec.DnsServiceType)
		}

		svc = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pihole.Name + "-dns",
				Namespace: pihole.Namespace,
				Labels:    labels,
			},
			Spec: corev1.ServiceSpec{
				Type:     serviceType,
				Selector: labels,
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

		if serviceType == corev1.ServiceTypeLoadBalancer && pihole.Spec.DnsLoadBalancerIP != "" {
			svc.Spec.LoadBalancerIP = pihole.Spec.DnsLoadBalancerIP
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

func (r *PiholeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&piholev1alpha1.Pihole{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Owns(&networkingv1.Ingress{}).
		Complete(r)
}
