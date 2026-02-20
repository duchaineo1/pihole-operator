//go:build e2e
// +build e2e

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

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/duchaineo1/pihole-operator/test/utils"
)

// namespace where the project is deployed in
const namespace = "pihole-operator-system"

// testNamespace is where we create test CRs (separate from the operator)
const testNamespace = "pihole-e2e-test"

// serviceAccountName created for the project
const serviceAccountName = "pihole-operator-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "pihole-operator-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "pihole-operator-metrics-binding"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("creating test namespace for CRs")
		cmd = exec.Command("kubectl", "create", "ns", testNamespace)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace")

		By("creating a shared Pihole CR for Whitelist/Blocklist/DNSRecord tests")
		sharedPiholeYAML := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Pihole
metadata:
  name: shared-pihole
  namespace: %s
spec:
  size: 1
  adminPassword: "shared-test-pw"
  dnsServiceType: "ClusterIP"
  webServiceType: "ClusterIP"
`, testNamespace)
		Expect(applyManifest(sharedPiholeYAML)).To(Succeed(), "Failed to create shared Pihole")
	})

	AfterAll(func() {
		By("cleaning up shared Pihole")
		cmd := exec.Command("kubectl", "delete", "pihole", "shared-pihole", "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("cleaning up test CRs namespace")
		cmd = exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("cleaning up the curl pod for metrics")
		cmd = exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", testNamespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=pihole-operator-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("waiting for the metrics endpoint to be ready")
			verifyMetricsEndpointReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "endpoints", metricsServiceName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("8443"), "Metrics endpoint is not ready")
			}
			Eventually(verifyMetricsEndpointReady).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("controller-runtime.metrics\tServing metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted).Should(Succeed())

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			verifyMetricsAvailable := func(g Gomega) {
				metricsOutput, err := getMetricsOutput()
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
				g.Expect(metricsOutput).NotTo(BeEmpty())
				g.Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
			}
			Eventually(verifyMetricsAvailable, 2*time.Minute).Should(Succeed())
		})
	})

	// ---------------------------------------------------------------
	// Pihole CR tests
	// ---------------------------------------------------------------
	Context("Pihole CR", func() {
		const piholeName = "test-pihole"

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "pihole", piholeName, "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should create a basic Pihole and reconcile all child resources", func() {
			By("applying a basic Pihole CR")
			piholeYAML := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Pihole
metadata:
  name: %s
  namespace: %s
spec:
  size: 1
  adminPassword: "testpassword123"
  timezone: "America/New_York"
  storageSize: "2Gi"
  dnsServiceType: "ClusterIP"
  webServiceType: "ClusterIP"
`, piholeName, testNamespace)
			err := applyManifest(piholeYAML)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply Pihole CR")

			By("verifying the StatefulSet is created with correct spec")
			verifySTS := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", piholeName,
					"-n", testNamespace, "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "StatefulSet should exist")

				var sts map[string]interface{}
				g.Expect(json.Unmarshal([]byte(output), &sts)).To(Succeed())

				spec := sts["spec"].(map[string]interface{})

				// Verify replicas
				replicas := int(spec["replicas"].(float64))
				g.Expect(replicas).To(Equal(1), "Should have 1 replica")

				// Verify the container image
				template := spec["template"].(map[string]interface{})
				podSpec := template["spec"].(map[string]interface{})
				containers := podSpec["containers"].([]interface{})
				g.Expect(containers).To(HaveLen(1))
				container := containers[0].(map[string]interface{})
				g.Expect(container["image"]).To(Equal("docker.io/pihole/pihole:2025.11.0"))

				// Verify timezone env var
				envVars := container["env"].([]interface{})
				foundTZ := false
				for _, e := range envVars {
					env := e.(map[string]interface{})
					if env["name"] == "TZ" {
						g.Expect(env["value"]).To(Equal("America/New_York"))
						foundTZ = true
					}
				}
				g.Expect(foundTZ).To(BeTrue(), "TZ env var should be set")

				// Verify VolumeClaimTemplates storage size
				vcts := spec["volumeClaimTemplates"].([]interface{})
				g.Expect(vcts).To(HaveLen(1))
				vct := vcts[0].(map[string]interface{})
				vctSpec := vct["spec"].(map[string]interface{})
				resources := vctSpec["resources"].(map[string]interface{})
				requests := resources["requests"].(map[string]interface{})
				g.Expect(requests["storage"]).To(Equal("2Gi"))
			}
			Eventually(verifySTS).Should(Succeed())

			By("verifying the admin Secret is created")
			verifySecret := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", piholeName+"-admin",
					"-n", testNamespace, "-o", "jsonpath={.data.password}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Admin secret should exist")
				g.Expect(output).NotTo(BeEmpty(), "Password should not be empty")
			}
			Eventually(verifySecret).Should(Succeed())

			By("verifying the DNS service is created with correct type")
			verifyDNSService := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "service", piholeName+"-dns",
					"-n", testNamespace, "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "DNS service should exist")

				var svc map[string]interface{}
				g.Expect(json.Unmarshal([]byte(output), &svc)).To(Succeed())
				spec := svc["spec"].(map[string]interface{})
				g.Expect(spec["type"]).To(Equal("ClusterIP"))

				// Verify DNS ports
				ports := spec["ports"].([]interface{})
				portNames := []string{}
				for _, p := range ports {
					port := p.(map[string]interface{})
					portNames = append(portNames, port["name"].(string))
					g.Expect(int(port["port"].(float64))).To(Equal(53))
				}
				g.Expect(portNames).To(ContainElements("dns-tcp", "dns-udp"))
			}
			Eventually(verifyDNSService).Should(Succeed())

			By("verifying the Web service is created with correct type")
			verifyWebService := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "service", piholeName+"-web",
					"-n", testNamespace, "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Web service should exist")

				var svc map[string]interface{}
				g.Expect(json.Unmarshal([]byte(output), &svc)).To(Succeed())
				spec := svc["spec"].(map[string]interface{})
				g.Expect(spec["type"]).To(Equal("ClusterIP"))

				// Verify web ports
				ports := spec["ports"].([]interface{})
				portNames := []string{}
				for _, p := range ports {
					port := p.(map[string]interface{})
					portNames = append(portNames, port["name"].(string))
				}
				g.Expect(portNames).To(ContainElements("http", "https"))
			}
			Eventually(verifyWebService).Should(Succeed())

			By("verifying the headless service is created")
			verifyHeadless := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "service", piholeName+"-headless",
					"-n", testNamespace, "-o", "jsonpath={.spec.clusterIP}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Headless service should exist")
				g.Expect(output).To(Equal("None"))
			}
			Eventually(verifyHeadless).Should(Succeed())

			By("verifying the Pihole status is updated")
			verifyStatus := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pihole", piholeName,
					"-n", testNamespace, "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())

				var pihole map[string]interface{}
				g.Expect(json.Unmarshal([]byte(output), &pihole)).To(Succeed())
				status := pihole["status"].(map[string]interface{})

				g.Expect(status["adminPasswordSecret"]).To(Equal(piholeName + "-admin"))
				g.Expect(status["serviceName"]).To(Equal(piholeName))

				// Verify condition
				conditions := status["conditions"].([]interface{})
				g.Expect(conditions).NotTo(BeEmpty())
				found := false
				for _, c := range conditions {
					cond := c.(map[string]interface{})
					if cond["type"] == "Available" {
						g.Expect(cond["status"]).To(Equal("True"))
						found = true
					}
				}
				g.Expect(found).To(BeTrue(), "Should have Available=True condition")
			}
			Eventually(verifyStatus, 3*time.Minute).Should(Succeed())

			By("verifying owner references are set on child resources")
			verifyOwnerRef := func(g Gomega) {
				for _, resource := range []string{
					"statefulset/" + piholeName,
					"service/" + piholeName + "-dns",
					"service/" + piholeName + "-web",
					"service/" + piholeName + "-headless",
					"secret/" + piholeName + "-admin",
				} {
					cmd := exec.Command("kubectl", "get", resource,
						"-n", testNamespace, "-o", "jsonpath={.metadata.ownerReferences[0].kind}")
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred(), "Resource %s should exist", resource)
					g.Expect(output).To(Equal("Pihole"), "Resource %s should be owned by Pihole", resource)
				}
			}
			Eventually(verifyOwnerRef).Should(Succeed())
		})

		It("should scale the StatefulSet when size is updated", func() {
			By("patching the Pihole CR to size 2")
			cmd := exec.Command("kubectl", "patch", "pihole", piholeName,
				"-n", testNamespace, "--type=merge",
				"-p", `{"spec":{"size":2}}`)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the StatefulSet is scaled to 2 replicas")
			verifyScale := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", piholeName,
					"-n", testNamespace, "-o", "jsonpath={.spec.replicas}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("2"))
			}
			Eventually(verifyScale).Should(Succeed())

			By("scaling back to 1")
			cmd = exec.Command("kubectl", "patch", "pihole", piholeName,
				"-n", testNamespace, "--type=merge",
				"-p", `{"spec":{"size":1}}`)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			verifyScaleDown := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", piholeName,
					"-n", testNamespace, "-o", "jsonpath={.spec.replicas}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("1"))
			}
			Eventually(verifyScaleDown).Should(Succeed())
		})

		It("should update the container image when spec.image changes", func() {
			By("patching the Pihole CR with a custom image")
			cmd := exec.Command("kubectl", "patch", "pihole", piholeName,
				"-n", testNamespace, "--type=merge",
				"-p", `{"spec":{"image":"docker.io/pihole/pihole:2025.06.0"}}`)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the StatefulSet container image is updated")
			verifyImage := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", piholeName,
					"-n", testNamespace,
					"-o", "jsonpath={.spec.template.spec.containers[0].image}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("docker.io/pihole/pihole:2025.06.0"))
			}
			Eventually(verifyImage).Should(Succeed())
		})
	})

	// ---------------------------------------------------------------
	// Pihole with existing Secret ref
	// ---------------------------------------------------------------
	Context("Pihole with existing Secret", func() {
		const piholeName = "test-pihole-secretref"
		const secretName = "my-existing-secret"

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "pihole", piholeName, "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "secret", secretName, "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should use an existing secret when adminPasswordSecretRef is set", func() {
			By("creating a pre-existing secret")
			cmd := exec.Command("kubectl", "create", "secret", "generic", secretName,
				"--from-literal=password=mysecretpassword",
				"-n", testNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("applying a Pihole CR referencing the existing secret")
			piholeYAML := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Pihole
metadata:
  name: %s
  namespace: %s
spec:
  size: 1
  adminPasswordSecretRef:
    name: %s
    key: password
`, piholeName, testNamespace, secretName)
			err = applyManifest(piholeYAML)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the operator does NOT create a new admin secret")
			verifyNoAutoSecret := func(g Gomega) {
				// The auto-generated secret name would be <piholeName>-admin
				cmd := exec.Command("kubectl", "get", "secret", piholeName+"-admin",
					"-n", testNamespace, "--ignore-not-found", "-o", "name")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(BeEmpty(),
					"Operator should not create auto-generated secret when secretRef is set")
			}
			// Wait for reconciliation to happen first
			time.Sleep(5 * time.Second)
			Consistently(verifyNoAutoSecret, 10*time.Second, 2*time.Second).Should(Succeed())

			By("verifying the StatefulSet references the existing secret")
			verifySTS := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", piholeName,
					"-n", testNamespace, "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())

				var sts map[string]interface{}
				g.Expect(json.Unmarshal([]byte(output), &sts)).To(Succeed())

				spec := sts["spec"].(map[string]interface{})
				template := spec["template"].(map[string]interface{})
				podSpec := template["spec"].(map[string]interface{})
				containers := podSpec["containers"].([]interface{})
				container := containers[0].(map[string]interface{})
				envVars := container["env"].([]interface{})

				foundSecretRef := false
				for _, e := range envVars {
					env := e.(map[string]interface{})
					if env["name"] == "FTLCONF_webserver_api_password" {
						valueFrom := env["valueFrom"].(map[string]interface{})
						secretKeyRef := valueFrom["secretKeyRef"].(map[string]interface{})
						g.Expect(secretKeyRef["name"]).To(Equal(secretName))
						g.Expect(secretKeyRef["key"]).To(Equal("password"))
						foundSecretRef = true
					}
				}
				g.Expect(foundSecretRef).To(BeTrue(), "Should reference the existing secret")
			}
			Eventually(verifySTS).Should(Succeed())

			By("verifying the status references the existing secret")
			verifyStatus := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pihole", piholeName,
					"-n", testNamespace, "-o", "jsonpath={.status.adminPasswordSecret}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(secretName))
			}
			Eventually(verifyStatus, 3*time.Minute).Should(Succeed())
		})
	})

	// ---------------------------------------------------------------
	// CRD validation tests
	// ---------------------------------------------------------------
	Context("CRD validation", func() {
		It("should reject a Whitelist with no domains", func() {
			yaml := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Whitelist
metadata:
  name: bad-whitelist
  namespace: %s
spec:
  domains: []
`, testNamespace)
			err := applyManifest(yaml)
			Expect(err).To(HaveOccurred(), "Should reject Whitelist with empty domains")
		})

		It("should reject a Blocklist with no sources", func() {
			yaml := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Blocklist
metadata:
  name: bad-blocklist
  namespace: %s
spec:
  sources: []
`, testNamespace)
			err := applyManifest(yaml)
			Expect(err).To(HaveOccurred(), "Should reject Blocklist with empty sources")
		})

		It("should reject a PiholeDNSRecord with invalid record type", func() {
			yaml := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: PiholeDNSRecord
metadata:
  name: bad-dnsrecord
  namespace: %s
spec:
  hostname: test.local
  recordType: MX
  ipAddress: "1.2.3.4"
`, testNamespace)
			err := applyManifest(yaml)
			Expect(err).To(HaveOccurred(), "Should reject PiholeDNSRecord with invalid recordType")
		})

		It("should reject a Pihole with invalid dnsServiceType", func() {
			yaml := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Pihole
metadata:
  name: bad-pihole
  namespace: %s
spec:
  size: 1
  dnsServiceType: "InvalidType"
`, testNamespace)
			err := applyManifest(yaml)
			Expect(err).To(HaveOccurred(), "Should reject Pihole with invalid dnsServiceType")
		})

		It("should reject a Blocklist with syncInterval below minimum", func() {
			yaml := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Blocklist
metadata:
  name: bad-sync
  namespace: %s
spec:
  sources:
    - https://example.com/hosts
  syncInterval: 5
`, testNamespace)
			err := applyManifest(yaml)
			Expect(err).To(HaveOccurred(), "Should reject Blocklist with syncInterval < 60")
		})
	})

	// ---------------------------------------------------------------
	// Whitelist CR tests
	// ---------------------------------------------------------------
	Context("Whitelist CR", func() {
		const whitelistName = "test-whitelist"

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "whitelist", whitelistName, "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should accept a valid Whitelist and update status", func() {
			By("applying a valid Whitelist CR")
			yaml := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Whitelist
metadata:
  name: %s
  namespace: %s
spec:
  enabled: true
  domains:
    - "example.com"
    - "safe-site.org"
  description: "E2E test whitelist"
`, whitelistName, testNamespace)
			err := applyManifest(yaml)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the Whitelist CR exists with correct spec")
			verifySpec := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "whitelist", whitelistName,
					"-n", testNamespace, "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())

				var wl map[string]interface{}
				g.Expect(json.Unmarshal([]byte(output), &wl)).To(Succeed())
				spec := wl["spec"].(map[string]interface{})
				g.Expect(spec["enabled"]).To(BeTrue())

				domains := spec["domains"].([]interface{})
				g.Expect(domains).To(HaveLen(2))
				g.Expect(domains).To(ContainElements("example.com", "safe-site.org"))
				g.Expect(spec["description"]).To(Equal("E2E test whitelist"))
			}
			Eventually(verifySpec).Should(Succeed())

			By("verifying the Whitelist has a status condition set by the controller")
			verifyStatus := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "whitelist", whitelistName,
					"-n", testNamespace, "-o", "jsonpath={.status.conditions}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(), "Controller should set status conditions")
			}
			Eventually(verifyStatus, 2*time.Minute).Should(Succeed())
		})
	})

	// ---------------------------------------------------------------
	// Blocklist CR tests
	// ---------------------------------------------------------------
	Context("Blocklist CR", func() {
		const blocklistName = "test-blocklist"

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "blocklist", blocklistName, "-n", testNamespace, "--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
			// Force-remove finalizer if stuck
			cmd = exec.Command("kubectl", "patch", "blocklist", blocklistName,
				"-n", testNamespace, "--type=merge",
				"-p", `{"metadata":{"finalizers":null}}`)
			_, _ = utils.Run(cmd)
		})

		It("should accept a valid Blocklist and set a finalizer", func() {
			By("applying a valid Blocklist CR")
			yaml := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Blocklist
metadata:
  name: %s
  namespace: %s
spec:
  enabled: true
  sources:
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
  description: "E2E test blocklist"
  syncInterval: 1440
`, blocklistName, testNamespace)
			err := applyManifest(yaml)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the Blocklist CR has a finalizer")
			verifyFinalizer := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "blocklist", blocklistName,
					"-n", testNamespace, "-o", "jsonpath={.metadata.finalizers}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("pihole-operator.org/blocklist-finalizer"))
			}
			Eventually(verifyFinalizer).Should(Succeed())

			By("verifying the Blocklist has a status condition set by the controller")
			verifyStatus := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "blocklist", blocklistName,
					"-n", testNamespace, "-o", "jsonpath={.status.conditions}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(), "Controller should set status conditions")
			}
			Eventually(verifyStatus, 2*time.Minute).Should(Succeed())
		})
	})

	// ---------------------------------------------------------------
	// PiholeDNSRecord CR tests
	// ---------------------------------------------------------------
	Context("PiholeDNSRecord CR", func() {
		const aRecordName = "test-a-record"
		const cnameRecordName = "test-cname-record"

		AfterAll(func() {
			for _, name := range []string{aRecordName, cnameRecordName} {
				cmd := exec.Command("kubectl", "delete", "piholednsrecord", name, "-n", testNamespace, "--ignore-not-found", "--timeout=30s")
				_, _ = utils.Run(cmd)
				cmd = exec.Command("kubectl", "patch", "piholednsrecord", name,
					"-n", testNamespace, "--type=merge",
					"-p", `{"metadata":{"finalizers":null}}`)
				_, _ = utils.Run(cmd)
			}
		})

		It("should accept a valid A record", func() {
			yaml := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: PiholeDNSRecord
metadata:
  name: %s
  namespace: %s
spec:
  hostname: myhost.home.local
  recordType: A
  ipAddress: "192.168.1.100"
  description: "E2E test A record"
`, aRecordName, testNamespace)
			err := applyManifest(yaml)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the PiholeDNSRecord spec is correct")
			verifySpec := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "piholednsrecord", aRecordName,
					"-n", testNamespace, "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())

				var rec map[string]interface{}
				g.Expect(json.Unmarshal([]byte(output), &rec)).To(Succeed())
				spec := rec["spec"].(map[string]interface{})
				g.Expect(spec["hostname"]).To(Equal("myhost.home.local"))
				g.Expect(spec["recordType"]).To(Equal("A"))
				g.Expect(spec["ipAddress"]).To(Equal("192.168.1.100"))
			}
			Eventually(verifySpec).Should(Succeed())

			By("verifying the controller set a finalizer")
			verifyFinalizer := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "piholednsrecord", aRecordName,
					"-n", testNamespace, "-o", "jsonpath={.metadata.finalizers}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("pihole-operator.org/dnsrecord-finalizer"))
			}
			Eventually(verifyFinalizer).Should(Succeed())
		})

		It("should accept a valid CNAME record", func() {
			yaml := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: PiholeDNSRecord
metadata:
  name: %s
  namespace: %s
spec:
  hostname: alias.home.local
  recordType: CNAME
  cnameTarget: myhost.home.local
  description: "E2E test CNAME record"
`, cnameRecordName, testNamespace)
			err := applyManifest(yaml)
			Expect(err).NotTo(HaveOccurred())

			verifySpec := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "piholednsrecord", cnameRecordName,
					"-n", testNamespace, "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())

				var rec map[string]interface{}
				g.Expect(json.Unmarshal([]byte(output), &rec)).To(Succeed())
				spec := rec["spec"].(map[string]interface{})
				g.Expect(spec["hostname"]).To(Equal("alias.home.local"))
				g.Expect(spec["recordType"]).To(Equal("CNAME"))
				g.Expect(spec["cnameTarget"]).To(Equal("myhost.home.local"))
			}
			Eventually(verifySpec).Should(Succeed())
		})
	})

	// ---------------------------------------------------------------
	// Upstream DNS e2e tests
	// ---------------------------------------------------------------
	Context("Pihole CR with custom upstream DNS", func() {
		const piholeName = "test-pihole-upstream-dns"

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "pihole", piholeName, "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should set FTLCONF_dns_upstreams env var in the StatefulSet", func() {
			By("applying a Pihole CR with custom upstream DNS servers")
			piholeYAML := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Pihole
metadata:
  name: %s
  namespace: %s
spec:
  size: 1
  adminPassword: "testpassword123"
  dnsServiceType: "ClusterIP"
  webServiceType: "ClusterIP"
  upstreamDNS:
    - "1.1.1.1"
    - "1.0.0.1"
`, piholeName, testNamespace)
			err := applyManifest(piholeYAML)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply Pihole CR with upstream DNS")

			By("verifying FTLCONF_dns_upstreams is set in the StatefulSet")
			verifyUpstreamDNS := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", piholeName,
					"-n", testNamespace, "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "StatefulSet should exist")

				var sts map[string]interface{}
				g.Expect(json.Unmarshal([]byte(output), &sts)).To(Succeed())
				spec := sts["spec"].(map[string]interface{})
				template := spec["template"].(map[string]interface{})
				podSpec := template["spec"].(map[string]interface{})
				containers := podSpec["containers"].([]interface{})
				container := containers[0].(map[string]interface{})
				envVars := container["env"].([]interface{})

				foundUpstream := false
				for _, e := range envVars {
					env := e.(map[string]interface{})
					if env["name"] == "FTLCONF_dns_upstreams" {
						g.Expect(env["value"]).To(Equal("1.1.1.1;1.0.0.1"))
						foundUpstream = true
					}
				}
				g.Expect(foundUpstream).To(BeTrue(), "FTLCONF_dns_upstreams env var should be set")
			}
			Eventually(verifyUpstreamDNS).Should(Succeed())

			By("verifying no PDB exists (size=1)")
			verifyNoPDB := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "poddisruptionbudget", piholeName,
					"-n", testNamespace, "--ignore-not-found", "-o", "name")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(BeEmpty(), "No PDB should exist for size=1")
			}
			Eventually(verifyNoPDB).Should(Succeed())
		})
	})

	// ---------------------------------------------------------------
	// RBAC permission checks
	// ---------------------------------------------------------------
	Context("Controller RBAC permissions", func() {
		// rbacCanI runs `kubectl auth can-i <verb> <resource> --as=system:serviceaccount:<ns>:<sa>`
		// and returns true when the answer is "yes".
		rbacCanI := func(verb, resource, subresource string) bool {
			resourceArg := resource
			if subresource != "" {
				resourceArg = resource + "/" + subresource
			}
			cmd := exec.Command("kubectl", "auth", "can-i", verb, resourceArg,
				"--as=system:serviceaccount:"+namespace+":"+serviceAccountName,
				"-n", testNamespace)
			out, err := utils.Run(cmd)
			if err != nil {
				return false
			}
			return strings.TrimSpace(out) == "yes"
		}

		It("should have core API group permissions", func() {
			By("checking pod read permissions")
			Expect(rbacCanI("get", "pods", "")).To(BeTrue(),
				"controller SA must be able to get pods")
			Expect(rbacCanI("list", "pods", "")).To(BeTrue(),
				"controller SA must be able to list pods")
			Expect(rbacCanI("watch", "pods", "")).To(BeTrue(),
				"controller SA must be able to watch pods")

			By("checking secrets permissions")
			Expect(rbacCanI("get", "secrets", "")).To(BeTrue(),
				"controller SA must be able to get secrets")
			Expect(rbacCanI("create", "secrets", "")).To(BeTrue(),
				"controller SA must be able to create secrets")
			Expect(rbacCanI("update", "secrets", "")).To(BeTrue(),
				"controller SA must be able to update secrets")
			Expect(rbacCanI("delete", "secrets", "")).To(BeTrue(),
				"controller SA must be able to delete secrets")

			By("checking services permissions")
			Expect(rbacCanI("get", "services", "")).To(BeTrue(),
				"controller SA must be able to get services")
			Expect(rbacCanI("create", "services", "")).To(BeTrue(),
				"controller SA must be able to create services")
			Expect(rbacCanI("update", "services", "")).To(BeTrue(),
				"controller SA must be able to update services")
			Expect(rbacCanI("delete", "services", "")).To(BeTrue(),
				"controller SA must be able to delete services")
		})

		It("should have apps API group permissions for StatefulSets", func() {
			Expect(rbacCanI("get", "statefulsets", "")).To(BeTrue(),
				"controller SA must be able to get statefulsets")
			Expect(rbacCanI("create", "statefulsets", "")).To(BeTrue(),
				"controller SA must be able to create statefulsets")
			Expect(rbacCanI("update", "statefulsets", "")).To(BeTrue(),
				"controller SA must be able to update statefulsets")
			Expect(rbacCanI("delete", "statefulsets", "")).To(BeTrue(),
				"controller SA must be able to delete statefulsets")
		})

		It("should have policy API group permissions for PodDisruptionBudgets", func() {
			By("checking PodDisruptionBudget CRUD permissions via 'kubectl auth can-i'")
			for _, verb := range []string{"get", "list", "watch", "create", "update", "patch", "delete"} {
				Expect(rbacCanI(verb, "poddisruptionbudgets", "")).To(BeTrue(),
					"controller SA must be able to %s poddisruptionbudgets (policy API group)", verb)
			}
		})

		It("should have networking.k8s.io permissions for Ingresses", func() {
			for _, verb := range []string{"get", "list", "watch", "create", "update", "patch", "delete"} {
				Expect(rbacCanI(verb, "ingresses", "")).To(BeTrue(),
					"controller SA must be able to %s ingresses", verb)
			}
		})

		It("should have pihole-operator.org permissions for custom resources", func() {
			for _, resource := range []string{"piholes", "blocklists", "whitelists", "piholednsrecords"} {
				for _, verb := range []string{"get", "list", "watch", "create", "update", "patch", "delete"} {
					Expect(rbacCanI(verb, resource, "")).To(BeTrue(),
						"controller SA must be able to %s %s", verb, resource)
				}
			}
		})

		It("should have no forbidden errors in controller logs after reconciliation", func() {
			By("ensuring at least one reconciliation has occurred by checking for a Pihole event")
			checkName := "rbac-log-check-pihole"
			piholeYAML := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Pihole
metadata:
  name: %s
  namespace: %s
spec:
  size: 1
  adminPassword: "rbaccheckpw"
  dnsServiceType: "ClusterIP"
  webServiceType: "ClusterIP"
`, checkName, testNamespace)
			Expect(applyManifest(piholeYAML)).To(Succeed(), "Failed to apply Pihole CR for log check")
			defer func() {
				cmd := exec.Command("kubectl", "delete", "pihole", checkName, "-n", testNamespace, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			}()

			By("waiting for the StatefulSet to appear (proves reconcile ran)")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", checkName, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}, 2*time.Minute).Should(Succeed())

			By("scanning controller logs for 'forbidden' errors")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			logs, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller logs")

			forbiddenLines := []string{}
			for _, line := range strings.Split(logs, "\n") {
				lower := strings.ToLower(line)
				if strings.Contains(lower, "forbidden") || strings.Contains(lower, "is not allowed") {
					forbiddenLines = append(forbiddenLines, line)
				}
			}
			Expect(forbiddenLines).To(BeEmpty(),
				"Controller logs must not contain forbidden/unauthorized errors:\n%s",
				strings.Join(forbiddenLines, "\n"))
		})
	})

	// ---------------------------------------------------------------
	// PodDisruptionBudget e2e tests
	// ---------------------------------------------------------------
	Context("Pihole CR with PodDisruptionBudget", func() {
		const piholeName = "test-pihole-pdb"

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "pihole", piholeName, "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should create a PDB when size > 1", func() {
			By("applying a Pihole CR with size=3")
			piholeYAML := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Pihole
metadata:
  name: %s
  namespace: %s
spec:
  size: 3
  adminPassword: "testpassword123"
  dnsServiceType: "ClusterIP"
  webServiceType: "ClusterIP"
`, piholeName, testNamespace)
			err := applyManifest(piholeYAML)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply Pihole CR")

			By("verifying PodDisruptionBudget is created with minAvailable=1")
			verifyPDB := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "poddisruptionbudget", piholeName,
					"-n", testNamespace, "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "PDB should exist")

				var pdb map[string]interface{}
				g.Expect(json.Unmarshal([]byte(output), &pdb)).To(Succeed())
				spec := pdb["spec"].(map[string]interface{})
				minAvailable := spec["minAvailable"]
				g.Expect(minAvailable).To(BeEquivalentTo(1), "minAvailable should be 1")

				selector := spec["selector"].(map[string]interface{})
				matchLabels := selector["matchLabels"].(map[string]interface{})
				g.Expect(matchLabels["app.kubernetes.io/instance"]).To(Equal(piholeName))
			}
			Eventually(verifyPDB).Should(Succeed())

			By("verifying PDB has correct owner reference")
			verifyPDBOwner := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "poddisruptionbudget", piholeName,
					"-n", testNamespace, "-o", "jsonpath={.metadata.ownerReferences[0].kind}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Pihole"), "PDB should be owned by Pihole")
			}
			Eventually(verifyPDBOwner).Should(Succeed())

			By("scaling down to size=1 and verifying PDB is deleted")
			cmd := exec.Command("kubectl", "patch", "pihole", piholeName,
				"-n", testNamespace, "--type=merge",
				"-p", `{"spec":{"size":1}}`)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			verifyPDBGone := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "poddisruptionbudget", piholeName,
					"-n", testNamespace, "--ignore-not-found", "-o", "name")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(BeEmpty(),
					"PDB should be deleted when size scales down to 1")
			}
			Eventually(verifyPDBGone, 2*time.Minute).Should(Succeed())
		})
	})

	// ---------------------------------------------------------------
	// Pihole CR cleanup / deletion test
	// ---------------------------------------------------------------
	Context("Pihole CR deletion", func() {
		const piholeName = "test-pihole-delete"

		It("should clean up all child resources when Pihole is deleted", func() {
			By("creating a Pihole CR")
			piholeYAML := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Pihole
metadata:
  name: %s
  namespace: %s
spec:
  size: 1
  adminPassword: "deleteme"
`, piholeName, testNamespace)
			err := applyManifest(piholeYAML)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for resources to be created")
			verifyCreated := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", piholeName,
					"-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}
			Eventually(verifyCreated).Should(Succeed())

			By("deleting the Pihole CR")
			cmd := exec.Command("kubectl", "delete", "pihole", piholeName,
				"-n", testNamespace, "--timeout=60s")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying child resources are garbage collected")
			verifyGone := func(g Gomega) {
				for _, resource := range []string{
					"statefulset/" + piholeName,
					"service/" + piholeName + "-dns",
					"service/" + piholeName + "-web",
					"service/" + piholeName + "-headless",
					"secret/" + piholeName + "-admin",
				} {
					cmd := exec.Command("kubectl", "get", resource,
						"-n", testNamespace, "--ignore-not-found", "-o", "name")
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(strings.TrimSpace(output)).To(BeEmpty(),
						"Resource %s should be deleted", resource)
				}
			}
			Eventually(verifyGone, 2*time.Minute).Should(Succeed())
		})
	})

	// ---------------------------------------------------------------
	// Config passthrough e2e tests
	// ---------------------------------------------------------------
	Context("Pihole CR with config passthrough", func() {
		const piholeName = "test-pihole-config"
		const password = "config-test-pw-12345"
		var helper *configAPITestHelper

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "pihole", piholeName, "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should apply config keys via the Pi-hole API", func() {
			By("creating a Pihole with config")
			piholeYAML := fmt.Sprintf(`apiVersion: pihole-operator.org/v1alpha1
kind: Pihole
metadata:
  name: %s
  namespace: %s
spec:
  size: 1
  adminPassword: "%s"
  dnsServiceType: "ClusterIP"
  webServiceType: "ClusterIP"
  config:
    dns.queryLogging: "true"
    dns.privacyLevel: "0"
`, piholeName, testNamespace, password)
			err := applyManifest(piholeYAML)
			Expect(err).NotTo(HaveOccurred(), "Failed to create Pihole with config")

			By("waiting for the StatefulSet pod to be Running")
			waitForPod := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", piholeName+"-0",
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"))
			}
			Eventually(waitForPod, 5*time.Minute).Should(Succeed())

			By("getting the pod IP for direct API access")
			var podIP string
			getPodIP := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", piholeName+"-0",
					"-n", testNamespace, "-o", "jsonpath={.status.podIP}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty())
				podIP = strings.TrimSpace(output)
			}
			Eventually(getPodIP).Should(Succeed())

			helper = newConfigAPITestHelper(piholeName, testNamespace, podIP, password)

			By("authenticating to the Pi-hole API")
			authSuccess := func(g Gomega) {
				err := helper.authenticate()
				g.Expect(err).NotTo(HaveOccurred(), "Authentication should succeed")
			}
			Eventually(authSuccess, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying dns.queryLogging was applied (should be 'true' from spec.config)")
			verifyQueryLogging := func(g Gomega) {
				value, err := helper.getConfig("dns.queryLogging")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(value).To(Equal("true"),
					"dns.queryLogging should be set to 'true' by the operator")
			}
			// The reconcile loop runs periodically; give it time to apply config
			Eventually(verifyQueryLogging, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying dns.privacyLevel was applied (should be '0')")
			verifyPrivacy := func(g Gomega) {
				value, err := helper.getConfig("dns.privacyLevel")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(value).To(Equal("0"),
					"dns.privacyLevel should be set to '0' by the operator")
			}
			Eventually(verifyPrivacy, 2*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should enforce desired state on drift (GitOps)", func() {
			By("manually changing dns.queryLogging to 'false' (simulating manual drift)")
			err := helper.setConfig("dns.queryLogging", "false")
			Expect(err).NotTo(HaveOccurred(), "Manual config change should succeed")

			By("verifying the drift is corrected by the operator (back to 'true')")
			verifyCorrection := func(g Gomega) {
				value, err := helper.getConfig("dns.queryLogging")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(value).To(Equal("true"),
					"Operator should revert manual drift back to spec value")
			}
			// The reconcile loop runs every ~60s by default; wait up to 3min
			Eventually(verifyCorrection, 3*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should reject keys with path traversal characters", func() {
			By("patching the Pihole CR with a malicious config key")
			cmd := exec.Command("kubectl", "patch", "pihole", piholeName,
				"-n", testNamespace, "--type=merge",
				"-p", `{"spec":{"config":{"../../etc/passwd":"bad"}}}`)
			output, err := utils.Run(cmd)

			// The kubebuilder validation won't catch map key patterns (CRD limitation),
			// but the runtime validation in the controller will skip it and log an error.
			// So we verify the CR is accepted, but the controller logs an error.
			if err != nil {
				// If CRD validation catches it (future enhancement), that's fine too
				Expect(output).To(ContainSubstring("invalid"))
			} else {
				By("checking controller logs for validation error")
				time.Sleep(5 * time.Second) // Give reconcile a chance to run
				cmd := exec.Command("kubectl", "logs", "-l", "control-plane=controller-manager",
					"-n", namespace, "--tail=50")
				logs, logErr := utils.Run(cmd)
				Expect(logErr).NotTo(HaveOccurred())
				Expect(logs).To(ContainSubstring("invalid config key"),
					"Controller should log validation error for path traversal key")
			}
		})
	})
})

// serviceAccountToken returns a token for the specified service account in the given namespace.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() (string, error) {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	return utils.Run(cmd)
}

// applyManifest writes a YAML string to a temp file and runs kubectl apply.
func applyManifest(yaml string) error {
	tmpFile, err := os.CreateTemp("", "e2e-manifest-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(yaml); err != nil {
		return err
	}
	tmpFile.Close()

	cmd := exec.Command("kubectl", "apply", "-f", tmpFile.Name())
	_, err = utils.Run(cmd)
	return err
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}

