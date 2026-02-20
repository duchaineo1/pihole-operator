//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/duchaineo1/pihole-operator/test/utils"
)

var _ = Describe("Pihole Config API passthrough (e2e)", Ordered, func() {
	const piholeName = "config-api-test-pihole"
	var podIP string
	var password string

	BeforeAll(func() {
		By("creating a test Pihole with config")
		password = "config-api-test-pw-12345"
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
		Expect(applyManifest(piholeYAML)).To(Succeed(), "Failed to create Pihole with config")

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
		getPodIP := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pod", piholeName+"-0",
				"-n", testNamespace, "-o", "jsonpath={.status.podIP}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).NotTo(BeEmpty())
			podIP = strings.TrimSpace(output)
		}
		Eventually(getPodIP).Should(Succeed())

		By("waiting for Pi-hole API to be responsive")
		waitForAPI := func(g Gomega) {
			baseURL := fmt.Sprintf("https://%s", podIP)
			client := &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
			resp, err := client.Get(baseURL + "/admin/")
			g.Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			g.Expect(resp.StatusCode).To(BeNumerically("<", 500))
		}
		Eventually(waitForAPI, 3*time.Minute, 5*time.Second).Should(Succeed())
	})

	AfterAll(func() {
		cmd := exec.Command("kubectl", "delete", "pihole", piholeName, "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
	})

	Context("when config is set via spec.config", func() {
		It("should apply config keys via the Pi-hole API", func() {
			By("authenticating to the Pi-hole API")
			baseURL := fmt.Sprintf("https://%s", podIP)
			client := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}

			authPayload := map[string]string{"password": password}
			authBody, err := json.Marshal(authPayload)
			Expect(err).NotTo(HaveOccurred())

			authResp, err := client.Post(baseURL+"/api/auth", "application/json", bytes.NewReader(authBody))
			Expect(err).NotTo(HaveOccurred())
			defer authResp.Body.Close()
			Expect(authResp.StatusCode).To(Equal(200), "Authentication should succeed")

			authRespBody, err := io.ReadAll(authResp.Body)
			Expect(err).NotTo(HaveOccurred())

			var authResult struct {
				Session struct {
					SID string `json:"sid"`
				} `json:"session"`
			}
			Expect(json.Unmarshal(authRespBody, &authResult)).To(Succeed())
			sid := authResult.Session.SID
			Expect(sid).NotTo(BeEmpty(), "SID should be present in auth response")

			By("verifying dns.queryLogging was applied (should be 'true' from spec.config)")
			req, err := http.NewRequest("GET", baseURL+"/api/config/dns.queryLogging", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("X-FTL-SID", sid)

			verifyConfig := func(g Gomega) {
				resp, err := client.Do(req)
				g.Expect(err).NotTo(HaveOccurred())
				defer resp.Body.Close()
				g.Expect(resp.StatusCode).To(Equal(200))

				body, err := io.ReadAll(resp.Body)
				g.Expect(err).NotTo(HaveOccurred())

				var configResp struct {
					Config struct {
						Value string `json:"value"`
					} `json:"config"`
				}
				g.Expect(json.Unmarshal(body, &configResp)).To(Succeed())
				g.Expect(configResp.Config.Value).To(Equal("true"),
					"dns.queryLogging should be set to 'true' by the operator")
			}
			// The reconcile loop runs periodically; give it time to apply config
			Eventually(verifyConfig, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying dns.privacyLevel was applied (should be '0')")
			req2, err := http.NewRequest("GET", baseURL+"/api/config/dns.privacyLevel", nil)
			Expect(err).NotTo(HaveOccurred())
			req2.Header.Set("X-FTL-SID", sid)

			verifyPrivacy := func(g Gomega) {
				resp, err := client.Do(req2)
				g.Expect(err).NotTo(HaveOccurred())
				defer resp.Body.Close()
				g.Expect(resp.StatusCode).To(Equal(200))

				body, err := io.ReadAll(resp.Body)
				g.Expect(err).NotTo(HaveOccurred())

				var configResp struct {
					Config struct {
						Value string `json:"value"`
					} `json:"config"`
				}
				g.Expect(json.Unmarshal(body, &configResp)).To(Succeed())
				g.Expect(configResp.Config.Value).To(Equal("0"),
					"dns.privacyLevel should be set to '0' by the operator")
			}
			Eventually(verifyPrivacy, 2*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should enforce desired state on drift (GitOps)", func() {
			By("authenticating again")
			baseURL := fmt.Sprintf("https://%s", podIP)
			client := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}

			authPayload := map[string]string{"password": password}
			authBody, err := json.Marshal(authPayload)
			Expect(err).NotTo(HaveOccurred())

			authResp, err := client.Post(baseURL+"/api/auth", "application/json", bytes.NewReader(authBody))
			Expect(err).NotTo(HaveOccurred())
			defer authResp.Body.Close()

			authRespBody, err := io.ReadAll(authResp.Body)
			Expect(err).NotTo(HaveOccurred())

			var authResult struct {
				Session struct {
					SID string `json:"sid"`
				} `json:"session"`
			}
			Expect(json.Unmarshal(authRespBody, &authResult)).To(Succeed())
			sid := authResult.Session.SID

			By("manually changing dns.queryLogging to 'false' (simulating manual drift)")
			patchPayload := map[string]string{"value": "false"}
			patchBody, err := json.Marshal(patchPayload)
			Expect(err).NotTo(HaveOccurred())

			patchReq, err := http.NewRequest("PATCH", baseURL+"/api/config/dns.queryLogging",
				bytes.NewReader(patchBody))
			Expect(err).NotTo(HaveOccurred())
			patchReq.Header.Set("Content-Type", "application/json")
			patchReq.Header.Set("X-FTL-SID", sid)

			patchResp, err := client.Do(patchReq)
			Expect(err).NotTo(HaveOccurred())
			defer patchResp.Body.Close()
			Expect(patchResp.StatusCode).To(Equal(200))

			By("verifying the drift is corrected by the operator (back to 'true')")
			req, err := http.NewRequest("GET", baseURL+"/api/config/dns.queryLogging", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("X-FTL-SID", sid)

			verifyCorrection := func(g Gomega) {
				resp, err := client.Do(req)
				g.Expect(err).NotTo(HaveOccurred())
				defer resp.Body.Close()

				body, err := io.ReadAll(resp.Body)
				g.Expect(err).NotTo(HaveOccurred())

				var configResp struct {
					Config struct {
						Value string `json:"value"`
					} `json:"config"`
				}
				g.Expect(json.Unmarshal(body, &configResp)).To(Succeed())
				g.Expect(configResp.Config.Value).To(Equal("true"),
					"Operator should revert manual drift back to spec value")
			}
			// The reconcile loop runs every ~60s by default; wait up to 2min
			Eventually(verifyCorrection, 3*time.Minute, 10*time.Second).Should(Succeed())
		})
	})

	Context("when config keys are invalid", func() {
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
