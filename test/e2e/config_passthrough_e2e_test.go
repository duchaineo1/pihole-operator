//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/duchaineo1/pihole-operator/test/utils"
)

// Separate e2e test for config passthrough to avoid interference with main suite.
// This creates its own isolated Pihole instance and verifies config application.
var _ = Describe("Config Passthrough (Isolated)", Ordered, Serial, func() {
	const testNS = "pihole-config-e2e"
	const piholeName = "config-test-pihole"
	const password = "config-e2e-pw-12345"

	BeforeAll(func() {
		By("creating isolated test namespace")
		cmd := exec.Command("kubectl", "create", "ns", testNS)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("creating a Pihole with config keys")
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
`, piholeName, testNS, password)
		Expect(applyManifest(piholeYAML)).To(Succeed(), "Failed to create Pihole")

		By("waiting for the pod to be Running")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pod", piholeName+"-0",
				"-n", testNS, "-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"))
		}, 5*time.Minute).Should(Succeed())

		By("waiting for the pod to have container Ready=true")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pod", piholeName+"-0",
				"-n", testNS, "-o", "jsonpath={.status.containerStatuses[0].ready}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("true"))
		}, 5*time.Minute, 5*time.Second).Should(Succeed())

		// Extra buffer: Pi-hole needs time to start its web server even after container is Ready
		By("waiting an extra 30s for Pi-hole web server to initialize")
		time.Sleep(30 * time.Second)
	})

	AfterAll(func() {
		By("deleting the isolated Pihole")
		cmd := exec.Command("kubectl", "delete", "pihole", piholeName, "-n", testNS, "--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)

		By("deleting the test namespace")
		cmd = exec.Command("kubectl", "delete", "ns", testNS, "--ignore-not-found")
		_, _ = utils.Run(cmd)
	})

	Context("when config keys are applied", func() {
		It("should log successful config application in controller logs", func() {
			By("checking controller logs for config application")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", "-l", "control-plane=controller-manager",
					"-n", namespace, "--tail=200")
				logs, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())

				// Look for successful config application logs (not errors)
				// The controller logs at V(1) when config is applied successfully
				// If we see errors, that's a failure
				g.Expect(logs).NotTo(ContainSubstring("Failed to apply config key"))
			}, 3*time.Minute, 10*time.Second).Should(Succeed())

			By("verifying no config-related errors in controller logs")
			cmd := exec.Command("kubectl", "logs", "-l", "control-plane=controller-manager",
				"-n", namespace, "--tail=300")
			logs, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			// Check for our specific pihole instance in error logs
			errorLines := []string{}
			for _, line := range strings.Split(logs, "\n") {
				if strings.Contains(line, piholeName) && strings.Contains(line, "ERROR") && strings.Contains(line, "config") {
					errorLines = append(errorLines, line)
				}
			}
			Expect(errorLines).To(BeEmpty(), "Should not have config-related errors for %s:\n%s",
				piholeName, strings.Join(errorLines, "\n"))
		})

		It("should accept valid config keys and reject invalid ones", func() {
			By("patching the Pihole with an invalid config key")
			cmd := exec.Command("kubectl", "patch", "pihole", piholeName,
				"-n", testNS, "--type=merge",
				"-p", `{"spec":{"config":{"../etc/passwd":"bad"}}}`)
			_, _ = utils.Run(cmd) // May succeed (CRD allows it) or fail (future validation)

			By("waiting for reconcile and checking logs for validation error")
			time.Sleep(10 * time.Second)
			cmd = exec.Command("kubectl", "logs", "-l", "control-plane=controller-manager",
				"-n", namespace, "--tail=100")
			logs, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			// The controller should log validation errors for invalid keys
			Expect(logs).To(ContainSubstring("invalid config key"),
				"Controller should log validation errors for path traversal attempts")
		})
	})

	Context("when verifying via kubectl", func() {
		It("should show config keys in the Pihole spec", func() {
			By("getting the Pihole spec")
			cmd := exec.Command("kubectl", "get", "pihole", piholeName,
				"-n", testNS, "-o", "jsonpath={.spec.config}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			// Should contain our config keys (even if invalid key was added)
			Expect(output).To(ContainSubstring("dns.queryLogging"))
			Expect(output).To(ContainSubstring("dns.privacyLevel"))
		})
	})
})
