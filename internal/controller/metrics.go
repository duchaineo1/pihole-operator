package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Prometheus gauges for Pi-hole instance statistics.
// Each metric carries {namespace, name} labels to identify the Pihole CR.
var (
	// piholeQueriesTotal is the total number of DNS queries processed.
	piholeQueriesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pihole_queries_total",
			Help: "Total number of DNS queries processed by Pi-hole.",
		},
		[]string{"namespace", "name"},
	)

	// piholeQueriesBlocked is the number of DNS queries that were blocked.
	piholeQueriesBlocked = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pihole_queries_blocked",
			Help: "Number of DNS queries blocked by Pi-hole.",
		},
		[]string{"namespace", "name"},
	)

	// piholeBlockPercentage is the percentage of queries that were blocked.
	piholeBlockPercentage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pihole_block_percentage",
			Help: "Percentage of DNS queries blocked by Pi-hole.",
		},
		[]string{"namespace", "name"},
	)

	// piholeGravityDomains is the number of domains in the gravity blocklist.
	piholeGravityDomains = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pihole_gravity_domains",
			Help: "Number of domains in Pi-hole's gravity blocklist.",
		},
		[]string{"namespace", "name"},
	)

	// piholeUniqueClients is the number of unique clients seen by Pi-hole.
	piholeUniqueClients = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pihole_unique_clients",
			Help: "Number of unique DNS clients seen by Pi-hole.",
		},
		[]string{"namespace", "name"},
	)
)

func init() {
	// Register all custom Pi-hole metrics with the controller-runtime metrics registry.
	// This makes them available at the /metrics endpoint served by the manager.
	ctrlmetrics.Registry.MustRegister(
		piholeQueriesTotal,
		piholeQueriesBlocked,
		piholeBlockPercentage,
		piholeGravityDomains,
		piholeUniqueClients,
	)
}
