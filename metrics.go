package unifinames

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// requestCount exports a prometheus metric that is incremented every time a query is seen by the example plugin.
var (
	UnifinamesCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "unifinames",
		Name:      "unifinames_request_count_total",
		Help:      "Counter of Requests Answered from Unifi Discovered Names",
	})

	UnifinamesHostsCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "unifinames",
		Name:      "unifinames_host_count",
		Help:      "Number of Hosts Discovered from Unifi",
	})
)
