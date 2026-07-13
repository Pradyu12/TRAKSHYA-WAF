package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	RequestsTotal    prometheus.Counter
	BlockedTotal     prometheus.Counter
	IncidentsTotal   prometheus.Counter
	ActiveConnections prometheus.Gauge
	RequestDuration  prometheus.Histogram
	AttackTypeCount  *prometheus.CounterVec
	UpstreamHealth   *prometheus.GaugeVec
}

func NewMetrics() *Metrics {
	m := &Metrics{
		RequestsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "kalki_requests_total",
			Help: "Total number of requests processed",
		}),
		BlockedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "kalki_blocked_total",
			Help: "Total number of blocked requests",
		}),
		IncidentsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "kalki_incidents_total",
			Help: "Total number of incidents",
		}),
		ActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kalki_active_connections",
			Help: "Current number of active connections",
		}),
		RequestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "kalki_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		AttackTypeCount: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kalki_attack_type_total",
			Help: "Total requests by attack type",
		}, []string{"attack_type"}),
		UpstreamHealth: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kalki_upstream_health",
			Help: "Upstream health status (1=healthy, 0=unhealthy)",
		}, []string{"upstream"}),
	}

	prometheus.MustRegister(
		m.RequestsTotal,
		m.BlockedTotal,
		m.IncidentsTotal,
		m.ActiveConnections,
		m.RequestDuration,
		m.AttackTypeCount,
		m.UpstreamHealth,
	)

	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}

func (m *Metrics) RecordRequest() {
	m.RequestsTotal.Inc()
}

func (m *Metrics) RecordBlocked(attackType string) {
	m.BlockedTotal.Inc()
	m.AttackTypeCount.WithLabelValues(attackType).Inc()
}

func (m *Metrics) RecordIncident() {
	m.IncidentsTotal.Inc()
}

func (m *Metrics) SetActiveConnections(n int) {
	m.ActiveConnections.Set(float64(n))
}

func (m *Metrics) ObserveDuration(seconds float64) {
	m.RequestDuration.Observe(seconds)
}

func (m *Metrics) SetUpstreamHealth(upstream string, healthy bool) {
	val := 0.0
	if healthy {
		val = 1.0
	}
	m.UpstreamHealth.WithLabelValues(upstream).Set(val)
}
