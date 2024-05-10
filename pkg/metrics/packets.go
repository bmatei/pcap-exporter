package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	SubsystemPackets = "packets"
	Namespace        = "pcap"
)

func init() {
	prometheus.MustRegister(Packets)
	prometheus.MustRegister(PacketsSize)
}

var Packets = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: SubsystemPackets,
		Name:      "total",
		Help:      "Total number of packets",
	},
	[]string{"direction", "remote", "appid", "layers"},
)

var PacketsSize = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: SubsystemPackets,
		Name:      "size",
		Help:      "Total size in bytes for all packets",
	},
	[]string{"direction", "remote", "appid", "layers"},
)
