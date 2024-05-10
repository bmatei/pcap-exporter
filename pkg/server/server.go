package server

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"

	"github.com/bmatei/pcap-exporter/pkg/metrics"
)

type Config struct {
	ListenAddr    string            `yaml:"listen_address" env:"PCAP_METICS_HOST" env-default:"127.0.0.1"`
	Port          int               `yaml:"port" env:"PCAP_METRICS_PORT" env-default:"9250"`
	IPNames       map[string]string `yaml:"ip_names"`
	LocalFilters  map[uint16]string `yaml:"local_filters"`
	RemoteFilters map[uint16]string `yaml:"remote_filters"`
}

func addr(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

func Start() {
	path := "/etc/pcap-exporter/config.yml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	var cfg Config
	err := cleanenv.ReadConfig(path, &cfg)
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("Failed to read config")

		return
	}

	log.Info().Str("cfg", fmt.Sprintf("%v", cfg)).Msg("starting server")

	go metrics.Collect("", "ip or ip6", cfg.IPNames, cfg.LocalFilters, cfg.RemoteFilters)

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", promhttp.Handler().ServeHTTP)

	ln, err := net.Listen("tcp", addr(cfg.ListenAddr, cfg.Port))
	if err != nil {
		log.Error().Err(err).Msg("Failed net.Listen")
		return
	}

	err = http.Serve(ln, mux)
	log.Error().Err(err).Msg("Stopped server")
}
