# pcap-exporter

 🦈 Prometheus exporter for pcap metrics

## Usage

```console
$ go run main.go
{"level":"info","cfg":"{127.0.0.1 9250}","time":"2024-05-10T19:45:57+03:00","message":"starting server"}
{"level":"info","interface":"en0","time":"2024-05-10T19:45:57+03:00","message":"capturing packets"}
...
```

```console
pcap_packets_size{appid,direction,layers,remote} # bytes counter
pcap_packets_total{appid,direction,layers,remote} # packets counter
```
