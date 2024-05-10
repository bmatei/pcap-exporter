package metrics

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog/log"
)

func defaultIface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get list of network interfaces")
		return ""
	}

	for _, ifc := range ifaces {
		if ifc.HardwareAddr != nil && ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagBroadcast != 0 {
			return ifc.Name
		}
	}

	return ""
}

func isLocal(localIPs []net.IP, ip net.IP) bool {
	for _, local := range localIPs {
		if net.IP.Equal(local, ip) {
			return true
		}
	}

	return false
}

func Collect(iface, filter string,
	remoteIPs map[string]string,
	localServices, remoteServices map[uint16]string,
) {
	if iface == "" {
		iface = defaultIface()
	}

	if iface == "" {
		log.Warn().Msg("Couldn't find a network interface to listen on")
		return
	}

	log.Info().Str("interface", iface).Msg("capturing packets")

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Error().Err(err).Msg("Couldn't find pcap devices")
		return
	}

	var (
		snapshotLen int32 = 65535
		promiscuous bool  = false

		pcapHandle *pcap.Handle
		localIPs   []net.IP
	)

	for _, device := range devices {
		if device.Name == iface {
			for _, adr := range device.Addresses {
				localIPs = append(localIPs, adr.IP)
			}

			pcapHandle, err = pcap.OpenLive(device.Name, snapshotLen, promiscuous, pcap.BlockForever)
			if err != nil {
				log.Error().Err(err).Str("interface", iface).Msg("Failed to open capture device")
				return
			}
		}
	}

	if pcapHandle != nil {
		defer pcapHandle.Close()

		if filter != "" {
			err := pcapHandle.SetBPFFilter(filter)
			if err != nil {
				log.Error().Err(err).Str("filter", filter).Msg("Failed to parse filter")
				return
			}
		}

		packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
		for packet := range packetSource.Packets() {
			ip := net.IP{}
			remote := ""
			app := ""
			currentLayers := ""
			dir := "in"
			localPort := uint16(0)
			remotePort := uint16(0)

			for _, layer := range packet.Layers() {
				currentLayers += fmt.Sprintf("/%s", layer.LayerType().String())
				switch layer.LayerType() {
				case layers.LayerTypeIPv4:
					ipv4 := layer.(*layers.IPv4)
					ip = ipv4.SrcIP
					if isLocal(localIPs, ipv4.SrcIP) {
						dir = "out"
						ip = ipv4.DstIP
					}
				case layers.LayerTypeIPv6:
					ipv6 := layer.(*layers.IPv6)
					ip = ipv6.SrcIP
					if isLocal(localIPs, ipv6.SrcIP) {
						dir = "out"
						ip = ipv6.DstIP
					}
				case layers.LayerTypeTCP:
					tcp := layer.(*layers.TCP)
					if dir == "in" {
						remotePort = uint16(tcp.SrcPort)
						localPort = uint16(tcp.DstPort)
					} else {
						remotePort = uint16(tcp.DstPort)
						localPort = uint16(tcp.SrcPort)
					}
				case layers.LayerTypeUDP:
					udp := layer.(*layers.UDP)
					if dir == "in" {
						remotePort = uint16(udp.SrcPort)
						localPort = uint16(udp.DstPort)
					} else {
						remotePort = uint16(udp.DstPort)
						localPort = uint16(udp.SrcPort)
					}
				}
			}

			if found, ok := remoteIPs[ip.String()]; ok {
				remote = found
			} else {
				remote = ip.String()
			}

			if localPort == 0 {
				app = "unknown"
			} else {
				if found, ok := localServices[localPort]; ok {
					app = found
				}

				if found, ok := remoteServices[remotePort]; ok {
					if app != "" {
						app += "/" + found
					} else {
						app = found
					}
				}
			}

			if app == "" {
				app = fmt.Sprintf("%d/%d", localPort, remotePort)
				if packet.Layers()[len(packet.Layers()) - 1].LayerType() == layers.LayerTypeTCP {
					app = "TCP control"
				}
			} else if app != "unknown" {
				currentLayers = ""
			}

			Packets.WithLabelValues(dir, remote, app, currentLayers).Inc()
			PacketsSize.WithLabelValues(dir, remote, app, currentLayers).Add(float64(len(packet.Data())))
		}
	}
}
