package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func parsePorts(spec string) []int {
	res := []int{}
	parts := strings.Split(spec, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			ab := strings.SplitN(p, "-", 2)
			a, _ := strconv.Atoi(ab[0])
			b, _ := strconv.Atoi(ab[1])
			if a > b {
				a, b = b, a
			}
			for i := a; i <= b; i++ {
				if i >= 1 && i <= 65535 {
					res = append(res, i)
				}
			}
		} else {
			v, _ := strconv.Atoi(p)
			if v >= 1 && v <= 65535 {
				res = append(res, v)
			}
		}
	}
	return res
}

func firstIPv4OnIface(device string) net.IP {
	devs, _ := pcap.FindAllDevs()
	for _, d := range devs {
		if d.Name != device {
			continue
		}
		for _, a := range d.Addresses {
			if a.IP != nil && a.IP.To4() != nil {
				return a.IP.To4()
			}
		}
	}
	return nil
}

func ifaceMAC(device string) (net.HardwareAddr, error) {
	ifc, err := net.InterfaceByName(device)
	if err != nil {
		return nil, err
	}
	return ifc.HardwareAddr, nil
}

// arpResolve sends an ARP who-has for ip on iface and returns MAC if answered.
func arpResolve(handle *pcap.Handle, ifaceName string, srcIP net.IP, srcMAC net.HardwareAddr, targetIP net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	// Build ARP who-has frame
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(targetIP.To4()),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &eth, &arp); err != nil {
		return nil, err
	}

	// Set a temporary BPF filter to capture only ARP replies for targetIP
	bpf := fmt.Sprintf("arp and arp[6:2] = 2 and ether dst %s", srcMAC.String())
	if err := handle.SetBPFFilter(bpf); err != nil {
		// not fatal; continue with broad capture
	}

	// Send ARP who-has a few times
	for i := 0; i < 3; i++ {
		_ = handle.WritePacketData(buf.Bytes())
		time.Sleep(20 * time.Millisecond)
	}

	// Wait for reply
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pkt, err := packetSource.NextPacket()
		if err != nil {
			continue
		}
		if layer := pkt.Layer(layers.LayerTypeARP); layer != nil {
			arpReply, _ := layer.(*layers.ARP)
			if arpReply.Operation == layers.ARPReply &&
				net.IP(arpReply.SourceProtAddress).Equal(targetIP.To4()) {
				return net.HardwareAddr(arpReply.SourceHwAddress), nil
			}
		}
	}
	return nil, fmt.Errorf("ARP timeout; host not on LAN or not responding")
}

func macFromString(s string) (net.HardwareAddr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	hw, err := net.ParseMAC(s)
	if err == nil {
		return hw, nil
	}
	// Accept forms without colons (12 hex chars)
	if len(s) == 12 {
		b, err := hex.DecodeString(s)
		if err == nil && len(b) == 6 {
			return net.HardwareAddr(b), nil
		}
	}
	return nil, fmt.Errorf("invalid mac format")
}

func main() {
	target := flag.String("target", "", "Target IP (single IPv4)")
	ports := flag.String("ports", "1-1024", "Ports e.g. 22,80,443 or 1-1024")
	iface := flag.String("iface", "", "Interface (auto if empty)")
	timeoutMs := flag.Int("timeout", 800, "Per-port wait timeout ms after last SYN")
	pps := flag.Int("pps", 2000, "Packets per second (rate)")
	dstmacStr := flag.String("dstmac", "", "Destination MAC override (aa:bb:cc:dd:ee:ff) for off-subnet scans")
	gatewayIP := flag.String("gateway", "", "Gateway IPv4 to ARP (for off-subnet scans)")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: synscan -target 192.168.1.10 [-ports 1-1024] [-iface eth0] [-dstmac aa:bb:..] [-gateway 192.168.1.1]")
		os.Exit(2)
	}
	dstIP := net.ParseIP(*target)
	if dstIP == nil || dstIP.To4() == nil {
		log.Fatalf("Invalid IPv4: %s", *target)
	}

	// Pick interface if not provided
	device := *iface
	if device == "" {
		devs, _ := pcap.FindAllDevs()
		for _, d := range devs {
			if len(d.Addresses) == 0 {
				continue
			}
			if strings.Contains(strings.ToLower(d.Name), "lo") {
				continue
			}
			device = d.Name
			break
		}
		if device == "" && len(devs) > 0 {
			device = devs[0].Name
		}
		if device == "" {
			log.Fatal("No interface found; specify -iface")
		}
	}

	// Open pcap
	handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	srcIP := firstIPv4OnIface(device)
	if srcIP == nil {
		log.Fatalf("No IPv4 on iface %s", device)
	}
	srcMAC, err := ifaceMAC(device)
	if err != nil {
		log.Fatalf("get iface MAC: %v", err)
	}

	// Resolve dst MAC:
	var dstMAC net.HardwareAddr
	if *dstmacStr != "" {
		dstMAC, err = macFromString(*dstmacStr)
		if err != nil {
			log.Fatalf("invalid dstmac: %v", err)
		}
	} else {
		// Try ARP target directly; if it fails and gateway is provided, ARP the gateway.
		dstMAC, err = arpResolve(handle, device, srcIP, srcMAC, dstIP, 800*time.Millisecond)
		if err != nil && *gatewayIP != "" {
			gw := net.ParseIP(*gatewayIP)
			if gw == nil || gw.To4() == nil {
				log.Fatalf("invalid gateway IP: %s", *gatewayIP)
			}
			dstMAC, err = arpResolve(handle, device, srcIP, srcMAC, gw, 800*time.Millisecond)
		}
		if err != nil {
			log.Fatalf("invalid dst MAC: %v (target may be off-LAN; use -gateway <gw-ip> or -dstmac <mac>)", err)
		}
	}

	// Listener for SYN-ACK replies (BPF to reduce noise)
	_ = handle.SetBPFFilter(fmt.Sprintf("tcp and src host %s and tcp[13] & 0x12 = 0x12", dstIP.String()))
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	in := src.Packets()

	// Rate control
	perPkt := time.Second / time.Duration(*pps)
	portsList := parsePorts(*ports)
	var srcPort layers.TCPPort = 54321

	// Print SYN-ACK as open
	go func() {
		for pkt := range in {
			if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)
				ip4Layer := pkt.Layer(layers.LayerTypeIPv4)
				if ip4Layer == nil {
					continue
				}
				ip4 := ip4Layer.(*layers.IPv4)
				if ip4.SrcIP.Equal(dstIP) && tcp.DstPort == srcPort && tcp.SYN && tcp.ACK {
					fmt.Printf("[OPEN] %s:%d\n", ip4.SrcIP.String(), tcp.SrcPort)
				}
			}
		}
	}()

	// Send SYNs (full Ethernet + IPv4 + TCP)
	for _, p := range portsList {
		eth := layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip4 := layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: layers.IPProtocolTCP,
		}
		tcp := layers.TCP{
			SrcPort: srcPort,
			DstPort: layers.TCPPort(p),
			SYN:     true,
			Window:  14600,
		}
		tcp.SetNetworkLayerForChecksum(&ip4)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, &eth, &ip4, &tcp); err != nil {
			continue
		}
		_ = handle.WritePacketData(buf.Bytes())
		time.Sleep(perPkt)
	}

	// Wait for late replies
	time.Sleep(time.Duration(*timeoutMs) * time.Millisecond)
}
