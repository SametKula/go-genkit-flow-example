// Package capture provides network packet capture functionality using gopacket.
// It listens on a specified network interface and extracts unique IP addresses
// for further security analysis.
package capture

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ConnectionContext holds aggregated network context for an IP.
type ConnectionContext struct {
	IP          string   `json:"ip"`
	Ports       []uint16 `json:"ports"`
	Protocols   []string `json:"protocols"`
	TotalBytes  int      `json:"total_bytes"`
	PacketCount int      `json:"packet_count"`
}

// ipStat tracks packets for rate limiting and dedup TTL.
type ipStat struct {
	lastAnalyzed  time.Time
	windowStart   time.Time
	packetCount   int
	fastBlocked   bool
	accessedPorts map[uint16]bool
	protocols     map[string]bool
	totalBytes    int
}

// Capturer manages packet capture on a network interface.
type Capturer struct {
	iface         string
	ctxChan       chan<- ConnectionContext
	fastBlockChan chan<- string
	stats         map[string]*ipStat
	mu            sync.Mutex
	dedupTTL      time.Duration
	privateNets   []*net.IPNet
	rateThreshold int // Packets per second to trigger fast-path
}

// NewCapturer creates a new Capturer for the given network interface.
func NewCapturer(iface string, ctxChan chan<- ConnectionContext, fastBlockChan chan<- string) *Capturer {
	// Build list of private IP CIDR ranges to filter out
	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	var privateNets []*net.IPNet
	for _, cidr := range privateCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			privateNets = append(privateNets, ipNet)
		}
	}

	return &Capturer{
		iface:         iface,
		ctxChan:       ctxChan,
		fastBlockChan: fastBlockChan,
		stats:         make(map[string]*ipStat),
		dedupTTL:      30 * time.Minute,
		privateNets:   privateNets,
		rateThreshold: 50, // 50 packets per second
	}
}

// isPrivate returns true if the IP is in a private/reserved range.
func (c *Capturer) isPrivate(ip net.IP) bool {
	for _, network := range c.privateNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// processIP tracks rate limits and sends IPs to the correct channel.
func (c *Capturer) processIP(ipStr string, isTCPSyn bool, port uint16, protocol string, size int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stat, exists := c.stats[ipStr]
	if !exists {
		stat = &ipStat{
			windowStart:   time.Now(),
			accessedPorts: make(map[uint16]bool),
			protocols:     make(map[string]bool),
		}
		c.stats[ipStr] = stat
	}

	if stat.fastBlocked {
		return // Already fast-blocked, ignore
	}

	if isTCPSyn {
		stat.packetCount++
	}

	// Update Context
	if port != 0 {
		stat.accessedPorts[port] = true
	}
	if protocol != "" {
		stat.protocols[protocol] = true
	}
	stat.totalBytes += size

	now := time.Now()
	// Check rate limit (1 second window)
	if now.Sub(stat.windowStart) >= time.Second {
		if stat.packetCount > c.rateThreshold {
			stat.fastBlocked = true
			log.Printf("[CAPTURE] [FAST-PATH] IP %s exceeded threshold (%d SYN pkts/sec)", ipStr, stat.packetCount)
			select {
			case c.fastBlockChan <- ipStr:
			default:
			}
			return
		}
		// Reset window
		stat.windowStart = now
		stat.packetCount = 0
	}

	// Slow path (AI Analysis) dedup
	if stat.lastAnalyzed.IsZero() || now.Sub(stat.lastAnalyzed) >= c.dedupTTL {
		stat.lastAnalyzed = now

		ctx := ConnectionContext{
			IP:          ipStr,
			TotalBytes:  stat.totalBytes,
			PacketCount: stat.packetCount,
		}
		for p := range stat.accessedPorts {
			ctx.Ports = append(ctx.Ports, p)
		}
		for p := range stat.protocols {
			ctx.Protocols = append(ctx.Protocols, p)
		}

		log.Printf("[CAPTURE] [NEW IP] Sending to AI: %s (Ports: %v)", ipStr, ctx.Ports)
		select {
		case c.ctxChan <- ctx:
		default:
			log.Printf("[CAPTURE] [WARNING] Channel full, dropping IP: %s", ipStr)
		}
	}
}

// Start begins packet capture. It blocks until the context is cancelled
// via the done channel. Call it in a goroutine.
func (c *Capturer) Start(done <-chan struct{}) error {
	log.Printf("[CAPTURE] Starting capture on interface: %s", c.iface)

	handle, err := pcap.OpenLive(c.iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %w", c.iface, err)
	}
	defer handle.Close()

	// Filter only IP traffic
	if err := handle.SetBPFFilter("ip or ip6"); err != nil {
		log.Printf("[CAPTURE] Warning: could not set BPF filter: %v", err)
	}

	log.Printf("[CAPTURE] [STARTED] Listening for packets on %s (dedup TTL: %v)", c.iface, c.dedupTTL)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	for {
		select {
		case <-done:
			log.Println("[CAPTURE] [STOPPED] Capture stopped.")
			return nil
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return nil
			}
			c.processPacket(packet)
		}
	}
}

// processPacket extracts source and destination IPs from a packet and
// sends unique, non-private IPs to the analysis channel.
func (c *Capturer) processPacket(packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	var srcIP, dstIP net.IP
	
	switch layer := networkLayer.(type) {
	case *layers.IPv4:
		srcIP = layer.SrcIP
		dstIP = layer.DstIP
	case *layers.IPv6:
		srcIP = layer.SrcIP
		dstIP = layer.DstIP
	default:
		return
	}

	var port uint16
	var protocol string
	size := len(packet.Data())
	isTCPSyn := false

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		protocol = "TCP"
		// Only consider it a new connection if SYN is set and ACK is not
		if tcp.SYN && !tcp.ACK {
			isTCPSyn = true
		}
		port = uint16(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		protocol = "UDP"
		port = uint16(udp.DstPort)
	}

	for _, ip := range []net.IP{srcIP, dstIP} {
		if ip == nil || c.isPrivate(ip) {
			continue
		}
		ipStr := ip.String()
		c.processIP(ipStr, isTCPSyn, port, protocol, size)
	}
}
