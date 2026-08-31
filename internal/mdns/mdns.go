// Package mdns implements a minimal Multicast DNS (mDNS, RFC 6762) client
// using only the Go standard library. It builds DNS queries, parses DNS
// responses (including name compression) into PTR / SRV / TXT / A / AAAA
// records, and aggregates them into mDNS asset entries.
package mdns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// DNS resource record type codes used by mDNS.
const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypePTR   = 12
	TypeTXT   = 16
	TypeAAAA  = 28
	TypeSRV   = 33
	TypeANY   = 255
)

// mDNS multicast group addresses and well-known port.
const (
	mdnsPort     = 5353
	mdnsIPv4Addr = "224.0.0.251"
	mdnsIPv6Addr = "ff02::fb"
)

// RR is a decoded DNS resource record.
type RR struct {
	Name   string
	Type   uint16
	Class  uint16
	TTL    uint32
	Target string
	Port   uint16
	A      net.IP
	AAAA   net.IP
	TXT    []string
}

// Asset is one mDNS asset entry produced by the discovery engine.
type Asset struct {
	IP          string
	Port        int
	Proto       string
	Host        string
	Instance    string
	Service     string
	ServiceType string
	TTL         uint32
	IPv6        string
	MAC         string
	Banner      map[string]string
	BannerOrder []string
}

// defaultServiceTypes is the set of mDNS service types queried during a scan.
var defaultServiceTypes = []string{
	"_workstation._tcp.local",
	"_http._tcp.local",
	"_smb._tcp.local",
	"_qdiscover._tcp.local",
	"_device-info._tcp.local",
	"_afpovertcp._tcp.local",
	"_airplay._tcp.local",
	"_raop._tcp.local",
	"_ssh._tcp.local",
	"_sftp-ssh._tcp.local",
	"_ipp._tcp.local",
	"_printer._tcp.local",
	"_googlecast._tcp.local",
	"_hap._tcp.local",
	"_services._dns-sd._udp.local",
}

// Options controls a discovery run.
type Options struct {
	Timeout      time.Duration
	ServiceTypes []string
}

// buildQuery encodes a DNS query message for the given name and QTYPE.
func buildQuery(id uint16, name string, qtype uint16) []byte {
	msg := make([]byte, 0, 64)
	msg = append(msg, byte(id>>8), byte(id))
	msg = append(msg, 0, 0) // flags
	msg = append(msg, 0, 1) // QDCOUNT = 1
	msg = append(msg, 0, 0, 0, 0, 0, 0)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = append(msg, byte(qtype>>8), byte(qtype))
	msg = append(msg, 0, 1) // QCLASS IN
	return msg
}

// readName decodes a possibly-compressed domain name starting at off.
// It returns the name and the offset just after the encoded name.
func readName(data []byte, off int) (string, int) {
	var labels []string
	pos := off
	next := off
	jumped := false
	jumps := 0
	for jumps < 64 {
		if pos >= len(data) {
			break
		}
		l := int(data[pos])
		if l == 0 {
			pos++
			if !jumped {
				next = pos
			}
			break
		}
		if l&0xC0 == 0xC0 {
			if pos+1 >= len(data) {
				break
			}
			ptr := int(l&0x3F)<<8 | int(data[pos+1])
			if !jumped {
				next = pos + 2
				jumped = true
			}
			pos = ptr
			jumps++
			continue
		}
		if l > 63 {
			break
		}
		pos++
		if pos+l > len(data) {
			break
		}
		labels = append(labels, string(data[pos:pos+l]))
		pos += l
		if !jumped {
			next = pos
		}
	}
	return strings.Join(labels, "."), next
}

// parseMessage decodes a DNS message and returns the records carried in the
// answer, authority and additional sections.
func parseMessage(data []byte) ([]RR, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("short dns message")
	}
	qd := int(binary.BigEndian.Uint16(data[4:6]))
	an := int(binary.BigEndian.Uint16(data[6:8]))
	ns := int(binary.BigEndian.Uint16(data[8:10]))
	ar := int(binary.BigEndian.Uint16(data[10:12]))

	off := 12
	for i := 0; i < qd; i++ {
		_, next := readName(data, off)
		off = next + 4 // QTYPE(2) + QCLASS(2)
		if off > len(data) {
			off = len(data)
		}
	}

	total := an + ns + ar
	rrs := make([]RR, 0, total)
	for i := 0; i < total; i++ {
		if off+10 > len(data) {
			break
		}
		name, next := readName(data, off)
		off = next
		if off+10 > len(data) {
			break
		}
		typ := binary.BigEndian.Uint16(data[off : off+2])
		cls := binary.BigEndian.Uint16(data[off+2 : off+4])
		ttl := binary.BigEndian.Uint32(data[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(data[off+8 : off+10]))
		off += 10
		if off+rdlen > len(data) {
			break
		}
		rdOff := off
		rd := data[off : off+rdlen]
		off += rdlen

		rr := RR{Name: name, Type: typ, Class: cls, TTL: ttl}
		switch typ {
		case TypePTR, TypeNS, TypeCNAME:
			rr.Target, _ = readName(data, rdOff)
		case TypeSRV:
			if rdlen >= 6 {
				rr.Port = binary.BigEndian.Uint16(rd[4:6])
				rr.Target, _ = readName(data, rdOff+6)
			}
		case TypeA:
			if rdlen >= 4 {
				rr.A = net.IP(append([]byte(nil), rd[:4]...))
			}
		case TypeAAAA:
			if rdlen >= 16 {
				rr.AAAA = net.IP(append([]byte(nil), rd[:16]...))
			}
		case TypeTXT:
			rr.TXT = parseTXT(rd)
		}
		rrs = append(rrs, rr)
	}
	return rrs, nil
}

// parseTXT decodes an mDNS TXT record: a sequence of length-prefixed strings.
func parseTXT(rd []byte) []string {
	var out []string
	for i := 0; i < len(rd); {
		l := int(rd[i])
		i++
		if i+l > len(rd) {
			break
		}
		out = append(out, string(rd[i:i+l]))
		i += l
	}
	return out
}

// serviceLabel extracts "http" from "_http._tcp.local".
func serviceLabel(t string) string {
	t = strings.TrimSuffix(strings.TrimSpace(t), ".")
	if strings.HasPrefix(t, "_") {
		t = t[1:]
	}
	if i := strings.Index(t, "._"); i > 0 {
		t = t[:i]
	}
	return t
}

// serviceProto returns "udp" when the type ends with ._udp.local, else "tcp".
func serviceProto(t string) string {
	if strings.HasSuffix(t, "._udp.local") {
		return "udp"
	}
	return "tcp"
}

// instanceBase strips a trailing "(...)" suffix from an instance name.
func instanceBase(instance string) string {
	if i := strings.IndexByte(instance, '('); i > 0 {
		return strings.TrimSpace(instance[:i])
	}
	return instance
}

// Discover performs an mDNS discovery run and returns aggregated assets plus
// the sorted list of discovered service type names.
func Discover(opts Options) ([]Asset, []string) {
	if opts.Timeout <= 0 {
		opts.Timeout = 1500 * time.Millisecond
	}
	types := opts.ServiceTypes
	if len(types) == 0 {
		types = defaultServiceTypes
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	rrCh := make(chan []RR, 64)
	go readLoop(ctx, rrCh)

	go func() {
		time.Sleep(50 * time.Millisecond)
		sendQueries(types)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sendQueries(types)
			}
		}
	}()

	col := newCollector()
	for {
		select {
		case rrs, ok := <-rrCh:
			if !ok {
				return col.assets(), col.serviceTypeList()
			}
			col.add(rrs)
		case <-ctx.Done():
			return col.assets(), col.serviceTypeList()
		}
	}
}

// sendQueries multicasts one PTR query for every requested service type.
func sendQueries(types []string) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(mdnsIPv4Addr), Port: mdnsPort})
	if err != nil {
		return
	}
	defer conn.Close()
	for i, t := range types {
		_, _ = conn.Write(buildQuery(uint16(0x1200+i), t, TypePTR))
	}
}

// readLoop opens multicast listeners and forwards parsed RRs until ctx ends.
func readLoop(ctx context.Context, rrCh chan<- []RR) {
	defer close(rrCh)
	conns := openListeners()
	if len(conns) == 0 {
		return
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func(c *net.UDPConn) {
			defer wg.Done()
			buf := make([]byte, 65535)
			for {
				_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				n, _, err := c.ReadFromUDP(buf)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					continue
				}
				rrs, err := parseMessage(buf[:n])
				if err != nil || len(rrs) == 0 {
					continue
				}
				select {
				case rrCh <- rrs:
				case <-ctx.Done():
					return
				}
			}
		}(c)
	}
	wg.Wait()
}

// openListeners joins the mDNS multicast groups on every capable interface.
func openListeners() []*net.UDPConn {
	var conns []*net.UDPConn
	ifaces, err := net.Interfaces()
	if err == nil {
		for i := range ifaces {
			ifc := ifaces[i]
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagMulticast == 0 {
				continue
			}
			if c, e := net.ListenMulticastUDP("udp4", &ifc, &net.UDPAddr{IP: net.ParseIP(mdnsIPv4Addr), Port: mdnsPort}); e == nil {
				conns = append(conns, c)
			}
		}
		for i := range ifaces {
			ifc := ifaces[i]
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagMulticast == 0 {
				continue
			}
			if c, e := net.ListenMulticastUDP("udp6", &ifc, &net.UDPAddr{IP: net.ParseIP(mdnsIPv6Addr), Port: mdnsPort}); e == nil {
				conns = append(conns, c)
			}
		}
	}
	if len(conns) == 0 {
		if c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: mdnsPort}); e == nil {
			conns = append(conns, c)
		}
	}
	return conns
}

type instRec struct {
	full        string
	instance    string
	serviceType string
	label       string
	proto       string
	port        int
	target      string
	ttl         uint32
	txt         []string
}

type hostRec struct {
	name string
	ipv4 string
	ipv6 string
}

type collector struct {
	mu       sync.Mutex
	insts    map[string]*instRec
	hosts    map[string]*hostRec
	svcTypes map[string]bool
}

func newCollector() *collector {
	return &collector{
		insts:    map[string]*instRec{},
		hosts:    map[string]*hostRec{},
		svcTypes: map[string]bool{},
	}
}

func (c *collector) add(rrs []RR) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rr := range rrs {
		switch rr.Type {
		case TypePTR:
			if rr.Name == "_services._dns-sd._udp.local" {
				c.svcTypes[strings.TrimSuffix(rr.Target, ".")] = true
				continue
			}
			c.svcTypes[strings.TrimSuffix(rr.Name, ".")] = true
			inst := c.ensureInst(rr.Target)
			if inst.serviceType == "" {
				inst.serviceType = strings.TrimSuffix(rr.Name, ".")
				inst.label = serviceLabel(inst.serviceType)
				inst.proto = serviceProto(inst.serviceType)
			}
		case TypeSRV:
			inst := c.ensureInst(rr.Name)
			inst.port = int(rr.Port)
			inst.target = strings.TrimSuffix(rr.Target, ".")
			inst.proto = serviceProto(inst.serviceType)
			if rr.TTL > 0 {
				inst.ttl = rr.TTL
			}
		case TypeTXT:
			inst := c.ensureInst(rr.Name)
			inst.txt = append([]string(nil), rr.TXT...)
			if rr.TTL > 0 {
				inst.ttl = rr.TTL
			}
		case TypeA:
			h := c.ensureHost(rr.Name)
			if h.ipv4 == "" {
				h.ipv4 = rr.A.String()
			}
		case TypeAAAA:
			h := c.ensureHost(rr.Name)
			if h.ipv6 == "" {
				h.ipv6 = rr.AAAA.String()
			}
		}
	}
}

func (c *collector) ensureInst(full string) *instRec {
	full = strings.TrimSuffix(full, ".")
	if i, ok := c.insts[full]; ok {
		return i
	}
	inst := &instRec{full: full}
	inst.instance = full
	if i := strings.Index(full, "."); i >= 0 {
		inst.instance = full[:i]
		inst.serviceType = full[i+1:]
		inst.label = serviceLabel(inst.serviceType)
		inst.proto = serviceProto(inst.serviceType)
	}
	c.insts[full] = inst
	return inst
}

func (c *collector) ensureHost(name string) *hostRec {
	name = strings.TrimSuffix(name, ".")
	if h, ok := c.hosts[name]; ok {
		return h
	}
	h := &hostRec{name: name}
	c.hosts[name] = h
	return h
}

func (c *collector) assets() []Asset {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Asset, 0, len(c.insts))
	for _, inst := range c.insts {
		host := inst.target
		if host == "" {
			host = instanceBase(inst.instance) + ".local"
		}
		h := c.hosts[host]
		ip := ""
		ipv6 := ""
		if h != nil {
			ip = h.ipv4
			ipv6 = h.ipv6
		}
		a := Asset{
			IP:          ip,
			Port:        inst.port,
			Proto:       inst.proto,
			Host:        host,
			Instance:    inst.instance,
			Service:     inst.label,
			ServiceType: inst.serviceType,
			TTL:         inst.ttl,
			IPv6:        ipv6,
			Banner:      map[string]string{},
		}
		for _, kv := range inst.txt {
			k, v, ok := strings.Cut(kv, "=")
			if ok {
				a.Banner[k] = v
				a.BannerOrder = append(a.BannerOrder, k)
			} else {
				a.Banner[kv] = ""
				a.BannerOrder = append(a.BannerOrder, kv)
			}
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Service < out[j].Service
	})
	return out
}

func (c *collector) serviceTypeList() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.svcTypes))
	for t := range c.svcTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}