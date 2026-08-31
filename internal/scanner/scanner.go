// Package scanner provides IP network / port range parsing and a lightweight
// concurrent TCP connect scanner used for active (non-mDNS) asset mapping.
package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxExpand caps the number of hosts an IP range may expand to, preventing
// accidental OOM for inputs like 0.0.0.0/0.
const maxExpand = 1 << 16

func ipToU32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func u32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// ParseIPs expands a CIDR ("192.168.1.0/24"), a range
// ("10.0.0.1-10.0.0.254") or a single IP into a list of IPv4 strings.
func ParseIPs(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if strings.Contains(s, "/") {
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			return nil, fmt.Errorf("only ipv4 cidr is supported, got %q", s)
		}
		start := ipToU32(ip.Mask(ipnet.Mask).To4())
		hostBits := uint(32 - ones)
		if hostBits >= 32 {
			return nil, fmt.Errorf("cidr %q is too large to expand", s)
		}
		size := uint32(1) << hostBits
		if size > maxExpand {
			return nil, fmt.Errorf("cidr %q expands to %d hosts, over the %d limit", s, size, maxExpand)
		}
		out := make([]string, 0, size)
		for i := uint32(0); i < size; i++ {
			out = append(out, u32ToIP(start+i).String())
		}
		return out, nil
	}
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		start := net.ParseIP(strings.TrimSpace(parts[0])).To4()
		end := net.ParseIP(strings.TrimSpace(parts[1])).To4()
		if start == nil || end == nil {
			return nil, fmt.Errorf("invalid ip range %q", s)
		}
		a, b := ipToU32(start), ipToU32(end)
		if b < a {
			a, b = b, a
		}
		count := uint64(b) - uint64(a) + 1
		if count > maxExpand {
			return nil, fmt.Errorf("ip range %q spans %d hosts, over the %d limit", s, count, maxExpand)
		}
		out := make([]string, 0, count)
		for v := a; ; v++ {
			out = append(out, u32ToIP(v).String())
			if v == b {
				break
			}
		}
		return out, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return []string{ip.String()}, nil
	}
	return nil, fmt.Errorf("invalid ip %q", s)
}

// ParsePorts expands "1-10000", "80,443" or a mixture into a unique port list.
func ParsePorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []int
	seen := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			ps := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(ps[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(ps[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			for p := lo; p <= hi; p++ {
				if p < 1 || p > 65535 {
					continue
				}
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// OpenPort is a single confirmed-open TCP port.
type OpenPort struct {
	IP   string
	Port int
}

// ScanPorts performs a concurrent TCP connect scan over ips x ports.
func ScanPorts(ips []string, ports []int, timeout time.Duration, concurrency int) []OpenPort {
	if len(ips) == 0 || len(ports) == 0 {
		return nil
	}
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	if concurrency <= 0 {
		concurrency = 256
	}

	type job struct {
		ip   string
		port int
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []OpenPort

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if connect(j.ip, j.port, timeout) {
					mu.Lock()
					out = append(out, OpenPort{IP: j.ip, Port: j.port})
					mu.Unlock()
				}
			}
		}()
	}

	go func() {
		for _, ip := range ips {
			for _, p := range ports {
				jobs <- job{ip, p}
			}
		}
		close(jobs)
	}()

	wg.Wait()
	return out
}

func connect(ip string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
