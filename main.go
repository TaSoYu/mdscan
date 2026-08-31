// Command mdscan is a website / network asset mapping CLI. It discovers mDNS
// services (PTR/SRV/TXT/A/AAAA) inside an IP network and optionally performs a
// TCP port scan with active HTTP banner grabbing, then emits ip/port/host plus
// a deep banner aligned with the reference sample.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"mdscan/internal/mdns"
	"mdscan/internal/output"
	"mdscan/internal/probe"
	"mdscan/internal/scanner"
)

func main() {
	cidr := flag.String("c", "", "target ip range: cidr (192.168.1.0/24) or start-end (10.0.0.1-10.0.0.254)")
	ports := flag.String("p", "", "port range, e.g. 1-10000 or 80,443,5000")
	timeout := flag.Duration("t", 1500*time.Millisecond, "mDNS listen / connect timeout")
	concurrency := flag.Int("j", 256, "TCP scan concurrency")
	format := flag.String("f", "text", "output format: text | json")
	outFile := flag.String("o", "", "output file (default stdout)")
	noMdns := flag.Bool("no-mdns", false, "disable mDNS discovery")
	noScan := flag.Bool("no-scan", false, "disable TCP port scan")
	flag.Parse()

	ipList, err := scanner.ParseIPs(*cidr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	portList, err := scanner.ParsePorts(*ports)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	ipSet := map[string]bool{}
	for _, ip := range ipList {
		ipSet[ip] = true
	}
	portSet := map[int]bool{}
	for _, p := range portList {
		portSet[p] = true
	}

	var assets []mdns.Asset
	var serviceTypes []string

	if !*noMdns {
		assets, serviceTypes = mdns.Discover(mdns.Options{Timeout: *timeout})
	}

	// Enrich mDNS-discovered HTTP(S) services with a real banner probe.
	for i := range assets {
		if assets[i].Service != "http" || assets[i].IP == "" || assets[i].Port <= 0 {
			continue
		}
		if r := probe.HTTP(assets[i].IP, assets[i].Port, *timeout); r != nil {
			assets[i].Banner = map[string]string{"path": r.Path, "server": r.Server, "title": r.Title}
			assets[i].BannerOrder = []string{"path", "server", "title"}
		}
	}

	// The port scan only fills gaps: ports already classified by mDNS win.
	covered := map[string]bool{}
	for _, a := range assets {
		if a.IP != "" && a.Port > 0 {
			covered[net.JoinHostPort(a.IP, strconv.Itoa(a.Port))] = true
		}
	}

	if !*noScan && len(ipList) > 0 && len(portList) > 0 {
		for _, op := range scanner.ScanPorts(ipList, portList, *timeout, *concurrency) {
			key := net.JoinHostPort(op.IP, strconv.Itoa(op.Port))
			if covered[key] {
				continue
			}
			if r := probe.HTTP(op.IP, op.Port, *timeout); r != nil {
				assets = append(assets, mdns.Asset{
					IP:          op.IP,
					Port:        op.Port,
					Proto:       "tcp",
					Host:        op.IP,
					Instance:    op.IP,
					Service:     "http",
					Banner:      map[string]string{"path": r.Path, "server": r.Server, "title": r.Title},
					BannerOrder: []string{"path", "server", "title"},
				})
				covered[key] = true
			}
		}
	}

	filtered := assets[:0]
	for _, a := range assets {
		if len(ipSet) > 0 && !ipSet[a.IP] {
			continue
		}
		if len(portSet) > 0 && a.Port > 0 && !portSet[a.Port] {
			continue
		}
		filtered = append(filtered, a)
	}
	assets = filtered

	w := ioWriter(*outFile)
	defer w.Close()

	switch *format {
	case "json":
		output.JSON(w, assets, serviceTypes)
	default:
		output.Text(w, assets, serviceTypes)
	}
}

// ioWriter returns stdout or the requested output file.
func ioWriter(path string) *os.File {
	if path == "" {
		return os.Stdout
	}
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	return f
}
