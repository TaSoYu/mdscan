// Package mockmdns builds the mDNS response messages a synthetic QNAP-like NAS
// would broadcast, so mdscan's banner depth can be verified end-to-end without
// requiring a physical device on the LAN.
package mockmdns

import (
	"encoding/binary"
	"net"
	"strings"
)

// DNS resource record type codes used by mDNS.
const (
	typeA    = 1
	typeAAAA = 28
	typePTR  = 12
	typeTXT  = 16
	typeSRV  = 33
)

// Service is a single mDNS service advertised by the mock device.
type Service struct {
	Type     string   // e.g. "_qdiscover._tcp.local"
	Instance string   // e.g. "slw-nas"
	Port     int      // SRV port, 0 for port-less services such as _device-info
	TXT      []string // ordered TXT key=value strings
}

// Device is a synthetic mDNS host.
type Device struct {
	Host     string
	IPv4     string
	IPv6     string
	MAC      string
	Services []Service
}

// QNAP returns the reference QNAP-like NAS used in the mdscan example output.
func QNAP() Device {
	return Device{
		Host: "slw-nas.local",
		IPv4: "192.168.1.100",
		IPv6: "fe80::265e:beff:fe69:a313",
		MAC:  "24:5e:be:69:a3:13",
		Services: []Service{
			{Type: "_workstation._tcp.local", Instance: "slw-nas", Port: 9, TXT: []string{"mac=24:5e:be:69:a3:13"}},
			{Type: "_http._tcp.local", Instance: "slw-nas", Port: 5000},
			{Type: "_smb._tcp.local", Instance: "slw-nas", Port: 445},
			{
				Type:     "_qdiscover._tcp.local",
				Instance: "slw-nas",
				Port:     5000,
				TXT: []string{
					"accessType=https",
					"accessPort=86",
					"model=TS-X64",
					"displayModel=TS-464C",
					"fwVer=5.2.9",
					"fwBuildNum=20260214",
				},
			},
			{Type: "_device-info._tcp.local", Instance: "slw-nas(AFP)", Port: 0, TXT: []string{"model=Xserve"}},
			{Type: "_afpovertcp._tcp.local", Instance: "slw-nas(AFP)", Port: 548},
		},
	}
}

// BuildMessages returns DNS response messages advertising the given device. All
// PTR/SRV/TXT/A/AAAA records are packed into a single response message, which
// is enough for the mdscan collector to aggregate the full asset catalogue.
func BuildMessages(d Device) [][]byte {
	type rec struct {
		name  string
		typ   uint16
		rdata []byte
	}

	const ttl = uint32(10)
	var recs []rec

	for _, svc := range d.Services {
		full := svc.Instance + "." + svc.Type

		recs = append(recs, rec{svc.Type, typePTR, encodeName(full)})

		if svc.Port > 0 {
			rd := []byte{0, 0, 0, 0} // priority, weight
			var p [2]byte
			binary.BigEndian.PutUint16(p[:], uint16(svc.Port))
			rd = append(rd, p[:]...)
			rd = append(rd, encodeName(d.Host)...)
			recs = append(recs, rec{full, typeSRV, rd})
		}

		if len(svc.TXT) > 0 {
			var rd []byte
			for _, t := range svc.TXT {
				rd = append(rd, byte(len(t)))
				rd = append(rd, t...)
			}
			recs = append(recs, rec{full, typeTXT, rd})
		}
	}

	if d.IPv4 != "" {
		recs = append(recs, rec{d.Host, typeA, net.ParseIP(d.IPv4).To4()})
	}
	if d.IPv6 != "" {
		recs = append(recs, rec{d.Host, typeAAAA, net.ParseIP(d.IPv6).To16()})
	}

	var body []byte
	for _, r := range recs {
		body = append(body, buildRR(r.name, r.typ, ttl, r.rdata)...)
	}

	msg := make([]byte, 0, 12+len(body))
	msg = append(msg, 0, 0)       // transaction id
	msg = append(msg, 0x84, 0x00) // QR=1, AA=1
	msg = append(msg, 0, 0)       // QDCOUNT = 0
	var an [2]byte
	binary.BigEndian.PutUint16(an[:], uint16(len(recs)))
	msg = append(msg, an[:]...)
	msg = append(msg, 0, 0, 0, 0) // NSCOUNT, ARCOUNT
	msg = append(msg, body...)

	return [][]byte{msg}
}

// encodeName encodes a domain name as a sequence of length-prefixed labels.
func encodeName(s string) []byte {
	s = strings.TrimSuffix(s, ".")
	var b []byte
	for _, l := range strings.Split(s, ".") {
		if l == "" {
			continue
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

// buildRR encodes a single resource record (name, type, class IN, ttl, rdata).
func buildRR(name string, typ uint16, ttl uint32, rdata []byte) []byte {
	var b []byte
	b = append(b, encodeName(name)...)
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], typ)
	binary.BigEndian.PutUint16(hdr[2:4], 1) // class IN
	binary.BigEndian.PutUint32(hdr[4:8], ttl)
	binary.BigEndian.PutUint16(hdr[8:10], uint16(len(rdata)))
	b = append(b, hdr[:]...)
	return append(b, rdata...)
}
