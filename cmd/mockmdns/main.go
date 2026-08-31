// Command mockmdns broadcasts a synthetic QNAP-like NAS over mDNS so that
// mdscan can be verified end-to-end on a LAN without a real device.
package main

import (
	"flag"
	"log"
	"net"
	"time"

	"mdscan/internal/mockmdns"
)

func main() {
	interval := flag.Duration("i", 1*time.Second, "broadcast interval")
	flag.Parse()

	msgs := mockmdns.BuildMessages(mockmdns.QNAP())
	addr := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	log.Printf("mockmdns: broadcasting %d response message(s) every %s", len(msgs), *interval)
	for {
		for _, m := range msgs {
			if _, err := conn.Write(m); err != nil {
				log.Printf("mockmdns: write: %v", err)
			}
		}
		time.Sleep(*interval)
	}
}
