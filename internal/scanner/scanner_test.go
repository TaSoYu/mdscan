package scanner

import "testing"

func TestParseIPsRejectsHugeCIDR(t *testing.T) {
	if _, err := ParseIPs("0.0.0.0/0"); err == nil {
		t.Fatal("expected error for /0, got nil")
	}
	if _, err := ParseIPs("10.0.0.0/8"); err == nil {
		t.Fatal("expected error for /8, got nil")
	}
}

func TestParseIPsRange(t *testing.T) {
	ips, err := ParseIPs("10.0.0.1-10.0.0.3")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 3 || ips[0] != "10.0.0.1" || ips[2] != "10.0.0.3" {
		t.Fatalf("unexpected ips: %v", ips)
	}
}

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("80,443,8000-8001")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 4 {
		t.Fatalf("want 4 ports, got %v", ports)
	}
}
