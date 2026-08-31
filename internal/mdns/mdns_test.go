package mdns

import (
	"testing"

	"mdscan/internal/mockmdns"
)

// TestBannerDepthFromMockQNAP feeds the mock QNAP NAS mDNS responses through
// the real parser + collector and asserts the deep banner fields described in
// the reference sample are all recovered.
func TestBannerDepthFromMockQNAP(t *testing.T) {
	col := newCollector()
	for _, m := range mockmdns.BuildMessages(mockmdns.QNAP()) {
		rrs, err := parseMessage(m)
		if err != nil {
			t.Fatalf("parseMessage: %v", err)
		}
		col.add(rrs)
	}
	assets := col.assets()

	byService := map[string]*Asset{}
	for i := range assets {
		byService[assets[i].Service] = &assets[i]
	}

	ws := byService["workstation"]
	if ws == nil {
		t.Fatal("workstation asset missing")
	}
	if ws.MAC != "24:5e:be:69:a3:13" {
		t.Errorf("workstation MAC = %q, want 24:5e:be:69:a3:13", ws.MAC)
	}
	if _, ok := ws.Banner["mac"]; ok {
		t.Errorf("mac should be extracted out of banner: %v", ws.Banner)
	}
	if ws.Port != 9 {
		t.Errorf("workstation port = %d, want 9", ws.Port)
	}

	q := byService["qdiscover"]
	if q == nil {
		t.Fatal("qdiscover asset missing")
	}
	wantBanner := map[string]string{
		"accessType":   "https",
		"accessPort":   "86",
		"model":        "TS-X64",
		"displayModel": "TS-464C",
		"fwVer":        "5.2.9",
		"fwBuildNum":   "20260214",
	}
	for k, v := range wantBanner {
		if q.Banner[k] != v {
			t.Errorf("qdiscover banner[%s] = %q, want %q", k, q.Banner[k], v)
		}
	}
	if q.Port != 5000 {
		t.Errorf("qdiscover port = %d, want 5000", q.Port)
	}

	di := byService["device-info"]
	if di == nil || di.Banner["model"] != "Xserve" || di.Port != 0 {
		t.Errorf("device-info wrong: %+v", di)
	}

	h := byService["http"]
	if h == nil {
		t.Fatal("http asset missing")
	}
	if h.IP != "192.168.1.100" || h.Host != "slw-nas.local" || h.Port != 5000 {
		t.Errorf("http asset wrong: %+v", h)
	}
	if h.IPv6 == "" {
		t.Errorf("http asset missing IPv6: %+v", h)
	}

	afp := byService["afpovertcp"]
	if afp == nil || afp.Port != 548 {
		t.Errorf("afpovertcp wrong: %+v", afp)
	}
}
