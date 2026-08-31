package output

import (
	"bytes"
	"strings"
	"testing"

	"mdscan/internal/mdns"
)

func TestTextRendersBannerDepth(t *testing.T) {
	assets := []mdns.Asset{
		{
			IP: "10.0.0.10", Port: 9, Proto: "tcp", Host: "slw-nas.local",
			Instance: "slw-nas", Service: "workstation", TTL: 10,
			MAC: "24:5e:be:69:a3:13",
		},
		{
			IP: "10.0.0.10", Port: 5000, Proto: "tcp", Host: "slw-nas.local",
			Instance: "slw-nas", Service: "http", TTL: 10,
			Banner:      map[string]string{"path": "/", "server": "nginx", "title": "QNAP"},
			BannerOrder: []string{"path", "server", "title"},
		},
		{
			IP: "10.0.0.10", Port: 5000, Proto: "tcp", Host: "slw-nas.local",
			Instance: "slw-nas", Service: "qdiscover", TTL: 10,
			Banner: map[string]string{
				"accessType":   "https",
				"accessPort":   "86",
				"model":        "TS-X64",
				"displayModel": "TS-464C",
				"fwVer":        "5.2.9",
				"fwBuildNum":   "20260214",
			},
			BannerOrder: []string{"accessType", "accessPort", "model", "displayModel", "fwVer", "fwBuildNum"},
		},
	}
	var buf bytes.Buffer
	Text(&buf, assets, []string{"_qdiscover._tcp.local"})
	got := buf.String()
	for _, want := range []string{
		"Name=slw-nas [24:5e:be:69:a3:13]",
		"path=/",
		"title=QNAP",
		"accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214",
		"PTR:",
		"_qdiscover._tcp.local",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestDedupAssets(t *testing.T) {
	a := []mdns.Asset{
		{IP: "10.0.0.10", Port: 5000, Proto: "tcp", Service: "http"},
		{IP: "10.0.0.10", Port: 5000, Proto: "tcp", Service: "http", Banner: map[string]string{"path": "/"}},
	}
	got := dedupAssets(a)
	if len(got) != 1 {
		t.Fatalf("want 1 deduped asset, got %d", len(got))
	}
	if got[0].Banner["path"] != "/" {
		t.Fatalf("want banner merged, got %v", got[0].Banner)
	}
}

func TestJSONEmptyIsArray(t *testing.T) {
	var buf bytes.Buffer
	JSON(&buf, nil, nil)
	if !strings.Contains(buf.String(), `"assets": []`) {
		t.Fatalf("want empty array for assets, got %s", buf.String())
	}
}
