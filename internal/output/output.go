// Package output renders discovered assets as human-readable text aligned to
// the reference sample, or as JSON.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"mdscan/internal/mdns"
)

// Text writes the reference-style text report.
func Text(w io.Writer, assets []mdns.Asset, serviceTypes []string) {
	assets = dedupAssets(assets)
	fmt.Fprintln(w, "services:")
	groups := groupAssets(assets)
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, a := range groups[k] {
			writeAsset(w, a)
		}
	}
	fmt.Fprintln(w, "answers:")
	fmt.Fprintln(w, "PTR:")
	for _, t := range serviceTypes {
		fmt.Fprintln(w, t)
	}
}

// JSON writes a machine-readable report.
func JSON(w io.Writer, assets []mdns.Asset, serviceTypes []string) {
	assets = dedupAssets(assets)
	if assets == nil {
		assets = []mdns.Asset{}
	}
	if serviceTypes == nil {
		serviceTypes = []string{}
	}
	payload := map[string]any{
		"assets":       assets,
		"serviceTypes": serviceTypes,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

// dedupAssets removes entries sharing the same ip:port:proto:service, keeping
// the first occurrence and merging banner info into it when it was empty.
func dedupAssets(assets []mdns.Asset) []mdns.Asset {
	seen := map[string]int{}
	out := assets[:0]
	for _, a := range assets {
		key := fmt.Sprintf("%s|%d|%s|%s", a.IP, a.Port, a.Proto, a.Service)
		if i, ok := seen[key]; ok {
			if len(out[i].Banner) == 0 && len(a.Banner) > 0 {
				out[i].Banner = a.Banner
				out[i].BannerOrder = a.BannerOrder
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, a)
	}
	return out
}

func groupAssets(assets []mdns.Asset) map[string][]mdns.Asset {
	m := map[string][]mdns.Asset{}
	for _, a := range assets {
		k := fmt.Sprintf("%05d/%s/%s", a.Port, a.Proto, a.Service)
		m[k] = append(m[k], a)
	}
	return m
}

func writeAsset(w io.Writer, a mdns.Asset) {
	if a.Port > 0 {
		fmt.Fprintf(w, "%d/%s %s:\n", a.Port, a.Proto, a.Service)
	} else {
		fmt.Fprintf(w, "%s:\n", a.Service)
	}
	name := a.Instance
	if a.MAC != "" {
		name += " [" + a.MAC + "]"
	}
	fmt.Fprintf(w, "Name=%s\n", name)
	if a.IP != "" {
		fmt.Fprintf(w, "IPv4=%s\n", a.IP)
	}
	if a.IPv6 != "" {
		fmt.Fprintf(w, "IPv6=%s\n", a.IPv6)
	}
	if a.Host != "" {
		fmt.Fprintf(w, "Hostname=%s\n", a.Host)
	}
	if a.TTL > 0 {
		fmt.Fprintf(w, "TTL=%d\n", a.TTL)
	}
	for _, line := range extraFields(a) {
		fmt.Fprintln(w, line)
	}
}

func extraFields(a mdns.Asset) []string {
	switch a.Service {
	case "http":
		path := a.Banner["path"]
		if path == "" {
			path = "/"
		}
		out := []string{"path=" + path}
		for _, k := range a.BannerOrder {
			if k == "path" || k == "server" {
				continue
			}
			v := a.Banner[k]
			if v == "" {
				out = append(out, k)
			} else {
				out = append(out, k+"="+v)
			}
		}
		return out
	default:
		if len(a.BannerOrder) == 0 {
			return nil
		}
		var parts []string
		for _, k := range a.BannerOrder {
			v := a.Banner[k]
			if v == "" {
				parts = append(parts, k)
			} else {
				parts = append(parts, k+"="+v)
			}
		}
		return []string{strings.Join(parts, ",")}
	}
}
