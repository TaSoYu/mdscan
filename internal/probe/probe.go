// Package probe performs lightweight active banner grabbing over TCP.
package probe

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Result is the outcome of an HTTP(S) probe.
type Result struct {
	Path   string
	Server string
	Title  string
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// HTTP probes the target and returns banner fields when it speaks HTTP(S).
func HTTP(ip string, port int, timeout time.Duration) *Result {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	scheme := "http"
	if port == 443 || port == 8443 || port == 5001 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip, fmt.Sprint(port)))
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	r := &Result{Path: "/", Server: resp.Header.Get("Server")}
	if m := titleRe.FindSubmatch(body); len(m) > 1 {
		r.Title = strings.TrimSpace(string(m[1]))
	}
	return r
}