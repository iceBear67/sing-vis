// Package dnsx provides a DNS-over-HTTPS resolver used to resolve domains to IP
// addresses when route rules depend on the resolved IP (ip_cidr, IP rule sets)
// or when a rule's action is "resolve".
//
// It uses the DoH JSON API (https://developers.google.com/speed/public-dns/docs/doh/json,
// also implemented by Cloudflare) rather than the RFC 8484 wireformat. In a
// browser this matters: a JSON GET with `Accept: application/dns-json` is a CORS
// "simple request", so it avoids the preflight that a wireformat POST with a
// custom Content-Type would trigger, and it needs no DNS message packer.
package dnsx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Resolver resolves a hostname to A/AAAA records.
type Resolver interface {
	// Resolve returns resolved addresses for name. strategy is one of
	// "", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only".
	Resolve(ctx context.Context, name string, strategy string) (*Result, error)
	Server() string
}

// Result holds resolved addresses and diagnostic info about the query.
type Result struct {
	Name  string   `json:"name"`
	IPv4  []string `json:"ipv4"`
	IPv6  []string `json:"ipv6"`
	Error string   `json:"error,omitempty"`
}

// All returns v4+v6 addresses honoring the strategy ordering.
func (r *Result) All(strategy string) []string {
	switch strategy {
	case "ipv4_only":
		return r.IPv4
	case "ipv6_only":
		return r.IPv6
	case "prefer_ipv6":
		return append(append([]string{}, r.IPv6...), r.IPv4...)
	default: // prefer_ipv4 / unset
		return append(append([]string{}, r.IPv4...), r.IPv6...)
	}
}

// DoHResolver implements Resolver against a DoH JSON endpoint.
type DoHResolver struct {
	server string
	client *http.Client

	mu    sync.Mutex
	cache map[string]*Result
}

// NewDoHResolver builds a resolver for the given DoH endpoint URL.
func NewDoHResolver(server string) *DoHResolver {
	return &DoHResolver{
		server: server,
		client: &http.Client{Timeout: 10 * time.Second},
		cache:  map[string]*Result{},
	}
}

func (d *DoHResolver) Server() string { return d.server }

// DNS record types used by the JSON API.
const (
	typeA    = 1
	typeAAAA = 28
)

// Resolve queries A and AAAA records for name over DoH JSON, caching per resolver.
func (d *DoHResolver) Resolve(ctx context.Context, name string, strategy string) (*Result, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	d.mu.Lock()
	if r, ok := d.cache[name]; ok {
		d.mu.Unlock()
		return r, nil
	}
	d.mu.Unlock()

	res := &Result{Name: name}
	var firstErr error

	if strategy != "ipv6_only" {
		v4, err := d.query(ctx, name, typeA)
		if err != nil {
			firstErr = err
		}
		res.IPv4 = v4
	}
	if strategy != "ipv4_only" {
		v6, err := d.query(ctx, name, typeAAAA)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		res.IPv6 = v6
	}

	if len(res.IPv4) == 0 && len(res.IPv6) == 0 && firstErr != nil {
		res.Error = firstErr.Error()
		return res, firstErr
	}
	d.mu.Lock()
	d.cache[name] = res
	d.mu.Unlock()
	return res, nil
}

// jsonResponse is the DoH JSON API response shape (Google/Cloudflare).
type jsonResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
	Comment string `json:"Comment,omitempty"`
}

func (d *DoHResolver) query(ctx context.Context, name string, qtype int) ([]string, error) {
	endpoint, err := url.Parse(d.server)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH server %q: %w", d.server, err)
	}
	q := endpoint.Query()
	q.Set("name", name)
	q.Set("type", fmt.Sprint(qtype))
	q.Set("ct", "application/dns-json")
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	// Accept is a CORS-safelisted header, so this stays a simple request.
	req.Header.Set("Accept", "application/dns-json")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed jsonResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("parse DoH JSON: %w", err)
	}
	var out []string
	for _, a := range parsed.Answer {
		if a.Type == qtype {
			out = append(out, a.Data)
		}
	}
	return out, nil
}
