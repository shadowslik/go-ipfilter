// Package ipfilter provides fast IP address matching against sets of exact IPs,
// CIDR subnets, and IP ranges. It uses a Patricia compressed trie (radix tree)
// for O(log n) CIDR lookups and an optional expirable LRU cache to avoid
// repeated lookups for recently seen addresses.
package ipfilter

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	lruexpirable "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/yl2chen/cidranger"
)

// Entry kinds.
const (
	KindExact  = "exact"
	KindCIDR   = "cidr"
	KindRange  = "range"
)

type ipRange struct {
	start net.IP
	end   net.IP
	raw   string
}

// Matcher holds a set of IP entries and provides thread-safe fast lookup.
// Supported entry formats:
//   - Exact IPv4/IPv6 address: "192.168.1.1"
//   - CIDR notation:           "10.0.0.0/8"
//   - IP range:                "192.168.1.1-192.168.1.254"
type Matcher struct {
	mu       sync.RWMutex
	exactIPs map[string]struct{}
	ranger   cidranger.Ranger
	ranges   []ipRange
	raw      []string
	cache    *lruexpirable.LRU[string, bool]
}

// New creates a Matcher with an LRU cache of the given size and TTL.
// Pass cacheSize=0 or cacheTTL=0 to disable caching.
func New(cacheSize int, cacheTTL time.Duration) *Matcher {
	m := &Matcher{
		exactIPs: make(map[string]struct{}),
		ranger:   cidranger.NewPCTrieRanger(),
	}
	if cacheSize > 0 && cacheTTL > 0 {
		m.cache = lruexpirable.NewLRU[string, bool](cacheSize, nil, cacheTTL)
	}
	return m
}

// Reset replaces all entries atomically.
func (m *Matcher) Reset(entries []string) error {
	exactIPs := make(map[string]struct{})
	ranger := cidranger.NewPCTrieRanger()
	var ranges []ipRange

	for _, entry := range entries {
		if err := addEntry(entry, exactIPs, ranger, &ranges); err != nil {
			return err
		}
	}

	m.mu.Lock()
	m.exactIPs = exactIPs
	m.ranger = ranger
	m.ranges = ranges
	m.raw = append([]string(nil), entries...)
	m.invalidateCache()
	m.mu.Unlock()
	return nil
}

// Add inserts a single entry. Returns an error if the format is invalid.
func (m *Matcher) Add(entry string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := addEntry(entry, m.exactIPs, m.ranger, &m.ranges); err != nil {
		return err
	}
	m.raw = append(m.raw, entry)
	m.invalidateCache()
	return nil
}

// Remove deletes an entry and rebuilds internal indexes.
func (m *Matcher) Remove(entry string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	filtered := m.raw[:0]
	for _, s := range m.raw {
		if s != entry {
			filtered = append(filtered, s)
		}
	}
	m.raw = filtered

	// Rebuild indexes (cidranger has no Delete method).
	exactIPs := make(map[string]struct{})
	ranger := cidranger.NewPCTrieRanger()
	var ranges []ipRange
	for _, s := range m.raw {
		_ = addEntry(s, exactIPs, ranger, &ranges)
	}
	m.exactIPs = exactIPs
	m.ranger = ranger
	m.ranges = ranges
	m.invalidateCache()
}

// Match reports whether ip is covered by any entry in the set.
func (m *Matcher) Match(ipStr string) (bool, error) {
	if m.cache != nil {
		if v, ok := m.cache.Get(ipStr); ok {
			return v, nil
		}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("ipfilter: invalid IP address %q", ipStr)
	}

	m.mu.RLock()
	result := m.matchLocked(ip, ipStr)
	m.mu.RUnlock()

	if m.cache != nil {
		m.cache.Add(ipStr, result)
	}
	return result, nil
}

func (m *Matcher) matchLocked(ip net.IP, ipStr string) bool {
	// 1. Exact match — O(1)
	if _, ok := m.exactIPs[ip.String()]; ok {
		return true
	}
	// 2. CIDR via Patricia trie — O(log n)
	if entries, err := m.ranger.ContainingNetworks(ip); err == nil && len(entries) > 0 {
		return true
	}
	// 3. IP ranges — linear but typically very few
	for _, r := range m.ranges {
		if bytes.Compare(ip, r.start) >= 0 && bytes.Compare(ip, r.end) <= 0 {
			return true
		}
	}
	return false
}

// Entries returns a copy of all raw entries.
func (m *Matcher) Entries() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.raw))
	copy(out, m.raw)
	return out
}

// InvalidateCache clears the LRU cache (e.g. after bulk reload).
func (m *Matcher) InvalidateCache() {
	m.mu.Lock()
	m.invalidateCache()
	m.mu.Unlock()
}

func (m *Matcher) invalidateCache() {
	if m.cache != nil {
		m.cache.Purge()
	}
}

// addEntry parses one entry string and populates the appropriate index.
func addEntry(entry string, exactIPs map[string]struct{}, ranger cidranger.Ranger, ranges *[]ipRange) error {
	entry = strings.TrimSpace(entry)
	switch {
	case strings.Contains(entry, "/"):
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return fmt.Errorf("ipfilter: invalid CIDR %q: %w", entry, err)
		}
		ranger.Insert(cidranger.NewBasicRangerEntry(*network))

	case strings.Contains(entry, "-"):
		parts := strings.SplitN(entry, "-", 2)
		if len(parts) != 2 {
			return fmt.Errorf("ipfilter: invalid range %q", entry)
		}
		start := net.ParseIP(strings.TrimSpace(parts[0]))
		end := net.ParseIP(strings.TrimSpace(parts[1]))
		if start == nil || end == nil {
			return fmt.Errorf("ipfilter: invalid range %q", entry)
		}
		*ranges = append(*ranges, ipRange{start: start, end: end, raw: entry})

	default:
		ip := net.ParseIP(entry)
		if ip == nil {
			return fmt.Errorf("ipfilter: invalid IP address %q", entry)
		}
		exactIPs[ip.String()] = struct{}{}
	}
	return nil
}
