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

const (
	KindExact = "exact"
	KindCIDR  = "cidr"
	KindRange = "range"
)

type ipRange struct {
	start net.IP
	end   net.IP
	raw   string
}

type Stats struct {
	ExactCount int
	RangeCount int
	CacheSize  int
}

type Matcher struct {
	mu       sync.RWMutex
	exactIPs map[string]struct{}
	ranger   cidranger.Ranger
	ranges   []ipRange
	raw      []string
	cache    *lruexpirable.LRU[string, bool]
}

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

func (m *Matcher) Remove(entry string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	found := false
	filtered := m.raw[:0]
	for _, s := range m.raw {
		if s == entry {
			found = true
		} else {
			filtered = append(filtered, s)
		}
	}
	if !found {
		return false
	}
	m.raw = filtered

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
	return true
}

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
	result := m.matchLocked(ip)
	m.mu.RUnlock()

	if m.cache != nil {
		m.cache.Add(ipStr, result)
	}
	return result, nil
}

func (m *Matcher) matchLocked(ip net.IP) bool {
	if _, ok := m.exactIPs[ip.String()]; ok {
		return true
	}
	if entries, err := m.ranger.ContainingNetworks(ip); err == nil && len(entries) > 0 {
		return true
	}
	cmp := ip
	if v4 := ip.To4(); v4 != nil {
		cmp = v4
	}
	for _, r := range m.ranges {
		if bytes.Compare(cmp, r.start) >= 0 && bytes.Compare(cmp, r.end) <= 0 {
			return true
		}
	}
	return false
}

func (m *Matcher) Entries() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.raw))
	copy(out, m.raw)
	return out
}

func (m *Matcher) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.raw)
}

func (m *Matcher) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := Stats{
		ExactCount: len(m.exactIPs),
		RangeCount: len(m.ranges),
	}
	if m.cache != nil {
		s.CacheSize = m.cache.Len()
	}
	return s
}

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
		if v4 := start.To4(); v4 != nil {
			start = v4
		}
		if v4 := end.To4(); v4 != nil {
			end = v4
		}
		if bytes.Compare(start, end) > 0 {
			return fmt.Errorf("ipfilter: invalid range %q: start must be <= end", entry)
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
