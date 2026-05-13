package ipfilter_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	ipfilter "github.com/shadowslik/go-ipfilter"
)

func TestMatchExact(t *testing.T) {
	m := ipfilter.New(0, 0)
	_ = m.Add("192.168.1.1")

	ok, err := m.Match("192.168.1.1")
	if err != nil || !ok {
		t.Fatalf("expected match for exact IP, got ok=%v err=%v", ok, err)
	}
	ok, _ = m.Match("192.168.1.2")
	if ok {
		t.Fatal("expected no match for unlisted IP")
	}
}

func TestMatchCIDR(t *testing.T) {
	m := ipfilter.New(0, 0)
	_ = m.Add("10.0.0.0/8")

	for _, ip := range []string{"10.0.0.1", "10.255.255.255", "10.1.2.3"} {
		ok, err := m.Match(ip)
		if err != nil || !ok {
			t.Fatalf("expected CIDR match for %s, got ok=%v err=%v", ip, ok, err)
		}
	}
	ok, _ := m.Match("11.0.0.1")
	if ok {
		t.Fatal("11.0.0.1 should not match 10.0.0.0/8")
	}
}

func TestMatchRange(t *testing.T) {
	m := ipfilter.New(0, 0)
	_ = m.Add("192.168.1.1-192.168.1.10")

	for _, ip := range []string{"192.168.1.1", "192.168.1.5", "192.168.1.10"} {
		ok, err := m.Match(ip)
		if err != nil || !ok {
			t.Fatalf("expected range match for %s, got ok=%v err=%v", ip, ok, err)
		}
	}
	ok, _ := m.Match("192.168.1.11")
	if ok {
		t.Fatal("192.168.1.11 should be outside range")
	}
}

func TestRemove(t *testing.T) {
	m := ipfilter.New(0, 0)
	_ = m.Add("1.2.3.4")

	removed := m.Remove("1.2.3.4")
	if !removed {
		t.Fatal("Remove should return true when entry exists")
	}
	ok, _ := m.Match("1.2.3.4")
	if ok {
		t.Fatal("IP should have been removed")
	}

	removed = m.Remove("9.9.9.9")
	if removed {
		t.Fatal("Remove should return false for non-existent entry")
	}
}

func TestReset(t *testing.T) {
	m := ipfilter.New(0, 0)
	_ = m.Add("1.1.1.1")
	_ = m.Reset([]string{"2.2.2.2"})

	ok, _ := m.Match("1.1.1.1")
	if ok {
		t.Fatal("old entry should be gone after Reset")
	}
	ok, _ = m.Match("2.2.2.2")
	if !ok {
		t.Fatal("new entry should match after Reset")
	}
}

func TestCache(t *testing.T) {
	m := ipfilter.New(100, 1*time.Second)
	_ = m.Add("5.5.5.5")

	ok1, _ := m.Match("5.5.5.5")
	ok2, _ := m.Match("5.5.5.5") // cache hit
	if !ok1 || !ok2 {
		t.Fatal("both calls should return true")
	}
}

func TestInvalidIP(t *testing.T) {
	m := ipfilter.New(0, 0)
	_, err := m.Match("not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestInvalidRange_Reversed(t *testing.T) {
	m := ipfilter.New(0, 0)
	err := m.Add("192.168.1.10-192.168.1.1")
	if err == nil {
		t.Fatal("expected error for reversed range (start > end)")
	}
}

func TestInvalidRange_BadIP(t *testing.T) {
	m := ipfilter.New(0, 0)
	err := m.Add("not-an-ip-not-an-ip")
	if err == nil {
		t.Fatal("expected error for malformed range")
	}
}

func TestStats(t *testing.T) {
	m := ipfilter.New(100, time.Minute)
	_ = m.Add("1.2.3.4")
	_ = m.Add("10.0.0.0/8")
	_ = m.Add("192.168.1.1-192.168.1.10")

	_, _ = m.Match("1.2.3.4") // populate cache

	s := m.Stats()
	if s.ExactCount != 1 {
		t.Errorf("ExactCount: want 1, got %d", s.ExactCount)
	}
	if s.RangeCount != 1 {
		t.Errorf("RangeCount: want 1, got %d", s.RangeCount)
	}
	if s.CacheSize != 1 {
		t.Errorf("CacheSize: want 1, got %d", s.CacheSize)
	}
}

func TestLen(t *testing.T) {
	m := ipfilter.New(0, 0)
	_ = m.Add("1.2.3.4")
	_ = m.Add("10.0.0.0/8")
	if m.Len() != 2 {
		t.Errorf("Len: want 2, got %d", m.Len())
	}
	m.Remove("1.2.3.4")
	if m.Len() != 1 {
		t.Errorf("Len after Remove: want 1, got %d", m.Len())
	}
}

func TestConcurrentAccess(t *testing.T) {
	m := ipfilter.New(100, time.Minute)
	_ = m.Reset([]string{"10.0.0.0/8", "192.168.1.1"})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = m.Match("10.0.0.1")
			_, _ = m.Match("192.168.1.1")
		}()
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := fmt.Sprintf("172.16.0.%d", n)
			_ = m.Add(ip)
		}(i)
	}
	wg.Wait()
}
