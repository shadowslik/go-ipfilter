package ipfilter_test

import (
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
	m.Remove("1.2.3.4")
	ok, _ := m.Match("1.2.3.4")
	if ok {
		t.Fatal("IP should have been removed")
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

	// First call populates cache
	ok1, _ := m.Match("5.5.5.5")
	// Second call hits cache
	ok2, _ := m.Match("5.5.5.5")
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
