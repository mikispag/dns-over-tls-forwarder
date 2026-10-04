package specialized

import "testing"

func TestRepeatedEvictionMembership(t *testing.T) {
	m := newMetrics(3, true)
	for _, key := range []string{"a", "b", "a", "c"} {
		m.evict(key)
	}
	m.miss("a")
	if m.RecentlyEvictedMiss != 1 {
		t.Fatalf("failed to count a still-recent eviction: ring=%v", m.store)
	}
	m.evict("d")
	m.evict("e")
	m.miss("a")
	if m.RecentlyEvictedMiss != 1 {
		t.Fatal("counted an eviction after its last ring entry expired")
	}
}
