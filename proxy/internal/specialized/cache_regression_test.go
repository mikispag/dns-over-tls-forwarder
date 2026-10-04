package specialized

import (
	"sync"
	"testing"
)

func TestRemove(t *testing.T) {
	c, _ := NewCache(4, true)
	for _, key := range []string{"a", "b", "c", "d"} {
		c.Put(key, key)
	}
	for i, key := range []string{"a", "c", "b", "d"} {
		c.Remove(key)
		c.Remove(key)
		if _, ok := c.Get(key); ok || c.Len() != 3-i {
			t.Fatalf("remove %s: hit=%v len=%d", key, ok, c.Len())
		}
	}
	for _, key := range []string{"a", "b", "c", "d"} {
		c.Put(key, key)
	}
	if c.Len() != 4 || c.Metrics().RecentlyEvictedMiss != 0 {
		t.Fatal("removal changed capacity or counted as an eviction")
	}
	var disabled *Cache
	disabled.Remove("missing")
}

func TestConcurrentOperations(t *testing.T) {
	c, _ := NewCache(128, true)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				key := string(rune((i + g) % 256))
				c.Put(key, i)
				c.Get(key)
				c.Metrics()
				if c.Len() > c.Cap() {
					t.Error("capacity exceeded")
				}
				c.Remove(key)
			}
		}(g)
	}
	wg.Wait()
}

func FuzzCache(f *testing.F) {
	f.Add(uint8(4), []byte{0, 1, 2, 1, 1, 0, 0, 2, 3, 0})
	f.Add(uint8(0), []byte{0, 1, 0, 2, 0, 3, 1, 1, 2, 2})
	f.Fuzz(func(t *testing.T, size uint8, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		c, _ := NewCache(int(size%128)+2, true)
		values := make(map[string]int)
		for i := 0; i+1 < len(data); i += 2 {
			key := string(rune(data[i+1]))
			switch data[i] % 3 {
			case 0:
				c.Put(key, i)
				values[key] = i
				// At capacity the admission policy may prefer an older hot item.
				if got, ok := c.Get(key); (!ok && c.Len() < c.Cap()) || (ok && got != i) {
					t.Fatalf("incorrect put result: got=%v hit=%v len=%d", got, ok, c.Len())
				}
			case 1:
				got, ok := c.Get(key)
				want, known := values[key]
				if ok && (!known || got != want) {
					t.Fatalf("unexpected cached value: got=%v want=%v known=%v", got, want, known)
				}
			case 2:
				c.Remove(key)
				delete(values, key)
				if _, ok := c.Get(key); ok {
					t.Fatal("removed key still present")
				}
			}
			if c.Len() > c.Cap() {
				t.Fatal("capacity exceeded")
			}
		}
	})
}
