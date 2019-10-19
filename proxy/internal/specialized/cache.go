// This example demonstrates a priority queue built using the heap interface.
package specialized

import (
	"fmt"
	"sync"
)

type Value interface{}

// Cache is a Least-Recently-Used Most-Frequently-Accessed concurrent safe cache.
// All its methods are safe to call concurrently.
type Cache struct {
	mu sync.Mutex
	// lru keeps track of most recently accessed items
	lru *store
	// mfa keeps track of most frequently accessed items
	mfa *store
	// t is a number representing the current time.
	// It will be used as a clock by the builtin now().
	t uint
	// timeNow can be set to override the builtin timing mechanism
	timeNow func() uint
	// capacity is the maximum storage the cache can hold
	capacity int
	// m is used to collect metrics to better tune cache
	m metrics
}

// compute max size at compile time since it depends on the target architecture
const maxsize = (^uint(0) >> 1)

// NewCache constructs a new Cache ready for use.
// The specified size should never be bigger or roughly as big as the maximum available value for uint.
// evictMetrics tells the cache to collect metrics on recently evicted items,
// which doubles the memory size of the cache.
// If evictMetrics is false only normal hits and misses will be collected.
func NewCache(size int, evictMetrics bool) (*Cache, error) {
	if size <= 0 {
		return nil, nil
	}
	if size < 2 {
		return nil, fmt.Errorf("cache size < 2 not supported, %d provided", size)
	}
	if uint(size) > maxsize {
		return nil, fmt.Errorf("cache size(%d) above supported limit(%d)", size, maxsize)
	}
	c := Cache{
		lru:      newStore(size/2, byTime),
		mfa:      newStore(size/2+size%2, byAccesses),
		capacity: size,
		m:        newMetrics(size, evictMetrics),
	}
	return &c, nil
}

// Metrics copies current metrics values and returns the snapshot.
// If the cache has size<=0 zero metrics will be returned.
func (c *Cache) Metrics() CacheMetrics {
	if c == nil {
		return CacheMetrics{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m.CacheMetrics
}

// SetTimer will set the cache internal timer to the given one.
// The given timer should behave as a monotonic clock and should update its value at least once a second.
// Calling this after the cache has already been used leads to undefined behavior.
func (c *Cache) SetTimer(timer func() uint) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.timeNow = timer
}

// Get retrieves an item from the cache.
// Its amortized worst-case complexity is ~O(log(c.Len())).
func (c *Cache) Get(k string) (v Value, ok bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()

	if v, ok := c.mfa.get(now, k); ok {
		// Hit on MFA
		c.m.hitMFA()
		return v, true
	}
	c.m.missMFA()
	if v, ok := c.lru.get(now, k); ok {
		// Hit on LRU
		c.m.hitLRU()
		return v, true
	}
	c.m.missLRU()
	c.m.miss(k)
	return nil, false
}

// Put stores an item in the cache.
// Its amortized worst-case complexity is ~O(log(c.Len())).
func (c *Cache) Put(k string, v Value) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()

	if c.mfa.update(now, k, v) {
		// Item was in MFA and was updated
		return
	}
	if c.lru.update(now, k, v) {
		// Item was in LRU and was updated
		return
	}
	// Item was not in cache, put in LRU first
	lruovf := c.lru.put(now, k, v, 1)
	if lruovf.v == nil {
		// LRU had room to accommodate the new entry
		return
	}
	// LRU popped out an item because of our push.
	// Let's promote to MFA if there is room.
	if c.mfa.Len() < c.mfa.cap() {
		c.mfa.put(now, lruovf.key, lruovf.v, lruovf.a)
		return
	}
	// No room in MFA.
	// Check if the evicted item was accessed enough times to be promoted to MFA.
	if c.mfa.peek().a > lruovf.a ||
		c.mfa.peek().a == lruovf.a && c.mfa.peek().t < lruovf.t {
		c.m.evict(lruovf.key)
		return
	}

	mfaovf := c.mfa.put(now, lruovf.key, lruovf.v, lruovf.a)
	if mfaovf.v == nil {
		return
	}
	// Pushing to MFA popped out an item. If the item was in MFA it means
	// it is probably worth keeping around for a while longer.
	if c.lru.Len() <= 0 || c.lru.peek().a >= mfaovf.a {
		// Evicted from MFA, no promotion
		c.m.evict(mfaovf.key)
		return
	}
	// Reset access count and push it to LRU if it was accessed more than the
	// last item in LRU, discard otherwise.
	lruovf = c.lru.put(now, mfaovf.key, mfaovf.v, 1)
	if lruovf.v == nil {
		// Evicted from MFA, promoted to LRU
		return
	}
	// Evicted from MFA, promoted to LRU, caused eviction
	c.m.evict(lruovf.key)
}

// Len returns the amount of items currently stored in the cache.
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len() + c.mfa.Len()
}

// Cap returns the maximum amount of items the cache can hold.
func (c *Cache) Cap() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.cap() + c.mfa.cap()
}

func (c *Cache) now() uint {
	if c.timeNow != nil {
		return c.timeNow()
	}
	c.t++
	if c.t == 0 {
		// Overflow: walk over the stores and reset times in a way
		// that preserves invariants after a time wraparound.
		c.t = c.lru.reset(c.t)
		c.t = c.mfa.reset(c.t)
	}
	return c.t
}
