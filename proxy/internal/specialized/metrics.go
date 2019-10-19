package specialized

// Metrics carries metrics about a cache usage.
type Metrics struct {
	// Stats on MFA

	// HitMFA is the count of hits that returned a value from MFA.
	// Note that a hit on MFA will make the cache skip LRU.
	HitMFA uint
	// MissMFA is the count of misses on MFA access.
	MissMFA uint

	// Stats on LRU

	// HitLRU is the count of hits that returned a value from LRU.
	// Note that a LRU is only accessed on MFA misses.
	HitLRU uint
	// MissLRU is the count of misses on LRU access.
	MissLRU uint

	// Stats for the cache as a whole

	// Miss is the overall amount of misses, which means the requested key was not in MFA nor in LRU.
	Miss uint

	// RecentlyEvictedMiss is the amount of misses that had a key which was recently evicted.
	// If the cache is not running with evicMetrics it will be set to 0.
	RecentlyEvictedMiss uint
}

// Hit returns the total amount of hits.
func (m Metrics) Hit() uint { return m.HitMFA + m.HitLRU }

// Tot returns the total amount of accesses.
func (m Metrics) Tot() uint { return m.Hit() + m.Miss }

// metrics is not safe for concurrent use, accessors should synchronize to access them
type metrics struct {
	Metrics

	// store is a storage for the recently evicted ring
	store []string
	// pos is the cursor for the store
	pos int
	// header is a backing map header to quickly check if the ring has an item
	header map[string]struct{}
}

func newMetrics(bufsize int, evictMetrics bool) metrics {
	var m metrics
	if !evictMetrics {
		return m
	}
	m.store = make([]string, 0, bufsize)
	m.header = make(map[string]struct{}, bufsize)
	return m
}

func (m *metrics) hitMFA()  { m.HitMFA++ }
func (m *metrics) hitLRU()  { m.HitLRU++ }
func (m *metrics) missMFA() { m.MissMFA++ }
func (m *metrics) missLRU() { m.MissLRU++ }
func (m *metrics) miss(k string) {
	m.Miss++
	if m.store == nil {
		return
	}
	if _, ok := m.header[k]; ok {
		m.RecentlyEvictedMiss++
	}
}
func (m *metrics) evict(k string) {
	if m.store == nil {
		return
	}
	if len(m.store) < cap(m.store) {
		m.pos = len(m.store)
		m.store = append(m.store, k)
		m.header[k] = struct{}{}
		return
	}
	m.pos = (m.pos + 1) % cap(m.store)
	delete(m.header, m.store[m.pos])
	m.header[k] = struct{}{}
	m.store[m.pos] = k
}
