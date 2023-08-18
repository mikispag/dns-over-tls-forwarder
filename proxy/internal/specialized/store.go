package specialized

import (
	"container/heap"
)

// item is an entry in the store.
type item struct {
	// key is the key for the store lookup
	key string
	// v is an arbitrary value
	v Value
	// t is the value of now() during the last access
	t uint
	// a is the amount of accesses for the current item
	a uint
	// index is needed by update and is maintained by the heap.Interface methods
	index int
}

type cmpBy bool

const (
	// default to LRU
	byTime     cmpBy = false
	byAccesses       = true
)

type store struct {
	// pq is a priority queue implemented as a min heap
	pq []item
	// m is a lookup map for the priority queue underlying data
	m map[string]int
	// cmp is how should two items be compared
	cmp cmpBy
}

func newStore(size int, cmp cmpBy) *store {
	c := store{
		pq:  make([]item, 0, size),
		m:   make(map[string]int, size),
		cmp: cmp,
	}
	// Put heap.Init(c) here if the cache starts with some elements in it.
	return &c
}

func (c *store) get(now uint, key string) (v Value, ok bool) {
	i, ok := c.m[key]
	if !ok {
		return nil, false
	}
	v = c.pq[i].v
	c.updateUnchecked(now, i, v, 1)
	return v, true
}

func (c *store) put(now uint, key string, v Value, startCount uint) (evicted item) {
	i, ok := c.m[key]
	if ok {
		c.updateUnchecked(now, i, v, startCount)
		return evicted
	}
	it := item{key: key, v: v, a: startCount, t: now}
	if len(c.pq) == cap(c.pq) {
		if len(c.pq) > 0 && c.less(it, c.peek()) {
			// We would be replacing something with something worth less,
			// which is a bad deal, maybe the worst deal ever.
			//
			// Bounce the provided item instead.
			return it
		}
		// We are full, discard item with lowest priority before inserting.
		evicted = heap.Pop(c).(item)
	}
	heap.Push(c, it)
	return evicted
}

func (c *store) update(now uint, key string, v Value) (updated bool) {
	i, ok := c.m[key]
	if !ok {
		return false
	}
	c.updateUnchecked(now, i, v, 1)
	return true
}

func (c *store) peek() item { return c.pq[0] }

// updateUnchecked updates the item as specified without checking if the item is there or checking
// for boundaries.
func (c *store) updateUnchecked(now uint, i int, v Value, startCount uint) {
	c.pq[i].v = v
	c.pq[i].a += startCount
	c.pq[i].t = now
	heap.Fix(c, i)
}

func (c *store) reset(start uint) uint {
	if c.cmp {
		// MFA doesn't really care about time of access, set everything to 0
		// and lazily refresh it when the records are actually used.
		for i := range c.pq {
			c.pq[i].t = 0
		}
		return start
	}
	// Create a clone of the LRU with all times rewritten starting from 0.
	// Every Pop takes O(log(n)) and the final Init takes O(n).
	// A potential different strategy would be to set all times to 0 and just
	// return, but I don't see much benefit in switching to random behavior
	// just to save a log(n).
	c2 := newStore(len(c.pq), c.cmp)
	k := start
	end := c.Len()
	for i := 0; i < end; i++ {
		itm := heap.Pop(c)
		ii := itm.(item)
		ii.t = k
		ii.index = i
		c2.pq = append(c2.pq, ii)
		c2.m[ii.key] = i
		k++
	}
	heap.Init(c2)
	*c = *c2
	return k
}

func (c *store) cap() int { return cap(c.pq) }

func (c *store) less(a, b item) bool {
	// LRU
	if c.cmp == byTime {
		if a.t != b.t {
			// If insertion time differs, compare by that
			return a.t < b.t
		}
		// If time is equal compare by access
		return a.a < b.a
	}
	// MFA
	if a.a != b.a {
		// # accesses differ, compare by that
		return a.a < b.a
	}
	// Same accessed, compare by time
	return a.t < b.t
}

// For use by the heap package only. Do not call directly.
// {{{

func (c *store) Len() int { return len(c.pq) }
func (c *store) Less(i, j int) bool {
	// This call is quite slow as it almost always resuts in a cache miss, but it is better to
	// keep this here for code readability and de-duplicaiton.
	return c.less(c.pq[i], c.pq[j])
}
func (c *store) Swap(i, j int) {
	c.pq[i], c.pq[j] = c.pq[j], c.pq[i]
	c.pq[i].index, c.pq[j].index = i, j
	c.m[c.pq[i].key], c.m[c.pq[j].key] = i, j
}
func (c *store) Push(x interface{}) {
	item := x.(item)
	n := len(c.pq)
	item.index = n
	c.m[item.key] = n
	c.pq = append(c.pq, item)
}
func (c *store) Pop() interface{} {
	n := len(c.pq)
	item := c.pq[n-1]
	item.index = -1 // for safety
	delete(c.m, item.key)
	c.pq = c.pq[:n-1]
	return item
}

// }}}
