package specialized

import (
	"fmt"
	"testing"
)

func TestCache(t *testing.T) {
	const (
		get = false
		put = true
	)
	type testOp struct {
		op   bool
		k, v string
	}

	tests := []struct {
		name    string
		size    int
		ops     []testOp
		wantErr bool
	}{
		{
			name: "negative",
			size: -42,
			ops: []testOp{
				{get, "foo", ""},
				{put, "foo", "bar"},
				{get, "foo", ""},
			},
		},
		{
			name: "empty",
			size: 0,
			ops: []testOp{
				{get, "foo", ""},
				{put, "foo", "bar"},
				{get, "foo", ""},
			},
		},
		{
			name:    "put and get",
			size:    1,
			wantErr: true,
			ops: []testOp{
				{get, "foo", ""},
				{put, "foo", "bar"},
				{get, "foo", "bar"},
			},
		},
		{
			name: "put get",
			size: 2,
			ops: []testOp{
				{get, "foo", ""},
				{put, "foo", "bar"},
				{get, "foo", "bar"},
			},
		},
		{
			name: "put get put get",
			size: 2,
			ops: []testOp{
				{get, "foo", ""},
				{put, "foo", "bar"},
				{get, "foo", "bar"},
				{put, "fooffa", "barba"},
				{get, "fooffa", "barba"},
			},
		},
		{
			name: "put put get get",
			size: 4,
			ops: []testOp{
				{put, "foo", "bar"},
				{put, "fooffa", "barba"},
				{get, "foo", "bar"},
				{get, "fooffa", "barba"},
			},
		},
		{
			name: "use all store",
			size: 4,
			ops: []testOp{
				{put, "foo1", "bar1"},
				{put, "foo2", "bar2"},
				{put, "foo3", "bar3"},
				{put, "foo4", "bar4"},

				{get, "foo1", "bar1"},
				{get, "foo2", "bar2"},
				{get, "foo3", "bar3"},
				{get, "foo4", "bar4"},
			},
		},
		{
			name: "use all store check MFA",
			size: 4,
			ops: []testOp{
				{put, "foo1", "bar1"},
				{get, "foo1", "bar1"},
				{put, "foo2", "bar2"},
				{put, "foo3", "bar3"},
				{put, "foo4", "bar4"},
				{put, "foo5", "bar5"},

				{get, "foo1", "bar1"},
				{get, "foo2", ""},
				{get, "foo3", "bar3"},
				{get, "foo4", "bar4"},
				{put, "foo5", "bar5"},
			},
		},
		{
			name: "use all store check MFA",
			size: 4,
			ops: []testOp{
				{put, "foo1", "bar1"},
				{get, "foo1", "bar1"},
				{put, "foo2", "bar2"},
				{put, "foo2", "barr"},
				{put, "foo3", "bar3"},
				{put, "foo4", "bar4"},
				{put, "foo5", "bar5"},

				{get, "foo1", "bar1"},
				{get, "foo2", "barr"},
				{get, "foo3", ""},
				{get, "foo4", "bar4"},
				{put, "foo5", "bar5"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s size %d", tt.name, tt.size), func(t *testing.T) {
			c, err := NewCache(tt.size)
			if err != nil != tt.wantErr {
				t.Fatalf("err: got %v want %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			for k, v := range tt.ops {
				switch v.op {
				case put:
					c.Put(v.k, v.v)
				case get:
					got, ok := c.Get(v.k)
					if !ok != (v.v == "") {
						t.Errorf("%d get(%q): got %v want %q", k, v.k, got, v.v)
						continue
					}
					if v.v != "" && got.(string) != v.v {
						t.Errorf("%d get(%q): got %q want %q", k, v.k, got.(string), v.v)
					}
				}
			}
		})
	}
}

func preloadCache(b *testing.B) *Cache {
	b.Helper()
	c, err := NewCache(65535)
	if err != nil {
		b.Fatalf("Cannot construct cache: %v", err)
	}
	for i := 0; i < 256; i++ {
		c.Put(string(i), i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	return c
}

func BenchmarkHit(b *testing.B) {
	c := preloadCache(b)
	for i := 0; i < b.N; i++ {
		k := i % 256
		vv, ok := c.Get(string(k))
		if !ok {
			b.Fatalf("Unexpected miss: %v", k)
		}
		v := vv.(int)
		if v != k {
			b.Fatalf("Unexpected value: got %v want %v", v, k)
		}
	}
}
func BenchmarkMiss(b *testing.B) {
	c := preloadCache(b)
	for i := 0; i < b.N; i++ {
		k := i%256 + 256
		_, ok := c.Get(string(k))
		if ok {
			b.Fatalf("Unexpected hit: %v", k)
		}
	}
}
func BenchmarkUpdate(b *testing.B) {
	var items [256]string
	for i := 0; i < 256; i++ {
		items[i] = string(i)
	}
	c := preloadCache(b)
	for i := 0; i < b.N; i++ {
		k := items[i%256]
		c.Put(k, i%256)
	}
}
func BenchmarkMix(b *testing.B) {
	var items [256]string
	for i := 0; i < 256; i++ {
		items[i] = string(i)
	}
	c := preloadCache(b)
	for i := 0; i < b.N; i++ {
		// Get
		{
			k := i % 256
			vv, ok := c.Get(string(k))
			if !ok {
				b.Fatalf("Unexpected miss: %v", k)
			}
			v := vv.(int)
			if v != k {
				b.Fatalf("Unexpected value: got %v want %v", v, k)
			}
		}
		// Update
		{
			k := items[i%256]
			c.Put(k, i%256)
		}
		// Miss
		{
			k := i%256 + 256
			_, ok := c.Get(string(k))
			if ok {
				b.Fatalf("Unexpected hit: %v", k)
			}
		}
	}
}
