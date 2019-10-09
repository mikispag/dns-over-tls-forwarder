package specialized

import (
	"fmt"
	"strconv"
	"testing"
)

func TestCompare(t *testing.T) {
	tests := []struct {
		name string
		by   cmpBy
		a, b item
		want bool
	}{
		{
			name: "time diff time",
			by:   byTime,
			a:    item{t: 1, a: 0},
			b:    item{t: 2, a: 0},
			want: true,
		},
		{
			name: "time diff all",
			by:   byTime,
			a:    item{t: 1, a: 2},
			b:    item{t: 2, a: 1},
			want: true,
		},
		{
			name: "time same time",
			by:   byTime,
			a:    item{t: 1, a: 2},
			b:    item{t: 1, a: 4},
			want: true,
		},
		{
			name: "acc diff acc",
			by:   byAccesses,
			a:    item{a: 1, t: 1},
			b:    item{a: 2, t: 1},
			want: true,
		},
		{
			name: "acc diff all",
			by:   byAccesses,
			a:    item{a: 1, t: 2},
			b:    item{a: 2, t: 1},
			want: true,
		},
		{
			name: "acc diff acc",
			by:   byAccesses,
			a:    item{a: 0, t: 1},
			b:    item{a: 0, t: 2},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(0, tt.by)
			if got := s.less(tt.a, tt.b); got != tt.want {
				t.Errorf("less(%+v,%+v): got %t want %t", tt.a, tt.b, got, tt.want)
			}
			if tt.a == tt.b {
				return
			}
			// Check that if the items are different less(a,b) == !less(b,a)
			if got, want := s.less(tt.b, tt.a), !tt.want; got != want {
				t.Errorf("less(%+v,%+v): got %t want %t", tt.a, tt.b, got, want)
			}
		})
	}
}

func TestStore(t *testing.T) {
	type put struct{ k, v, wantEvict string }
	type get struct{ k, want string }
	type upd struct {
		k, v    string
		wantUpd bool
	}

	const lru, mfa = byTime, byAccesses
	var tests = []struct {
		name           string
		typ            cmpBy
		size, wantSize int
		ops            []interface{}
	}{
		{
			name:     "empty should be a miss",
			typ:      lru,
			size:     0,
			wantSize: 0,
			ops: []interface{}{
				get{"test", ""},
			},
		},
		{
			name:     "put and get",
			typ:      lru,
			size:     2,
			wantSize: 1,
			ops: []interface{}{
				put{"test", "42", ""},

				get{"test", "42"},
			},
		},
		{
			name:     "put over cap",
			typ:      lru,
			size:     2,
			wantSize: 2,
			ops: []interface{}{
				put{"0.test", "41", ""},
				put{"1.test", "42", ""},
				put{"2.test", "43", "0.test"},
				put{"4.test", "44", "1.test"},

				get{"4.test", "44"},
				get{"2.test", "43"},
				get{"1.test", ""},
				get{"0.test", ""},
			},
		},
		{
			name:     "put over cap",
			typ:      mfa,
			size:     3,
			wantSize: 3,
			ops: []interface{}{
				put{"0.test", "41", ""},
				put{"1.test", "42", ""},
				put{"1.test", "42", ""},
				put{"0.test", "41", ""},
				put{"2.test", "43", ""},
				put{"3.test", "43", "2.test"},
				put{"3.test", "44", ""},
				put{"4.test", "45", "4.test"}, // bounced

				get{"0.test", "41"},
				get{"1.test", "42"},
				get{"2.test", ""},
				get{"3.test", "44"},
				get{"4.test", ""},
			},
		},
		{
			name:     "put and get over cap",
			typ:      lru,
			size:     2,
			wantSize: 2,
			ops: []interface{}{
				put{"0.test", "41", ""},
				put{"1.test", "42", ""},
				get{"0.test", "41"},
				put{"2.test", "43", "1.test"},
				upd{"0.test", "42", true},
				put{"4.test", "44", "2.test"},

				get{"4.test", "44"},
				get{"2.test", ""},
				get{"1.test", ""},
				get{"0.test", "42"},
			},
		},
		{
			name:     "put upd and get over cap",
			typ:      mfa,
			size:     3,
			wantSize: 3,
			ops: []interface{}{
				put{"0.test", "41", ""},
				put{"1.test", "42", ""},
				put{"0.test", "41", ""},
				get{"1.test", "42"},
				put{"2.test", "43", ""},
				put{"3.test", "43", "2.test"},
				upd{"3.test", "41", true},
				upd{"7.test", "41", false},
				put{"4.test", "44", "4.test"}, // bounced

				get{"0.test", "41"},
				get{"1.test", "42"},
				get{"2.test", ""},
				get{"3.test", "41"},
				get{"4.test", ""},
			},
		},
	}
	for _, tt := range tests {
		mode := "lru"
		if tt.typ == mfa {
			mode = "mfa"
		}
		t.Run(fmt.Sprintf("%s %s[%d]", tt.name, mode, tt.size), func(t *testing.T) {
			s := newStore(tt.size, tt.typ)
			checkSize := make(map[string]struct{})
			for i, v := range tt.ops {
				switch v := v.(type) {
				case put:
					e := s.put(uint(i), v.k, v.v, 1)
					if e.key != v.wantEvict {
						t.Errorf("put[%d](%q,%q) evict %+v, want %q", i, v.k, v.v, e, v.wantEvict)
					}
					checkSize[v.k] = struct{}{}
					want := len(checkSize)
					if want > tt.size {
						want = tt.size
					}
					if s.Len() != want {
						t.Errorf("put[%d](%q,%q) len: %d want %d", i, v.k, v.v, s.Len(), want)
					}
				case get:
					prev := s.Len()
					got, ok := s.get(uint(i), v.k)
					if !ok && v.want == "" {
						continue
					}
					if !ok && v.want != "" {
						t.Errorf("get[%d](%q): miss, want hit(%q)", i, v.k, v.want)
					}
					if ok && v.want == "" {
						t.Errorf("get[%d](%q): hit(%q), want miss", i, v.k, got)
						continue
					}
					if ok && got.(string) != v.want {
						t.Errorf("get[%d](%q): got %q want %q", i, v.k, got, v.want)
					}
					if prev != s.Len() {
						t.Errorf("get[%d](%q): len got %d want %d", i, v.k, s.Len(), prev)
					}
				case upd:
					prev := s.Len()
					if got := s.update(uint(i), v.k, v.v); got != v.wantUpd {
						t.Errorf("upd[%d](%q): got %t want %t", i, v.k, got, v.wantUpd)
					}
					if prev != s.Len() {
						t.Errorf("upd[%d](%q): len got %d want %d", i, v.k, s.Len(), prev)
					}
				}
				if len(s.m) != len(s.pq) {
					t.Errorf("[%d] corruption: map len: %d pq len%d", i, len(s.m), len(s.pq))
				}
			}
			if s.Len() != tt.wantSize {
				t.Errorf("size: got %d want %d", s.Len(), tt.wantSize)
			}
		})
	}
}

func TestReset(t *testing.T) {
	size := 4
	s := newStore(size, byTime)
	time := (^uint(0) - uint(size))
	for k := 0; k < size; k++ {
		s.put(time+uint(k), strconv.Itoa(k), k, 1)
	}
	time = s.reset(0)
	if time != uint(size) {
		t.Errorf("reset time got %d want %d", time, size+1)
	}
	for k := 0; k < size; k++ {
		got := s.put(time+uint(k), strconv.Itoa(k)+"evict", k, 1)
		if want := strconv.Itoa(k); got.key != want {
			t.Errorf("evict %d: got %q want %q", k, got.key, want)
		}
	}
}
