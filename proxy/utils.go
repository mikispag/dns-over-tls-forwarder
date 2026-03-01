package proxy

import "codeberg.org/miekg/dns"

// CloneMsg returns a deep copy of the given DNS message.
// This is necessary in v2 because Msg.Copy() performs a shallow copy of slices.
func CloneMsg(m *dns.Msg) *dns.Msg {
	if m == nil {
		return nil
	}
	c := m.Copy()
	if m.Question != nil {
		c.Question = make([]dns.RR, len(m.Question))
		for i, q := range m.Question {
			c.Question[i] = q.Clone()
		}
	}
	if m.Answer != nil {
		c.Answer = make([]dns.RR, len(m.Answer))
		for i, a := range m.Answer {
			c.Answer[i] = a.Clone()
		}
	}
	if m.Ns != nil {
		c.Ns = make([]dns.RR, len(m.Ns))
		for i, n := range m.Ns {
			c.Ns[i] = n.Clone()
		}
	}
	if m.Extra != nil {
		c.Extra = make([]dns.RR, len(m.Extra))
		for i, e := range m.Extra {
			c.Extra[i] = e.Clone()
		}
	}
	if m.Pseudo != nil {
		c.Pseudo = make([]dns.RR, len(m.Pseudo))
		for i, p := range m.Pseudo {
			c.Pseudo[i] = p.Clone()
		}
	}
	// Data buffer also needs cloning if we want to be truly safe,
	// though Pack() often overwrites it.
	if m.Data != nil {
		c.Data = make([]byte, len(m.Data))
		copy(c.Data, m.Data)
	}
	return c
}
