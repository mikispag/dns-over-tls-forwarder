package proxy

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestCloneMsg(t *testing.T) {
	m := dns.NewMsg("example.com.", dns.TypeA)
	ans, _ := dns.New("example.com. 3600 IN A 1.2.3.4")
	m.Answer = append(m.Answer, ans)

	opt := &dns.OPT{}
	opt.Header().Name = "."
	opt.Header().Class = 4096
	// Security/DO bit is in the TTL field for OPT RRs in miekg/dns
	opt.Header().TTL = 1 << 15
	m.Extra = append(m.Extra, opt)

	c := CloneMsg(m)

	if c == nil {
		t.Fatal("Cloned message is nil")
	}

	// Basic check
	if c.ID != m.ID {
		t.Errorf("ID mismatch: got %d, want %d", c.ID, m.ID)
	}

	// Verify deep copy of Question
	if len(c.Question) != len(m.Question) {
		t.Errorf("Question length mismatch")
	}
	if c.Question[0].String() != m.Question[0].String() {
		t.Errorf("Question content mismatch")
	}
	// Modify original question and verify clone is unchanged
	oldQ := m.Question[0]
	dnsutil.SetQuestion(m, "different.com.", dns.TypeAAAA)
	if c.Question[0].String() == m.Question[0].String() {
		t.Errorf("Question is not deep copied")
	}
	m.Question[0] = oldQ

	// Verify deep copy of Answer
	if len(c.Answer) != len(m.Answer) {
		t.Errorf("Answer length mismatch")
	}
	// Modify original answer and verify clone is unchanged
	m.Answer[0].Header().TTL = 1234
	if c.Answer[0].Header().TTL == 1234 {
		t.Errorf("Answer is not deep copied (TTL changed in clone)")
	}

	// Verify deep copy of Pseudo (OPT)
	// In v2 Pseudo is a slice of RR just like others if added via m.Extra or similar?
	// Actually CloneMsg specifically clones c.Pseudo.
	// dns.Msg has both Extra and Pseudo.
	m.Pseudo = append(m.Pseudo, opt.Clone())
	c2 := CloneMsg(m)
	if len(c2.Pseudo) != len(m.Pseudo) {
		t.Errorf("Pseudo length mismatch")
	}
	m.Pseudo[0].Header().TTL = 0x12345678
	if c2.Pseudo[0].Header().TTL == 0x12345678 {
		t.Errorf("Pseudo is not deep copied")
	}

	// Verify Data buffer
	m.Data = []byte{1, 2, 3}
	c3 := CloneMsg(m)
	m.Data[0] = 9
	if c3.Data[0] == 9 {
		t.Errorf("Data buffer is not deep copied")
	}
}

func TestCloneMsgNil(t *testing.T) {
	if CloneMsg(nil) != nil {
		t.Error("CloneMsg(nil) should be nil")
	}
}
