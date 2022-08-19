package matcher

import (
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

type MatcherSet struct {
	Op             MatchOp
	Invalid        bool
	DnstapMatchers []DnstapMatcher
	DnsMsgMatchers []DnsMsgMatcher
	SubSets        []*MatcherSet
}

func NewMatcherSet() *MatcherSet {
	return &MatcherSet{
		Op: MatchOpAND,
	}
}

func (d *MatcherSet) result(ok bool) bool {
	if d.Invalid {
		return !ok
	}
	return ok
}

func (d *MatcherSet) matchDnstap(dt *dnstap.Dnstap) bool {
	var ok bool
	for _, matcher := range d.DnstapMatchers {
		ok = matcher.Match(dt)
		if ok && d.Op == MatchOpOR {
			return true
		}
		if !ok && d.Op == MatchOpAND {
			return false
		}
	}
	return ok
}

func (d *MatcherSet) matchDnsMsg(msg *dns.Msg) bool {
	var ok bool
	for _, matcher := range d.DnsMsgMatchers {
		ok = matcher.Match(msg)
		if ok && d.Op == MatchOpOR {
			return true
		}
		if !ok && d.Op == MatchOpAND {
			return false
		}
	}
	return ok
}

func (d *MatcherSet) Match(dt *dnstap.Dnstap, msg *dns.Msg) bool {
	var ok bool
	if len(d.DnstapMatchers) > 0 {
		ok = d.matchDnstap(dt)
		if ok && d.Op == MatchOpOR {
			return d.result(true)
		}
		if !ok && d.Op == MatchOpAND {
			return d.result(false)
		}
	}
	if len(d.DnsMsgMatchers) > 0 {
		ok = d.matchDnsMsg(msg)
		if ok && d.Op == MatchOpOR {
			return d.result(true)
		}
		if !ok && d.Op == MatchOpAND {
			return d.result(false)
		}
	}
	for _, subset := range d.SubSets {
		ok = subset.Match(dt, msg)
		if ok && d.Op == MatchOpOR {
			return d.result(true)
		}
		if !ok && d.Op == MatchOpAND {
			return d.result(false)
		}
	}
	return d.result(ok)
}

func (d *MatcherSet) MatchDnstap(dt *dnstap.Dnstap) bool {
	var ok bool
	if len(d.DnstapMatchers) > 0 {
		ok = d.matchDnstap(dt)
		if ok && d.Op == MatchOpOR {
			return d.result(true)
		}
		if !ok && d.Op == MatchOpAND {
			return d.result(false)
		}
	}
	for _, subset := range d.SubSets {
		ok = subset.MatchDnstap(dt)
		if ok && d.Op == MatchOpOR {
			return d.result(true)
		}
		if !ok && d.Op == MatchOpAND {
			return d.result(false)
		}
	}
	return d.result(ok)
}

func (d *MatcherSet) MatchDnsMsg(msg *dns.Msg) bool {
	var ok bool
	if len(d.DnsMsgMatchers) > 0 {
		ok = d.matchDnsMsg(msg)
		if ok && d.Op == MatchOpOR {
			return d.result(true)
		}
		if !ok && d.Op == MatchOpAND {
			return d.result(false)
		}
	}
	for _, subset := range d.SubSets {
		ok = subset.MatchDnsMsg(msg)
		if ok && d.Op == MatchOpOR {
			return d.result(true)
		}
		if !ok && d.Op == MatchOpAND {
			return d.result(false)
		}
	}
	return d.result(ok)
}
