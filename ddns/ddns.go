package ddns

import (
	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
)

// UpdateInterface is update zone interface
type UpdateInterface interface {
	// add or create RR
	AddRR(rr dns.RR) error
	// replace rrset
	ReplaceRRSet(dnsutils.RRSetInterface) error
	// remove zone apex name rr other than SOA,NS
	RemoveNameApex(name string) error
	// remove name rr ignore SOA, NS
	RemoveName(name string) error
	// remove name rr ignore SOA, NS
	RemoveRRSet(name string, rtype uint16) error

	// remove name rr ignore SOA, NS
	RemoveRR(rr dns.RR) error

	// it can rollback zone records when UpdateProcessing returns error
	UpdateFailedPostProcess(error)

	// it can apply zone records when UpdateProcessing is successful
	UpdatePostProcess() error

	IsPrecheckSupportedRtype(uint16) bool
	IsUpdateSupportedRtype(uint16) bool
}

// NewDDNS is create DDNS
// ui is nil, return nil
func NewDDNS(ui UpdateInterface) *DDNS {
	if ui == nil {
		return nil
	}
	return &DDNS{
		ui: ui,
	}
}

// DDNS is dynamic update struct
// It can process update message and It updates zone data using UpdateInterface.
type DDNS struct {
	ui UpdateInterface
}

// DDNS.ServeUpdate is process update message
func (d *DDNS) ServeUpdate(zone dnsutils.ZoneInterface, r *dns.Msg) (int, error) {
	// zone not found
	if zone == nil {
		return dns.RcodeRefused, nil
	}
	rcode := d.CheckZoneSection(zone, r)
	if rcode != dns.RcodeSuccess {
		return rcode, nil
	}
	rcode = d.UpdatePrescan(zone, r)
	if rcode != dns.RcodeSuccess {
		return rcode, nil
	}

	rcode = d.PrerequisiteProessing(zone, r)
	if rcode != dns.RcodeSuccess {
		return rcode, nil
	}

	err := d.UpdateProcessing(zone, r)
	if err != nil {
		d.ui.UpdateFailedPostProcess(err)
		return dns.RcodeServerFailure, err
	}
	if err := d.ui.UpdatePostProcess(); err != nil {
		return dns.RcodeServerFailure, err
	}

	return dns.RcodeSuccess, nil
}

/*
   3.1.2 - Pseudocode For Zone Section Processing

      if (zcount != 1 || ztype != SOA)
           return (FORMERR)
      if (zone_type(zname, zclass) == SLAVE)
           return forward()
      if (zone_type(zname, zclass) == MASTER)
           return update()
      return (NOTAUTH)
*/
func (d *DDNS) CheckZoneSection(z dnsutils.ZoneInterface, msg *dns.Msg) int {
	if len(msg.Question) != 1 {
		return dns.RcodeFormatError
	}
	if msg.Question[0].Qtype != dns.TypeSOA {
		return dns.RcodeFormatError
	}
	if !dnsutils.Equals(z.GetName(), msg.Question[0].Name) {
		return dns.RcodeNotAuth
	}
	return dns.RcodeSuccess
}

/*
   3.2.5 - Pseudocode for Prerequisite Section Processing

      for rr in prerequisites
           if (rr.ttl != 0)
                return (FORMERR)
           if (zone_of(rr.name) != ZNAME)
                return (NOTZONE);
           if (rr.class == ANY)
                if (rr.rdlength != 0)
                     return (FORMERR)
                if (rr.type == ANY)
                     if (!zone_name<rr.name>)
                          return (NXDOMAIN)
                else
                     if (!zone_rrset<rr.name, rr.type>)
                          return (NXRRSET)
           if (rr.class == NONE)
                if (rr.rdlength != 0)
                     return (FORMERR)
                if (rr.type == ANY)
                     if (zone_name<rr.name>)
                          return (YXDOMAIN)
                else
                     if (zone_rrset<rr.name, rr.type>)
                          return (YXRRSET)
           if (rr.class == zclass)
                temp<rr.name, rr.type> += rr
           else
                return (FORMERR)

      for rrset in temp
           if (zone_rrset<rrset.name, rrset.type> != rrset)
                return (NXRRSET)
*/
func (d *DDNS) PrerequisiteProessing(z dnsutils.ZoneInterface, msg *dns.Msg) int {
	tempNode, _ := dnsutils.NewNameNode(z.GetName(), z.GetClass())
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype != dns.TypeANY {
			if !d.ui.IsPrecheckSupportedRtype(rr.Header().Rrtype) {
				return dns.RcodeNotImplemented
			}
		}
		if rr.Header().Ttl != 0 {
			return dns.RcodeFormatError
		}
		if !dns.IsSubDomain(z.GetName(), rr.Header().Name) {
			// TODO NS
			return dns.RcodeNotZone
		}
		if rr.Header().Class == dns.ClassANY {
			if rr.Header().Rdlength != 0 {
				return dns.RcodeFormatError
			}
			if rr.Header().Rrtype == dns.TypeANY {
				if _, ok := z.GetRootNode().GetNameNode(rr.Header().Name); !ok {
					return dns.RcodeNameError
				}
			} else {
				node, ok := z.GetRootNode().GetNameNode(rr.Header().Name)
				if !ok {
					return dns.RcodeNXRrset
				}
				if set := node.GetRRSet(rr.Header().Rrtype); set == nil || set.Len() == 0 {
					return dns.RcodeNXRrset
				}
			}
		} else if rr.Header().Class == dns.ClassNONE {
			if rr.Header().Rdlength != 0 {
				return dns.RcodeFormatError
			}
			if rr.Header().Rrtype == dns.TypeANY {
				if _, ok := z.GetRootNode().GetNameNode(rr.Header().Name); ok {
					return dns.RcodeYXDomain
				}
			} else {
				if node, ok := z.GetRootNode().GetNameNode(rr.Header().Name); ok {
					if set := node.GetRRSet(rr.Header().Rrtype); set != nil && set.Len() > 0 {
						return dns.RcodeYXRrset
					}
				}
			}
		} else if rr.Header().Class == uint16(z.GetClass()) {
			if _, ok := z.GetRootNode().GetNameNode(rr.Header().Name); !ok {
				return dns.RcodeNXRrset
			}
			nn, _ := dnsutils.GetNameNodeOrCreate(tempNode, rr.Header().Name)
			set, err := dnsutils.GetRRSetOrCreate(nn, rr.Header().Rrtype, rr.Header().Ttl)
			if err != nil {
				return dns.RcodeFormatError
			}
			if err := set.AddRR(rr); err != nil {
				return dns.RcodeFormatError
			}
			if err := nn.SetRRSet(set); err != nil {
				return dns.RcodeServerFailure
			}
			if err := tempNode.SetNameNode(nn); err != nil {
				return dns.RcodeServerFailure
			}
		} else {
			return dns.RcodeFormatError
		}
	}

	var rcode = dns.RcodeSuccess
	tempNode.IterateNameNode(func(node dnsutils.NameNodeInterface) error {
		zNode, ok := z.GetRootNode().GetNameNode(node.GetName())
		if !ok {
			rcode = dns.RcodeNXRrset
			return nil
		}
		node.IterateNameRRSet(func(set dnsutils.RRSetInterface) error {
			zset := zNode.GetRRSet(set.GetRRtype())
			if zset == nil {
				rcode = dns.RcodeNXRrset
				return nil
			}
			if !dnsutils.IsEqualsRRSet(zset, set) {
				rcode = dns.RcodeNXRrset
				return nil
			}
			return nil
		})
		return nil
	})

	return rcode
}

/*
   3.4.1.3 - Pseudocode For Update Section Prescan

      [rr] for rr in updates
           if (zone_of(rr.name) != ZNAME)
                return (NOTZONE);
           if (rr.class == zclass)
                if (rr.type & ANY|AXFR|MAILA|MAILB)
                     return (FORMERR)
           elsif (rr.class == ANY)
                if (rr.ttl != 0 || rr.rdlength != 0
                    || rr.type & AXFR|MAILA|MAILB)
                     return (FORMERR)
           elsif (rr.class == NONE)
                if (rr.ttl != 0 || rr.type & ANY|AXFR|MAILA|MAILB)
                     return (FORMERR)
           else
                return (FORMERR)

*/

func (d *DDNS) UpdatePrescan(z dnsutils.ZoneInterface, msg *dns.Msg) int {
	for _, rr := range msg.Ns {
		if !dns.IsSubDomain(z.GetName(), rr.Header().Name) {
			return dns.RcodeNotZone
		}
		switch rr.Header().Class {
		case msg.Question[0].Qclass:
			switch rr.Header().Rrtype {
			case dns.TypeANY, dns.TypeAXFR, dns.TypeMAILA, dns.TypeMAILB:
				return dns.RcodeFormatError
			}
		case dns.ClassANY:
			switch rr.Header().Rrtype {
			case dns.TypeAXFR, dns.TypeMAILA, dns.TypeMAILB:
				return dns.RcodeFormatError
			}
			if rr.Header().Ttl != 0 {
				return dns.RcodeFormatError
			}
			if rr.Header().Rdlength != 0 {
				return dns.RcodeFormatError
			}
		case dns.ClassNONE:
			switch rr.Header().Rrtype {
			case dns.TypeANY, dns.TypeAXFR, dns.TypeMAILA, dns.TypeMAILB:
				return dns.RcodeFormatError
			}
			if rr.Header().Ttl != 0 {
				return dns.RcodeFormatError
			}
		default:
			return dns.RcodeFormatError
		}
		switch rr.Header().Rrtype {
		case dns.TypeANY:
		default:
			if !d.ui.IsUpdateSupportedRtype(rr.Header().Rrtype) {
				return dns.RcodeNotImplemented
			}
		}
	}
	return dns.RcodeSuccess
}

/*
   3.4.2.7 - Pseudocode For Update Section Processing

      [rr] for rr in updates
           if (rr.class == zclass)
                if (rr.type == CNAME)
                     if (zone_rrset<rr.name, ~CNAME>)
                          next [rr]
                elsif (zone_rrset<rr.name, CNAME>)
                     next [rr]
                if (rr.type == SOA)
                     if (!zone_rrset<rr.name, SOA> ||
                         zone_rr<rr.name, SOA>.serial > rr.soa.serial)
                          next [rr]
                for zrr in zone_rrset<rr.name, rr.type>
                     if (rr.type == CNAME || rr.type == SOA ||
                         (rr.type == WKS && rr.proto == zrr.proto &&
                          rr.address == zrr.address) ||
                         rr.rdata == zrr.rdata)
                          zrr = rr
                          next [rr]
                zone_rrset<rr.name, rr.type> += rr
           elsif (rr.class == ANY)
                if (rr.type == ANY)
                     if (rr.name == zname)
                          zone_rrset<rr.name, ~(SOA|NS)> = Nil
                     else
                          zone_rrset<rr.name, *> = Nil
                elsif (rr.name == zname &&
                       (rr.type == SOA || rr.type == NS))
                     next [rr]
                else
                     zone_rrset<rr.name, rr.type> = Nil
           elsif (rr.class == NONE)
                if (rr.type == SOA)
                     next [rr]
                if (rr.type == NS && zone_rrset<rr.name, NS> == rr)
                     next [rr]
                zone_rr<rr.name, rr.type, rr.data> = Nil
      return (NOERROR)

*/

func (d *DDNS) UpdateProcessing(z dnsutils.ZoneInterface, m *dns.Msg) error {
	for _, rr := range m.Ns {
		if rr.Header().Class == m.Question[0].Qclass {
			if err := d.UpdateAdd(z, rr); err != nil {
				return err
			}
		}
		if rr.Header().Class == dns.ClassANY {
			if err := d.UpdateRemoveRR(z, rr); err != nil {
				return err
			}
		}
		if rr.Header().Class == dns.ClassNONE {
			if err := d.UpdateRemoveRDATA(z, rr); err != nil {
				return err
			}
		}
	}
	return nil
}

/*
   if (rr.type == CNAME)
        if (zone_rrset<rr.name, ~CNAME>)
             next [rr]
   elsif (zone_rrset<rr.name, CNAME>)
        next [rr]
   if (rr.type == SOA)
        if (!zone_rrset<rr.name, SOA> ||
            zone_rr<rr.name, SOA>.serial > rr.soa.serial)
             next [rr]
   for zrr in zone_rrset<rr.name, rr.type>
        if (rr.type == CNAME || rr.type == SOA ||
            (rr.type == WKS && rr.proto == zrr.proto &&
             rr.address == zrr.address) ||
            rr.rdata == zrr.rdata)
             zrr = rr
             next [rr]
   zone_rrset<rr.name, rr.type> += rr
*/
func (d *DDNS) UpdateAdd(z dnsutils.ZoneInterface, rr dns.RR) error {
	var set dnsutils.RRSetInterface
	nn, ok := z.GetRootNode().GetNameNode(rr.Header().Name)
	if !ok {
		nn = nil
	} else {
		set = nn.GetRRSet(rr.Header().Rrtype)
	}
	if nn != nil {
		/*
			 if (rr.type == CNAME)
						if (zone_rrset<rr.name, ~CNAME>)
								 next [rr]
			 elsif (zone_rrset<rr.name, CNAME>)
						next [rr]
		*/
		if rr.Header().Rrtype == dns.TypeCNAME {
			if dnsutils.IsEmptyRRSet(set) && nn.RRSetLen() > 0 {
				return nil
			}
		} else if !dnsutils.IsEmptyRRSet(nn.GetRRSet(dns.TypeCNAME)) {
			return nil
		}
		/*
			if (rr.type == SOA)
						if (!zone_rrset<rr.name, SOA> ||
								zone_rr<rr.name, SOA>.serial > rr.soa.serial)
								next [rr]

		*/
		if rr.Header().Rrtype == dns.TypeSOA {
			if dnsutils.IsEmptyRRSet(set) {
				return nil
			}
			soa, ok := set.GetRRs()[0].(*dns.SOA)
			if !ok {
				return nil
			}
			srr, ok := rr.(*dns.SOA)
			if !ok {
				return nil
			}
			if soa.Serial > srr.Serial {
				return nil
			}
		}
		/*
			for zrr in zone_rrset<rr.name, rr.type>
				if (rr.type == CNAME || rr.type == SOA ||
						(rr.type == WKS && rr.proto == zrr.proto &&
							rr.address == zrr.address) ||
						rr.rdata == zrr.rdata)
							zrr = rr
							next [rr]
			wks is not supported
		*/
		if rr.Header().Rrtype == dns.TypeCNAME || rr.Header().Rrtype == dns.TypeSOA {
			set := dnsutils.NewRRSetFromRR(rr)
			if err := d.ui.ReplaceRRSet(set); err != nil {
				return err
			}
			return nil
		}
	}
	/*
	 zone_rrset<rr.name, rr.type> += rr
	*/
	if err := d.ui.AddRR(rr); err != nil {
		return err
	}
	return nil
}

// process Remove name and rrset
func (d *DDNS) UpdateRemoveRR(z dnsutils.ZoneInterface, rr dns.RR) error {
	if rr.Header().Rrtype == dns.TypeANY {
		// Delete all RRsets from a name
		if dnsutils.Equals(rr.Header().Name, z.GetName()) {
			// remove zone apex name rr other than SOA,NS
			if err := d.ui.RemoveNameApex(rr.Header().Name); err != nil {
				return err
			}
		} else {
			if err := d.ui.RemoveName(rr.Header().Name); err != nil {
				return err
			}
		}
	} else {
		// Delete An RRset
		if dnsutils.Equals(rr.Header().Name, z.GetName()) && rr.Header().Rrtype == dns.TypeSOA || rr.Header().Rrtype == dns.TypeNS {
			// can not remove APEX SOA, NS
			return nil
		} else {
			if err := d.ui.RemoveRRSet(rr.Header().Name, rr.Header().Rrtype); err != nil {
				return err
			}
		}
	}
	return nil
}

// process remove RR
func (d *DDNS) UpdateRemoveRDATA(z dnsutils.ZoneInterface, rr dns.RR) error {
	if rr.Header().Rrtype == dns.TypeSOA {
		return nil
	}
	if dnsutils.Equals(rr.Header().Name, z.GetName()) && rr.Header().Rrtype == dns.TypeNS {
		return nil
	}
	if err := d.ui.RemoveRR(rr); err != nil {
		return err
	}
	return nil
}
