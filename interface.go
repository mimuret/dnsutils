package dnsutils

import (
	"fmt"

	"github.com/miekg/dns"
)

var (
	ErrNotSupport            = fmt.Errorf("not support")
	ErrNotChangeAbleNameNode = fmt.Errorf("name node not changeable")
	ErrNotChangeAbleRRset    = fmt.Errorf("rrset not changeable")
)

type ZoneInterface interface {
	// return canonical zone name
	GetName() string
	GetRootNode() NameNodeInterface
	GetClass() dns.Class
}

type NameNodeInterface interface {
	// GetName returns canonical name
	GetName() string
	// GetName returns class
	GetClass() dns.Class

	// GetNameNode returns NameNode by target name
	// if return value isStrict is true, NameNode is target name NameNode. (strict match)
	// if isStrict is false and node nos it nil, node is nearly parrent path node. (loose match)
	// if isStrict is false and node is nil, target name is not in-domain.
	GetNameNode(target string) (node NameNodeInterface, isStrict bool)

	// CopyChildNodes returns child name node map
	// map key is canonical name
	CopyChildNodes() map[string]NameNodeInterface

	// CopyRRSetMap returns rrset map
	// map key is uint16 rrtype
	CopyRRSetMap() map[uint16]RRSetInterface

	// GetRRSet returns rrset by rrtype
	// if not exist rrset return nil
	GetRRSet(rrtype uint16) RRSetInterface

	// IterateNameRRSet can iterate function by RRSetInterface
	// sort oreder is implementation dependent.
	IterateNameRRSet(func(RRSetInterface) error) error

	// IterateNameNode can iterate function by NameNodeInterface
	// sort oreder is implementation dependent.
	IterateNameNode(func(NameNodeInterface) error) error

	// AddChildNode adds child node into children.
	AddChildNameNode(NameNodeInterface) error

	// RemoveNameNode removed child node.
	RemoveChildNameNode(name string) error

	// SetValue override child and rrsetMap
	SetValue(NameNodeInterface) error

	// override rrset
	SetRRSet(RRSetInterface) error
	// remove rrset
	RemoveRRSet(rrtype uint16) error
	// return not empty rrset
	RRSetLen() int
}

type RRSetInterface interface {
	// return canonical name
	GetName() string
	// return rtype
	GetRRtype() uint16
	// return dns.Class
	GetClass() dns.Class

	// return rtype
	GetTTL() uint32
	// set ttl
	SetTTL(uint32)

	// return rr slice
	GetRRs() []dns.RR
	// number of rdata
	Len() int

	// Add Resource record
	AddRR(dns.RR) error

	// Remove Resource record
	// return err
	// return err When rtype is SOA or CNAME, and it number is multiple.
	RemoveRR(dns.RR) error

	Copy() RRSetInterface
}
