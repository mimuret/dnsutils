package dnsutils

import (
	"fmt"

	"github.com/miekg/dns"
)

var (
	// ErrNotSupport returns when method is not implemented.
	ErrNotSupport = fmt.Errorf("not support")
	// ErrNotChangeAble returns by change methods when can not change values.
	ErrNotChangeAble = fmt.Errorf("not changeable")
)

// ZoneInterface manages zone root node
type ZoneInterface interface {
	// return canonical zone name
	GetName() string
	GetRootNode() NameNodeInterface
	GetClass() dns.Class
}

// NameNodeInterface manages node of name tree
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

	// IterateNameNode can iterate function by NameNodeInterface
	// sort oreder is implementation dependent.
	IterateNameNodeWithValue(f func(NameNodeInterface, any) (any, error), v any) error

	// AddChildNode adds child node into children.
	AddChildNameNode(NameNodeInterface) error

	// RemoveNameNode removed child node.
	RemoveChildNameNode(name string) error

	// SetValue override child and rrsetMap
	SetValue(NameNodeInterface) error

	// SetRRSet overrides rrset
	SetRRSet(RRSetInterface) error

	// RemoveRRSet removes rrset
	RemoveRRSet(rrtype uint16) error

	// RRSetLen returns the number of not empty rrset
	RRSetLen() int
}

// RRSetInterface manages rrset
type RRSetInterface interface {
	// GetName returns canonical name
	GetName() string

	// GetRRtype returns rrtype
	GetRRtype() uint16

	// GetClass returns dns.Class
	GetClass() dns.Class

	// GetTTL returns rtype
	GetTTL() uint32

	// SetTTL sets ttl
	SetTTL(uint32) error

	// GetRRs returns rr slice
	GetRRs() []dns.RR

	// Len returns number of rdata
	Len() int

	// AddRR adds dns.RR
	AddRR(dns.RR) error

	// RemoveRR removes dns.RR
	RemoveRR(dns.RR) error

	// Copy returns a copy
	Copy() RRSetInterface
}
