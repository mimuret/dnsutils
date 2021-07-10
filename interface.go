package dnsutils

import (
	"fmt"

	"github.com/miekg/dns"
)

var (
	NotSupport            = fmt.Errorf("not support")
	NotChangeAbleNameNode = fmt.Errorf("name node not changeable")
	NotChangeAbleRRset    = fmt.Errorf("rrset not changeable")
)

type ZoneInterface interface {
	// return canonical zone name
	GetName() string
	GetRootNode() NameNodeInterface
}

type NameNodeInterface interface {
	// return canonical name
	GetName() string

	// isStrict=true, NameNode is target name
	// isStrict=false, NameNode is nearly parrent path node
	GetNameNode(target string) (node NameNodeInterface, isStrict bool)

	// return child name
	CopyChildNodes() map[string]NameNodeInterface

	// return rrset map
	CopyRRSetMap() map[uint16]RRSetInterface

	// return rrset
	GetRRSet(rrtype uint16) RRSetInterface

	// iterate by RRSetInterface
	IterateNameRRSet(func(RRSetInterface) error) error

	// add directly child node
	AddChildNode(NameNodeInterface) error

	// set NameNode into tree
	// if not exist parent not, create ENT node
	// if exist same node, override child and rrsetMpa
	SetNameNode(NameNodeInterface) error

	// override child and rrsetMpa
	SetValue(NameNodeInterface) error

	// childRemoved used by RemoveNameNode for ENT removed.
	// usually,There is no need to consider.
	// if child node is removed, childRemoved returned true
	// if grand child node is removed but child node is not removed, childRemoved returned false
	RemoveNameNode(name string) (childRemoved bool, err error)

	// override rrset
	SetRRSet(RRSetInterface) error
	// remove rrset
	RemoveRRSet(rrtype uint16) error
}

type RRSetInterface interface {
	// return canonical name
	GetName() string
	// return rtype
	GetRRtype() uint16
	// return rr slice
	GetRRs() []dns.RR
	// number of rdata
	Len() int
}

type ChangeableRRSetInterface interface {
	RRSetInterface
	AddRR(dns.RR) error
	RemoveRR(dns.RR) error
}
