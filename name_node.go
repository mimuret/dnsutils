package dnsutils

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

var (
	// ErrBadName returns when name is not domain name.
	ErrBadName = fmt.Errorf("bad name")
	// ErrNotDirectlyName returns by AddChildNode when arg node is not child name
	ErrNotDirectlyName = fmt.Errorf("add label count must be equals to parent label count +1")
	// ErrNotInDomain returns when arg node is in-domain.
	ErrNotInDomain = fmt.Errorf("name is not subdomain")
	// ErrChildExist returns when already exist arg node's name node.
	ErrChildExist = fmt.Errorf("child name is exist")
	// ErrNameNotEqual returns when arg name node's name is not equal.
	ErrNameNotEqual = fmt.Errorf("name not equals")
	// ErrClassNotEqual returns when arg name node's class is not equal.
	ErrClassNotEqual = fmt.Errorf("class not equals")
	// ErrConflictCNAME returns by SetRRSet when there is more than one SOA RDATA.
	ErrConflictCNAME = fmt.Errorf("name node can't set both CNAME and other")
	// ErrConflictCNAME returns by SetRRSet when there is more than one RDATA RDATA.
	ErrConflictDNAME = fmt.Errorf("name node can't set both DNAME and other")
)

var _ NameNodeInterface = &NameNode{}

// NameNode is implement of NameNodeInterface
type NameNode struct {
	sync.Mutex
	name          string
	class         dns.Class
	rrsetValue    atomic.Value
	childrenValue atomic.Value
}

// NewNameNode create NameNode
func NewNameNode(name string, class dns.Class) (*NameNode, error) {
	name = dns.CanonicalName(name)
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, ErrBadName
	}
	nnn := &NameNode{
		name:  name,
		class: class,
	}
	nnn.rrsetValue.Store(make(map[uint16]RRSetInterface))
	nnn.childrenValue.Store(make(map[string]NameNodeInterface))
	return nnn, nil
}

func (n *NameNode) rrsetMap() map[uint16]RRSetInterface {
	m1 := n.rrsetValue.Load().(map[uint16]RRSetInterface)
	return m1
}

func (n *NameNode) children() map[string]NameNodeInterface {
	m1 := n.childrenValue.Load().(map[string]NameNodeInterface)
	return m1
}

// GetName is implement of NameNodeInterface.GetName
func (n *NameNode) GetName() string {
	return n.name
}

// GetClass is implement of NameNodeInterface.GetClass
func (n *NameNode) GetClass() dns.Class {
	return n.class
}

// GetNameNode is implement of NameNodeInterface.GetNameNode
func (n *NameNode) GetNameNode(name string) (node NameNodeInterface, strict bool) {
	name = dns.CanonicalName(name)
	if !dns.IsSubDomain(n.GetName(), name) {
		return nil, false
	}
	if Equals(n.GetName(), name) {
		return n, true
	}
	for _, child := range n.children() {
		if dns.IsSubDomain(child.GetName(), name) {
			return child.GetNameNode(name)
		}
	}
	return n, false
}

// CopyChildNodes is implement of NameNodeInterface.CopyChildNodes
func (n *NameNode) CopyChildNodes() map[string]NameNodeInterface {
	childMap := map[string]NameNodeInterface{}
	for name, child := range n.children() {
		childMap[name] = child
	}
	return childMap
}

// CopyRRSetMap is implement of NameNodeInterface.CopyRRSetMap
func (n *NameNode) CopyRRSetMap() map[uint16]RRSetInterface {
	rrsetMap := map[uint16]RRSetInterface{}
	for rrtype, set := range n.rrsetMap() {
		if set != nil {
			rrsetMap[rrtype] = set.Copy()
		}
	}
	return rrsetMap
}

// GetRRSet is implement of NameNodeInterface.GetRRSet
func (n *NameNode) GetRRSet(rrtype uint16) RRSetInterface {
	set := n.rrsetMap()[rrtype]
	if set == nil {
		return nil
	}
	return set.Copy()
}

// SetValue is implement of NameNodeInterface.SetValue
func (n *NameNode) SetValue(nn NameNodeInterface) error {
	if n.GetName() != nn.GetName() {
		return ErrNameNotEqual
	}
	if n.GetClass() != nn.GetClass() {
		return ErrClassNotEqual
	}
	n.Lock()
	defer n.Unlock()
	n.childrenValue.Store(nn.CopyChildNodes())
	n.rrsetValue.Store(nn.CopyRRSetMap())
	return nil
}

// IterateNameRRSet is implement of NameNodeInterface.IterateNameRRSet
// first order is SOA.
// Other than, sort  order by ASC.
func (n *NameNode) IterateNameRRSet(f func(RRSetInterface) error) error {
	rrsetMap := n.rrsetMap()
	keys := []uint16{}
	for key := range rrsetMap {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i] == dns.TypeSOA {
			return true
		}
		if keys[j] == dns.TypeSOA {
			return false
		}
		return keys[i] < keys[j]
	})
	for _, rrtype := range keys {
		if err := f(rrsetMap[rrtype]); err != nil {
			return err
		}
	}
	return nil
}

// IterateNameNode is implement of NameNodeInterface.IterateNameNode
// sort order using sort.StringSlice Sort.
func (n *NameNode) IterateNameNode(f func(NameNodeInterface) error) error {
	if err := f(n); err != nil {
		return err
	}
	rrsetMap := n.children()
	keys := sort.StringSlice{}
	for key := range rrsetMap {
		keys = append(keys, key)
	}
	keys.Sort()
	for _, name := range keys {
		if err := rrsetMap[name].IterateNameNode(f); err != nil {
			return err
		}
	}
	return nil
}

// AddChildNameNode is implement of NameNodeInterface.AddChildNameNode
func (n *NameNode) AddChildNameNode(nn NameNodeInterface) error {
	parentLabels := dns.SplitDomainName(n.GetName())
	childLabels := dns.SplitDomainName(nn.GetName())
	if len(parentLabels)+1 != len(childLabels) {
		return ErrNotDirectlyName
	}
	n.Lock()
	defer n.Unlock()
	if _, ok := n.children()[nn.GetName()]; ok {
		return ErrChildExist
	}
	cMap := n.children()
	cMap[nn.GetName()] = nn
	n.childrenValue.Store(cMap)
	return nil
}

// RemoveNameNode is implement of NameNodeInterface.RemoveNameNode
// childRemoved used by RemoveNameNode for ENT removed.
// usually,There is no need to consider.
// if grand child node is removed but child node is not removed, childRemoved returned false
func (n *NameNode) RemoveChildNameNode(name string) error {
	name = dns.CanonicalName(name)
	if !dns.IsSubDomain(n.GetName(), name) {
		return ErrNotInDomain
	}
	if Equals(n.GetName(), name) {
		return fmt.Errorf("name and NameNode's names are equals")
	}
	n.Lock()
	defer n.Unlock()
	newChild := map[string]NameNodeInterface{}
	var delete bool
	for childName, child := range n.children() {
		if Equals(child.GetName(), name) {
			delete = true
			continue
		}
		newChild[childName] = child
	}
	if delete {
		n.childrenValue.Store(newChild)
	}
	return nil
}

func (n *NameNode) SetRRSet(set RRSetInterface) error {
	if set.GetName() != n.GetName() {
		return ErrNameNotEqual
	}
	n.Lock()
	defer n.Unlock()
	rrsetMap := n.rrsetMap()
	rrsetMap[set.GetRRtype()] = set

	if !IsEmptyRRSet(rrsetMap[dns.TypeCNAME]) {
		if n.RRSetLen() > 1 {
			return ErrConflictCNAME
		}
	}
	if !IsEmptyRRSet(rrsetMap[dns.TypeDNAME]) {
		if n.RRSetLen() > 1 {
			return ErrConflictDNAME
		}
	}
	n.rrsetValue.Store(rrsetMap)
	return nil
}

func (n *NameNode) RemoveRRSet(rrtype uint16) error {
	n.Lock()
	defer n.Unlock()
	rrsetMap := n.rrsetMap()
	delete(rrsetMap, rrtype)
	n.rrsetValue.Store(rrsetMap)
	return nil
}

func (n *NameNode) RRSetLen() int {
	i := 0
	for _, set := range n.rrsetMap() {
		if set.Len() > 0 {
			i++
		}
	}
	return i
}
