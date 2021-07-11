package dnsutils

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

var ErrNotDirectlyName = fmt.Errorf("Add label count must be equals to parent label count +1")
var ErrNotSubdomain = fmt.Errorf("name is not subdomain")
var ErrChildExist = fmt.Errorf("child name is exist")
var ErrNameNotEqual = fmt.Errorf("name not equals")
var ErrConflictCNAME = fmt.Errorf("name node can't set both CNAME and other")
var ErrConflictDNAME = fmt.Errorf("name node can't set both DNAME and other")
var _ NameNodeInterface = &NameNode{}

type NameNode struct {
	sync.Mutex
	name          string
	class         dns.Class
	rrsetValue    atomic.Value
	childrenValue atomic.Value
}

func NewNameNode(name string, class dns.Class) *NameNode {
	name = dns.CanonicalName(name)
	nnn := &NameNode{
		name:  name,
		class: class,
	}
	nnn.rrsetValue.Store(make(map[uint16]RRSetInterface))
	nnn.childrenValue.Store(make(map[string]NameNodeInterface))
	return nnn
}

func (n *NameNode) rrsetMap() map[uint16]RRSetInterface {
	m1 := n.rrsetValue.Load().(map[uint16]RRSetInterface)
	return m1
}

func (n *NameNode) children() map[string]NameNodeInterface {
	m1 := n.childrenValue.Load().(map[string]NameNodeInterface)
	return m1
}

func (n *NameNode) GetName() string {
	return n.name
}

func (n *NameNode) GetClass() dns.Class {
	return n.class
}

func (n *NameNode) GetNameNode(name string) (NameNodeInterface, bool) {
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

func (n *NameNode) CopyChildNodes() map[string]NameNodeInterface {
	childMap := map[string]NameNodeInterface{}
	for name, child := range n.children() {
		childMap[name] = child
	}
	return childMap
}

func (n *NameNode) CopyRRSetMap() map[uint16]RRSetInterface {
	rrsetMap := map[uint16]RRSetInterface{}
	for rrtype, set := range n.rrsetMap() {
		if set != nil {
			rrsetMap[rrtype] = set.Copy()
		}
	}
	return rrsetMap
}

func (n *NameNode) GetRRSet(rrtype uint16) RRSetInterface {
	set := n.rrsetMap()[rrtype]
	if set == nil {
		return nil
	}
	return set.Copy()
}

func (n *NameNode) SetValue(nn NameNodeInterface) error {
	if n.name != nn.GetName() {
		return ErrNameNotEqual
	}
	n.Lock()
	defer n.Unlock()
	n.childrenValue.Store(nn.CopyChildNodes())
	n.rrsetValue.Store(nn.CopyRRSetMap())
	return nil
}

func (n *NameNode) IterateNameRRSet(f func(RRSetInterface) error) error {
	for _, set := range n.rrsetMap() {
		if err := f(set); err != nil {
			return err
		}
	}
	return nil
}

func (n *NameNode) IterateNameNode(f func(NameNodeInterface) error) error {
	if err := f(n); err != nil {
		return err
	}
	for _, nn := range n.children() {
		if err := nn.IterateNameNode(f); err != nil {
			return err
		}
	}
	return nil
}

func (n *NameNode) AddChildNode(nn NameNodeInterface) error {
	parentLabels := dns.SplitDomainName(n.GetName())
	childLabels := dns.SplitDomainName(nn.GetName())
	if len(parentLabels)+1 != len(childLabels) {
		return ErrNotDirectlyName
	}
	if _, ok := n.children()[nn.GetName()]; ok {
		return ErrChildExist
	}
	n.Lock()
	defer n.Unlock()
	cMap := n.children()
	cMap[nn.GetName()] = nn
	n.childrenValue.Store(cMap)
	return nil
}

func (n *NameNode) SetNameNode(nn NameNodeInterface) error {
	if !dns.IsSubDomain(n.GetName(), nn.GetName()) {
		return ErrNotSubdomain
	}
	searchNode, ok := n.GetNameNode(nn.GetName())
	for !ok {
		parentLabels := dns.SplitDomainName(searchNode.GetName())
		childLabels := dns.SplitDomainName(nn.GetName())
		childName := strings.Join(childLabels[len(childLabels)-len(parentLabels)-1:], ".")
		childNode := NewNameNode(childName, n.GetClass())
		if err := searchNode.AddChildNode(childNode); err != nil {
			return err
		}
		searchNode, ok = n.GetNameNode(nn.GetName())
	}
	searchNode.SetValue(nn)
	return nil
}

//
func (n *NameNode) RemoveNameNode(name string) (bool, error) {
	name = dns.CanonicalName(name)
	if !dns.IsSubDomain(n.GetName(), name) {
		return false, ErrNotSubdomain
	}
	if Equals(n.GetName(), name) {
		return false, ErrNotSubdomain
	}
	n.Lock()
	defer n.Unlock()
	newChild := map[string]NameNodeInterface{}
	var delete bool
	for childName, child := range n.children() {
		if dns.IsSubDomain(child.GetName(), name) {
			if Equals(child.GetName(), name) {
				delete = true
			} else {
				// child is parent path name
				res, err := child.RemoveNameNode(name)
				if err != nil {
					return false, err
				}
				if res {
					// child is delete
					if IsENT(child) {
						// this node is ENT, remove
						delete = true
					}
				}
			}
			if !delete {
				newChild[childName] = child
			}
		} else {
			newChild[childName] = child
		}
	}
	n.childrenValue.Store(newChild)
	return delete, nil
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
