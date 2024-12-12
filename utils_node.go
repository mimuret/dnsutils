package dnsutils

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var (
	// ErrRdata returns when rdata is invalid while parsing RDATA.
	ErrRdata = dns.ErrRdata

	// ErrNotTreeBroken returns tree is broken
	ErrNameTreeBroken = fmt.Errorf("name tree broken")

	// ErrBadZone
	ErrBadZone = fmt.Errorf("invalid zone")

	// Err
	ErrEmptyRRs = fmt.Errorf("rrs is empty")
)

type Generator interface {
	NameNodeGenerator
	RRSetGenerator
}

type NameNodeGenerator interface {
	NewNameNode(name string, class dns.Class) (NameNodeInterface, error)
}

type RRSetGenerator interface {
	NewRRSet(name string, ttl uint32, class dns.Class, rrtype uint16) (RRSetInterface, error)
}

var _ Generator = &DefaultGenerator{}

type DefaultGenerator struct{}

func (DefaultGenerator) NewNameNode(name string, class dns.Class) (NameNodeInterface, error) {
	return NewNameNode(name, class)
}
func (DefaultGenerator) NewRRSet(name string, ttl uint32, class dns.Class, rrtype uint16) (RRSetInterface, error) {
	return NewRRSet(name, ttl, class, rrtype, nil)
}

// IsENT check that node is empty non terminal.
func IsENT(n NameNodeInterface) bool {
	for _, set := range n.CopyRRSetMap() {
		if set.Len() > 0 {
			return false
		}
	}
	return true
}

func toRaws(rrs []dns.RR) (res sort.StringSlice, err error) {
	var offset int
	for _, rr := range rrs {
		rr2 := dns.Copy(rr)
		rr2.Header().Ttl = 0
		var buf = make([]byte, math.MaxUint16)
		offset, err = dns.PackRR(rr2, buf, 0, nil, false)
		if err != nil {
			panic(err)
		}
		res = append(res, string(buf[0:offset]))
	}
	return
}

// IsEqualsRRSet check that both rrset equal.However ttl value will be ignored.
func IsEqualsRRSet(a, b RRSetInterface) bool {
	if a.GetName() != b.GetName() {
		return false
	}
	if a.GetRRtype() != b.GetRRtype() {
		return false
	}
	if a.Len() != b.Len() {
		return false
	}
	arr, err := toRaws(a.GetRRs())
	if err != nil {
		return false
	}
	brr, err := toRaws(b.GetRRs())
	if err != nil {
		return false
	}
	arr.Sort()
	brr.Sort()
	for i := range arr {
		if arr[i] != brr[i] {
			return false
		}
	}
	return true
}

// IsCompleteEqualsRRSet check that both rrset equal.
func IsCompleteEqualsRRSet(a, b RRSetInterface) bool {
	if IsEqualsRRSet(a, b) {
		if a.GetTTL() == b.GetTTL() {
			return true
		}
	}
	return false
}

// IsEqualsNode check that both node equal. However ttl value will be ignored.
func IsEqualsNode(a, b NameNodeInterface, ttl bool) bool {
	if a.GetName() != b.GetName() {
		return false
	}
	aRRSet := a.CopyRRSetMap()
	bRRSet := b.CopyRRSetMap()
	exist := map[uint16]struct{}{}
	for rrTypes := range bRRSet {
		exist[rrTypes] = struct{}{}
	}
	for rrType := range aRRSet {
		if _, ok := bRRSet[rrType]; !ok {
			return false
		}
		if ttl {
			if !IsCompleteEqualsRRSet(aRRSet[rrType], bRRSet[rrType]) {
				return false
			}
		} else {
			if !IsEqualsRRSet(aRRSet[rrType], bRRSet[rrType]) {
				return false
			}
		}
		delete(exist, rrType)
	}
	return len(exist) == 0
}

// IsEqualsNode check that both tree equal. However ttl value will be ignored.
func IsEqualsAllTree(a, b NameNodeInterface, ttl bool) bool {
	if a.GetName() != b.GetName() {
		return false
	}
	err := a.IterateNameNode(func(ani NameNodeInterface) error {
		bni, strict := b.GetNameNode(ani.GetName())
		if !strict {
			return fmt.Errorf("not exist %s", ani.GetName())
		}
		if !IsEqualsNode(ani, bni, ttl) {
			return fmt.Errorf("not equals %s %s", ani.GetName(), bni.GetName())
		}
		return nil
	})
	if err != nil {
		return false
	}
	err = b.IterateNameNode(func(bni NameNodeInterface) error {
		_, strict := a.GetNameNode(bni.GetName())
		if !strict {
			return fmt.Errorf("not exist %s", bni.GetName())
		}
		return nil
	})
	return err == nil
}

// IsEmptyRRSet check that rrset is empty.
// if rrset is nil, it returns false.
// if radata is empty, return false.
// other than that return true.
func IsEmptyRRSet(set RRSetInterface) bool {
	if set == nil {
		return true
	}
	return set.Len() == 0
}

// GetRRSetOrCreate returns rrset from name node.
// if exist rrset, returns it.
// if not exist rrset, It create new rrset and return it.
// but new rrset is not link to NameNode. Maybe you can use SetRRSet.
func GetRRSetOrCreate(n NameNodeInterface, rrtype uint16, ttl uint32, generator RRSetGenerator) (RRSetInterface, error) {
	if generator == nil {
		generator = &DefaultGenerator{}
	}
	set := n.GetRRSet(rrtype)
	if set == nil {
		return generator.NewRRSet(n.GetName(), ttl, n.GetClass(), rrtype)
	}
	return set, nil
}

// GetNameNodeOrCreate returns name node from arg name node.
// if exist NameNode, returns it.
// if not exist NameNode, It create new NameNode and return it.
// but new NameNode is not link to from arg name node. Maybe you can use SetNameNode.
func GetNameNodeOrCreate(n NameNodeInterface, name string, generator NameNodeGenerator) (NameNodeInterface, error) {
	if generator == nil {
		generator = &DefaultGenerator{}
	}
	name = dns.CanonicalName(name)
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, ErrBadName
	}
	if !dns.IsSubDomain(n.GetName(), name) {
		return nil, ErrNotInDomain
	}
	nn, ok := n.GetNameNode(name)
	if !ok {
		return generator.NewNameNode(name, n.GetClass())
	}
	return nn, nil
}

// SetNameNode adds NameNode into tree.
// if not exist parent, create ENT NameNodeInterface by newFunc.s
// if exist same node, it overrides children and rrests.
func SetNameNode(n, nn NameNodeInterface, generator NameNodeGenerator) error {
	if generator == nil {
		generator = &DefaultGenerator{}
	}
	if !dns.IsSubDomain(n.GetName(), nn.GetName()) {
		return ErrNotInDomain
	}
	searchNode, ok := n.GetNameNode(nn.GetName())
	for !ok {
		parentLabels := dns.SplitDomainName(searchNode.GetName())
		childLabels := dns.SplitDomainName(nn.GetName())
		childName := strings.Join(childLabels[len(childLabels)-len(parentLabels)-1:], ".")
		childNode, err := generator.NewNameNode(childName, n.GetClass())
		if err != nil {
			return fmt.Errorf("failed to create ENT node: %w", err)
		}
		if err := searchNode.AddChildNameNode(childNode); err != nil {
			return err
		}
		searchNode, ok = n.GetNameNode(nn.GetName())
	}
	searchNode.SetValue(nn)
	return nil
}

// RemoveNameNode remove NameNodeInterface from tree.
func RemoveNameNode(n NameNodeInterface, name string) error {
	name = dns.CanonicalName(name)
	if !dns.IsSubDomain(n.GetName(), name) {
		return ErrNotInDomain
	}
	if Equals(n.GetName(), name) {
		return ErrRemoveItself
	}
	_, exist := n.GetNameNode(name)
	if !exist {
		return nil
	}
	childLabels := dns.SplitDomainName(name)
	for i := 0; i < len(childLabels)-1; i++ {
		childName := dns.CanonicalName(strings.Join(childLabels[i:], "."))
		subName := dns.CanonicalName(strings.Join(childLabels[i+1:], "."))
		subNode, exist := n.GetNameNode(subName)
		if !exist {
			return ErrNameTreeBroken
		}
		if subNode == n {
			return subNode.RemoveChildNameNode(childName)
		}
		if !IsENT(subNode) {
			return subNode.RemoveChildNameNode(childName)
		}
	}
	return nil
}

// GetRDATA returns RDATA from dns.RR
func GetRDATA(rr dns.RR) string {
	v := strings.SplitN(rr.String(), "\t", 5)
	if len(v) != 5 {
		return ""
	}
	return v[4]
}

// GetRDATASlice returns RDATA from rrset
func GetRDATASlice(rrset RRSetInterface) []string {
	rdata := []string{}
	rdataMap := map[string]struct{}{}
	for _, rr := range rrset.GetRRs() {
		s := GetRDATA(rr)
		if _, ok := rdataMap[s]; !ok {
			rdata = append(rdata, s)
		}
		rdataMap[s] = struct{}{}
	}
	return rdata
}

// SetRdata set rdata into rrset
func SetRdata(set RRSetInterface, rdata []string) error {
	rrs := []dns.RR{}
	for _, v := range rdata {
		rr, err := MakeRR(set, v)
		if err != nil {
			return ErrRdata
		}
		rrs = append(rrs, rr)
	}
	for _, rr := range rrs {
		if err := set.AddRR(rr); err != nil {
			return err
		}
	}
	return nil

}

// MakeRR returns dns.RR by RRSet and rdata string
func MakeRR(r RRSetInterface, rdata string) (dns.RR, error) {
	return dns.NewRR(r.GetName() + "\t" + strconv.FormatInt(int64(r.GetTTL()), 10) + "\t" + dns.ClassToString[uint16(r.GetClass())] + "\t" + dns.TypeToString[r.GetRRtype()] + "\t" + rdata)
}

func GetSOA(z ZoneInterface) (*dns.SOA, error) {
	soaRRSet := z.GetRootNode().GetRRSet(dns.TypeSOA)
	if soaRRSet == nil {
		return nil, ErrBadZone
	}
	soa, ok := soaRRSet.GetRRs()[0].(*dns.SOA)
	if !ok {
		return nil, ErrBadZone
	}
	return soa, nil
}

func NewRRSetFromRRsWithGenerator(rrs []dns.RR, generator RRSetGenerator) (RRSetInterface, error) {
	if generator == nil {
		generator = DefaultGenerator{}
	}
	if len(rrs) == 0 {
		return nil, ErrEmptyRRs
	}
	rr := rrs[0]
	rrset, err := generator.NewRRSet(rr.Header().Name, rr.Header().Ttl, dns.Class(rr.Header().Class), rr.Header().Rrtype)
	if err != nil {
		return nil, err
	}
	for _, rr := range rrs {
		if err := rrset.AddRR(rr); err != nil {
			return nil, fmt.Errorf("failed to add rr: %w", err)
		}
	}
	return rrset, nil
}

func NewRRSetFromRRWithGenerator(rr dns.RR, generator RRSetGenerator) (RRSetInterface, error) {
	return NewRRSetFromRRsWithGenerator([]dns.RR{rr}, generator)
}

func CreateOrReplaceRRSetFromRRs(ni NameNodeInterface, rrs []dns.RR, generator Generator) error {
	if len(rrs) == 0 {
		return ErrEmptyRRs
	}
	rr := rrs[0]
	targetNode, err := GetNameNodeOrCreate(ni, rr.Header().Name, generator)
	if err != nil {
		return fmt.Errorf("failed to create node: %w", err)
	}
	rrSet, err := NewRRSetFromRRsWithGenerator(rrs, generator)
	if err != nil {
		return fmt.Errorf("failed to create rrset: %w", err)
	}
	if err := targetNode.SetRRSet(rrSet); err != nil {
		return fmt.Errorf("failed to set rrset: %w", err)
	}
	if err := SetNameNode(ni, targetNode, generator); err != nil {
		return fmt.Errorf("failed to set node: %w", err)
	}
	return nil
}

func SortedIterateNameNode(nni NameNodeInterface, f func(NameNodeInterface) error) error {
	nodeMap := map[string]NameNodeInterface{}
	nodeNames := []string{}
	nni.IterateNameNode(func(nni NameNodeInterface) error {
		nodeMap[nni.GetName()] = nni
		nodeNames = append(nodeNames, nni.GetName())
		return nil
	})
	SortNames(nodeNames)
	for _, name := range nodeNames {
		err := f(nodeMap[name])
		if err != nil {
			return err
		}
	}
	return nil
}

// asc
func SortedIterateRRset(nni NameNodeInterface, f func(RRSetInterface) error) error {
	rrSets := nni.CopyRRSetMap()
	rrtypes := make([]uint16, 0, len(rrSets))
	for rrtype := range rrSets {
		rrtypes = append(rrtypes, rrtype)
	}
	sort.Slice(rrtypes, func(i, j int) bool { return rrtypes[i] < rrtypes[j] })
	for _, rrtype := range rrtypes {
		err := f(nni.GetRRSet(uint16(rrtype)))
		if err != nil {
			return err
		}
	}
	return nil
}

func SortedIterateRR(set RRSetInterface, f func(dns.RR) error) error {
	rrs := set.GetRRs()
	if err := SortRRs(rrs); err != nil {
		return fmt.Errorf("failed to sort RR: %w", err)
	}
	for _, rr := range rrs {
		err := f(rr)
		if err != nil {
			return err
		}
	}
	return nil
}
