package dnsutils

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/mimuret/intcast"
	"golang.org/x/exp/constraints"
)

var (
	// ErrRdata returns when rdata is invalid while parsing RDATA.
	ErrRdata = dns.ErrRdata

	// ErrNotTreeBroken returns tree is broken
	ErrNameTreeBroken = fmt.Errorf("name tree broken")

	// ErrBadZone
	ErrBadZone = fmt.Errorf("invalid zone")
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

func isBorderChar(t byte) bool {
	return (t >= '0' && t <= '9') ||
		(t >= 'a' && t <= 'z') ||
		(t >= 'A' && t <= 'Z')
}

func isMiddleChar(t byte) bool {
	return isBorderChar(t) || t == '-'
}

// IsHostname checks if name is a valid RFC1123 hostname.
func IsHostname(name string) bool {
	buf := make([]byte, 255)
	offset, err := dns.PackDomainName(dns.CanonicalName(name), buf, 0, nil, false)
	if err != nil {
		// Not domain name
		return false
	}
	var i byte
	for i < byte(offset) {
		labelLen := buf[i]
		i++
		for j := byte(0); j < labelLen; j++ {
			if j == 0 || j == labelLen-1 {
				if !isBorderChar(buf[i+j]) {
					return false
				}
			} else {
				if !isMiddleChar(buf[i+j]) {
					return false
				}
			}
		}
		i += labelLen
	}
	return true
}

// Equals check that both names are equal.
// Input names can accept non-normalized name.
func Equals(a, b string) bool {
	bufa := make([]byte, 255)
	bufb := make([]byte, 255)
	_, err := dns.PackDomainName(dns.CanonicalName(a), bufa, 0, nil, false)
	if err != nil {
		return false
	}
	_, err = dns.PackDomainName(dns.CanonicalName(b), bufb, 0, nil, false)
	if err != nil {
		return false
	}

	return bytes.Equal(bufa, bufb)
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
	var arr, brr sort.StringSlice
	for _, rr := range a.GetRRs() {
		v := strings.SplitN(rr.String(), "\t", 5)
		arr = append(arr, v[4])
	}
	for _, rr := range b.GetRRs() {
		v := strings.SplitN(rr.String(), "\t", 5)
		brr = append(brr, v[4])
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

// ConvertStringToType returns uint16 dns rrtype by string
// If it failed to parse, returns ErrInvalid
func ConvertStringToType(s string) (uint16, error) {
	return ConvertToStringToNumber(dns.StringToType, "TYPE", s)
}

// ConvertStringToClass returns dns.Class by string
// If it failed to parse, returns ErrInvalid
func ConvertStringToClass(s string) (dns.Class, error) {
	class, err := ConvertToStringToNumber(dns.StringToClass, "CLASS", s)
	return dns.Class(class), err
}

func ConvertToStringToNumber[T constraints.Integer](def map[string]T, prefix, s string) (T, error) {
	var (
		t  T
		ok bool
	)
	if t, ok = def[s]; ok {
		return t, nil
	}
	if strings.HasPrefix(s, prefix) {
		v := strings.TrimLeft(s, prefix)
		res, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, ErrInvalid
		}
		if err := intcast.Cast(res, &t); err != nil {
			return 0, ErrInvalid
		}
		return t, nil
	}
	return 0, ErrInvalid
}

// ConvertTypeToString returns RRType string by uint16 dns rrtype.
func ConvertTypeToString(i uint16) string {
	return ConvertNumberToString(dns.TypeToString, "TYPE", i)
}

// ConvertClassToString returns DNS Class string by dns.Class
func ConvertClassToString(i dns.Class) string {
	return ConvertNumberToString(dns.ClassToString, "CLASS", uint16(i))
}

func ConvertNumberToString[T constraints.Integer](def map[T]string, prefix string, i T) string {
	if s, ok := def[i]; ok {
		return s
	}
	return prefix + strconv.FormatUint(uint64(i), 10)
}

// GetAllParentNames returns a name slice containing parent names and itself.
func GetAllParentNames(name string, level uint) ([]string, bool) {
	_, ok := dns.IsDomainName(name)
	if !ok {
		return nil, false
	}
	names := []string{}
	labels := dns.SplitDomainName(name)
	for i := len(labels) - int(level) - 1; i >= 0; i-- {
		names = append(names, dns.CanonicalName(strings.Join(labels[i:], ".")))
	}
	return names, true
}

// https://datatracker.ietf.org/doc/html/rfc4034#section-6.1
// SortNamesFunc returns sorted names
func SortNames(names []string) ([]string, error) {
	var err error
	sort.SliceStable(names, func(i, j int) bool {
		cmp, cErr := CompareName(names[i], names[j])
		if cErr != nil {
			err = cErr
		}
		return cmp < 0
	})
	if err != nil {
		return nil, err
	}
	return names, nil
}

func SplitLabelsBytes(name string) ([][]byte, error) {
	buf := make([]byte, 255)
	offset, err := dns.PackDomainName(name, buf, 0, nil, false)
	if err != nil {
		return nil, ErrBadName
	}
	var res [][]byte
	var i byte
	for i < byte(offset) {
		labelLen := buf[i]
		if labelLen == 0 {
			break
		}
		i++
		label := make([]byte, labelLen)
		copy(label, buf[i:i+labelLen])
		res = append(res, label)
		i = i + labelLen
	}
	return res, nil
}

// The result will be 0 if a == b, -1 if a < b, and +1 if a > b.
func CompareName(a, b string) (int, error) {
	al, err := SplitLabelsBytes(dns.CanonicalName(a))
	if err != nil {
		return 0, ErrBadName
	}
	bl, err := SplitLabelsBytes(dns.CanonicalName(b))
	if err != nil {
		return 0, ErrBadName
	}
	slices.Reverse(al)
	slices.Reverse(bl)
	for i := 0; i < len(al) && i < len(bl); i++ {
		if res := bytes.Compare(al[i], bl[i]); res != 0 {
			return res, nil
		}
	}
	if len(al) == len(bl) {
		return 0, nil
	}
	if len(al) > len(bl) {
		return 1, nil
	}
	return -1, nil
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
