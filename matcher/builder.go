package matcher

import "fmt"

func BuilderMatchSet(c *Config) (*MatcherSet, error) {
	set := NewMatcherSet()
	switch c.Op.Get() {
	case MatchOpAND:
		set.Op = SetOpAND
	case MatchOpOR:
		set.Op = SetOpOR
	default:
		return nil, fmt.Errorf("unknown op `%s`", c.Op)
	}
	for _, mc := range c.Matchers {
		switch mc.Type.Get() {
		case MatcherTypeDnstap:
			m, err := BuildDnstapMatcher(mc)
			if err != nil {
				return nil, fmt.Errorf("failed to create dnstap matcher: %w", err)
			}
			set.DnstapMatchers = append(set.DnstapMatchers, m)
		case MatcherTypeDnsMsg:
			m, err := BuildDnsMsgMatcher(mc)
			if err != nil {
				return nil, fmt.Errorf("failed to create dns matcher: %w", err)
			}
			set.DnsMsgMatchers = append(set.DnsMsgMatchers, m)
		default:
			return nil, fmt.Errorf("unknown type `%s`", mc.Type)
		}
	}
	for _, subConfig := range c.SubConfigs {
		subSet, err := BuilderMatchSet(&subConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create subset: %w", err)
		}
		set.SubSets = append(set.SubSets, subSet)
	}
	return set, nil
}

func BuildDnstapMatcher(mc MatcherConfig) (DnstapMatcher, error) {
	if !mc.Type.Equals(MatcherTypeDnstap) {
		return nil, fmt.Errorf("matcher config Type is not DNSTAP: `%s`", mc.Type)
	}
	newFunc, exist := newDnstapMatchers[mc.Name.Get()]
	if !exist {
		return nil, fmt.Errorf("matcher config Type: DNSTAP, Matcher Name: %s is not found", mc.Name)
	}
	return newFunc(mc.Arg)
}

func BuildDnsMsgMatcher(mc MatcherConfig) (DnsMsgMatcher, error) {
	if !mc.Type.Equals(MatcherTypeDnsMsg) {
		return nil, fmt.Errorf("matcher config Type is not DNS: `%s`", mc.Type)
	}
	newFunc, exist := newDnsMsgMatchers[mc.Name.Get()]
	if !exist {
		return nil, fmt.Errorf("matcher config Type: DNS, Matcher Name: %s is not found", mc.Name)
	}
	return newFunc(mc.Arg)
}
