package matcher

import "fmt"

func BuilderMatchSet(c *Config) (*MatcherSet, error) {
	set := NewMatcherSet()
	if c.Op != MatchOpAND || c.Op == MatchOpOR {
		return nil, fmt.Errorf("unknown op `%s`", c.Op)
	}
	for _, mc := range c.Matchers {
		switch mc.Type {
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
	if mc.Type != MatcherTypeDnstap {
		return nil, fmt.Errorf("matcher config Type is not DNSTAP: `%s`", mc.Type)
	}
	newFunc, exist := newDnstapMatchers[mc.Name]
	if !exist {
		return nil, fmt.Errorf("matcher config Type: DNSTAP, Matcher Name: %s is not found", mc.Name)
	}
	return newFunc(mc.Arg)
}

func BuildDnsMsgMatcher(mc MatcherConfig) (DnsMsgMatcher, error) {
	if mc.Type != MatcherTypeDnsMsg {
		return nil, fmt.Errorf("matcher config Type is not DNS: `%s`", mc.Type)
	}
	newFunc, exist := newDnsMsgMatchers[mc.Name]
	if !exist {
		return nil, fmt.Errorf("matcher config Type: DNS, Matcher Name: %s is not found", mc.Name)
	}
	return newFunc(mc.Arg)
}
