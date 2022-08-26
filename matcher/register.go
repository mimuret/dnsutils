package matcher

var (
	dnstapUnmarshaler = map[MatcherName]UnmarshalFunc{}
	newDnstapMatchers = map[MatcherName]NewDnstapMatcher{}
	dnsMsgUnmarshaler = map[MatcherName]UnmarshalFunc{}
	newDnsMsgMatchers = map[MatcherName]NewDnsMsgMatcher{}
)

func RegisterDnstapMatcher(name MatcherName, newFunc NewDnstapMatcher, unmarshaler UnmarshalFunc) {
	if name == "" {
		panic("name is empty")
	}
	if newFunc == nil || unmarshaler == nil {
		panic("invalid args for RegisterDnstapMacher")
	}
	dnstapUnmarshaler[name.Get()] = unmarshaler
	newDnstapMatchers[name.Get()] = newFunc
}

func RegisterDnsMsgMatcher(name MatcherName, newFunc NewDnsMsgMatcher, unmarshaler UnmarshalFunc) {
	if name == "" {
		panic("name is empty")
	}
	if newFunc == nil || unmarshaler == nil {
		panic("invalid args for RegisterDnsMsgMatcher")
	}
	dnsMsgUnmarshaler[name.Get()] = unmarshaler
	newDnsMsgMatchers[name.Get()] = newFunc
}
