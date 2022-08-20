package matcher

var (
	dnstapUnmarshaler = map[string]UnmarshalFunc{}
	newDnstapMatchers = map[string]NewDnstapMatcher{}
	dnsMsgUnmarshaler = map[string]UnmarshalFunc{}
	newDnsMsgMatchers = map[string]NewDnsMsgMatcher{}
)

func RegisterDnstapMatcher(name string, newFunc NewDnstapMatcher, unmarshaler UnmarshalFunc) {
	if name == "" {
		panic("name is empty")
	}
	if newFunc == nil || unmarshaler == nil {
		panic("invalid args for RegisterDnstapMacher")
	}
	dnstapUnmarshaler[name] = unmarshaler
	newDnstapMatchers[name] = newFunc
}

func RegisterDnsMsgMatcher(name string, newFunc NewDnsMsgMatcher, unmarshaler UnmarshalFunc) {
	if name == "" {
		panic("name is empty")
	}
	if newFunc == nil || unmarshaler == nil {
		panic("invalid args for RegisterDnsMsgMatcher")
	}
	dnsMsgUnmarshaler[name] = unmarshaler
	newDnsMsgMatchers[name] = newFunc
}
