package matcher

import (
	"encoding/json"

	"github.com/pkg/errors"
)

func GetBool(arg interface{}) (bool, error) {
	var t bool
	switch v := arg.(type) {
	case bool:
		t = v
	default:
		return false, errors.Errorf("invalid bool type %v", arg)
	}
	return t, nil
}

func UnmarshalBoolArg(bs json.RawMessage) (interface{}, error) {
	var ok bool
	if err := json.Unmarshal(bs, &ok); err != nil {
		return nil, err
	}
	return ok, nil
}

func UnmarshalStringArg(bs json.RawMessage) (interface{}, error) {
	var str string
	if err := json.Unmarshal(bs, &str); err != nil {
		return nil, err
	}
	return str, nil
}

func UnmarshalUint32Arg(bs json.RawMessage) (interface{}, error) {
	var u32 uint32
	if err := json.Unmarshal(bs, &u32); err != nil {
		return nil, err
	}
	return u32, nil
}
