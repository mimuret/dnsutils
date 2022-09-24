package testtool

import (
	"math/rand"
	"time"
)

const (
	numericAlphabet       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	numericAlphabetHyphen = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
)

func GetRandomHostName() string {
	// maxlen: 254
	// min: 2 = 1 numericAlphabet + "."
	// random: 252
	l := 2 + rand.Int()%253
	name := GetRandomHostLabel(l)
	for len(name) < l-2 {
		name = name + GetRandomHostLabel(l-len(name))
	}
	return name
}

func GetRandomHostLabel(maxLen int) string {
	// max random Len = 62
	if maxLen > 63 {
		maxLen = 63
	}
	l := 2 + rand.Int()%maxLen
	label := make([]byte, l)
	label[0] = numericAlphabet[rand.Int()%len(numericAlphabet)]
	label[l-2] = numericAlphabet[rand.Int()%len(numericAlphabet)]
	label[l-1] = '.'
	// random string
	for i := 1; i < l-2; i++ {
		label[i] += numericAlphabetHyphen[rand.Int()%len(numericAlphabetHyphen)]
	}
	return string(label)
}

func init() {
	rand.Seed(time.Now().Unix())
}
