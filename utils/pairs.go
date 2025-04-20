package utils

import (
	"errors"
	"strconv"
	"strings"
)

var (
	ErrInvalidPair = errors.New("pair is not in key=value format or couldn't be parsed")
)

type Value interface {
	string | uint64
}

func ToMap[T Value](in string) (m map[string]T, e error) {
	m = map[string]T{}

	pairs := strings.Split(in, ",")
	for _, pair := range pairs {
		k, v, err := kv[T](pair)
		if err != nil {
			return nil, err
		}
		m[k] = v
	}
	return
}

func kv[T Value](pair string) (k string, v T, e error) {
	var p T
	spl := strings.SplitN(pair, "=", 2)
	if len(spl) != 2 {
		return "", p, ErrInvalidPair
	}

	k = spl[0]

	switch any(p).(type) {
	case string:
		v = any(spl[1]).(T)
	case uint64:
		parsed, err := strconv.ParseUint(spl[1], 10, 64)
		if err != nil {
			return "", p, err
		}
		v = any(parsed).(T)
	}
	return
}
