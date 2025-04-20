package utils

import (
	"errors"
	"strconv"
	"strings"
)

var (
	// ErrInvalidPair is returned when a key=value pair cannot be parsed (splitting the pair using SplitN with N=2 results in a number of elements that isn't 2).
	ErrInvalidPair = errors.New("pair is not in key=value format or couldn't be parsed")
)

// Value is a constraint of the types supported by the kv / ToMap functions.
type Value interface {
	string | uint64
}

// ToMap takes a ',' separated list of 'key=value' pairs and parses them into a map.
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

// kv takes a 'key=value' pair and returns the key and the parsed value.
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
