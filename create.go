package argon2id

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	saltLength = uint(16)
	time       = uint32(1)
	memory     = uint32(64 * 1024)
	threads    = uint8(4)
	keyLen     = uint32(32)
)

// New takes in a password (or another string to hash), hashes it and returns an HObject containing the result or an error.
// It takes care of generating a salt using crypto/rand.Read().
// The current length of the salt is 16 bytes.
func New(passwd string) (o *HObject, e error) {
	s, err := salt(saltLength)
	if err != nil {
		return nil, err
	}

	h := argon2.IDKey([]byte(passwd), s, time, memory, threads, keyLen)
	return &HObject{
		Hash:        h,
		Salt:        s,
		Memory:      memory,
		Iterations:  time,
		Parallelism: threads,
		Version:     fmt.Sprintf("%d", argon2.Version),
		Algorithm:   supportedAlg,
	}, nil
}

// Parse is a convenience wrapper around *HObject.Deserialize().
// It takes care of creating an object, calls deserialize, and returns it.
// In case of an error, an error is returned instead.
func Parse(input string) (o *HObject, e error) {
	var ho HObject
	if err := ho.Deserialize(input); err != nil {
		return nil, err
	}

	return &ho, nil
}

// salt uses rand.Read() to generate a random salt of the asked for length.
func salt(length uint) (s []byte, e error) {
	s = make([]byte, length)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return
}
