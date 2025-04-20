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

func salt(length uint) (s []byte, e error) {
	s = make([]byte, length)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return
}
