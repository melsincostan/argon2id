package argon2id

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/melsincostan/argon2id/utils"
	"golang.org/x/crypto/argon2"
)

var (
	ErrUnparseableHash      = errors.New("hash format not understood or invalid")
	ErrUnsupportedAlgorithm = fmt.Errorf("only the %s algorithm is supported", supportedAlg)
	ErrVersionNotFound      = errors.New("couldn't find the version key (v)")
	ErrIterationsNotFound   = errors.New("couldn't find the iterations key (t)")
	ErrParallelismNotFound  = errors.New("couldn't find the parallelism key (p)")
	ErrMemoryNotFound       = errors.New("couldn't find the memory key (m)")
)

const (
	supportedAlg = "argon2id"
)

type HObject struct {
	Hash        []byte
	Salt        []byte
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	Version     string
	Algorithm   string
}

func (ho HObject) Compare(passwd string) bool {
	cmph := argon2.IDKey([]byte(passwd), ho.Salt, ho.Iterations, ho.Memory, ho.Parallelism, uint32(len(ho.Hash)))
	return subtle.ConstantTimeCompare(cmph, ho.Hash) == 1
}

func (ho HObject) MarshalJSON() ([]byte, error) {
	return []byte(ho.Serialize()), nil
}

func (ho *HObject) UnmarshalJSON(in []byte) error {
	var s string
	if err := json.Unmarshal(in, &s); err != nil {
		return err
	}
	return ho.Deserialize(s)
}

func (ho HObject) Serialize() string {
	hashEnc := base64.RawStdEncoding.EncodeToString(ho.Hash)
	saltEnc := base64.RawStdEncoding.EncodeToString(ho.Salt)
	return fmt.Sprintf("$%s$v=%s$m=%d,t=%d,p=%d$%s$%s", ho.Algorithm, ho.Version, ho.Memory, ho.Iterations, ho.Parallelism, saltEnc, hashEnc)
}

func (ho *HObject) Deserialize(in string) error {
	spl := strings.Split(strings.TrimPrefix(in, "$"), "$")
	if len(spl) != 5 {
		return ErrUnparseableHash
	}

	if spl[0] != supportedAlg {
		return ErrUnsupportedAlgorithm
	}

	ho.Algorithm = spl[0]

	vm, err := utils.ToMap[string](spl[1])
	if err != nil {
		return err
	}

	if ver, ok := vm["v"]; ok {
		ho.Version = ver
	} else {
		return ErrVersionNotFound
	}

	pm, err := utils.ToMap[uint64](spl[2])
	if err != nil {
		return err
	}

	if mem, ok := pm["m"]; ok {
		ho.Memory = uint32(mem)
	} else {
		return ErrMemoryNotFound
	}

	if iters, ok := pm["t"]; ok {
		ho.Iterations = uint32(iters)
	} else {
		return ErrIterationsNotFound
	}

	if par, ok := pm["p"]; ok {
		ho.Parallelism = uint8(par)
	} else {
		return ErrParallelismNotFound
	}

	salt, err := base64.RawStdEncoding.DecodeString(spl[3])

	if err != nil {
		return err
	}

	ho.Salt = salt

	hash, err := base64.RawStdEncoding.DecodeString(spl[4])

	if err != nil {
		return err
	}

	ho.Hash = hash

	return nil
}
