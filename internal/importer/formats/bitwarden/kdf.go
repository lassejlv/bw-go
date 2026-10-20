package bitwarden

import (
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/importer"
)

// Bounds from bitwarden/password-protected-kdf-config.ts (import floors) and
// legacy-crypto/src/models/kdf-config.ts (upper bounds the settings UI enforces).
const (
	pbkdf2ImportIterationsMin = 5000
	pbkdf2IterationsMax       = 2_000_000

	argon2ImportIterationsMin  = 2
	argon2IterationsMax        = 10
	argon2ImportMemoryMin      = 16
	argon2MemoryMax            = 1024
	argon2ImportParallelismMin = 1
	argon2ParallelismMax       = 16
)

func inBounds(n importer.JSONNumber, lo, hi int) bool {
	return n.Valid && n.IsInteger() && n.Value >= float64(lo) && n.Value <= float64(hi)
}

// KdfConfigFromPasswordProtectedExport is kdfConfigFromPasswordProtectedExport: the file's KDF
// parameters if they are within the range Bitwarden clients produce, else ok=false (the file is
// attacker controlled; Argon2 memory is allocated up front).
func kdfConfigFromPasswordProtectedExport(f *exportFile) (crypto.KdfConfig, bool) {
	if !f.KdfType.IsNumber {
		return crypto.KdfConfig{}, false
	}
	switch f.KdfType.Value {
	case float64(crypto.KdfPBKDF2):
		if inBounds(f.KdfIterations, pbkdf2ImportIterationsMin, pbkdf2IterationsMax) {
			return crypto.KdfConfig{Type: crypto.KdfPBKDF2, Iterations: f.KdfIterations.Int()}, true
		}
	case float64(crypto.KdfArgon2id):
		if inBounds(f.KdfIterations, argon2ImportIterationsMin, argon2IterationsMax) &&
			inBounds(f.KdfMemory, argon2ImportMemoryMin, argon2MemoryMax) &&
			inBounds(f.KdfParallelism, argon2ImportParallelismMin, argon2ParallelismMax) {
			mem, par := f.KdfMemory.Int(), f.KdfParallelism.Int()
			return crypto.KdfConfig{Type: crypto.KdfArgon2id, Iterations: f.KdfIterations.Int(), Memory: &mem, Parallelism: &par}, true
		}
	}
	return crypto.KdfConfig{}, false
}

// deriveVaultExportKey is KeyGenerationService.deriveVaultExportKey: the master-key derivation
// with the export's salt, stretched with HKDF into an enc+mac key.
func deriveVaultExportKey(password, salt string, kdf crypto.KdfConfig) (*crypto.SymmetricKey, error) {
	mk, err := crypto.MakeMasterKey(password, salt, kdf)
	if err != nil {
		return nil, err
	}
	return crypto.StretchKey(mk), nil
}
