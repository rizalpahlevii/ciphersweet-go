package blindindex

import (
	"github.com/rizalpahlevii/ciphersweet-go/argon"
	"github.com/rizalpahlevii/ciphersweet-go/blindindex/transform"
)

// DefaultBits is the default blind index width in bits.
// Matches PHP BlindIndex default of 256.
const DefaultBits = 256

// BlindIndex describes a single searchable index for an encrypted field.
type BlindIndex struct {
	// Name is used for key derivation and as the key in the returned IndexMap.
	Name string

	// OutputBits is the index width in bits. Defaults to DefaultBits (256).
	// Matches PHP BlindIndex $filterBits parameter.
	//
	//   Table size    Recommended bits
	//   ──────────    ────────────────
	//   < 1 000       16
	//   < 1 000 000   32
	//   > 1 000 000   64
	OutputBits int

	// Fast switches from Argon2id (default) to BLAKE2b hashing.
	// Matches PHP BlindIndex $fastHash parameter.
	//
	// false (default) → Argon2id  (PHP: new BlindIndex('name'))
	// true            → BLAKE2b   (PHP: new BlindIndex('name', [], 256, true))
	Fast bool

	// ArgonCfg holds Argon2id parameters when Fast is false.
	// nil uses argon.DefaultConfig().
	ArgonCfg *argon.Config

	// Transformations are applied to the plaintext in order before hashing.
	Transformations []transform.RowTransformation
}

// Option is a functional option for BlindIndex.
type Option func(*BlindIndex)

// New creates a BlindIndex with defaults matching PHP's BlindIndex:
//   - 256 bits wide
//   - Argon2id hashing (fastHash=false in PHP)
//   - No transforms
func New(name string, opts ...Option) *BlindIndex {
	bi := &BlindIndex{
		Name:       name,
		OutputBits: DefaultBits,
		Fast:       false, // matches PHP default fastHash=false → Argon2id
	}
	for _, o := range opts {
		o(bi)
	}
	return bi
}

// WithBits sets the output bit width.
// Matches PHP BlindIndex $filterBits parameter.
func WithBits(bits int) Option {
	return func(bi *BlindIndex) { bi.OutputBits = bits }
}

// WithFast enables BLAKE2b hashing (fast but less brute-force resistant).
// Matches PHP: new BlindIndex('name', [], 256, true)
func WithFast() Option {
	return func(bi *BlindIndex) { bi.Fast = true }
}

// WithSlow explicitly enables Argon2id hashing with the given config.
// This is the default — only needed if you previously called WithFast()
// and want to revert, or if you want custom Argon2id parameters.
// Pass nil cfg to use argon.DefaultConfig().
func WithSlow(cfg *argon.Config) Option {
	return func(bi *BlindIndex) {
		bi.Fast = false
		bi.ArgonCfg = cfg
	}
}

// WithTransform appends one or more transformations applied before hashing.
func WithTransform(ts ...transform.RowTransformation) Option {
	return func(bi *BlindIndex) {
		bi.Transformations = append(bi.Transformations, ts...)
	}
}

// Apply runs all registered transformations on value in order.
func (bi *BlindIndex) Apply(value string) string {
	for _, t := range bi.Transformations {
		value = t.Transform(value)
	}
	return value
}

// IsSlow returns true if this index uses Argon2id (the default).
// Convenience method for readability.
func (bi *BlindIndex) IsSlow() bool { return !bi.Fast }
