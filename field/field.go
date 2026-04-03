package field

import (
	"fmt"

	"github.com/rizalpahlevii/ciphersweet-go/blindindex"
	"github.com/rizalpahlevii/ciphersweet-go/engine"
)

// IndexMap maps index name → computed blind index value.
type IndexMap map[string]string

// EncryptedField manages encryption and blind-index generation for a single
// database column.
type EncryptedField struct {
	eng       *engine.Engine
	tableName string
	fieldName string
	aad       []byte // optional additional authenticated data
	indexes   []*blindindex.BlindIndex
}

// New creates an EncryptedField for the given table and column.
func New(eng *engine.Engine, tableName, fieldName string) *EncryptedField {
	return &EncryptedField{
		eng:       eng,
		tableName: tableName,
		fieldName: fieldName,
	}
}

// WithAAD binds additional authenticated data to every ciphertext produced by
// this field.  The same aad must be supplied on decryption.
// Returns the receiver for chaining.
func (ef *EncryptedField) WithAAD(aad []byte) *EncryptedField {
	ef.aad = aad
	return ef
}

// AddBlindIndex registers a blind index on this field.
// Returns the receiver for chaining.
func (ef *EncryptedField) AddBlindIndex(bi *blindindex.BlindIndex) *EncryptedField {
	ef.indexes = append(ef.indexes, bi)
	return ef
}

// ── Core operations ───────────────────────────────────────────────────────────

// PrepareForStorage encrypts plaintext and computes all registered blind indexes.
//
// Returns:
//   - ciphertext: the encrypted value to store in the column
//   - indexes: map of index name → value; store each in its companion column
//   - err: non-nil on any cryptographic failure
func (ef *EncryptedField) PrepareForStorage(plaintext string) (ciphertext string, indexes IndexMap, err error) {
	ciphertext, err = ef.eng.EncryptField([]byte(plaintext), ef.tableName, ef.fieldName, ef.aad)
	if err != nil {
		return "", nil, fmt.Errorf("field[%s.%s]: encrypt: %w", ef.tableName, ef.fieldName, err)
	}

	indexes = make(IndexMap, len(ef.indexes))
	for _, bi := range ef.indexes {
		val, err := ef.computeIndex(bi, plaintext)
		if err != nil {
			return "", nil, fmt.Errorf("field[%s.%s]: blind index %q: %w", ef.tableName, ef.fieldName, bi.Name, err)
		}
		indexes[bi.Name] = val
	}
	return ciphertext, indexes, nil
}

// Decrypt decrypts a ciphertext produced by PrepareForStorage.
func (ef *EncryptedField) Decrypt(ciphertext string) (string, error) {
	pt, err := ef.eng.DecryptField(ciphertext, ef.tableName, ef.fieldName, ef.aad)
	if err != nil {
		return "", fmt.Errorf("field[%s.%s]: decrypt: %w", ef.tableName, ef.fieldName, err)
	}
	return string(pt), nil
}

// GetBlindIndex computes the blind index for a search value without encrypting.
//
//	idx, err := ef.GetBlindIndex("alice@example.com", "email_index")
//	// → db.Query("SELECT * FROM users WHERE email_index = ?", idx)
func (ef *EncryptedField) GetBlindIndex(plaintext, indexName string) (string, error) {
	bi := ef.findIndex(indexName)
	if bi == nil {
		return "", fmt.Errorf("field[%s.%s]: no blind index named %q", ef.tableName, ef.fieldName, indexName)
	}
	return ef.computeIndex(bi, plaintext)
}

// GetAllBlindIndexes computes all registered blind index values for plaintext.
// Useful when you need to update every index column after a plaintext change.
func (ef *EncryptedField) GetAllBlindIndexes(plaintext string) (IndexMap, error) {
	out := make(IndexMap, len(ef.indexes))
	for _, bi := range ef.indexes {
		val, err := ef.computeIndex(bi, plaintext)
		if err != nil {
			return nil, fmt.Errorf("field[%s.%s]: blind index %q: %w", ef.tableName, ef.fieldName, bi.Name, err)
		}
		out[bi.Name] = val
	}
	return out, nil
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (ef *EncryptedField) computeIndex(bi *blindindex.BlindIndex, plaintext string) (string, error) {
	transformed := bi.Apply(plaintext)
	if !bi.Fast {
		return ef.eng.BlindIndexSlow(transformed, ef.tableName, ef.fieldName, bi.Name, bi.OutputBits, bi.ArgonCfg)
	}
	return ef.eng.BlindIndexFast(transformed, ef.tableName, ef.fieldName, bi.Name, bi.OutputBits)
}

func (ef *EncryptedField) findIndex(name string) *blindindex.BlindIndex {
	for _, bi := range ef.indexes {
		if bi.Name == name {
			return bi
		}
	}
	return nil
}
