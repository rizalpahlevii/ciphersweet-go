package row

import (
	"fmt"

	"github.com/rizalpahlevii/ciphersweet-go/blindindex"
	"github.com/rizalpahlevii/ciphersweet-go/engine"
)

// ── Type aliases ──────────────────────────────────────────────────────────────

// RowData is a map of fieldName → plaintext value passed to PrepareForStorage.
type RowData = map[string]string

// EncryptedData is a map of fieldName → ciphertext returned by PrepareForStorage
// and consumed by DecryptRow.
type EncryptedData = map[string]string

// IndexMap is a map of indexName → blind-index value returned by PrepareForStorage.
type IndexMap = map[string]string

// ── Field type ────────────────────────────────────────────────────────────────

// FieldType describes the semantic type of a registered field.
// Currently all types encrypt as UTF-8 strings; the type is available for
// application-level validation and future typed-encoding extensions.
type FieldType int

const (
	TypeText    FieldType = iota // plain string (default)
	TypeBoolean                  // "true" / "false" or "1" / "0"
	TypeInteger                  // decimal integer string
	TypeFloat                    // decimal float string
)

type fieldDef struct {
	name      string
	fieldType FieldType
	optional  bool // if true, an empty plaintext is stored as "" without encryption
}

// ── EncryptedRow ──────────────────────────────────────────────────────────────

// EncryptedRow manages encryption for multiple columns of one database table row.
// It is safe for concurrent use after all AddField / AddBlindIndex calls are done.
type EncryptedRow struct {
	eng       *engine.Engine
	tableName string
	fields    []fieldDef
	fieldIdx  map[string]int                      // name → position in fields slice
	indexes   map[string][]*blindindex.BlindIndex // fieldName → []BlindIndex
	strict    bool                                // if true, PrepareForStorage returns an error for missing fields
}

// New creates an EncryptedRow for tableName.
func New(eng *engine.Engine, tableName string) *EncryptedRow {
	return &EncryptedRow{
		eng:       eng,
		tableName: tableName,
		fieldIdx:  make(map[string]int),
		indexes:   make(map[string][]*blindindex.BlindIndex),
	}
}

// WithStrict enables strict mode: PrepareForStorage and DecryptRow return an
// error when a registered field is absent from the supplied map.
// Default is lenient (missing fields are silently skipped).
func (er *EncryptedRow) WithStrict() *EncryptedRow {
	er.strict = true
	return er
}

// ── Field registration ────────────────────────────────────────────────────────

// AddField registers a required plaintext field.
func (er *EncryptedRow) AddField(name string) *EncryptedRow {
	return er.addField(fieldDef{name: name, fieldType: TypeText})
}

// AddBooleanField registers a boolean field (values should be "1"/"0" or "true"/"false").
func (er *EncryptedRow) AddBooleanField(name string) *EncryptedRow {
	return er.addField(fieldDef{name: name, fieldType: TypeBoolean})
}

// AddIntegerField registers an integer field (decimal string representation).
func (er *EncryptedRow) AddIntegerField(name string) *EncryptedRow {
	return er.addField(fieldDef{name: name, fieldType: TypeInteger})
}

// AddFloatField registers a float field (decimal string representation).
func (er *EncryptedRow) AddFloatField(name string) *EncryptedRow {
	return er.addField(fieldDef{name: name, fieldType: TypeFloat})
}

// AddOptionalTextField registers a text field that may legitimately be empty.
// An empty string is stored as-is without encryption; a non-empty string is
// encrypted normally.
func (er *EncryptedRow) AddOptionalTextField(name string) *EncryptedRow {
	return er.addField(fieldDef{name: name, fieldType: TypeText, optional: true})
}

func (er *EncryptedRow) addField(fd fieldDef) *EncryptedRow {
	er.fieldIdx[fd.name] = len(er.fields)
	er.fields = append(er.fields, fd)
	return er
}

// AddBlindIndex registers a blind index on fieldName.
// Multiple blind indexes on the same field are allowed.
func (er *EncryptedRow) AddBlindIndex(fieldName string, bi *blindindex.BlindIndex) *EncryptedRow {
	er.indexes[fieldName] = append(er.indexes[fieldName], bi)
	return er
}

// ── Core operations ───────────────────────────────────────────────────────────

// PrepareForStorage encrypts every registered field found in data and computes
// all blind indexes.
//
// In lenient mode (default), fields absent from data are silently skipped.
// In strict mode (WithStrict), a missing required field returns an error.
//
// Returns:
//   - encrypted: fieldName → ciphertext  (store in the ciphertext column)
//   - indexes:   indexName → index value (store in each companion index column)
func (er *EncryptedRow) PrepareForStorage(data RowData) (encrypted EncryptedData, indexes IndexMap, err error) {
	encrypted = make(EncryptedData, len(er.fields))
	indexes = make(IndexMap)

	for _, fd := range er.fields {
		plaintext, ok := data[fd.name]
		if !ok {
			if er.strict && !fd.optional {
				return nil, nil, fmt.Errorf("row[%s]: PrepareForStorage: missing required field %q", er.tableName, fd.name)
			}
			continue
		}

		// Optional empty field → store empty string unencrypted.
		if fd.optional && plaintext == "" {
			encrypted[fd.name] = ""
			continue
		}

		ct, err := er.eng.EncryptField([]byte(plaintext), er.tableName, fd.name, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("row[%s.%s]: encrypt: %w", er.tableName, fd.name, err)
		}
		encrypted[fd.name] = ct

		// Compute every blind index registered for this field.
		for _, bi := range er.indexes[fd.name] {
			val, err := er.computeIndex(bi, fd.name, plaintext)
			if err != nil {
				return nil, nil, fmt.Errorf("row[%s.%s]: blind index %q: %w", er.tableName, fd.name, bi.Name, err)
			}
			indexes[bi.Name] = val
		}
	}
	return encrypted, indexes, nil
}

// DecryptRow decrypts all registered fields found in encData.
//
// In lenient mode, fields absent from encData are silently skipped.
// In strict mode, a missing required field returns an error.
func (er *EncryptedRow) DecryptRow(encData EncryptedData) (RowData, error) {
	out := make(RowData, len(er.fields))

	for _, fd := range er.fields {
		ct, ok := encData[fd.name]
		if !ok {
			if er.strict && !fd.optional {
				return nil, fmt.Errorf("row[%s]: DecryptRow: missing field %q", er.tableName, fd.name)
			}
			continue
		}

		// Optional empty ciphertext → return empty string.
		if fd.optional && ct == "" {
			out[fd.name] = ""
			continue
		}

		pt, err := er.eng.DecryptField(ct, er.tableName, fd.name, nil)
		if err != nil {
			return nil, fmt.Errorf("row[%s.%s]: decrypt: %w", er.tableName, fd.name, err)
		}
		out[fd.name] = string(pt)
	}
	return out, nil
}

// GetBlindIndex computes the blind index value for plaintext on the named field
// and index.  Use the returned string in a WHERE clause:
//
//	idx, err := er.GetBlindIndex("email", "alice@example.com", "email_index")
//	db.Query("SELECT * FROM users WHERE email_index = ?", idx)
func (er *EncryptedRow) GetBlindIndex(fieldName, plaintext, indexName string) (string, error) {
	for _, bi := range er.indexes[fieldName] {
		if bi.Name == indexName {
			return er.computeIndex(bi, fieldName, plaintext)
		}
	}
	return "", fmt.Errorf("row[%s.%s]: no blind index named %q", er.tableName, fieldName, indexName)
}

// GetAllBlindIndexes computes all blind index values for plaintext on fieldName.
// Useful when updating a row and needing to refresh every index column.
func (er *EncryptedRow) GetAllBlindIndexes(fieldName, plaintext string) (IndexMap, error) {
	bis := er.indexes[fieldName]
	if len(bis) == 0 {
		return nil, fmt.Errorf("row[%s.%s]: no blind indexes registered", er.tableName, fieldName)
	}
	out := make(IndexMap, len(bis))
	for _, bi := range bis {
		val, err := er.computeIndex(bi, fieldName, plaintext)
		if err != nil {
			return nil, fmt.Errorf("row[%s.%s]: blind index %q: %w", er.tableName, fieldName, bi.Name, err)
		}
		out[bi.Name] = val
	}
	return out, nil
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (er *EncryptedRow) computeIndex(bi *blindindex.BlindIndex, fieldName, plaintext string) (string, error) {
	transformed := bi.Apply(plaintext)
	if !bi.Fast {
		// bi.ArgonCfg may be nil — engine passes it to argon.Resolved() which
		// substitutes DefaultConfig() in that case.
		return er.eng.BlindIndexSlow(transformed, er.tableName, fieldName, bi.Name, bi.OutputBits, bi.ArgonCfg)
	}
	return er.eng.BlindIndexFast(transformed, er.tableName, fieldName, bi.Name, bi.OutputBits)
}
