package gormcrypt

// ── Tag-based API ─────────────────────────────────────────────────────────────
//
// Recommended integration: struct tags + RegisterTagCallbacks (see package doc in doc.go).
//
// Tag your model fields with `gormcrypt` and call RegisterTagCallbacks once.
// No shadow fields, no manual hooks, no columns() method.
//
// Usage:
//
//	// main.go
//	gormcrypt.Setup(eng)
//	gormcrypt.RegisterTagCallbacks(db)
//
//	// models/user.go
//	type User struct {
//	    gorm.Model
//	    Name       string
//	    Email      string `gormcrypt:"blind_index=email_index"`
//	    EmailIndex string
//	    Phone      string `gormcrypt:"blind_index=phone_index"`
//	    PhoneIndex string
//	    Nisn       string `gormcrypt:"blind_index=nisn_index,fast=true,bits=256"`
//	    NisnIndex  string
//	}
//
// Tag options (comma-separated key=value):
//
//	blind_index=<column>   blind index column name (required)
//	fast=true              BLAKE2b — matches Laravel ->fast(true)  (default: true)
//	fast=false             Argon2id — Laravel default blind index
//	bits=256               blind index width in bits (default: 256)
//
// How it works:
//   - On BeforeCreate / BeforeSave: the tagged field contains the plaintext.
//     The library reads it, encrypts it in-place (writes nacl:... back),
//     and writes the blind index to the companion index field.
//   - On AfterFind: the tagged field contains the ciphertext (nacl:...).
//     The library decrypts it and writes the plaintext back in-place.
//
// Search:
//
//	idx, err := gormcrypt.TagIndex(&User{}, "email", "alice@example.com")
//	db.Where("email_index = ?", idx).Find(&users)
//
//	// Scopes:
//	db.Scopes(gormcrypt.WhereTag(&User{}, "email", "alice@example.com")).Find(&users)
//	db.Scopes(gormcrypt.WhereTagMulti(&User{}, "email", "a@b.c", "phone", "+1")).Find(&users)

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"gorm.io/gorm"

	"github.com/rizalpahlevii/ciphersweet-go/blindindex"
	"github.com/rizalpahlevii/ciphersweet-go/row"
)

// ── Tag parsing ───────────────────────────────────────────────────────────────

// tagMeta holds parsed information from one `gormcrypt:"..."` tag.
type tagMeta struct {
	fieldName  string // struct field name (e.g. "Email")
	csField    string // CipherSweet field name = lowercase of struct field name (e.g. "email")
	indexCol   string // companion index column name (e.g. "email_index")
	indexField string // struct field name of the index column (e.g. "EmailIndex")
	bits       int
	fast       bool
}

// modelMeta holds all tagMeta entries for one struct type.
type modelMeta struct {
	tableName string
	tags      []tagMeta
	byField   map[string]tagMeta // CipherSweet field name (lowercase) → metadata
}

var (
	metaCache   = make(map[reflect.Type]*modelMeta)
	metaCacheMu sync.RWMutex
)

// getModelMeta parses and caches the tagMeta for a struct type.
func getModelMeta(v interface{}) (*modelMeta, error) {
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("gormcrypt: expected struct, got %s", t.Kind())
	}

	metaCacheMu.RLock()
	if m, ok := metaCache[t]; ok {
		metaCacheMu.RUnlock()
		return m, nil
	}
	metaCacheMu.RUnlock()

	metaCacheMu.Lock()
	defer metaCacheMu.Unlock()
	if m, ok := metaCache[t]; ok {
		return m, nil
	}

	meta := &modelMeta{}

	// Derive table name from struct name (snake_case plural) if not overridden.
	// Override with gormcrypt.SetTableName. Default: plural lowercase of type name.
	meta.tableName = toSnakePlural(t.Name())

	// Build a map of all string-like field names for index field lookup.
	allFields := make(map[string]string) // lowerName → structFieldName
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if isStringLikeType(sf.Type) {
			allFields[strings.ToLower(sf.Name)] = sf.Name
		}
	}

	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		tag := sf.Tag.Get("gormcrypt")
		if tag == "" || !isStringLikeType(sf.Type) {
			continue
		}

		kv := parseTagKV(tag)

		indexCol, ok := kv["blind_index"]
		if !ok {
			continue // gormcrypt tag without blind_index is ignored
		}

		bits := 256
		if b, ok := kv["bits"]; ok {
			if n, err := strconv.Atoi(b); err == nil {
				bits = n
			}
		}

		fast := true // default fast=true (most common in Laravel apps)
		if f, ok := kv["fast"]; ok {
			fast = f != "false" && f != "0"
		}

		// Find the index struct field: look for a field whose lowercase name
		// matches the index column name (stripping underscores for comparison).
		indexFieldName := ""
		// First try exact match (e.g. "email_index" → "EmailIndex")
		normalised := strings.ReplaceAll(indexCol, "_", "")
		for lname, sname := range allFields {
			if strings.ReplaceAll(lname, "_", "") == normalised {
				indexFieldName = sname
				break
			}
		}

		meta.tags = append(meta.tags, tagMeta{
			fieldName:  sf.Name,
			csField:    strings.ToLower(sf.Name),
			indexCol:   indexCol,
			indexField: indexFieldName,
			bits:       bits,
			fast:       fast,
		})
	}

	meta.byField = make(map[string]tagMeta, len(meta.tags))
	for i := range meta.tags {
		tm := meta.tags[i]
		meta.byField[tm.csField] = tm
	}

	metaCache[t] = meta
	return meta, nil
}

// ── EncryptedRow cache ────────────────────────────────────────────────────────

var (
	tagRowCache   = make(map[reflect.Type]*row.EncryptedRow)
	tagRowCacheMu sync.RWMutex
)

func getTagRow(t reflect.Type, meta *modelMeta) (*row.EncryptedRow, error) {
	tagRowCacheMu.RLock()
	if r, ok := tagRowCache[t]; ok {
		tagRowCacheMu.RUnlock()
		return r, nil
	}
	tagRowCacheMu.RUnlock()

	tagRowCacheMu.Lock()
	defer tagRowCacheMu.Unlock()
	if r, ok := tagRowCache[t]; ok {
		return r, nil
	}

	eng, err := getEng()
	if err != nil {
		return nil, err
	}

	r := row.New(eng, meta.tableName)
	for _, tm := range meta.tags {
		r.AddField(tm.csField)
		opts := []blindindex.Option{blindindex.WithBits(tm.bits)}
		if tm.fast {
			opts = append(opts, blindindex.WithFast())
		}
		r.AddBlindIndex(tm.csField, blindindex.New(tm.indexCol, opts...))
	}

	tagRowCache[t] = r
	return r, nil
}

// ── Tag-based encrypt / decrypt ───────────────────────────────────────────────

// encryptByTag encrypts a struct in-place using gormcrypt tags.
func encryptByTag(v interface{}) error {
	meta, err := getModelMeta(v)
	if err != nil || len(meta.tags) == 0 {
		return err
	}

	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}

	t := rv.Type()
	er, err := getTagRow(t, meta)
	if err != nil {
		return err
	}

	// Collect plaintext values from tagged fields.
	data := make(row.RowData, len(meta.tags))
	for _, tm := range meta.tags {
		fv := rv.FieldByName(tm.fieldName)
		val, ok := stringLikeValue(fv)
		if !ok {
			continue
		}
		// Skip if already a ciphertext (idempotent — don't double-encrypt).
		if strings.HasPrefix(val, "nacl:") || strings.HasPrefix(val, "boring:") {
			return nil
		}
		data[tm.csField] = val
	}

	encrypted, indexes, err := er.PrepareForStorage(data)
	if err != nil {
		return fmt.Errorf("gormcrypt tag encrypt: %w", err)
	}

	// Write ciphertexts back into the tagged fields.
	for _, tm := range meta.tags {
		fv := rv.FieldByName(tm.fieldName)
		if !fv.IsValid() || !fv.CanSet() {
			continue
		}
		if ct, ok := encrypted[tm.csField]; ok {
			setStringLikeValue(fv, ct)
		}
	}

	// Write index values into companion index fields.
	for _, tm := range meta.tags {
		if tm.indexField == "" {
			continue
		}
		fv := rv.FieldByName(tm.indexField)
		if !fv.IsValid() || !fv.CanSet() {
			continue
		}
		if val, ok := indexes[tm.indexCol]; ok {
			setStringLikeValue(fv, val)
		}
	}

	return nil
}

// decryptByTag decrypts a struct in-place using gormcrypt tags.
func decryptByTag(v interface{}) error {
	return decryptByTagLoaded(v, nil)
}

// EncryptTagged encrypts all gormcrypt-tagged string fields in place. This is the
// same operation as the Create/Update callbacks. Use it if you encrypt outside
// GORM or after temporarily calling DecryptTagged.
func EncryptTagged(v interface{}) error {
	return encryptByTag(v)
}

// DecryptTagged decrypts tagged fields in place (same as the Query/Row callbacks).
// After db.Create or db.Update, tagged columns are ciphertext in memory; call
// DecryptTagged if a hook (e.g. AfterCreate) needs plaintext for a welcome email,
// then avoid persisting that struct without EncryptTagged before the next Save.
func DecryptTagged(v interface{}) error {
	return decryptByTag(v)
}

func decryptByTagLoaded(v interface{}, isLoaded func(tagMeta) bool) error {
	meta, err := getModelMeta(v)
	if err != nil || len(meta.tags) == 0 {
		return err
	}

	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}

	t := rv.Type()
	er, err := getTagRow(t, meta)
	if err != nil {
		return err
	}

	// Collect ciphertexts from tagged fields.
	encData := make(row.EncryptedData, len(meta.tags))
	for _, tm := range meta.tags {
		if isLoaded != nil && !isLoaded(tm) {
			continue
		}
		fv := rv.FieldByName(tm.fieldName)
		ct, ok := stringLikeValue(fv)
		if !ok {
			continue
		}
		encData[tm.csField] = ct
	}

	decrypted, err := er.DecryptRow(encData)
	if err != nil {
		return fmt.Errorf("gormcrypt tag decrypt: %w", err)
	}

	// Write plaintexts back into the tagged fields.
	for _, tm := range meta.tags {
		fv := rv.FieldByName(tm.fieldName)
		if !fv.IsValid() || !fv.CanSet() {
			continue
		}
		if pt, ok := decrypted[tm.csField]; ok {
			setStringLikeValue(fv, pt)
		}
	}

	return nil
}

// ── Tag callbacks ─────────────────────────────────────────────────────────────

// RegisterTagCallbacks registers global GORM callbacks for tag-based encrypt/decrypt.
//
// Call once at startup after gormcrypt.Setup(eng):
//
//	gormcrypt.Setup(eng)
//	gormcrypt.RegisterTagCallbacks(db)
//
// Chain positions (add your own callbacks before/after the same anchors):
//
//	Create / Update — Before("gorm:create") and Before("gorm:update"): encrypt
//	Query / Row     — After("gorm:query") and After("gorm:row"): decrypt
//
// This does not replace your model methods: (u *User) BeforeCreate, AfterCreate,
// AfterFind, etc. still run as usual. Typical order around Create is: model
// BeforeCreate → gormcrypt encrypt → SQL INSERT → model AfterCreate.
//
// After Create/Update, tagged fields on the in-memory struct hold ciphertext
// (what was written to the DB). For side effects that need plaintext—e.g.
// sending email in AfterCreate—either copy the value before Create, or call
// DecryptTagged(u) inside AfterCreate (see EncryptTagged if you mutate and Save again).
//
// To change gormcrypt’s behavior you can remove or replace the named callbacks
// ("gormcrypt:tag:encrypt", "gormcrypt:tag:decrypt"); if you remove encryption,
// call EncryptTagged yourself before insert/update or ciphertext will not be stored.
func RegisterTagCallbacks(db *gorm.DB) error {
	cb := db.Callback()

	if err := cb.Create().Before("gorm:create").Register("gormcrypt:tag:encrypt", tagEncryptCallback); err != nil {
		return fmt.Errorf("gormcrypt: register tag create callback: %w", err)
	}
	if err := cb.Update().Before("gorm:update").Register("gormcrypt:tag:encrypt", tagUpdateEncryptCallback); err != nil {
		return fmt.Errorf("gormcrypt: register tag update callback: %w", err)
	}
	if err := cb.Query().After("gorm:query").Register("gormcrypt:tag:decrypt", tagDecryptCallback); err != nil {
		return fmt.Errorf("gormcrypt: register tag query callback: %w", err)
	}
	if err := cb.Row().After("gorm:row").Register("gormcrypt:tag:decrypt", tagDecryptCallback); err != nil {
		return fmt.Errorf("gormcrypt: register tag row callback: %w", err)
	}
	return nil
}

func tagEncryptCallback(db *gorm.DB) {
	if db.Error != nil || db.Statement == nil || db.Statement.Model == nil {
		return
	}
	if err := encryptByTag(db.Statement.Model); err != nil {
		_ = db.AddError(fmt.Errorf("gormcrypt tag encrypt: %w", err))
	}
}

func tagUpdateEncryptCallback(db *gorm.DB) {
	if db.Error != nil || db.Statement == nil || db.Statement.Model == nil {
		return
	}
	if err := encryptUpdateMapByTag(db); err != nil {
		_ = db.AddError(fmt.Errorf("gormcrypt tag encrypt: %w", err))
		return
	}
	if err := encryptUpdateStructByTag(db); err != nil {
		_ = db.AddError(fmt.Errorf("gormcrypt tag encrypt: %w", err))
		return
	}
	if db.Statement.Dest == db.Statement.Model {
		if err := encryptByTag(db.Statement.Model); err != nil {
			_ = db.AddError(fmt.Errorf("gormcrypt tag encrypt: %w", err))
		}
	}
}

func encryptUpdateMapByTag(db *gorm.DB) error {
	values, ok := db.Statement.Dest.(map[string]interface{})
	if !ok {
		return nil
	}

	meta, err := getModelMeta(db.Statement.Model)
	if err != nil || len(meta.tags) == 0 {
		return err
	}

	t := reflect.TypeOf(db.Statement.Model)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	er, err := getTagRow(t, meta)
	if err != nil {
		return err
	}

	for _, tm := range meta.tags {
		key, plaintext, ok := taggedUpdateValue(values, tm)
		if !ok {
			continue
		}
		if strings.HasPrefix(plaintext, "nacl:") || strings.HasPrefix(plaintext, "boring:") {
			continue
		}

		encrypted, indexes, err := er.PrepareForStorage(row.RowData{tm.csField: plaintext})
		if err != nil {
			return fmt.Errorf("gormcrypt tag encrypt: %w", err)
		}
		if ct, ok := encrypted[tm.csField]; ok {
			values[key] = ct
		}
		if idx, ok := indexes[tm.indexCol]; ok {
			values[tm.indexCol] = idx
		}
	}

	return nil
}

func encryptUpdateStructByTag(db *gorm.DB) error {
	if _, ok := db.Statement.Dest.(map[string]interface{}); ok {
		return nil
	}

	meta, err := getModelMeta(db.Statement.Model)
	if err != nil || len(meta.tags) == 0 {
		return err
	}

	rv := reflect.ValueOf(db.Statement.Dest)
	if !rv.IsValid() {
		return nil
	}
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil
	}

	t := reflect.TypeOf(db.Statement.Model)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	er, err := getTagRow(t, meta)
	if err != nil {
		return err
	}

	copyValue := reflect.New(rv.Type()).Elem()
	copyValue.Set(rv)
	changed := false

	for _, tm := range meta.tags {
		fv := copyValue.FieldByName(tm.fieldName)
		plaintext, ok := stringLikeValue(fv)
		if !ok || !fv.CanSet() {
			continue
		}
		if plaintext == "" || strings.HasPrefix(plaintext, "nacl:") || strings.HasPrefix(plaintext, "boring:") {
			continue
		}

		encrypted, indexes, err := er.PrepareForStorage(row.RowData{tm.csField: plaintext})
		if err != nil {
			return fmt.Errorf("gormcrypt tag encrypt: %w", err)
		}
		if ct, ok := encrypted[tm.csField]; ok {
			setStringLikeValue(fv, ct)
			changed = true
		}
		if idx, ok := indexes[tm.indexCol]; ok && tm.indexField != "" {
			idxField := copyValue.FieldByName(tm.indexField)
			if idxField.IsValid() && idxField.CanSet() {
				setStringLikeValue(idxField, idx)
			}
		}
	}

	if changed {
		db.Statement.Dest = copyValue.Addr().Interface()
	}
	return nil
}

func taggedUpdateValue(values map[string]interface{}, tm tagMeta) (string, string, bool) {
	for _, key := range []string{tm.fieldName, tm.csField} {
		if value, ok := values[key]; ok {
			switch v := value.(type) {
			case string:
				return key, v, true
			case *string:
				if v == nil {
					return key, "", false
				}
				return key, *v, true
			default:
				return key, "", false
			}
		}
	}
	return "", "", false
}

func tagDecryptCallback(db *gorm.DB) {
	if db.Error != nil || db.Statement == nil || db.Statement.Dest == nil {
		return
	}
	tagWalkDest(db, db.Statement.Dest)
}

func tagWalkDest(db *gorm.DB, dest interface{}) {
	isLoaded := selectedTagFieldFilter(db)
	rv := reflect.ValueOf(dest)
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Slice:
		for i := 0; i < rv.Len(); i++ {
			elem := rv.Index(i)
			if elem.Kind() == reflect.Ptr {
				if elem.IsNil() {
					continue
				}
				elem = elem.Elem()
			}
			if elem.Kind() != reflect.Struct {
				continue
			}
			if err := decryptByTagLoaded(elem.Addr().Interface(), isLoaded); err != nil {
				_ = db.AddError(fmt.Errorf("gormcrypt tag decrypt: %w", err))
			}
		}
	case reflect.Struct:
		if err := decryptByTagLoaded(dest, isLoaded); err != nil {
			_ = db.AddError(fmt.Errorf("gormcrypt tag decrypt: %w", err))
		}
	}
}

func selectedTagFieldFilter(db *gorm.DB) func(tagMeta) bool {
	if db == nil || db.Statement == nil || db.Statement.Schema == nil {
		return nil
	}

	columns, restricted := db.Statement.SelectAndOmitColumns(false, false)
	addCommaSeparatedSelectColumns(db, columns)
	if len(columns) == 0 && !restricted {
		return nil
	}

	return func(tm tagMeta) bool {
		dbName := tm.csField
		if field := db.Statement.Schema.LookUpField(tm.fieldName); field != nil && field.DBName != "" {
			dbName = field.DBName
		}

		if selected, ok := columns[dbName]; ok {
			return selected
		}
		return !restricted
	}
}

func addCommaSeparatedSelectColumns(db *gorm.DB, columns map[string]bool) {
	for _, column := range db.Statement.Selects {
		addCommaSeparatedColumn(db, columns, column, true)
	}
	for _, column := range db.Statement.Omits {
		addCommaSeparatedColumn(db, columns, column, false)
	}
}

func addCommaSeparatedColumn(db *gorm.DB, columns map[string]bool, column string, selected bool) {
	if !strings.Contains(column, ",") {
		return
	}

	for _, part := range strings.Split(column, ",") {
		name := strings.TrimSpace(part)
		name = strings.Trim(name, "`\"")
		if name == "" || strings.ContainsAny(name, " ()") {
			continue
		}
		if dot := strings.LastIndex(name, "."); dot >= 0 {
			name = strings.Trim(name[dot+1:], "`\"")
		}
		if field := db.Statement.Schema.LookUpField(name); field != nil && field.DBName != "" {
			columns[field.DBName] = selected
			continue
		}
		columns[name] = selected
	}
}

func isStringLikeType(t reflect.Type) bool {
	return t.Kind() == reflect.String || (t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.String)
}

func stringLikeValue(v reflect.Value) (string, bool) {
	if !v.IsValid() {
		return "", false
	}
	switch v.Kind() {
	case reflect.String:
		return v.String(), true
	case reflect.Ptr:
		if v.IsNil() || v.Type().Elem().Kind() != reflect.String {
			return "", false
		}
		return v.Elem().String(), true
	default:
		return "", false
	}
}

func setStringLikeValue(v reflect.Value, value string) bool {
	if !v.IsValid() || !v.CanSet() {
		return false
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(value)
		return true
	case reflect.Ptr:
		if v.Type().Elem().Kind() != reflect.String {
			return false
		}
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		v.Elem().SetString(value)
		return true
	default:
		return false
	}
}

// ── Search helpers ────────────────────────────────────────────────────────────

func tagModelStructType(model interface{}) (reflect.Type, error) {
	if model == nil {
		return nil, fmt.Errorf("gormcrypt: model must not be nil")
	}
	t := reflect.TypeOf(model)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("gormcrypt: expected struct model, got %s", t.Kind())
	}
	return t, nil
}

func blindIndexForTagField(model interface{}, fieldName, plaintext string) (idx, col string, err error) {
	t, err := tagModelStructType(model)
	if err != nil {
		return "", "", err
	}

	meta, err := getModelMeta(model)
	if err != nil {
		return "", "", err
	}

	tm, ok := meta.byField[strings.ToLower(fieldName)]
	if !ok {
		return "", "", fmt.Errorf("gormcrypt: no gormcrypt tag for field %q", fieldName)
	}

	er, err := getTagRow(t, meta)
	if err != nil {
		return "", "", err
	}

	idx, err = er.GetBlindIndex(tm.csField, plaintext, tm.indexCol)
	if err != nil {
		return "", "", fmt.Errorf("gormcrypt: blind index for field %q: %w", fieldName, err)
	}
	return idx, tm.indexCol, nil
}

// TagIndex computes the blind index value for a search query on a tagged field.
// Pass a zero-value pointer of your model to identify the type.
//
//	idx, err := gormcrypt.TagIndex(&User{}, "email", "alice@example.com")
//	db.Where("email_index = ?", idx).Find(&users)
func TagIndex(model interface{}, fieldName, plaintext string) (string, error) {
	idx, _, err := blindIndexForTagField(model, fieldName, plaintext)
	return idx, err
}

// WhereTag returns a GORM scope that filters by a blind index on a tagged field.
// Metadata is cached per model type; the blind index is computed when WhereTag
// is called, not on each scope invocation.
//
//	db.Scopes(gormcrypt.WhereTag(&User{}, "email", "alice@example.com")).Find(&users)
func WhereTag(model interface{}, fieldName, plaintext string) func(*gorm.DB) *gorm.DB {
	idx, col, err := blindIndexForTagField(model, fieldName, plaintext)
	if err != nil {
		resolveErr := err
		return func(db *gorm.DB) *gorm.DB {
			_ = db.AddError(resolveErr)
			return db
		}
	}
	return func(db *gorm.DB) *gorm.DB {
		return db.Where(col+" = ?", idx)
	}
}

// WhereTagMulti returns a scope that ANDs blind-index equality conditions for
// several tagged fields on the same model. Arguments are pairs: fieldName,
// plaintext, fieldName, plaintext, ...
//
//	db.Scopes(gormcrypt.WhereTagMulti(&User{},
//	    "email", "alice@example.com",
//	    "phone", "+6281234567890",
//	)).Find(&users)
func WhereTagMulti(model interface{}, fieldPlaintext ...string) func(*gorm.DB) *gorm.DB {
	if len(fieldPlaintext)%2 != 0 {
		err := fmt.Errorf("gormcrypt WhereTagMulti: want even argument count (field, plaintext, ...), got %d", len(fieldPlaintext))
		return func(db *gorm.DB) *gorm.DB {
			_ = db.AddError(err)
			return db
		}
	}
	type cond struct {
		col, idx string
	}
	var conds []cond
	for i := 0; i < len(fieldPlaintext); i += 2 {
		idx, col, err := blindIndexForTagField(model, fieldPlaintext[i], fieldPlaintext[i+1])
		if err != nil {
			resolveErr := err
			return func(db *gorm.DB) *gorm.DB {
				_ = db.AddError(resolveErr)
				return db
			}
		}
		conds = append(conds, cond{col: col, idx: idx})
	}
	return func(db *gorm.DB) *gorm.DB {
		for _, c := range conds {
			db = db.Where(c.col+" = ?", c.idx)
		}
		return db
	}
}

// ── Table name override ───────────────────────────────────────────────────────

// SetTableName overrides the derived table name for a model type.
// Call this in init() if your table name does not follow the snake_case plural convention.
//
//	func init() {
//	    gormcrypt.SetTableName(&User{}, "my_users")
//	}
func SetTableName(model interface{}, tableName string) {
	t := reflect.TypeOf(model)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	metaCacheMu.Lock()
	defer metaCacheMu.Unlock()

	if m, ok := metaCache[t]; ok {
		m.tableName = tableName
		// Invalidate the row cache so it is rebuilt with the new table name.
		tagRowCacheMu.Lock()
		delete(tagRowCache, t)
		tagRowCacheMu.Unlock()
	} else {
		// Parse the meta now so the table name is set before first use.
		metaCacheMu.Unlock()
		m, _ := getModelMeta(model)
		metaCacheMu.Lock()
		if m != nil {
			m.tableName = tableName
			tagRowCacheMu.Lock()
			delete(tagRowCache, t)
			tagRowCacheMu.Unlock()
		}
	}
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// parseTagKV parses "key=value,key2=value2" (comma-separated) into a map.
func parseTagKV(tag string) map[string]string {
	result := make(map[string]string)
	for _, part := range strings.Split(tag, ",") {
		part = strings.TrimSpace(part)
		if kv := strings.SplitN(part, "=", 2); len(kv) == 2 {
			result[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return result
}

// toSnakePlural converts "UserProfile" → "user_profiles".
func toSnakePlural(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r | 32) // to lower
	}
	result := b.String()
	// Simple pluralisation: append 's' (works for most table names).
	if !strings.HasSuffix(result, "s") {
		result += "s"
	}
	return result
}
