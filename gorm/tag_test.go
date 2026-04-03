package gormcrypt

import (
	"reflect"
	"strings"
	"testing"

	cstesting "github.com/rizalpahlevii/ciphersweet-go/cstesting"
	"github.com/rizalpahlevii/ciphersweet-go/row"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func resetGormcryptTestState(t *testing.T) {
	t.Helper()
	metaCacheMu.Lock()
	metaCache = make(map[reflect.Type]*modelMeta)
	metaCacheMu.Unlock()
	tagRowCacheMu.Lock()
	tagRowCache = make(map[reflect.Type]*row.EncryptedRow)
	tagRowCacheMu.Unlock()
	engMu.Lock()
	globalEng = nil
	engMu.Unlock()
}

func TestParseTagKV(t *testing.T) {
	t.Parallel()
	m := parseTagKV(`blind_index=email_index,fast=true,bits=256`)
	if m["blind_index"] != "email_index" || m["fast"] != "true" || m["bits"] != "256" {
		t.Fatalf("got %#v", m)
	}
}

func TestToSnakePlural(t *testing.T) {
	t.Parallel()
	if got := toSnakePlural("User"); got != "users" {
		t.Fatalf("User: got %q", got)
	}
	if got := toSnakePlural("UserProfile"); got != "user_profiles" {
		t.Fatalf("UserProfile: got %q", got)
	}
}

func TestGetModelMetaCachesFields(t *testing.T) {
	resetGormcryptTestState(t)
	meta, err := getModelMeta(&User{})
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.tags) != 3 || len(meta.byField) != 3 {
		t.Fatalf("tags=%d byField=%d", len(meta.tags), len(meta.byField))
	}
	if _, ok := meta.byField["email"]; !ok {
		t.Fatal("missing email")
	}
	nisn := meta.byField["nisn"]
	if !nisn.fast || nisn.bits != 256 || nisn.indexCol != "nisn_index" {
		t.Fatalf("nisn meta: %+v", nisn)
	}
	meta2, err := getModelMeta(&User{})
	if err != nil || meta2 != meta {
		t.Fatal("expected identical cached meta")
	}
}

func TestTagIndexMatchesPrepareForStorage(t *testing.T) {
	resetGormcryptTestState(t)
	Setup(cstesting.NewEngine(t))

	plain := "alice@example.com"
	idx, err := TagIndex(&User{}, "Email", plain)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := getModelMeta(&User{})
	if err != nil {
		t.Fatal(err)
	}
	er, err := getTagRow(reflect.TypeOf(User{}), meta)
	if err != nil {
		t.Fatal(err)
	}
	_, indexes, err := er.PrepareForStorage(row.RowData{"email": plain})
	if err != nil {
		t.Fatal(err)
	}
	if indexes["email_index"] != idx {
		t.Fatalf("TagIndex %q != PrepareForStorage %q", idx, indexes["email_index"])
	}
}

func TestBlindIndexForTagFieldErrors(t *testing.T) {
	resetGormcryptTestState(t)
	Setup(cstesting.NewEngine(t))
	_, _, err := blindIndexForTagField(&User{}, "nosuch", "x")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTagIndexEngineNotConfigured(t *testing.T) {
	resetGormcryptTestState(t)
	_, err := TagIndex(&User{}, "email", "x")
	if err == nil || !strings.Contains(err.Error(), "Setup") {
		t.Fatalf("err = %v", err)
	}
}

func TestWhereTagMultiOddArgs(t *testing.T) {
	resetGormcryptTestState(t)
	Setup(cstesting.NewEngine(t))

	db := testDB(t)
	db = WhereTagMulti(&User{}, "email", "a@b", "odd")(db)
	if db.Error == nil || !strings.Contains(db.Error.Error(), "even") {
		t.Fatalf("expected even-count error, got %v", db.Error)
	}
}

func TestWhereTagAppliesCondition(t *testing.T) {
	resetGormcryptTestState(t)
	Setup(cstesting.NewEngine(t))

	db := testDB(t).Session(&gorm.Session{DryRun: true})
	db = db.Scopes(WhereTag(&User{}, "email", "bob@example.com")).Find(&[]User{})
	stmt := db.Statement
	if stmt.SQL.String() == "" {
		t.Fatal("expected SQL")
	}
	if !strings.Contains(stmt.SQL.String(), "email_index") {
		t.Fatalf("SQL %q should mention email_index", stmt.SQL.String())
	}
}

func TestWhereTagMultiAppliesConditions(t *testing.T) {
	resetGormcryptTestState(t)
	Setup(cstesting.NewEngine(t))

	db := testDB(t).Session(&gorm.Session{DryRun: true})
	db = db.Scopes(WhereTagMulti(&User{},
		"email", "a@b.c",
		"phone", "+1555",
	)).Find(&[]User{})
	sql := db.Statement.SQL.String()
	if !strings.Contains(sql, "email_index") || !strings.Contains(sql, "phone_index") {
		t.Fatalf("SQL %q", sql)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	resetGormcryptTestState(t)
	Setup(cstesting.NewEngine(t))

	u := &User{
		Email: "plain@example.com",
		Phone: "+100",
		Nisn:  "12345",
	}
	if err := EncryptTagged(u); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u.Email, "nacl:") && !strings.HasPrefix(u.Email, "boring:") {
		t.Fatalf("expected ciphertext prefix, got %q", u.Email)
	}
	if u.EmailIndex == "" || u.NisnIndex == "" {
		t.Fatal("indexes should be set")
	}
	if err := DecryptTagged(u); err != nil {
		t.Fatal(err)
	}
	if u.Email != "plain@example.com" || u.Phone != "+100" || u.Nisn != "12345" {
		t.Fatalf("got %+v", u)
	}
}

func TestDecryptByTagSlice(t *testing.T) {
	resetGormcryptTestState(t)
	Setup(cstesting.NewEngine(t))

	users := []User{
		{Email: "slice1@example.com"},
		{Email: "slice2@example.com"},
	}

	for i := range users {
		if err := EncryptTagged(&users[i]); err != nil {
			t.Fatal(err)
		}
	}

	// Verify they are encrypted
	if !strings.HasPrefix(users[0].Email, "nacl:") && !strings.HasPrefix(users[0].Email, "boring:") {
		t.Fatalf("Failed to encrypt slice element")
	}

	// Decrypt slice in place
	tagWalkDest(testDB(t), &users)

	if users[0].Email != "slice1@example.com" || users[1].Email != "slice2@example.com" {
		t.Fatalf("Failed to decrypt slice elements: %+v", users)
	}
}

func TestRegisterTagCallbacksRegisters(t *testing.T) {
	resetGormcryptTestState(t)
	Setup(cstesting.NewEngine(t))

	db := testDB(t)
	if err := RegisterTagCallbacks(db); err != nil {
		t.Fatal(err)
	}
}

func TestSetTableNameInvalidatesRowCache(t *testing.T) {
	resetGormcryptTestState(t)
	Setup(cstesting.NewEngine(t))

	typ := reflect.TypeOf(User{})
	if _, err := getTagRow(typ, mustMeta(t, &User{})); err != nil {
		t.Fatal(err)
	}
	tagRowCacheMu.RLock()
	if _, ok := tagRowCache[typ]; !ok {
		tagRowCacheMu.RUnlock()
		t.Fatal("expected tag row cache entry")
	}
	tagRowCacheMu.RUnlock()

	SetTableName(&User{}, "members")

	metaCacheMu.RLock()
	tn := metaCache[typ].tableName
	metaCacheMu.RUnlock()
	if tn != "members" {
		t.Fatalf("table name = %q", tn)
	}
	tagRowCacheMu.RLock()
	_, still := tagRowCache[typ]
	tagRowCacheMu.RUnlock()
	if still {
		t.Fatal("row cache should be cleared after SetTableName")
	}
}

func mustMeta(t *testing.T, m interface{}) *modelMeta {
	t.Helper()
	meta, err := getModelMeta(m)
	if err != nil {
		t.Fatal(err)
	}
	return meta
}

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	d, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Skipf("sqlite: %v (try CGO_ENABLED=1)", err)
	}
	return d
}
func TestGormCallbacksDB(t *testing.T) {
	resetGormcryptTestState(t)
	Setup(cstesting.NewEngine(t))

	db := testDB(t)
	err := db.AutoMigrate(&User{})
	if err != nil {
		t.Skipf("AutoMigrate failed: %v", err)
	}

	if err := RegisterTagCallbacks(db); err != nil {
		t.Fatal(err)
	}

	u := User{
		Email: "integrate@example.com",
		Phone: "+6281",
		Nisn:  "9000",
	}

	// Triggers BeforeCreate (encrypting fields)
	if err := db.Create(&u).Error; err != nil {
		t.Fatal(err)
	}

	// Verify encryption applied directly after Create
	if !strings.HasPrefix(u.Email, "nacl:") && !strings.HasPrefix(u.Email, "boring:") {
		t.Fatalf("Expected ciphertext after create, got %s", u.Email)
	}

	// Triggers AfterFind/AfterRow decrypt callbacks
	var retrieved User
	if err := db.First(&retrieved, u.ID).Error; err != nil {
		t.Fatal(err)
	}

	if retrieved.Email != "integrate@example.com" {
		t.Fatalf("Expected decrypted email integrate@example.com, got %s", retrieved.Email)
	}
}
