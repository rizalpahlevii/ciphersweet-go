package transform

import (
	"strings"
	"unicode"
)

// RowTransformation processes a plaintext string before blind-index hashing.
type RowTransformation interface {
	Transform(value string) string
}

// ── String case ───────────────────────────────────────────────────────────────

// Lowercase converts value to Unicode lower-case.
// Use for case-insensitive exact-match indexes (e.g. email addresses).
type Lowercase struct{}

func (Lowercase) Transform(value string) string { return strings.ToLower(value) }

// Uppercase converts value to Unicode upper-case.
type Uppercase struct{}

func (Uppercase) Transform(value string) string { return strings.ToUpper(value) }

// ── Character filtering ───────────────────────────────────────────────────────

// DigitsOnly strips every character that is not a Unicode decimal digit [0-9].
// Useful for phone numbers or IDs stored with hyphens/spaces/parentheses.
type DigitsOnly struct{}

func (DigitsOnly) Transform(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// AlphaOnly strips every character that is not a Unicode letter.
type AlphaOnly struct{}

func (AlphaOnly) Transform(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if unicode.IsLetter(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// AlphaNumericOnly strips every character that is not a letter or digit.
type AlphaNumericOnly struct{}

func (AlphaNumericOnly) Transform(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ── Prefix / suffix extractors ────────────────────────────────────────────────

// FirstCharacter keeps only the first Unicode character of value.
// Returns an empty string if value is empty.
type FirstCharacter struct{}

func (FirstCharacter) Transform(value string) string {
	for _, r := range value {
		return string(r)
	}
	return ""
}

// FirstN keeps only the first n Unicode characters.
// If value is shorter than n, the full value is returned.
type FirstN struct{ N int }

func (f FirstN) Transform(value string) string {
	runes := []rune(value)
	if len(runes) <= f.N {
		return value
	}
	return string(runes[:f.N])
}

// LastN keeps only the last n Unicode characters.
// If value is shorter than n, the full value is returned.
type LastN struct{ N int }

func (l LastN) Transform(value string) string {
	runes := []rune(value)
	if len(runes) <= l.N {
		return value
	}
	return string(runes[len(runes)-l.N:])
}

// LastFourDigits strips non-digits then keeps the last four.
//
// Classic use-case: indexing the last four digits of a Social Security Number
// or credit card number stored with formatting.
//
//	transform.LastFourDigits{}.Transform("123-45-6789") → "6789"
//	transform.LastFourDigits{}.Transform("6789")        → "6789"
//	transform.LastFourDigits{}.Transform("89")          → "89"
type LastFourDigits struct{}

func (LastFourDigits) Transform(value string) string {
	digits := DigitsOnly{}.Transform(value)
	return LastN{N: 4}.Transform(digits)
}

// ── Whitespace ────────────────────────────────────────────────────────────────

// TrimSpace strips leading and trailing Unicode whitespace.
type TrimSpace struct{}

func (TrimSpace) Transform(value string) string { return strings.TrimSpace(value) }

// CollapseSpace trims and collapses all internal whitespace runs to a single space.
type CollapseSpace struct{}

func (CollapseSpace) Transform(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

// ── Composition ───────────────────────────────────────────────────────────────

// Compose chains multiple RowTransformations left-to-right.
// The output of each step is the input to the next.
//
//	Compose{Transformations: []RowTransformation{
//	    Lowercase{},
//	    FirstCharacter{},
//	}}
type Compose struct {
	Transformations []RowTransformation
}

func (c Compose) Transform(value string) string {
	for _, t := range c.Transformations {
		value = t.Transform(value)
	}
	return value
}

// Fn wraps an arbitrary function as a RowTransformation.
// Useful for one-off transforms in tests without defining a new type.
//
//	transform.Fn(func(s string) string { return s[strings.Index(s, "@")+1:] })
type Fn func(string) string

func (f Fn) Transform(value string) string { return f(value) }
