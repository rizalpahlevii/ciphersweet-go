package transform

import "testing"

func TestLowercaseUppercase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		out  string
		fn   func(string) string
	}{
		{
			name: "lowercase ascii",
			in:   "Alice@EXAMPLE.com",
			out:  "alice@example.com",
			fn:   (Lowercase{}).Transform,
		},
		{
			name: "uppercase ascii",
			in:   "Alice@example.com",
			out:  "ALICE@EXAMPLE.COM",
			fn:   (Uppercase{}).Transform,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.fn(tt.in); got != tt.out {
				t.Fatalf("got %q want %q", got, tt.out)
			}
		})
	}
}

func TestDigitsOnlyAlphaNumericOnly(t *testing.T) {
	t.Parallel()

	if got, want := (DigitsOnly{}).Transform("123-45-6789"), "123456789"; got != want {
		t.Fatalf("DigitsOnly: got %q want %q", got, want)
	}

	// Ensure behavior on typical mixed input.
	if got, want := (AlphaOnly{}).Transform("a1b2Ç3"), "abÇ"; got != want {
		t.Fatalf("AlphaOnly unicode: got %q want %q", got, want)
	}
	if got, want := (AlphaOnly{}).Transform("a1b2c"), "abc"; got != want {
		t.Fatalf("AlphaOnly: got %q want %q", got, want)
	}
	if got, want := (AlphaNumericOnly{}).Transform("a1-b_2c"), "a1b2c"; got != want {
		t.Fatalf("AlphaNumericOnly: got %q want %q", got, want)
	}
}

func TestFirstLastN(t *testing.T) {
	t.Parallel()

	if got, want := (FirstCharacter{}).Transform("hello"), "h"; got != want {
		t.Fatalf("FirstCharacter: got %q want %q", got, want)
	}
	if got, want := (FirstCharacter{}).Transform(""), ""; got != want {
		t.Fatalf("FirstCharacter empty: got %q want %q", got, want)
	}

	if got, want := (FirstN{N: 3}).Transform("abcdef"), "abc"; got != want {
		t.Fatalf("FirstN: got %q want %q", got, want)
	}
	// N > length => full value.
	if got, want := (FirstN{N: 10}).Transform("abc"), "abc"; got != want {
		t.Fatalf("FirstN long: got %q want %q", got, want)
	}

	if got, want := (LastN{N: 2}).Transform("abcdef"), "ef"; got != want {
		t.Fatalf("LastN: got %q want %q", got, want)
	}
	if got, want := (LastFourDigits{}).Transform("123-45-6789"), "6789"; got != want {
		t.Fatalf("LastFourDigits: got %q want %q", got, want)
	}
	// fewer than 4 digits: preserve what remains after digit filtering.
	if got, want := (LastFourDigits{}).Transform("12-3"), "123"; got != want {
		t.Fatalf("LastFourDigits short: got %q want %q", got, want)
	}
}

func TestTrimAndCollapseSpace(t *testing.T) {
	t.Parallel()

	if got, want := (TrimSpace{}).Transform("  a b  "), "a b"; got != want {
		t.Fatalf("TrimSpace: got %q want %q", got, want)
	}
	if got, want := (CollapseSpace{}).Transform("a  b   c"), "a b c"; got != want {
		t.Fatalf("CollapseSpace: got %q want %q", got, want)
	}
	if got, want := (CollapseSpace{}).Transform("  a   b  "), "a b"; got != want {
		t.Fatalf("CollapseSpace trimmed: got %q want %q", got, want)
	}
}

func TestComposeAndFn(t *testing.T) {
	t.Parallel()

	// Lowercase then take first character.
	c := Compose{Transformations: []RowTransformation{
		Lowercase{},
		FirstCharacter{},
	}}
	if got, want := c.Transform("AlIcE"), "a"; got != want {
		t.Fatalf("Compose: got %q want %q", got, want)
	}

	// Compose should run transforms left-to-right.
	one := Fn(func(s string) string { return s + "1" })
	two := Fn(func(s string) string { return s + "2" })
	c2 := Compose{Transformations: []RowTransformation{one, two}}
	if got, want := c2.Transform("x"), "x12"; got != want {
		t.Fatalf("Compose order: got %q want %q", got, want)
	}
}
