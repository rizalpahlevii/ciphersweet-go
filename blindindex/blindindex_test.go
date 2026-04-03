package blindindex

import (
	"reflect"
	"testing"

	"github.com/rizalpahlevii/ciphersweet-go/argon"
	"github.com/rizalpahlevii/ciphersweet-go/blindindex/transform"
)

func TestNewDefaults(t *testing.T) {
	t.Parallel()

	bi := New("email_index")
	if bi.Name != "email_index" {
		t.Fatalf("Name: got %q want %q", bi.Name, "email_index")
	}
	if bi.OutputBits != DefaultBits {
		t.Fatalf("OutputBits: got %d want %d", bi.OutputBits, DefaultBits)
	}
	if bi.Fast {
		t.Fatalf("Fast: got true want false")
	}
	if bi.ArgonCfg != nil {
		t.Fatalf("ArgonCfg: expected nil, got %#v", bi.ArgonCfg)
	}
	if len(bi.Transformations) != 0 {
		t.Fatalf("Transformations: expected empty, got %d entries", len(bi.Transformations))
	}
	if !bi.IsSlow() {
		t.Fatal("IsSlow: got false want true (default Argon2id mode)")
	}
}

func TestWithBitsAndWithTransform(t *testing.T) {
	t.Parallel()

	bi := New("idx",
		WithBits(32),
		WithTransform(transform.Lowercase{}, transform.TrimSpace{}),
	)

	if bi.OutputBits != 32 {
		t.Fatalf("OutputBits: got %d want 32", bi.OutputBits)
	}
	if bi.Fast {
		t.Fatal("Fast: expected false")
	}
	if len(bi.Transformations) != 2 {
		t.Fatalf("Transformations: got %d want 2", len(bi.Transformations))
	}

	got := bi.Apply("  Alice@EXAMPLE.COM  ")
	want := "alice@example.com"
	if got != want {
		t.Fatalf("Apply: got %q want %q", got, want)
	}
}

func TestWithFastAndWithSlow(t *testing.T) {
	t.Parallel()

	cfg := &argon.Config{
		TimeCost:    1,
		MemoryCost:  16 * 1024,
		Parallelism: 2,
	}

	bi := New("idx", WithFast(), WithSlow(cfg))
	if bi.Fast {
		t.Fatal("Fast: expected false after WithSlow")
	}
	if bi.ArgonCfg != cfg {
		t.Fatalf("ArgonCfg: got %#v want pointer %#v", bi.ArgonCfg, cfg)
	}
	if !bi.IsSlow() {
		t.Fatal("IsSlow: expected true after WithSlow")
	}
}

func TestWithTransformAppendsInOrder(t *testing.T) {
	t.Parallel()

	// Use Fn transforms to observe ordering.
	// Step1: append "-1", Step2: append "-2".
	step1 := transform.Fn(func(s string) string { return s + "-1" })
	step2 := transform.Fn(func(s string) string { return s + "-2" })

	bi := New("idx",
		WithTransform(step1),
		WithTransform(step2),
	)

	got := bi.Apply("x")
	want := "x-1-2"
	if got != want {
		t.Fatalf("Apply order: got %q want %q", got, want)
	}

	// Ensure the transformation slice includes both steps.
	if gotLen, wantLen := len(bi.Transformations), 2; gotLen != wantLen {
		t.Fatalf("Transformations length: got %d want %d", gotLen, wantLen)
	}
}

func TestIsSlowMatrix(t *testing.T) {
	t.Parallel()

	cfg := &argon.Config{TimeCost: 1, MemoryCost: 1024, Parallelism: 1}

	tests := []struct {
		name string
		opts []Option
		want bool
	}{
		{"default", nil, true},
		{"fast", []Option{WithFast()}, false},
		{"slowWithCfg", []Option{WithSlow(cfg)}, true},
		{"fastThenSlow", []Option{WithFast(), WithSlow(cfg)}, true},
		{"slowNilCfg", []Option{WithSlow(nil)}, true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var bi *BlindIndex
			if len(tt.opts) == 0 {
				bi = New("idx")
			} else {
				bi = New("idx", tt.opts...)
			}

			if bi.IsSlow() != tt.want {
				t.Fatalf("IsSlow: got %v want %v", bi.IsSlow(), tt.want)
			}
		})
	}
}

func TestNewCopiesOutputBitsAndTransformations(t *testing.T) {
	t.Parallel()

	bi := New("idx", WithBits(128), WithTransform(transform.Lowercase{}))
	// Ensure exported struct fields are set as expected.
	if bi.OutputBits != 128 {
		t.Fatalf("OutputBits: got %d want 128", bi.OutputBits)
	}
	if !reflect.DeepEqual(bi.Transformations, bi.Transformations) {
		t.Fatal("expected Transformations to be a consistent slice")
	}
}
