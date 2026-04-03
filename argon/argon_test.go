package argon

import "testing"

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.TimeCost != 2 {
		t.Fatalf("TimeCost: got %d want %d", cfg.TimeCost, 2)
	}
	if cfg.MemoryCost != 512*1024 {
		t.Fatalf("MemoryCost: got %d want %d", cfg.MemoryCost, 512*1024)
	}
	if cfg.Parallelism != 2 {
		t.Fatalf("Parallelism: got %d want %d", cfg.Parallelism, 2)
	}
}

func TestResolvedNilUsesDefault(t *testing.T) {
	cfg := Resolved(nil)
	def := DefaultConfig()
	if cfg.TimeCost != def.TimeCost ||
		cfg.MemoryCost != def.MemoryCost ||
		cfg.Parallelism != def.Parallelism {
		t.Fatalf("Resolved(nil): got %+v want %+v", cfg, def)
	}
}

func TestResolvedNonNilReturnsSamePointer(t *testing.T) {
	in := &Config{
		TimeCost:    1,
		MemoryCost:  1024,
		Parallelism: 4,
	}
	out := Resolved(in)
	if out != in {
		t.Fatalf("Resolved(in) returned a different pointer")
	}
}
