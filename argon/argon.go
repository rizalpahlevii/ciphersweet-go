package argon

// Config holds Argon2id parameters for slow blind indexes.
// Leave all fields zero to get DefaultConfig().
type Config struct {
	TimeCost    uint32
	MemoryCost  uint32 // in KiB
	Parallelism uint8
}

// DefaultConfig returns sane defaults matching the PHP paragonie/ciphersweet library.
func DefaultConfig() *Config {
	return &Config{
		TimeCost:    2,
		MemoryCost:  512 * 1024, // 512 MiB
		Parallelism: 2,
	}
}

// Resolved returns cfg if non-nil, otherwise DefaultConfig().
func Resolved(cfg *Config) *Config {
	if cfg != nil {
		return cfg
	}
	return DefaultConfig()
}
