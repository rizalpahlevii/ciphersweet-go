package gormcrypt

import (
	"fmt"
	"sync"

	"github.com/rizalpahlevii/ciphersweet-go/engine"
)

var (
	globalEng *engine.Engine
	engMu     sync.RWMutex
)

// Setup sets the global CipherSweet engine used by tag-based encryption.
// Call once at application startup.
//
//	gormcrypt.Setup(eng)
func Setup(e *engine.Engine) {
	engMu.Lock()
	defer engMu.Unlock()
	globalEng = e
}

func getEng() (*engine.Engine, error) {
	engMu.RLock()
	defer engMu.RUnlock()
	if globalEng == nil {
		return nil, fmt.Errorf("gormcrypt: engine not initialised — call gormcrypt.Setup(eng) first")
	}
	return globalEng, nil
}
