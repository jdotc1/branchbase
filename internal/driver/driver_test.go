package driver

import (
	"errors"
	"testing"
)

func TestDriverRegistration(t *testing.T) {
	// Backup registry and restore on test exit
	registryMu.Lock()
	oldRegistry := make(map[string]DriverFactory, len(registry))
	for k, v := range registry {
		oldRegistry[k] = v
	}
	registry = make(map[string]DriverFactory)
	registryMu.Unlock()

	defer func() {
		registryMu.Lock()
		registry = oldRegistry
		registryMu.Unlock()
	}()

	Register("dummy", func(params map[string]interface{}) (Driver, error) {
		if val, ok := params["fail"]; ok && val == true {
			return nil, errors.New("factory failure")
		}
		return nil, nil // returning nil for Driver is enough to test registry
	})

	t.Run("successful get", func(t *testing.T) {
		_, err := GetDriver("dummy", map[string]interface{}{})
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("unregistered driver", func(t *testing.T) {
		_, err := GetDriver("nonexistent", map[string]interface{}{})
		if err == nil {
			t.Error("expected error for unregistered driver, got nil")
		}
	})

	t.Run("factory error", func(t *testing.T) {
		_, err := GetDriver("dummy", map[string]interface{}{"fail": true})
		if err == nil {
			t.Error("expected factory error, got nil")
		}
	})
}
