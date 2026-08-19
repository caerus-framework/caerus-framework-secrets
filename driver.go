package cf_secrets

import (
	"context"
	"encoding/json"
	"fmt"
)

// driver is one live backend. The chassis holds drivers by provider name.
type driver interface {
	kind() string
	get(ctx context.Context, ref Ref) ([]byte, error)
	ping(ctx context.Context) error
	close() error
}

func extractJSONKey(payload []byte, key string) ([]byte, error) {
	if key == "" {
		return payload, nil
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, fmt.Errorf("payload is not a JSON object; cannot select key %q: %w", key, err)
	}
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found in secret payload", key)
	}
	switch t := v.(type) {
	case string:
		return []byte(t), nil
	case nil:
		return nil, fmt.Errorf("key %q is null", key)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", key, err)
		}
		return b, nil
	}
}
