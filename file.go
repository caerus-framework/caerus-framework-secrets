package cf_secrets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type fileDriver struct {
	root string
}

func newFileDriver(p ProviderConfig) (*fileDriver, error) {
	root, err := filepath.Abs(p.Root)
	if err != nil {
		return nil, err
	}
	return &fileDriver{root: root}, nil
}

func (d *fileDriver) kind() string { return kindFile }

func (d *fileDriver) close() error { return nil }

func (d *fileDriver) ping(ctx context.Context) error {
	_ = ctx
	st, err := os.Stat(d.root)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("file root %s is not a directory", d.root)
	}
	return nil
}

func (d *fileDriver) get(ctx context.Context, ref Ref) ([]byte, error) {
	_ = ctx
	rel := filepath.Clean("/" + strings.ReplaceAll(ref.Path, "\\", "/"))
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("invalid file secret path %q", ref.Path)
	}
	full := filepath.Join(d.root, rel)
	if !strings.HasPrefix(full, d.root+string(os.PathSeparator)) && full != d.root {
		return nil, fmt.Errorf("invalid file secret path %q", ref.Path)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}
	return extractJSONKey(b, ref.Key)
}
