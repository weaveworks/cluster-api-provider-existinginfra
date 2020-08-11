package path

import (
	"os"
	"path/filepath"
	"strings"
)

// Expand expands the provided path, evaluating all symlinks (including "~").
func Expand(path string) (string, error) {
	path = ExpandHome(path)
	return filepath.EvalSymlinks(path)
}

func ExpandHome(s string) string {
	home, _ := os.UserHomeDir()
	if strings.HasPrefix(s, "~/") {
		return filepath.Join(home, s[2:])
	}
	return s
}
