package generator

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func walkFunc(path string, info os.FileInfo, err error) error {
	if err != nil {
		return fmt.Errorf("%v unable to access path: %q", err, path)
	}
	f, err := elf.Open(path)
	if f != nil {
		defer f.Close()
	}
	if err != nil {
		return nil
	}
	if info.IsDir() {
		return filepath.Walk(path, walkFunc)
	}
	g := NewElfByPath(path)
	if g == nil {
		return fmt.Errorf("%v failed to NewElfByPath: %q", err, path)
	}
	err = g.InitFuncTable()
	if err != nil && fmt.Sprintf("%v", err) != "no symbol section" {
		return fmt.Errorf("%v failed to init func table: %q", err, path)
	}
	_, err = g.Analyze()
	if err != nil {
		return fmt.Errorf("%v failed to analyze: %q", err, path)
	}
	return nil
}

func TestGenerator_Analyze(t *testing.T) {
	err := filepath.Walk("/tmp/samples", walkFunc)
	if err != nil {
		t.Fatal(err)
	}
}
