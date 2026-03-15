package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsStaticAsset(t *testing.T) {
	trueTests := []string{
		"style.css", "app.js", "font.woff2", "font.woff",
		"logo.png", "favicon.ico", "icon.svg", "photo.jpg",
		"hero.webp", "banner.avif",
	}
	for _, tc := range trueTests {
		if !isStaticAsset(tc) {
			t.Errorf("isStaticAsset(%q) = false, want true", tc)
		}
	}

	falseTests := []string{
		"index.html", "data.json", "page.go", "README.md",
		"", "css", ".css/",
	}
	for _, tc := range falseTests {
		if isStaticAsset(tc) {
			t.Errorf("isStaticAsset(%q) = true, want false", tc)
		}
	}
}

func TestFindTemplatesDir(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, "templates"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	got := findTemplatesDir()
	if got != "templates" {
		t.Errorf("findTemplatesDir() = %q, want %q", got, "templates")
	}
}

func TestFindTemplatesDirFallback(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	got := findTemplatesDir()
	if got != "templates" {
		t.Errorf("findTemplatesDir() fallback = %q, want %q", got, "templates")
	}
}

func TestFindStaticDir(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, "static"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	got := findStaticDir()
	if got != "static" {
		t.Errorf("findStaticDir() = %q, want %q", got, "static")
	}
}

func TestFindStaticDirFallback(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	got := findStaticDir()
	if got != "static" {
		t.Errorf("findStaticDir() fallback = %q, want %q", got, "static")
	}
}
