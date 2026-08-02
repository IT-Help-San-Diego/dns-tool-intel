// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
//
// The cloud→local lever is re-keyed for the AWS migration: CLOUD_DEPLOYMENT
// (platform-neutral) OR REPLIT_DEPLOYMENT (legacy, kept for rollback) both
// mean "deployed cloud instance". These tests pin that both keys drive the
// lever AND the boot guards — an AWS deploy that only set the new key while
// the guards still watched the old one would boot with zero deployment
// validation, which is exactly the silent-wrong class the guards exist for.
package config

import (
	"strings"
	"testing"
)

func TestIsCloudDeploymentEnv_BothKeysRecognized(t *testing.T) {
	cases := []struct {
		name    string
		replit  string
		cloud   string
		want    bool
	}{
		{"neither set", "", "", false},
		{"replit key only", "1", "", true},
		{"cloud key only", "", "1", true},
		{"both set", "1", "1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REPLIT_DEPLOYMENT", tc.replit)
			t.Setenv("CLOUD_DEPLOYMENT", tc.cloud)
			if got := IsCloudDeploymentEnv(); got != tc.want {
				t.Errorf("IsCloudDeploymentEnv() = %v, want %v (REPLIT_DEPLOYMENT=%q CLOUD_DEPLOYMENT=%q)",
					got, tc.want, tc.replit, tc.cloud)
			}
		})
	}
}

func TestLoad_CloudDeploymentKey_SetsLever(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test")
	t.Setenv("SESSION_SECRET", "test-secret")
	t.Setenv("BASE_URL", "")
	t.Setenv("CLOUD_DEPLOYMENT", "1")
	t.Setenv("REPLIT_DEPLOYMENT", "")
	t.Setenv("REPLIT_DEV_DOMAIN", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IsCloudDeployment {
		t.Error("CLOUD_DEPLOYMENT=1 must set IsCloudDeployment — otherwise an AWS deploy runs as a local build (no privacy banner, local badge, /history flipper, Wayback archival off)")
	}
	if cfg.IsDevEnvironment {
		t.Error("cloud deployment must not read as dev environment")
	}
}

// The boot guards must fire under the NEW key, not just the legacy one:
// assertDeploymentEnvironment refusing REPLIT_DEV_BANNER=1 proves the guard
// body runs when CLOUD_DEPLOYMENT alone marks the deployment.
func TestLoad_CloudDeploymentKey_DevBannerGuardFires(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test")
	t.Setenv("SESSION_SECRET", "test-secret")
	t.Setenv("BASE_URL", "")
	t.Setenv("CLOUD_DEPLOYMENT", "1")
	t.Setenv("REPLIT_DEPLOYMENT", "")
	t.Setenv("REPLIT_DEV_BANNER", "1")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for REPLIT_DEV_BANNER=1 under CLOUD_DEPLOYMENT — the guard must be keyed to the shared lever")
	}
	if !strings.Contains(err.Error(), "REPLIT_DEV_BANNER") {
		t.Errorf("error should name the offending variable, got: %v", err)
	}
}

func TestLoad_CloudDeploymentKey_EphemeralBaseURLRefused(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test")
	t.Setenv("SESSION_SECRET", "test-secret")
	t.Setenv("BASE_URL", "https://f2c73519-00-2qa7mtebx8ii8.picard.replit.dev")
	t.Setenv("CLOUD_DEPLOYMENT", "1")
	t.Setenv("REPLIT_DEPLOYMENT", "")
	t.Setenv("REPLIT_DEV_BANNER", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for ephemeral BASE_URL under CLOUD_DEPLOYMENT")
	}
	if !strings.Contains(err.Error(), "BASE_URL") {
		t.Errorf("error should name BASE_URL, got: %v", err)
	}
}

func TestLoad_TrustedProxies_DefaultLoopback(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test")
	t.Setenv("SESSION_SECRET", "test-secret")
	t.Setenv("TRUSTED_PROXIES", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[0] != "127.0.0.1/8" || cfg.TrustedProxies[1] != "::1/128" {
		t.Errorf("default trusted proxies must be loopback only, got %v", cfg.TrustedProxies)
	}
}

func TestLoad_TrustedProxies_CustomList(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test")
	t.Setenv("SESSION_SECRET", "test-secret")
	// Mixed CIDR + bare IP, with sloppy spacing — the operator-typed shape.
	t.Setenv("TRUSTED_PROXIES", " 10.0.0.0/8 , 192.168.1.7 ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[0] != "10.0.0.0/8" || cfg.TrustedProxies[1] != "192.168.1.7" {
		t.Errorf("expected [10.0.0.0/8 192.168.1.7], got %v", cfg.TrustedProxies)
	}
}

func TestLoad_TrustedProxies_InvalidEntryFailsBoot(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test")
	t.Setenv("SESSION_SECRET", "test-secret")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8,not-a-cidr")

	_, err := Load()
	if err == nil {
		t.Fatal("a typo'd TRUSTED_PROXIES entry must fail the boot loudly, not silently trust the wrong peers")
	}
	for _, want := range []string{"TRUSTED_PROXIES", "not-a-cidr"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should contain %q, got: %v", want, err)
		}
	}
}

func TestLoad_TrustedProxies_AllTrustingCIDRRefused(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		t.Run(cidr, func(t *testing.T) {
			t.Setenv("DATABASE_URL", "postgres://test")
			t.Setenv("SESSION_SECRET", "test-secret")
			t.Setenv("TRUSTED_PROXIES", cidr)

			_, err := Load()
			if err == nil {
				t.Fatalf("%s trusts every peer (X-Forwarded-For becomes client-forgeable) and must be refused at boot", cidr)
			}
			if !strings.Contains(err.Error(), "forgeable") {
				t.Errorf("refusal should explain the forgeability risk, got: %v", err)
			}
		})
	}
}

func TestLoad_TrustedProxies_OnlySeparatorsFailsBoot(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test")
	t.Setenv("SESSION_SECRET", "test-secret")
	t.Setenv("TRUSTED_PROXIES", " , ,")

	_, err := Load()
	if err == nil {
		t.Fatal("TRUSTED_PROXIES set but empty must fail — it reads as intent to override with nothing")
	}
}
