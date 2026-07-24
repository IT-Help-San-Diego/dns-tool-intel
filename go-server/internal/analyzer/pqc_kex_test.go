// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestClassifyPQCKexTriState(t *testing.T) {
	tests := []struct {
		name        string
		handshakeOK bool
		version     uint16
		curve       tls.CurveID
		wantState   string
		wantSubstr  string
	}{
		{"handshake failure is indeterminate never absent", false, 0, 0, pqcKexIndeterminate, "cannot be determined"},
		{"tls12 x25519 unavailable", true, tls.VersionTLS12, tls.X25519, pqcKexUnavailable, "requires TLS 1.3"},
		{"tls10 unavailable", true, tls.VersionTLS10, 0, pqcKexUnavailable, "requires TLS 1.3"},
		{"tls13 hybrid negotiated", true, tls.VersionTLS13, tls.X25519MLKEM768, pqcKexNegotiated, "FIPS 203"},
		{"tls13 x25519 not selected", true, tls.VersionTLS13, tls.X25519, pqcKexNotSelected, "offered the hybrid group"},
		{"tls13 p256 not selected", true, tls.VersionTLS13, tls.CurveP256, pqcKexNotSelected, "offered the hybrid group"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, detail := classifyPQCKex(tt.handshakeOK, tt.version, tt.curve)
			if state != tt.wantState {
				t.Errorf("state = %q, want %q", state, tt.wantState)
			}
			if !strings.Contains(detail, tt.wantSubstr) {
				t.Errorf("detail %q missing substring %q", detail, tt.wantSubstr)
			}
			if state != pqcKexNegotiated && strings.Contains(detail, "does not support") {
				t.Errorf("detail overclaims lack of support: %q", detail)
			}
		})
	}
}

func TestKeyExchangeLabelStrings(t *testing.T) {
	if got := keyExchangeLabel(0); got != "RSA (legacy key exchange)" {
		t.Errorf("zero curve label = %q", got)
	}
	if got := keyExchangeLabel(tls.X25519MLKEM768); got != tls.X25519MLKEM768.String() {
		t.Errorf("hybrid label = %q, want %q", got, tls.X25519MLKEM768.String())
	}
	if got := keyExchangeLabel(tls.X25519); got != tls.X25519.String() {
		t.Errorf("x25519 label = %q, want %q", got, tls.X25519.String())
	}
}

func genPQCTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pqc-test.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"pqc-test.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestNegotiateTLSCapturesPQCKex(t *testing.T) {
	cert := genPQCTestCert(t)
	tests := []struct {
		name      string
		serverCfg *tls.Config
		wantState string
		wantKex   string
	}{
		{
			name:      "server prefers hybrid group",
			serverCfg: &tls.Config{Certificates: []tls.Certificate{cert}, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}},
			wantState: pqcKexNegotiated,
			wantKex:   tls.X25519MLKEM768.String(),
		},
		{
			name:      "tls13 server forces classical group",
			serverCfg: &tls.Config{Certificates: []tls.Certificate{cert}, CurvePreferences: []tls.CurveID{tls.CurveP256}},
			wantState: pqcKexNotSelected,
			wantKex:   tls.CurveP256.String(),
		},
		{
			name:      "tls12 server",
			serverCfg: &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: tls.VersionTLS12},
			wantState: pqcKexUnavailable,
			wantKex:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()
			srvDone := make(chan error, 1)
			go func() {
				c, acceptErr := ln.Accept()
				if acceptErr != nil {
					srvDone <- acceptErr
					return
				}
				defer c.Close()
				srv := tls.Server(c, tt.serverCfg)
				hsErr := srv.Handshake()
				if hsErr == nil {
					_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))
					buf := make([]byte, 16)
					_, _ = srv.Read(buf)
				}
				srvDone <- hsErr
			}()

			clientConn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer clientConn.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			result := map[string]any{}
			negotiateTLS(ctx, clientConn, "pqc-test.invalid", result)

			if srvErr := <-srvDone; srvErr != nil {
				t.Fatalf("server handshake: %v", srvErr)
			}
			if got, _ := result[mapKeyPqcKexState].(string); got != tt.wantState {
				t.Errorf("pqc_kex_state = %q, want %q", got, tt.wantState)
			}
			detail, _ := result[mapKeyPqcKexDetail].(string)
			if detail == "" {
				t.Error("pqc_kex_detail is empty")
			}
			if tt.wantKex != "" {
				if got, _ := result[mapKeyKeyExchange].(string); got != tt.wantKex {
					t.Errorf("key_exchange = %q, want %q", got, tt.wantKex)
				}
			}
		})
	}
}

func TestNegotiateTLSHandshakeFailureIndeterminate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr == nil {
			_ = c.Close()
		}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := map[string]any{}
	negotiateTLS(ctx, clientConn, "pqc-test.invalid", result)

	if got, _ := result[mapKeyPqcKexState].(string); got != pqcKexIndeterminate {
		t.Errorf("pqc_kex_state = %q, want %q", got, pqcKexIndeterminate)
	}
	if _, hasVersion := result[mapKeyTlsVersion]; hasVersion {
		t.Error("tls_version should not be recorded on failed handshake")
	}
}
