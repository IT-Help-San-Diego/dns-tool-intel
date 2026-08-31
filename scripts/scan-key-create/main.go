// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Operator tool: create a batch-scan API key. Run ON THE BOX with the
// DATABASE_URL env set (systemd environment or /etc/dnstool/env):
//
//	go run ./scripts/scan-key-create -label "decay-battery-runner"
//
// The plaintext key is shown ONCE and never stored; only the sha256 lands
// in scan_api_keys. Revocation is a SQL UPDATE (revoked_at=now()).
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	label := flag.String("label", "", "human description for the key (required)")
	flag.Parse()
	if *label == "" {
		fmt.Fprintln(os.Stderr, "usage: scan-key-create -label <description>")
		os.Exit(1)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		fmt.Fprintln(os.Stderr, "key entropy failed:", err)
		os.Exit(1)
	}
	key := "sk_" + hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(key))
	hash := hex.EncodeToString(sum[:])

	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "open failed:", err)
		os.Exit(1)
	}
	defer db.Close()
	var id int
	err = db.QueryRow(
		`INSERT INTO scan_api_keys (label, key_hash) VALUES ($1, $2) RETURNING id`,
		*label, hash,
	).Scan(&id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "insert failed:", err)
		os.Exit(1)
	}
	fmt.Printf("key created (id %d, label %q)\n", id, *label)
	fmt.Println("API KEY (shown ONCE — store it now):")
	fmt.Println(key)
}
