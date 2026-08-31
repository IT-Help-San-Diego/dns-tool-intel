// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package db

import (
	"context"
	"time"
)

// LookupScanKey implements middleware.ScanKeyLookup: read-only, active-keys-only
// (revoked_at IS NULL), sha256-hex exact match. The pool query is deliberately
// inline (not sqlc) — one lookup, one table, and the key-hash column is
// partial-indexed by the migration.
func (d *Database) LookupScanKey(keyHash string) (int32, string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var id int32
	var label string
	err := d.Pool.QueryRow(ctx,
		`SELECT id, label FROM scan_api_keys
		 WHERE key_hash = $1 AND revoked_at IS NULL`,
		keyHash,
	).Scan(&id, &label)
	if err != nil {
		return 0, "", false
	}
	return id, label, true
}

// MarkScanKeyUsed bumps use_count + last_used_at for observability. Best-effort:
// a failure here must never block a scan (the honesty is in the scan, not the
// counter); the error is returned for callers that want to log it.
func (d *Database) MarkScanKeyUsed(ctx context.Context, keyID int32) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE scan_api_keys
		 SET use_count = use_count + 1, last_used_at = now()
		 WHERE id = $1`,
		keyID,
	)
	return err
}
