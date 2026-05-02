// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsSchemaAlreadyAppliedError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "plain error", err: errors.New("boom"), want: false},
		{name: "duplicate_table", err: &pgconn.PgError{Code: "42P07", Message: `relation "users" already exists`}, want: true},
		{name: "duplicate_object index", err: &pgconn.PgError{Code: "42710", Message: `relation "ix_users_email" already exists`}, want: true},
		{name: "duplicate_column", err: &pgconn.PgError{Code: "42701", Message: `column "x" already exists`}, want: true},
		{name: "duplicate_function", err: &pgconn.PgError{Code: "42723", Message: `function f() already exists`}, want: true},
		{name: "duplicate_schema", err: &pgconn.PgError{Code: "42P06", Message: `schema "s" already exists`}, want: true},
		{name: "wrapped duplicate_table", err: fmt.Errorf("apply schema: %w", &pgconn.PgError{Code: "42P07"}), want: true},
		{name: "undefined_table", err: &pgconn.PgError{Code: "42P01", Message: `relation "users" does not exist`}, want: false},
		{name: "syntax_error", err: &pgconn.PgError{Code: "42601", Message: "syntax error"}, want: false},
		{name: "connection failure", err: &pgconn.PgError{Code: "08006", Message: "connection failure"}, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSchemaAlreadyAppliedError(tc.err); got != tc.want {
				t.Fatalf("isSchemaAlreadyAppliedError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
