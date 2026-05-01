// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
//
// exports.go is the constants/variables half of the sub-package test seam.
// Any unexported constant or package-level variable in this sub-package that
// is referenced by a test in a sibling package (typically the parent
// `handlers` package, including its build-tagged suites such as
// `//go:build scientific` or `//go:build coverage`) MUST be re-exported here.
//
// Function and method wrappers belong in the paired testing.go file.
//
// Convention rationale: when the auth split moved helpers out of `handlers/`
// into `authpkg/`, several constants (e.g. googleUserInfoURL, oauthStateCookie)
// became inaccessible to the scientific tag suite, silently breaking
// `go test -tags scientific ./internal/handlers/` until task #95 retrofitted
// these wrappers. See replit.md § "Test Build Tags (CRITICAL)" →
// "Sub-Package Test Seam Pattern" for the full rule and audit checklist.
package authpkg

const (
	OauthStateCookie  = oauthStateCookie
	OauthCVCookie     = oauthCVCookie
	OauthNonceCookie  = oauthNonceCookie
	SessionCookieName = sessionCookieName
	GoogleAuthURL     = googleAuthURL
	GoogleTokenURL    = googleTokenURL
	GoogleUserInfoURL = googleUserInfoURL
	SessionMaxAge     = sessionMaxAge
	OauthHTTPTimeout  = oauthHTTPTimeout
	IatMaxSkew        = iatMaxSkew
)
