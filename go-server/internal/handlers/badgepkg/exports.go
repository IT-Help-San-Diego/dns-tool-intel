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
// See replit.md § "Test Build Tags (CRITICAL)" → "Sub-Package Test Seam
// Pattern" for the full rule and the audit checklist that must be run before
// splitting code into a new sub-package.
package badgepkg

const (
	HexGreen    = hexGreen
	HexYellow   = hexYellow
	HexRed      = hexRed
	HexScGreen  = hexScGreen
	HexScYellow = hexScYellow
	HexScRed    = hexScRed
	HexDimGrey  = hexDimGrey

	ColorDanger = colorDanger
	ColorGrey   = colorGrey

	MapKeyLightgrey = mapKeyLightgrey

	ProtoMTASTS = protoMTASTS
	ProtoTLSRPT = protoTLSRPT
	ProtoDMARC  = protoDMARC
	ProtoDNSSEC = protoDNSSEC
)
