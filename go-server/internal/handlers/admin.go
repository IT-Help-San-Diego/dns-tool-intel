// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/handlers/adminpkg"
)

type AdminHandler = adminpkg.AdminHandler
type ProbeAdminHandler = adminpkg.ProbeAdminHandler
type AdminAnalysis = adminpkg.AdminAnalysis
type AdminICAERun = adminpkg.AdminICAERun
type AdminScannerAlert = adminpkg.AdminScannerAlert
type AdminStats = adminpkg.AdminStats
type AdminUser = adminpkg.AdminUser
type CmdRunner = adminpkg.CmdRunner
type CmdRunResult = adminpkg.CmdRunResult

func NewAdminHandler(database *db.Database, cfg *config.Config, bpFunc func() int64) *AdminHandler {
	return adminpkg.NewAdminHandler(database, cfg, NewTemplateData, bpFunc)
}

func NewProbeAdminHandler(database *db.Database, cfg *config.Config) *ProbeAdminHandler {
	return adminpkg.NewProbeAdminHandler(database, cfg, NewTemplateData)
}
