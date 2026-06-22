// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package contentpkg

import (
	"net/http"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

type TemplateDataFunc func(c *gin.Context, cfg *config.Config, activePage string) gin.H

type AboutHandler struct {
	Config       *config.Config
	TemplateData TemplateDataFunc
}

func NewAboutHandler(cfg *config.Config, tdf TemplateDataFunc) *AboutHandler {
	return &AboutHandler{Config: cfg, TemplateData: tdf}
}

func (h *AboutHandler) About(c *gin.Context) {
	data := h.TemplateData(c, h.Config, "about")
	c.HTML(http.StatusOK, "about.html", data)
}

type ApproachHandler struct {
	Config       *config.Config
	TemplateData TemplateDataFunc
}

func NewApproachHandler(cfg *config.Config, tdf TemplateDataFunc) *ApproachHandler {
	return &ApproachHandler{Config: cfg, TemplateData: tdf}
}

func (h *ApproachHandler) Approach(c *gin.Context) {
	data := h.TemplateData(c, h.Config, "approach")
	data["YouTubeID"] = h.Config.YouTubeVideoIDs["forgotten-domain"]
	c.HTML(http.StatusOK, "approach.html", data)
}

type ArchitectureHandler struct {
	Config       *config.Config
	TemplateData TemplateDataFunc
}

func NewArchitectureHandler(cfg *config.Config, tdf TemplateDataFunc) *ArchitectureHandler {
	return &ArchitectureHandler{Config: cfg, TemplateData: tdf}
}

func (h *ArchitectureHandler) Architecture(c *gin.Context) {
	data := h.TemplateData(c, h.Config, "architecture")
	c.HTML(http.StatusOK, "architecture.html", data)
}

type ColorScienceHandler struct {
	Config       *config.Config
	TemplateData TemplateDataFunc
}

func NewColorScienceHandler(cfg *config.Config, tdf TemplateDataFunc) *ColorScienceHandler {
	return &ColorScienceHandler{Config: cfg, TemplateData: tdf}
}

func (h *ColorScienceHandler) ColorScience(c *gin.Context) {
	data := h.TemplateData(c, h.Config, "color-science")
	c.HTML(http.StatusOK, "color_science.html", data)
}

type CommunicationStandardsHandler struct {
	Config       *config.Config
	TemplateData TemplateDataFunc
}

func NewCommunicationStandardsHandler(cfg *config.Config, tdf TemplateDataFunc) *CommunicationStandardsHandler {
	return &CommunicationStandardsHandler{Config: cfg, TemplateData: tdf}
}

func (h *CommunicationStandardsHandler) CommunicationStandards(c *gin.Context) {
	data := h.TemplateData(c, h.Config, "communication-standards")
	c.HTML(http.StatusOK, "communication_standards.html", data)
}

type ContactHandler struct {
	Config       *config.Config
	TemplateData TemplateDataFunc
}

func NewContactHandler(cfg *config.Config, tdf TemplateDataFunc) *ContactHandler {
	return &ContactHandler{Config: cfg, TemplateData: tdf}
}

func (h *ContactHandler) Contact(c *gin.Context) {
	data := h.TemplateData(c, h.Config, "contact")
	c.HTML(http.StatusOK, "contact.html", data)
}

type FAQHandler struct {
	Config       *config.Config
	TemplateData TemplateDataFunc
}

func NewFAQHandler(cfg *config.Config, tdf TemplateDataFunc) *FAQHandler {
	return &FAQHandler{Config: cfg, TemplateData: tdf}
}

func (h *FAQHandler) SubdomainDiscovery(c *gin.Context) {
	data := h.TemplateData(c, h.Config, "faq")
	c.HTML(http.StatusOK, "faq_subdomains.html", data)
}

type ManifestoHandler struct {
	Config       *config.Config
	TemplateData TemplateDataFunc
}

func NewManifestoHandler(cfg *config.Config, tdf TemplateDataFunc) *ManifestoHandler {
	return &ManifestoHandler{Config: cfg, TemplateData: tdf}
}

func (h *ManifestoHandler) Manifesto(c *gin.Context) {
	data := h.TemplateData(c, h.Config, "manifesto")
	c.HTML(http.StatusOK, "manifesto.html", data)
}

type PrivacyHandler struct {
	Config       *config.Config
	TemplateData TemplateDataFunc
}

func NewPrivacyHandler(cfg *config.Config, tdf TemplateDataFunc) *PrivacyHandler {
	return &PrivacyHandler{Config: cfg, TemplateData: tdf}
}

func (h *PrivacyHandler) Privacy(c *gin.Context) {
	data := h.TemplateData(c, h.Config, "privacy")
	c.HTML(http.StatusOK, "privacy.html", data)
}

type ReferenceLibraryHandler struct {
	Config       *config.Config
	TemplateData TemplateDataFunc
}

func NewReferenceLibraryHandler(cfg *config.Config, tdf TemplateDataFunc) *ReferenceLibraryHandler {
	return &ReferenceLibraryHandler{Config: cfg, TemplateData: tdf}
}

func (h *ReferenceLibraryHandler) ReferenceLibrary(c *gin.Context) {
	data := h.TemplateData(c, h.Config, "reference-library")
	c.HTML(http.StatusOK, "reference_library.html", data)
}

type ROEHandler struct {
	Config       *config.Config
	TemplateData TemplateDataFunc
}

func NewROEHandler(cfg *config.Config, tdf TemplateDataFunc) *ROEHandler {
	return &ROEHandler{Config: cfg, TemplateData: tdf}
}

func (h *ROEHandler) ROE(c *gin.Context) {
	data := h.TemplateData(c, h.Config, "roe")
	c.HTML(http.StatusOK, "roe.html", data)
}

type SecurityPolicyHandler struct {
	Config       *config.Config
	TemplateData TemplateDataFunc
}

func NewSecurityPolicyHandler(cfg *config.Config, tdf TemplateDataFunc) *SecurityPolicyHandler {
	return &SecurityPolicyHandler{Config: cfg, TemplateData: tdf}
}

func (h *SecurityPolicyHandler) SecurityPolicy(c *gin.Context) {
	data := h.TemplateData(c, h.Config, "security-policy")
	c.HTML(http.StatusOK, "security_policy.html", data)
}
