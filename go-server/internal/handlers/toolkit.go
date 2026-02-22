// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

type ToolkitHandler struct {
	Config *config.Config
}

func NewToolkitHandler(cfg *config.Config) *ToolkitHandler {
	return &ToolkitHandler{Config: cfg}
}

func (h *ToolkitHandler) ToolkitPage(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")
	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":        h.Config.BetaPages,
		"CspNonce":        nonce,
		"CsrfToken":       csrfToken,
		"ActivePage":      "toolkit",
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "toolkit.html", data)
}

func (h *ToolkitHandler) MyIP(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	platform := detectPlatform(userAgent)

	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":        h.Config.BetaPages,
		"CspNonce":        nonce,
		"CsrfToken":       csrfToken,
		"ActivePage":      "toolkit",
		"ClientIP":        clientIP,
		"Platform":        platform,
		"ShowMyIP":        true,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "toolkit.html", data)
}

func (h *ToolkitHandler) PortCheck(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	targetHost := strings.TrimSpace(c.PostForm("target_host"))
	targetPort := strings.TrimSpace(c.PostForm("target_port"))

	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":        h.Config.BetaPages,
		"CspNonce":        nonce,
		"CsrfToken":       csrfToken,
		"ActivePage":      "toolkit",
		"TargetHost":      targetHost,
		"TargetPort":      targetPort,
		"ShowPortCheck":   true,
	}

	if targetHost == "" {
		data["ProbeError"] = "Please enter a target host (IP address or hostname)."
		mergeAuthData(c, h.Config, data)
		c.HTML(http.StatusOK, "toolkit.html", data)
		return
	}

	portNum, err := strconv.Atoi(targetPort)
	if err != nil || portNum < 1 || portNum > 65535 {
		data["ProbeError"] = "Please enter a valid port number between 1 and 65535."
		mergeAuthData(c, h.Config, data)
		c.HTML(http.StatusOK, "toolkit.html", data)
		return
	}

	if h.Config.ProbeAPIURL == "" {
		data["ProbeError"] = "Port check service is not configured."
		mergeAuthData(c, h.Config, data)
		c.HTML(http.StatusOK, "toolkit.html", data)
		return
	}

	probeURL := h.Config.ProbeAPIURL + "/api/v2/tcp-check?host=" + url.QueryEscape(targetHost) + "&port=" + targetPort

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", probeURL, nil)
	if err != nil {
		data["ProbeError"] = "Failed to create request to probe service."
		mergeAuthData(c, h.Config, data)
		c.HTML(http.StatusOK, "toolkit.html", data)
		return
	}

	req.Header.Set("X-Probe-Key", h.Config.ProbeAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		data["ProbeError"] = "Could not connect to the probe service. It may be temporarily unavailable."
		mergeAuthData(c, h.Config, data)
		c.HTML(http.StatusOK, "toolkit.html", data)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		data["ProbeError"] = "Failed to read response from probe service."
		mergeAuthData(c, h.Config, data)
		c.HTML(http.StatusOK, "toolkit.html", data)
		return
	}

	if resp.StatusCode != 200 {
		data["ProbeError"] = fmt.Sprintf("Probe service returned an error (status %d).", resp.StatusCode)
		mergeAuthData(c, h.Config, data)
		c.HTML(http.StatusOK, "toolkit.html", data)
		return
	}

	var probeResult map[string]any
	if err := json.Unmarshal(body, &probeResult); err != nil {
		data["ProbeError"] = "Failed to parse response from probe service."
		mergeAuthData(c, h.Config, data)
		c.HTML(http.StatusOK, "toolkit.html", data)
		return
	}

	data["ProbeResult"] = probeResult
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "toolkit.html", data)
}

func detectPlatform(userAgent string) string {
	ua := strings.ToLower(userAgent)

	if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ipod") {
		return "ios"
	}

	if strings.Contains(ua, "android") {
		return "android"
	}

	if strings.Contains(ua, "mac") {
		return "macos"
	}

	if strings.Contains(ua, "windows") {
		return "windows"
	}

	if strings.Contains(ua, "linux") {
		return "linux"
	}

	return "unknown"
}
