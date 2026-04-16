// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny design
package handlers

import (
        "time"

        "dnstool/go-server/internal/handlers/authpkg"

        "github.com/gin-gonic/gin"
)

type AuthHandler = authpkg.AuthHandler

type AuthStore = authpkg.AuthStore

var NewAuthHandler = authpkg.NewAuthHandler

var NewAuthHandlerWithStore = authpkg.NewAuthHandlerWithStore

func missionCriticalDomainsFromBaseURL(baseURL string) []string {
        return authpkg.MissionCriticalDomainsFromBaseURL(baseURL)
}

func computeCodeChallenge(verifier string) string {
        return authpkg.ComputeCodeChallenge(verifier)
}

func generateRandomBase64URL(n int) (string, error) {
        return authpkg.GenerateRandomBase64URL(n)
}

func generateSessionID() (string, error) {
        return authpkg.GenerateSessionID()
}

func extractUserClaims(userInfo map[string]any) (string, string, string, bool) {
        return authpkg.ExtractUserClaims(userInfo)
}

func parseIDTokenPayload(idTokenStr string) (map[string]any, error) {
        return authpkg.ParseIDTokenPayload(idTokenStr)
}

func validateIDTokenIssuerAndAudience(claims map[string]any, expectedClientID string) error {
        return authpkg.ValidateIDTokenIssuerAndAudience(claims, expectedClientID)
}

func validateIDTokenTiming(claims map[string]any) error {
        return authpkg.ValidateIDTokenTiming(claims)
}

func validateIDTokenNonce(claims map[string]any, expectedNonce string) error {
        return authpkg.ValidateIDTokenNonce(claims, expectedNonce)
}

func extractOAuthCallbackParams(c *gin.Context) (string, string, string, string, bool) {
        return authpkg.ExtractOAuthCallbackParams(c)
}

const (
        oauthStateCookie  = "_oauth_state"
        oauthCVCookie     = "_oauth_cv"
        oauthNonceCookie  = "_oauth_nonce"
        sessionCookieName = "_dns_session"

        googleAuthURL    = "https://accounts.google.com/o/oauth2/v2/auth"
        googleTokenURL   = "https://oauth2.googleapis.com/token"
        sessionMaxAge    = 30 * 24 * 60 * 60
        oauthHTTPTimeout = 10 * time.Second
        iatMaxSkew       = 5 * time.Minute
)
