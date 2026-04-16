// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package authpkg

import (
        "context"

        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

func (h *AuthHandler) DetermineRole(ctx context.Context, email string) (string, bool) {
        return h.determineRole(ctx, email)
}

func (h *AuthHandler) BootstrapAdminIfNeeded(ctx context.Context, userID int32, currentRole string, shouldBootstrap bool, email string) string {
        return h.bootstrapAdminIfNeeded(ctx, userID, currentRole, shouldBootstrap, email)
}

func (h *AuthHandler) SeedAdminWatchlist(ctx context.Context, userID int32) {
        h.seedAdminWatchlist(ctx, userID)
}

func (h *AuthHandler) SeedDiscordEndpoint(ctx context.Context, userID int32) {
        h.seedDiscordEndpoint(ctx, userID)
}

func (h *AuthHandler) CreateUserSession(ctx context.Context, userID int32) (string, error) {
        return h.createUserSession(ctx, userID)
}

func (h *AuthHandler) FinalizeLogin(c *gin.Context, sessionID string, user dbq.User, name, email string) {
        h.finalizeLogin(c, sessionID, user, name, email)
}

func ComputeCodeChallenge(verifier string) string {
        return computeCodeChallenge(verifier)
}

func GenerateRandomBase64URL(n int) (string, error) {
        return generateRandomBase64URL(n)
}

func GenerateSessionID() (string, error) {
        return generateSessionID()
}

func ExtractUserClaims(userInfo map[string]any) (string, string, string, bool) {
        return extractUserClaims(userInfo)
}

func ParseIDTokenPayload(idTokenStr string) (map[string]any, error) {
        return parseIDTokenPayload(idTokenStr)
}

func ValidateIDTokenIssuerAndAudience(claims map[string]any, expectedClientID string) error {
        return validateIDTokenIssuerAndAudience(claims, expectedClientID)
}

func ValidateIDTokenTiming(claims map[string]any) error {
        return validateIDTokenTiming(claims)
}

func ValidateIDTokenNonce(claims map[string]any, expectedNonce string) error {
        return validateIDTokenNonce(claims, expectedNonce)
}

func ExtractOAuthCallbackParams(c *gin.Context) (string, string, string, string, bool) {
        return extractOAuthCallbackParams(c)
}
