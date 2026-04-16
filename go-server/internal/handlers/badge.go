// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "strings"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/handlers/badgepkg"

        "github.com/gin-gonic/gin"
)

type BadgeHandler = badgepkg.BadgeHandler

func NewBadgeHandler(database *db.Database, cfg *config.Config) *BadgeHandler {
        return badgepkg.NewBadgeHandler(database, cfg, NewTemplateData)
}

func NewBadgeHandlerWithStore(s badgepkg.LookupStore, cfg *config.Config) *BadgeHandler {
        return badgepkg.NewBadgeHandlerWithStore(s, cfg, nil)
}

func unmarshalResults(fullResults []byte, caller string) map[string]any {
        return badgepkg.UnmarshalResults(fullResults, caller)
}

func extractPostureRisk(results map[string]any) (string, string) {
        return badgepkg.ExtractPostureRisk(results)
}

func riskColorToHex(color string) string {
        return badgepkg.RiskColorToHex(color)
}

func normalizeRiskColor(label, color string) string {
        return badgepkg.NormalizeRiskColor(label, color)
}

func reportRiskColor(color string) string {
        return badgepkg.ReportRiskColor(color)
}

func scotopicRiskColor(color string) string {
        return badgepkg.ScotopicRiskColor(color)
}

func badgeSVG(label, value, color string) []byte {
        return badgepkg.BadgeSVG(label, value, color)
}

func shieldsErrorJSON(msg string, isError bool) gin.H {
        return badgepkg.ShieldsErrorJSON(msg, isError)
}

func riskColorToShields(color string) string {
        return badgepkg.RiskColorToShields(color)
}

func covertRiskLabel(riskLabel string) string {
        return badgepkg.CovertRiskLabel(riskLabel)
}

func covertTagline(riskLabel string) string {
        return badgepkg.CovertTagline(riskLabel)
}

func riskBorderColor(riskColorName string) string {
        return badgepkg.RiskBorderColor(riskColorName)
}

type protocolNode = badgepkg.ProtocolNode

func countMissing(nodes []protocolNode) int {
        return badgepkg.CountMissing(nodes)
}

func countVulnerable(nodes []protocolNode) int {
        return badgepkg.CountVulnerable(nodes)
}

func covertProtocolLine(abbrev, status string) badgepkg.CovertLine {
        return badgepkg.CovertProtocolLine(abbrev, status)
}

func covertSummaryLines(p badgepkg.CovertSummaryParams) []badgepkg.CovertLine {
        return badgepkg.CovertSummaryLines(p)
}

func badgeSVGCovert(domain string, results map[string]any, scanTime time.Time, scanID int32, postureHash string, baseURL string) []byte {
        return badgepkg.BadgeSVGCovert(domain, results, scanTime, scanID, postureHash, baseURL)
}

func badgeSVGDetailed(domain string, results map[string]any, scanTime time.Time, scanID int32, postureHash, baseURL string) []byte {
        return badgepkg.BadgeSVGDetailed(domain, results, scanTime, scanID, postureHash, baseURL)
}

func pluralS(n int) string {
        return badgepkg.PluralS(n)
}

func protocolGroupColor(abbrev string) string {
        return badgepkg.ProtocolGroupColor(abbrev)
}

func extractProtocolIndicators(results map[string]any) []protocolNode {
        return badgepkg.ExtractProtocolIndicators(results)
}

type exposureFinding = badgepkg.ExposureFinding
type exposureData = badgepkg.ExposureData

func extractExposure(results map[string]any) exposureData {
        return badgepkg.ExtractExposure(results)
}

func extractPostureScore(results map[string]any) int {
        return badgepkg.ExtractPostureScore(results)
}

func scoreColor(score int) string {
        return badgepkg.ScoreColor(score)
}

func isGatewayDerivedResult(results map[string]any) bool {
        return badgepkg.IsGatewayDerivedResult(results)
}

func extractWeb3Status(results map[string]any) string {
        return badgepkg.ExtractWeb3Status(results)
}

func buildPostureContext(nodes []protocolNode, missing, controlCount int) string {
        return badgepkg.BuildPostureContext(nodes, missing, controlCount)
}

func firstMissingProtocol(nodes []protocolNode) string {
        return badgepkg.FirstMissingProtocol(nodes)
}

type nodePos = badgepkg.NodePos
type topoEdge = badgepkg.TopoEdge
type topoNodeStyle = badgepkg.TopoNodeStyle
type covertLine = badgepkg.CovertLine
type covertDesc = badgepkg.CovertDesc
type covertRenderCtx = badgepkg.CovertRenderCtx
type covertSummaryParams = badgepkg.CovertSummaryParams

func renderTopoEdges(svg *strings.Builder, edges []topoEdge, nodes []protocolNode, positions []nodePos, nodeR int) {
        badgepkg.RenderTopoEdges(svg, edges, nodes, positions, nodeR)
}

func renderTopoNodes(nodeSVG, glowDefs *strings.Builder, nodes []protocolNode, positions []nodePos, nodeR int) {
        badgepkg.RenderTopoNodes(nodeSVG, glowDefs, nodes, positions, nodeR)
}

func topoNodeStyleFor(n protocolNode) topoNodeStyle {
        return badgepkg.TopoNodeStyleFor(n)
}

func abbrevFontSize(abbrev string) int {
        return badgepkg.AbbrevFontSize(abbrev)
}

func topoEdgeColors(dn protocolNode) (string, string, float64, string) {
        return badgepkg.TopoEdgeColors(dn)
}

func renderArrowHead(svg *strings.Builder, fp, tp nodePos, nodeR int, lineColor, lineOpacity string) {
        badgepkg.RenderArrowHead(svg, fp, tp, nodeR, lineColor, lineOpacity)
}

func covertStatusPrefix(status string) string {
        return badgepkg.CovertStatusPrefix(status)
}

func covertExposureLines(exposure exposureData, sRed, alt, baseURL string, scanID int32) []covertLine {
        return badgepkg.CovertExposureLines(exposure, sRed, alt, baseURL, scanID)
}

func covertPrefixColor(prefix, dimLocked, sRed, alt string) string {
        return badgepkg.CovertPrefixColor(prefix, dimLocked, sRed, alt)
}

func renderCovertLines(svg *strings.Builder, lines []covertLine, startY int, rc covertRenderCtx) (int, int) {
        return badgepkg.RenderCovertLines(svg, lines, startY, rc)
}

func renderCovertLineText(svg *strings.Builder, line covertLine, y int, pfxColor, color string, rc covertRenderCtx) {
        badgepkg.RenderCovertLineText(svg, line, y, pfxColor, color, rc)
}

func renderCovertFooter(svg *strings.Builder, lineIdx, y int, rc covertRenderCtx, domainDisplay, scanTimeStr string) {
        badgepkg.RenderCovertFooter(svg, lineIdx, y, rc, domainDisplay, scanTimeStr)
}

func protocolStatusToNodeColor(status, groupColor string) string {
        return badgepkg.ProtocolStatusToNodeColor(status, groupColor)
}

func covertSeverityTag(severity string) string {
        return badgepkg.CovertSeverityTag(severity)
}
