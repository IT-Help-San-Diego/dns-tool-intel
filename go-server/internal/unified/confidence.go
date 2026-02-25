package unified

import (
	"fmt"
	"math"
)

const (
	LevelHigh     = "HIGH"
	LevelModerate = "MODERATE"
	LevelLow      = "LOW"

	ThresholdHigh     = 75.0
	ThresholdModerate = 50.0
)

var maturityCeilings = map[string]float64{
	"development": 60,
	"verified":    75,
	"consistent":  85,
	"gold":        95,
	"gold_master": 100,
}

var levelBootstrapClass = map[string]string{
	LevelHigh:     "success",
	LevelModerate: "warning",
	LevelLow:      "danger",
}

var levelIcons = map[string]string{
	LevelHigh:     "fa-shield-alt",
	LevelModerate: "fa-exclamation-triangle",
	LevelLow:      "fa-times-circle",
}

type UnifiedConfidence struct {
	Level             string  `json:"level"`
	Score             float64 `json:"score"`
	AccuracyFactor    float64 `json:"accuracy_factor"`
	CurrencyFactor    float64 `json:"currency_factor"`
	MaturityCeiling   float64 `json:"maturity_ceiling"`
	MaturityLevel     string  `json:"maturity_level"`
	WeakestLink       string  `json:"weakest_link"`
	WeakestDetail     string  `json:"weakest_detail"`
	Explanation       string  `json:"explanation"`
	ProtocolCount     int     `json:"protocol_count"`
}

func (uc UnifiedConfidence) BootstrapClass() string {
	if c, ok := levelBootstrapClass[uc.Level]; ok {
		return c
	}
	return "secondary"
}

func (uc UnifiedConfidence) Icon() string {
	if i, ok := levelIcons[uc.Level]; ok {
		return i
	}
	return "fa-question-circle"
}

func (uc UnifiedConfidence) ScoreDisplay() string {
	return fmt.Sprintf("%.0f", uc.Score)
}

func (uc UnifiedConfidence) AccuracyDisplay() string {
	return fmt.Sprintf("%.0f%%", uc.AccuracyFactor)
}

func (uc UnifiedConfidence) CurrencyDisplay() string {
	return fmt.Sprintf("%.0f", uc.CurrencyFactor)
}

type Input struct {
	CalibratedConfidence map[string]float64
	CurrencyScore        float64
	MaturityLevel        string
}

func ComputeUnifiedConfidence(input Input) UnifiedConfidence {
	accuracyFactor := computeAccuracyFactor(input.CalibratedConfidence)

	currencyFactor := input.CurrencyScore
	if currencyFactor < 0 {
		currencyFactor = 0
	}
	if currencyFactor > 100 {
		currencyFactor = 100
	}

	ceiling := maturityCeiling(input.MaturityLevel)

	rawScore := geometricMean(accuracyFactor, currencyFactor)

	score := math.Min(rawScore, ceiling)

	score = math.Round(score*10) / 10

	level := scoreToLevel(score)

	weakest, weakestDetail := identifyWeakestLink(accuracyFactor, currencyFactor, ceiling)

	explanation := buildExplanation(level, accuracyFactor, currencyFactor, input.MaturityLevel, weakest)

	return UnifiedConfidence{
		Level:           level,
		Score:           score,
		AccuracyFactor:  math.Round(accuracyFactor*10) / 10,
		CurrencyFactor:  math.Round(currencyFactor*10) / 10,
		MaturityCeiling: ceiling,
		MaturityLevel:   input.MaturityLevel,
		WeakestLink:     weakest,
		WeakestDetail:   weakestDetail,
		Explanation:     explanation,
		ProtocolCount:   len(input.CalibratedConfidence),
	}
}

func computeAccuracyFactor(calibrated map[string]float64) float64 {
	if len(calibrated) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range calibrated {
		sum += v
	}
	mean := sum / float64(len(calibrated))
	return mean * 100
}

func maturityCeiling(level string) float64 {
	if c, ok := maturityCeilings[level]; ok {
		return c
	}
	return 60
}

func geometricMean(a, b float64) float64 {
	if a <= 0 || b <= 0 {
		return 0
	}
	return math.Sqrt(a * b)
}

func scoreToLevel(score float64) string {
	if score >= ThresholdHigh {
		return LevelHigh
	}
	if score >= ThresholdModerate {
		return LevelModerate
	}
	return LevelLow
}

func identifyWeakestLink(accuracy, currency, ceiling float64) (string, string) {
	factors := []struct {
		name   string
		value  float64
		detail string
	}{
		{"accuracy", accuracy, "Resolver agreement is low for this scan — some protocols returned inconsistent results across resolvers"},
		{"currency", currency, "Data currency is degraded — some records may be stale, incomplete, or inconsistent with authoritative sources"},
		{"maturity", ceiling, "System maturity is still developing — more scan history is needed to reach higher confidence tiers"},
	}

	weakest := factors[0]
	for _, f := range factors[1:] {
		if f.value < weakest.value {
			weakest = f
		}
	}
	return weakest.name, weakest.detail
}

func buildExplanation(level string, accuracy, currency float64, maturity, weakest string) string {
	switch level {
	case LevelHigh:
		return "Strong resolver agreement, fresh and complete data, and proven measurement tooling support high confidence in this analysis."
	case LevelModerate:
		switch weakest {
		case "accuracy":
			return "Resolver agreement is inconsistent for some protocols, limiting confidence. Data currency and system maturity are adequate."
		case "currency":
			return "Some DNS data may be stale or incomplete, limiting confidence. Resolver agreement and system maturity are adequate."
		case "maturity":
			return "The measurement system is still accumulating scan history. Accuracy and currency are adequate but the system has not yet reached full maturity."
		default:
			return "Confidence is moderate — one or more factors are below the high-confidence threshold."
		}
	default:
		switch weakest {
		case "accuracy":
			return "Significant disagreement between resolvers undermines confidence in the analysis results."
		case "currency":
			return "DNS data appears stale or substantially incomplete, undermining confidence in the analysis results."
		case "maturity":
			return "The measurement system is in early development with limited scan history."
		default:
			return "Multiple factors are below the confidence threshold."
		}
	}
}
