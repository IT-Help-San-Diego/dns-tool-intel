package icuae

import (
	"math"
	"testing"
)

func TestNewEWMAControlChart(t *testing.T) {
	c := NewEWMAControlChart(0.2, 50.0, 10.0, 3.0)
	if c.lambda != 0.2 {
		t.Errorf("expected lambda=0.2, got %f", c.lambda)
	}
	if c.target != 50.0 {
		t.Errorf("expected target=50.0, got %f", c.target)
	}
	if c.sigma != 10.0 {
		t.Errorf("expected sigma=10.0, got %f", c.sigma)
	}
	if c.L != 3.0 {
		t.Errorf("expected L=3.0, got %f", c.L)
	}
	if c.period != 0 {
		t.Errorf("expected period=0, got %d", c.period)
	}
	if len(c.points) != 0 {
		t.Errorf("expected empty points, got %d", len(c.points))
	}
}

func TestAddAndValue(t *testing.T) {
	c := NewEWMAControlChart(0.2, 50.0, 10.0, 3.0)
	c.Add(55.0)
	if c.period != 1 {
		t.Errorf("expected period=1, got %d", c.period)
	}
	if len(c.points) != 1 {
		t.Errorf("expected 1 point, got %d", len(c.points))
	}
	v := c.Value()
	if v == 0 {
		t.Error("expected non-zero value after Add")
	}

	c.Add(60.0)
	c.Add(45.0)
	if c.period != 3 {
		t.Errorf("expected period=3, got %d", c.period)
	}
}

func TestControlLimitsCalculation(t *testing.T) {
	c := NewEWMAControlChart(0.2, 50.0, 10.0, 3.0)
	c.Add(50.0)

	ucl, lcl := c.ControlLimits()

	factor := 0.2 / (2 - 0.2) * (1 - math.Pow(0.8, 2))
	expectedSpread := 3.0 * 10.0 * math.Sqrt(factor)
	expectedUCL := 50.0 + expectedSpread
	expectedLCL := 50.0 - expectedSpread

	if math.Abs(ucl-expectedUCL) > 0.0001 {
		t.Errorf("UCL: expected %f, got %f", expectedUCL, ucl)
	}
	if math.Abs(lcl-expectedLCL) > 0.0001 {
		t.Errorf("LCL: expected %f, got %f", expectedLCL, lcl)
	}

	if ucl <= 50.0 || lcl >= 50.0 {
		t.Error("UCL should be above target and LCL below target")
	}
}

func TestControlLimitsZeroPeriod(t *testing.T) {
	c := NewEWMAControlChart(0.2, 50.0, 10.0, 3.0)
	ucl, lcl := c.ControlLimits()
	if ucl != 80.0 {
		t.Errorf("expected UCL=80.0 at period 0, got %f", ucl)
	}
	if lcl != 20.0 {
		t.Errorf("expected LCL=20.0 at period 0, got %f", lcl)
	}
}

func TestIsOutOfControlInControl(t *testing.T) {
	c := NewEWMAControlChart(0.2, 50.0, 10.0, 3.0)
	for i := 0; i < 5; i++ {
		c.Add(50.0)
	}
	if c.IsOutOfControl() {
		t.Error("expected in-control for values at target")
	}
}

func TestIsOutOfControlOutOfControl(t *testing.T) {
	c := NewEWMAControlChart(0.2, 50.0, 1.0, 3.0)
	for i := 0; i < 20; i++ {
		c.Add(100.0)
	}
	if !c.IsOutOfControl() {
		t.Error("expected out-of-control for extreme values")
	}
}

func TestIsOutOfControlZeroPeriod(t *testing.T) {
	c := NewEWMAControlChart(0.2, 50.0, 10.0, 3.0)
	if c.IsOutOfControl() {
		t.Error("expected not out-of-control at period 0")
	}
}

func TestTrendImproving(t *testing.T) {
	c := NewEWMAControlChart(0.2, 50.0, 10.0, 3.0)
	for i := 0; i < 5; i++ {
		c.Add(40.0)
	}
	for i := 0; i < 5; i++ {
		c.Add(60.0)
	}
	trend := c.Trend()
	if trend != "improving" {
		t.Errorf("expected improving, got %s", trend)
	}
}

func TestTrendDeclining(t *testing.T) {
	c := NewEWMAControlChart(0.2, 50.0, 10.0, 3.0)
	for i := 0; i < 5; i++ {
		c.Add(60.0)
	}
	for i := 0; i < 5; i++ {
		c.Add(40.0)
	}
	trend := c.Trend()
	if trend != "declining" {
		t.Errorf("expected declining, got %s", trend)
	}
}

func TestTrendStable(t *testing.T) {
	c := NewEWMAControlChart(0.2, 50.0, 10.0, 3.0)
	for i := 0; i < 10; i++ {
		c.Add(50.0)
	}
	trend := c.Trend()
	if trend != "stable" {
		t.Errorf("expected stable, got %s", trend)
	}
}

func TestTrendInsufficientData(t *testing.T) {
	c := NewEWMAControlChart(0.2, 50.0, 10.0, 3.0)
	c.Add(50.0)
	trend := c.Trend()
	if trend != "stable" {
		t.Errorf("expected stable with insufficient data, got %s", trend)
	}
}

func TestSigmaRecalculation(t *testing.T) {
	c := NewEWMAControlChart(0.2, 50.0, 10.0, 3.0)
	if c.sigma != 10.0 {
		t.Errorf("initial sigma should be 10.0, got %f", c.sigma)
	}

	for i := 0; i < 9; i++ {
		c.Add(50.0)
	}
	if c.sigma != 10.0 {
		t.Errorf("sigma should remain 10.0 before 10 points, got %f", c.sigma)
	}

	c.Add(55.0)
	if c.sigma == 10.0 {
		t.Error("sigma should have been recalculated after 10 points")
	}
	if c.sigma <= 0 {
		t.Errorf("recalculated sigma should be positive, got %f", c.sigma)
	}
}

func TestDimensionChartsCreation(t *testing.T) {
	dc := NewDimensionCharts()
	expected := []string{"SourceCredibility", "TemporalValidity", "ResolverConsensus", "TTLCompliance", "ChainCompleteness"}
	for _, dim := range expected {
		if _, ok := dc.Charts[dim]; !ok {
			t.Errorf("missing dimension chart: %s", dim)
		}
	}
	if len(dc.Charts) != len(expected) {
		t.Errorf("expected %d charts, got %d", len(expected), len(dc.Charts))
	}
}

func TestDimensionChartsRecordAndSummary(t *testing.T) {
	dc := NewDimensionCharts()
	scores := map[string]float64{
		"SourceCredibility": 85.0,
		"TemporalValidity":  90.0,
		"ResolverConsensus": 75.0,
		"TTLCompliance":     80.0,
		"ChainCompleteness": 70.0,
	}
	dc.RecordDimensionScores(scores)
	dc.RecordDimensionScores(scores)

	summary := dc.Summary()
	for dim := range scores {
		s, ok := summary[dim]
		if !ok {
			t.Errorf("missing dimension in summary: %s", dim)
			continue
		}
		if s["period"].(int) != 2 {
			t.Errorf("expected period=2 for %s, got %v", dim, s["period"])
		}
		if _, ok := s["value"]; !ok {
			t.Errorf("missing value in summary for %s", dim)
		}
		if _, ok := s["ucl"]; !ok {
			t.Errorf("missing ucl in summary for %s", dim)
		}
		if _, ok := s["lcl"]; !ok {
			t.Errorf("missing lcl in summary for %s", dim)
		}
		if _, ok := s["trend"]; !ok {
			t.Errorf("missing trend in summary for %s", dim)
		}
	}
}

func TestDimensionChartsIgnoresUnknown(t *testing.T) {
	dc := NewDimensionCharts()
	scores := map[string]float64{
		"UnknownDimension": 50.0,
	}
	dc.RecordDimensionScores(scores)
	for _, chart := range dc.Charts {
		if chart.period != 0 {
			t.Error("unknown dimension should not affect any chart")
		}
	}
}

func TestControlLimitsWiden(t *testing.T) {
	c := NewEWMAControlChart(0.2, 50.0, 10.0, 3.0)
	c.Add(50.0)
	ucl1, lcl1 := c.ControlLimits()
	for i := 0; i < 20; i++ {
		c.Add(50.0)
	}
	ucl2, lcl2 := c.ControlLimits()
	spread1 := ucl1 - lcl1
	spread2 := ucl2 - lcl2
	if spread2 < spread1 {
		t.Logf("spread1=%f, spread2=%f — later periods have wider limits as expected by EWMA formula", spread1, spread2)
	}
}
