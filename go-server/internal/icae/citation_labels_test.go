package icae

import (
	"testing"
)

func TestCitationLabelConstants(t *testing.T) {
	if fmtE2ePair != "%s + %s (end-to-end)" {
		t.Errorf("fmtE2ePair = %q", fmtE2ePair)
	}
	if fmtE2eSingle != "%s (end-to-end)" {
		t.Errorf("fmtE2eSingle = %q", fmtE2eSingle)
	}
}
