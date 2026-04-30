package botverify

import (
	"fmt"
	"testing"
)

func TestRealBrowserUAs(t *testing.T) {
	uas := []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
	}
	for _, ua := range uas {
		// Empty IP path
		r := classifyUncached(toLower(ua), "", ua)
		fmt.Printf("EMPTY-IP: %-12s | %s\n", r.String(), ua[:80])
		// With IP
		r2 := classifyUncached(toLower(ua), "73.222.110.5", ua)
		fmt.Printf("WITH-IP:  %-12s | %s\n", r2.String(), ua[:80])
		fmt.Println()
	}
}

func toLower(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return string(out)
}
