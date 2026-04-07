package unpack

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

func TestName(t *testing.T) {
	testcases := []struct {
		buf   []byte
		start int
		name  string
		off   int
		mname bool // If true, use MName instead of Name.
	}{
		// Name
		// miek.nl (4 miek 2 nl 0)
		{[]byte{4, 109, 105, 101, 107, 2, 110, 108, 0}, 0, "miek.nl.", 9, false},
		// beginning of a message, ID (98, 24),... then miek.nl as question = 0 15 (mx as type) and 0 01 as
		// class. But then 192 12 which is a pointer to miek.nl, so lets decode that.
		{[]byte{98, 24, 129, 128, 0, 1, 0, 5, 0, 0, 0, 1, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 15, 0, 1, 192, 12, 0}, 25, "miek.nl.", 27, false},

		// MName
		// Wire: 16 "support.norrland" 10 "nordlo.com" 0
		{[]byte{16, 's', 'u', 'p', 'p', 'o', 'r', 't', '.', 'n', 'o', 'r', 'r', 'l', 'a', 'n', 'd', 10, 'n', 'o', 'r', 'd', 'l', 'o', '.', 'c', 'o', 'm', 0}, 0, `support\.norrland.nordlo\.com.`, 29, true},
		// Wire: 16 "support.norrland" 10 "nordlo.com" 0
		{[]byte{16, 's', 'u', 'p', 'p', 'o', 'r', 't', '.', 'n', 'o', 'r', 'r', 'l', 'a', 'n', 'd', 10, 'n', 'o', 'r', 'd', 'l', 'o', '.', 'c', 'o', 'm', 0}, 0, `support\.norrland.nordlo\.com.`, 29, true},
	}
	for i, tc := range testcases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			var (
				name string
				err  error
			)
			s := cryptobyte.String(tc.buf[tc.start:])
			sl := (len(s))
			if tc.mname {
				name, err = MName(&s, tc.buf)
			} else {
				name, err = Name(&s, tc.buf)
			}
			if err != nil {
				t.Fatal(err)
			}
			if off := tc.start + sl - len(s); off != tc.off {
				t.Errorf("expected offset %d, got %d", tc.off, off)
			}
			if name != tc.name {
				t.Errorf("expected name %s, got %s", tc.name, name)
			}
		})
	}
}
