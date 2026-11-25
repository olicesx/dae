/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package netutils

import (
	"testing"

	dnsmessage "github.com/miekg/dns"
)

// The error is the only place a rejected rcode surfaces, so its text is
// pinned as a reader sees it. RcodeToString names the codes the library
// knows; any other one is reported as "unknown", where the number is all
// there is to go on.
func TestDecodeResolvedAnswerRcodeErrorText(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rcode int
		want  string
	}{
		{"servfail", dnsmessage.RcodeServerFailure, "dns rcode SERVFAIL (2)"},
		{"refused", dnsmessage.RcodeRefused, "dns rcode REFUSED (5)"},
		{"code without a name", 12, "dns rcode unknown (12)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, id := packedAnswer(t, tc.rcode, false)
			got := decodeResolvedAnswer(payload, id)
			if got.err == nil {
				t.Fatalf("rcode %d: want an error, got answers %v", tc.rcode, got.ans)
			}
			if got.err.Error() != tc.want {
				t.Fatalf("error text: got %q, want %q", got.err, tc.want)
			}
		})
	}
}
