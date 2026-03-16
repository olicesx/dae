package dns

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestRequestInterfaceMatcher(t *testing.T) {
	rules := []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{
			Name: consts.Function_Interface,
			Params: []*config_parser.Param{
				{Key: "wan", Val: "0eth"},
			},
		}},
		Outbound: config_parser.Function{Name: "reject"},
	}}
	b, err := NewRequestMatcherBuilder(logrus.New(), rules, map[string]uint8{}, config.FunctionOrString("asis"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	hit, err := m.MatchWithInterface("", 1, routing.InterfaceDirectionOut, "wan.0eth")
	if err != nil {
		t.Fatal(err)
	}
	if hit != consts.DnsRequestOutboundIndex_Reject {
		t.Fatalf("want reject, got %v", hit)
	}
	notHit, err := m.MatchWithInterface("", 1, routing.InterfaceDirectionIn, "wan.0eth")
	if err != nil {
		t.Fatal(err)
	}
	if notHit != consts.DnsRequestOutboundIndex_AsIs {
		t.Fatalf("want asis, got %v", notHit)
	}
}
