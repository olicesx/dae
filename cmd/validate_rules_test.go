/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestValidateRoutingRulesRejectsIllegalRules is the P3-5 regression: `dae
// validate` used to accept any config that parsed, so an illegal rule set (a
// rule the daemon refuses at startup) exited 0. It now dry-runs the run-time
// rule validation chain.
func TestValidateRoutingRulesRejectsIllegalRules(t *testing.T) {
	parse := func(t *testing.T, src string) *config.Config {
		t.Helper()
		sections, err := config_parser.Parse(src)
		require.NoError(t, err)
		conf, err := config.New(sections)
		require.NoError(t, err)
		return conf
	}

	t.Run("unknown function", func(t *testing.T) {
		conf := parse(t, `
global {}
routing {
  domainx(suffix: a.com) -> direct
}
`)
		err := validateRoutingRules(logrus.New(), conf, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown function")
	})

	t.Run("unsupported domain key", func(t *testing.T) {
		conf := parse(t, `
global {}
routing {
  domain(bogus: a.com) -> direct
}
`)
		err := validateRoutingRules(logrus.New(), conf, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported key")
	})

	t.Run("malformed cidr", func(t *testing.T) {
		conf := parse(t, `
global {}
routing {
  ip(1.2.3.4/999) -> direct
}
`)
		err := validateRoutingRules(logrus.New(), conf, nil)
		require.Error(t, err)
	})

	t.Run("unknown outbound group", func(t *testing.T) {
		conf := parse(t, `
global {}
routing {
  domain(suffix: a.com) -> missing_group
}
`)
		err := validateRoutingRules(logrus.New(), conf, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("unknown fallback outbound param", func(t *testing.T) {
		conf := parse(t, `
global {}
routing {
  fallback: direct(bogus: 1)
}
`)
		err := validateRoutingRules(logrus.New(), conf, nil)
		require.Error(t, err)
	})

	t.Run("valid config passes", func(t *testing.T) {
		conf := parse(t, `
global {}
group {
  proxy {
    policy: fixed(0)
    filter: name(keyword: hk)
  }
}
node {
  "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@127.0.0.1:8388"
}
routing {
  domain(suffix: a.com) -> proxy
  pname(curl) -> direct
  fallback: direct
}
`)
		require.NoError(t, validateRoutingRules(logrus.New(), conf, nil))
	})
}

// TestValidateRoutingRulesUsesConfigGroups pins that the dry-run resolves rule
// outbounds against the configured groups (like the matcher builder), not
// against node names or an empty namespace.
func TestValidateRoutingRulesUsesConfigGroups(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
group {
  proxy {
    policy: fixed(0)
    filter: name(keyword: hk)
  }
}
routing {
  domain(suffix: a.com) -> proxy
  fallback: direct
}
`)
	require.NoError(t, err)
	conf, err := config.New(sections)
	require.NoError(t, err)
	require.NoError(t, validateRoutingRules(logrus.New(), conf, nil))
	// A node-only name is not an outbound: the matcher builder resolves rule
	// outbounds against groups, so it must be rejected.
	sections, err = config_parser.Parse(`
global {}
node {
  "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@127.0.0.1:8388"
}
routing {
  domain(suffix: a.com) -> some_tag
  fallback: direct
}
`)
	require.NoError(t, err)
	confWithNode, err := config.New(sections)
	require.NoError(t, err)
	err = validateRoutingRules(logrus.New(), confWithNode, nil)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "some_tag"), err)
}
