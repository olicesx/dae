/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"errors"
	"fmt"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

var ErrNoAliveDialer = fmt.Errorf("no alive dialer")
var ErrFixedDialerNotAlive = fmt.Errorf("fixed dialer is not alive")

type DialerGroup struct {
	netproxy.Dialer

	log  *logrus.Logger
	Name string

	Dialers         []*dialer.Dialer
	aliveDialerSets [6]*dialer.AliveDialerSet
	selectionPolicy *dialer.DialerSelectionPolicy
}

func NewDialerGroup(
	option *dialer.GlobalOption,
	name string,
	dialers []*dialer.Dialer,
	dialersAnnotations []*dialer.Annotation,
	selectionPolicy dialer.DialerSelectionPolicy,
	needAliveState bool,
	aliveChangeCallback func(alive bool, networkType *dialer.NetworkType),
) *DialerGroup {
	if selectionPolicy.FixedIndex < 0 || selectionPolicy.FixedIndex >= len(dialers) {
		panic(fmt.Sprintf("selected dialer index is out of range, group: %v, index: %v", name, selectionPolicy.FixedIndex))
	}

	var aliveDnsTcp4DialerSet *dialer.AliveDialerSet
	var aliveDnsTcp6DialerSet *dialer.AliveDialerSet
	var aliveTcp4DialerSet *dialer.AliveDialerSet
	var aliveTcp6DialerSet *dialer.AliveDialerSet
	var aliveDnsUdp4DialerSet *dialer.AliveDialerSet
	var aliveDnsUdp6DialerSet *dialer.AliveDialerSet

	if needAliveState {
		if option.CheckDnsTcp {
			aliveDnsTcp4DialerSet = dialer.NewAliveDialerSet(option.Log, name, &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_4,
				IsDns:     true,
			}, option.CheckTolerance, selectionPolicy, dialers, dialersAnnotations, func(alive bool, networkType *dialer.NetworkType) {})

			aliveDnsTcp6DialerSet = dialer.NewAliveDialerSet(option.Log, name, &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_6,
				IsDns:     true,
			}, option.CheckTolerance, selectionPolicy, dialers, dialersAnnotations, func(alive bool, networkType *dialer.NetworkType) {})
		}

		aliveTcp4DialerSet = dialer.NewAliveDialerSet(option.Log, name, &dialer.NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_4,
			IsDns:     false,
		}, option.CheckTolerance, selectionPolicy, dialers, dialersAnnotations, aliveChangeCallback)
		aliveTcp6DialerSet = dialer.NewAliveDialerSet(option.Log, name, &dialer.NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_6,
			IsDns:     false,
		}, option.CheckTolerance, selectionPolicy, dialers, dialersAnnotations, aliveChangeCallback)
		aliveDnsUdp4DialerSet = dialer.NewAliveDialerSet(option.Log, name, &dialer.NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_4,
			IsDns:     true,
		}, option.CheckTolerance, selectionPolicy, dialers, dialersAnnotations, aliveChangeCallback)
		aliveDnsUdp6DialerSet = dialer.NewAliveDialerSet(option.Log, name, &dialer.NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_6,
			IsDns:     true,
		}, option.CheckTolerance, selectionPolicy, dialers, dialersAnnotations, aliveChangeCallback)

	}

	for _, d := range dialers {
		d.RegisterAliveDialerSet(aliveTcp4DialerSet)
		d.RegisterAliveDialerSet(aliveTcp6DialerSet)
		d.RegisterAliveDialerSet(aliveDnsTcp4DialerSet)
		d.RegisterAliveDialerSet(aliveDnsTcp6DialerSet)
		d.RegisterAliveDialerSet(aliveDnsUdp4DialerSet)
		d.RegisterAliveDialerSet(aliveDnsUdp6DialerSet)
	}

	return &DialerGroup{
		log:     option.Log,
		Name:    name,
		Dialers: dialers,
		aliveDialerSets: [6]*dialer.AliveDialerSet{
			aliveDnsTcp4DialerSet,
			aliveDnsTcp6DialerSet,
			aliveDnsUdp4DialerSet,
			aliveDnsUdp6DialerSet,
			aliveTcp4DialerSet,
			aliveTcp6DialerSet,
		},
		selectionPolicy: &selectionPolicy,
	}
}

func (g *DialerGroup) Close() error {
	for _, d := range g.Dialers {
		for _, a := range g.aliveDialerSets {
			d.UnregisterAliveDialerSet(a)
		}
	}
	return nil
}

func (g *DialerGroup) SetSelectionPolicy(policy dialer.DialerSelectionPolicy) {
	// TODO:
	g.selectionPolicy = &policy
}

func (g *DialerGroup) GetSelectionPolicy() (policy consts.DialerSelectionPolicy) {
	return g.selectionPolicy.Policy
}

func (d *DialerGroup) MustGetAliveDialerSet(typ *dialer.NetworkType) *dialer.AliveDialerSet {
	if typ.IsDns {
		switch typ.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return d.aliveDialerSets[0]
			case consts.IpVersionStr_6:
				return d.aliveDialerSets[1]
			}
		case consts.L4ProtoStr_UDP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return d.aliveDialerSets[2]
			case consts.IpVersionStr_6:
				return d.aliveDialerSets[3]
			}
		}
	} else {
		switch typ.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return d.aliveDialerSets[4]
			case consts.IpVersionStr_6:
				return d.aliveDialerSets[5]
			}
		case consts.L4ProtoStr_UDP:
			// UDP share the DNS check result.
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return d.aliveDialerSets[2]
			case consts.IpVersionStr_6:
				return d.aliveDialerSets[3]
			}
		}
	}
	panic("invalid param")
}

// SelectFallbackIpVersion selects a dialer from group according to selectionPolicy. If 'strictIpVersion' is false and no alive dialer, it will fallback to another ipversion.
func (g *DialerGroup) SelectFallbackIpVersion(networkType *dialer.NetworkType, strictIpVersion bool) (dialer *dialer.Dialer, latency time.Duration, err error) {
	dialer, latency, err = g.Select(networkType)
	if !strictIpVersion && errors.Is(err, ErrNoAliveDialer) {
		networkType.IpVersion = (consts.IpVersion_X - networkType.IpVersion.ToIpVersionType()).ToIpVersionStr()
		dialer, latency, err = g.Select(networkType)
	}
	return
}

func (g *DialerGroup) Select(networkType *dialer.NetworkType) (dialer *dialer.Dialer, latency time.Duration, err error) {
	if len(g.Dialers) == 0 {
		return nil, 0, fmt.Errorf("no dialer in this group")
	}
	aliveDialerSet := g.MustGetAliveDialerSet(networkType)
	switch g.selectionPolicy.Policy {
	case consts.DialerSelectionPolicy_Fixed:
		dialer = g.Dialers[g.selectionPolicy.FixedIndex]
		latency = 0
	case consts.DialerSelectionPolicy_Random:
		dialer = aliveDialerSet.GetRand()
		latency = 0
	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		dialer, latency = aliveDialerSet.GetMinLatency()
	default:
		return nil, 0, oops.Errorf("unsupported DialerSelectionPolicy: %v", g.selectionPolicy)
	}

	if dialer == nil {
		// No alive dialer.
		return nil, time.Hour, ErrNoAliveDialer
	}
	if aliveDialerSet != nil && !dialer.MustGetAlive(networkType) {
		return nil, time.Hour, ErrFixedDialerNotAlive
	}

	return dialer, latency, nil
}
