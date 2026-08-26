/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

// controlPlaneUDPRuntime groups the UDP data-plane subsystems owned by a
// ControlPlane generation: endpoint admission, ingress admission, and the
// QUIC DCID negative cache.
type controlPlaneUDPRuntime struct {
	udpEndpointAdmission udpEndpointAdmissionGate
	udpIngressAdmission  routingEpochIngressGate
	failedQuicDcidCache  *failedQuicDcidCache
}
