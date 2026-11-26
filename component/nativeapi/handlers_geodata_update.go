/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import "net/http"

const geoDataUpdatePath = BasePath + "/geodata/update"

func (s *Server) geoDataSettingsCapabilities() *GeoDataSettingsCapabilities {
	if provider, ok := s.runtimeSettings.(GeoDataSettingsProvider); ok && s.geodata != nil {
		return provider.GeoDataSettingsCapabilities()
	}
	return nil
}

func (s *Server) handleGeoDataUpdate(w http.ResponseWriter, r *http.Request) {
	id := requestIDFromContext(r.Context())
	provider, ok := s.geodata.(GeoDataUpdateProvider)
	if !ok || s.operations == nil || !provider.GeoDataUpdateAvailable() {
		writeError(w, id, http.StatusNotFound, codeCapabilityNotSupported, "geodata updates are not available")
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, id, http.MethodPost)
		return
	}
	if s.cfg.Secret == "" {
		writeError(w, id, http.StatusForbidden, codePermissionDenied, "geodata updates require a credential")
		return
	}
	if r.Body != nil && r.ContentLength != 0 {
		writeError(w, id, http.StatusBadRequest, codeInvalidRequest, "geodata update takes no request body")
		return
	}
	accepted, err := provider.StartGeoDataUpdate(r.Context(), r.Method+" "+r.URL.Path, r.Header.Get("Idempotency-Key"))
	if err != nil {
		s.writeProviderFailure(w, id, err)
		return
	}
	writeAccepted(w, accepted)
}
