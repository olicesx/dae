/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org
 */

package nativeapi

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// providersPath is the providers collection; one provider lives under it.
const providersPath = "/api/v1/providers"

// ProviderCreate limits the contract sets on the request body.
const (
	providerNameMaxRunes = 64
	providerURLMaxBytes  = 4096
	providerIntervalMax  = 31536000
	providerAgentMax     = 256
)

// handleCreateProvider writes one subscription provider into the managed
// configuration. File and inline providers are authored in the configuration
// sources, so only kind subscription is accepted. The engine writes and
// reloads, so the answer is the queued operation, or the provider once it is
// active.
func (s *Server) handleCreateProvider(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	manager := s.providerManager()
	if manager == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "provider management is not supported by this engine")
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, requestID, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var body struct {
		Name           string  `json:"name"`
		Kind           string  `json:"kind"`
		URL            string  `json:"url"`
		UpdateInterval *int    `json:"update_interval"`
		UserAgent      *string `json:"user_agent"`
		Cache          *bool   `json:"cache"`
	}
	if err := decodeLimitedJSON(r, s.cfg.MaxJSONBodyBytes, &body); err != nil {
		if err == errLimitedJSONBodyTooLarge {
			writeError(w, requestID, http.StatusRequestEntityTooLarge, codeRequestTooLarge, "The request exceeds a size limit.")
			return
		}
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "invalid JSON body: "+err.Error())
		return
	}
	if body.Name == "" || body.Kind == "" || body.URL == "" {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "name, kind and url are required")
		return
	}
	if body.Kind != "subscription" {
		writeError(w, requestID, http.StatusUnprocessableEntity, codeUnsupportedValue,
			"Only a subscription provider can be created here; file and inline providers are authored in the configuration.")
		return
	}
	if err := validateProviderName(body.Name); err != nil {
		writeError(w, requestID, http.StatusUnprocessableEntity, codeUnsupportedValue, err.Error())
		return
	}
	if !isHTTPURL(body.URL) {
		writeError(w, requestID, http.StatusUnprocessableEntity, codeUnsupportedValue, "The subscription URL must start with http:// or https://.")
		return
	}
	if err := validateProviderCreateOptions(s.providers.ProviderCapabilities(), body.UpdateInterval, body.UserAgent, body.Cache); err != nil {
		writeError(w, requestID, http.StatusUnprocessableEntity, codeUnsupportedValue, err.Error())
		return
	}
	outcome, err := manager.CreateProvider(r.Context(), ProviderCreateRequest{
		Name:           body.Name,
		URL:            body.URL,
		UpdateInterval: body.UpdateInterval,
		UserAgent:      body.UserAgent,
		Cache:          body.Cache,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if outcome.Provider != nil {
		w.Header().Set("Location", providersPath+"/"+outcome.Provider.ID)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, *outcome.Provider)
		return
	}
	writeAccepted(w, outcome.Accepted)
}

// handleDeleteProvider removes one subscription or file provider from the
// managed configuration. The engine writes and reloads, so the answer is the
// queued operation; an id that names nothing answers 200 with deleted 0.
func (s *Server) handleDeleteProvider(w http.ResponseWriter, r *http.Request, providerID string) {
	requestID := requestIDFromContext(r.Context())
	manager := s.providerManager()
	if manager == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "provider management is not supported by this engine")
		return
	}
	outcome, err := manager.DeleteProvider(r.Context(), ProviderDeleteRequest{
		ProviderID:     providerID,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if outcome.Deleted == 0 {
		writeJSON(w, http.StatusOK, map[string]int{"deleted": 0})
		return
	}
	writeAccepted(w, outcome.Accepted)
}

// providerManager returns the provider's management surface, or nil when
// providers cannot be written. Both the capability and the method set have to
// say so: a provider that advertises management without implementing it would
// otherwise answer 500 on the first write.
func (s *Server) providerManager() ProviderManager {
	if s.providers == nil || !s.providers.ProviderCapabilities().CanManage {
		return nil
	}
	manager, ok := s.providers.(ProviderManager)
	if !ok {
		return nil
	}
	return manager
}

// validateProviderName keeps a name the configuration can carry as a tag. Any
// text without control characters is accepted; the editor quotes what a bare
// key cannot hold.
func validateProviderName(name string) error {
	if count := utf8.RuneCountInString(name); count < 1 || count > providerNameMaxRunes {
		return fmt.Errorf("name must be 1-64 characters, got %d", count)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("name must not contain control characters")
		}
	}
	return nil
}

// isHTTPURL reports whether raw is an http or https URL with a host.
func isHTTPURL(raw string) bool {
	if len(raw) > providerURLMaxBytes {
		return false
	}
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Host != ""
}

// validateProviderCreateOptions accepts an optional field only when the
// engine lists it in create_options, and checks the value against the limits
// the contract sets.
func validateProviderCreateOptions(caps ProviderCapabilities, interval *int, agent *string, cache *bool) error {
	listed := func(field string) bool {
		_, ok := caps.CreateOptions[field]
		return ok
	}
	if interval != nil {
		if !listed("update_interval") {
			return fmt.Errorf("update_interval is not supported by this engine")
		}
		if *interval < 0 || *interval > providerIntervalMax {
			return fmt.Errorf("update_interval must be 0..%d seconds", providerIntervalMax)
		}
	}
	if agent != nil {
		if !listed("user_agent") {
			return fmt.Errorf("user_agent is not supported by this engine")
		}
		if len(*agent) < 1 || len(*agent) > providerAgentMax {
			return fmt.Errorf("user_agent must be 1-256 characters")
		}
		for i := 0; i < len(*agent); i++ {
			if (*agent)[i] < 0x20 || (*agent)[i] > 0x7e {
				return fmt.Errorf("user_agent must be printable ASCII")
			}
		}
	}
	if cache != nil && !listed("cache") {
		return fmt.Errorf("cache is not supported by this engine")
	}
	return nil
}
