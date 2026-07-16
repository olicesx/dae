/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

func TestControlPlaneServeLifecycleHooksRestore(t *testing.T) {
	cp := &ControlPlane{}
	commit := func() error { return nil }
	restore := cp.SetServeLifecycleHooks(ServeLifecycleHooks{
		CommitPreparedDatapath:  commit,
		PublishListenerSockets:  func(*Listener) error { return nil },
		ActivatePreparedRuntime: func() error { return nil },
	})

	hooks := cp.serveLifecycleHooks()
	if hooks.CommitPreparedDatapath == nil || hooks.PublishListenerSockets == nil || hooks.ActivatePreparedRuntime == nil {
		t.Fatal("SetServeLifecycleHooks() did not install all hooks")
	}
	restore()
	if hooks := cp.serveLifecycleHooks(); hooks.CommitPreparedDatapath != nil || hooks.PublishListenerSockets != nil || hooks.ActivatePreparedRuntime != nil {
		t.Fatalf("serveLifecycleHooks() after restore = %+v, want empty hooks", hooks)
	}
	restore()
}
