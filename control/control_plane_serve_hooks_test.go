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
		ValidateListener:        func(*Listener) error { return nil },
		CommitPreparedDatapath:  commit,
		PublishListenerSockets:  func(*Listener) error { return nil },
		ActivatePreparedRuntime: func() error { return nil },
	})

	hooks := cp.serveLifecycleHooks()
	if hooks.ValidateListener == nil || hooks.CommitPreparedDatapath == nil || hooks.PublishListenerSockets == nil || hooks.ActivatePreparedRuntime == nil {
		t.Fatal("SetServeLifecycleHooks() did not install all hooks")
	}
	restore()
	if hooks := cp.serveLifecycleHooks(); hooks.ValidateListener != nil || hooks.CommitPreparedDatapath != nil || hooks.PublishListenerSockets != nil || hooks.ActivatePreparedRuntime != nil {
		t.Fatalf("serveLifecycleHooks() after restore = %+v, want empty hooks", hooks)
	}
	restore()
}

func TestControlPlaneServeValidatesListenerBeforeLifecycleMutation(t *testing.T) {
	cp := &ControlPlane{}
	hookCalled := false
	cp.SetServeLifecycleHooks(ServeLifecycleHooks{
		CommitPreparedDatapath: func() error {
			hookCalled = true
			return nil
		},
		PublishListenerSockets: func(*Listener) error {
			hookCalled = true
			return nil
		},
		ActivatePreparedRuntime: func() error {
			hookCalled = true
			return nil
		},
	})

	ready := make(chan bool, 1)
	if err := cp.Serve(ready, &Listener{}); err == nil {
		t.Fatal("Serve() error = nil, want invalid listener failure")
	}
	if hookCalled {
		t.Fatal("Serve() ran lifecycle mutation before listener validation")
	}
	select {
	case got := <-ready:
		if got {
			t.Fatal("Serve() reported ready for an invalid listener")
		}
	default:
		t.Fatal("Serve() did not report readiness failure")
	}
}
